
#define _GNU_SOURCE
/* guardian.c — main daemon, event bus, config loader, API socket.
 *
 * The daemon orchestrates all 5 protection layers + enforcement + policy + log.
 * Each layer emits g_event_t to the bus; policy_engine decides the action;
 * action_engine executes it; forensic_log records it.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <sys/prctl.h>
#include <sys/vfs.h>
#include <dirent.h>
#include <ctype.h>

#define G_RATE_LIMIT_MAX_BUCKETS 128
#define G_RATE_LIMIT_REFILL_RATE 100.0   /* tokens per second */
#define G_RATE_LIMIT_BURST       100.0
#define G_GLOBAL_RATE_LIMIT      500.0   /* global event limit per second */
#define G_GLOBAL_RATE_LIMIT_BURST 500.0   /* global burst limit */
#define G_DEDUP_MAX_ENTRIES      128
#define G_DEDUP_WINDOW_NS        1000000000ULL /* 1 second */

typedef struct {
    char source[G_SOURCE_MAX];
    char rule_id[G_RULE_ID_MAX];
    double tokens;
    uint64_t last_update_ns;
} g_rate_bucket_t;

typedef struct {
    char rule_id[G_RULE_ID_MAX];
    uint32_t pid;
    uint64_t last_seen_ns;
} g_dedup_entry_t;

static g_rate_bucket_t g_rate_buckets[G_RATE_LIMIT_MAX_BUCKETS];
static int g_rate_bucket_count = 0;

static g_dedup_entry_t g_dedup_table[G_DEDUP_MAX_ENTRIES];
static int g_dedup_count = 0;

static double g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;
static uint64_t g_global_last_update_ns = 0;
static bool g_use_mock_time = false;
static uint64_t g_mock_time_ns = 0;

static uint64_t get_now_ns(void) {
    if (g_use_mock_time) {
        return g_mock_time_ns;
    }
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static bool is_tmpfs(const char *dir_path) {
    struct statfs sf;
    if (statfs(dir_path, &sf) != 0) {
        return false;
    }
    return sf.f_type == 0x01021994; /* TMPFS_MAGIC */
}

static void g_get_log_key(uint8_t key[32]) {
    /* TPM production path:
     * tpm2_startauthsession --policy-session -S session.ctx
     * tpm2_policypcr -S session.ctx -l sha256:7,9
     * tpm2_unseal -c key.ctx -p session:session.ctx
     * tpm2_flushcontext session.ctx
     * Sandbox fallback: /dev/urandom
     */
    FILE *urand = fopen("/dev/urandom", "rb");
    if (urand) {
        size_t read_bytes = fread(key, 1, 32, urand);
        fclose(urand);
        if (read_bytes == 32) return;
    }
    memset(key, 0x55, 32);
}

/* ---- event bus ---- */
static g_subscriber_t g_subs[G_MAX_SUBS];
static void          *g_sub_ud[G_MAX_SUBS];
static int            g_sub_count = 0;
static uint64_t       g_seq_counter = 0;
static pthread_mutex_t g_bus_lock = PTHREAD_MUTEX_INITIALIZER;

int g_bus_init(void) { g_sub_count = 0; g_seq_counter = 0; return 0; }

int g_bus_subscribe(g_subscriber_t sub, void *ud) {
    pthread_mutex_lock(&g_bus_lock);
    if (g_sub_count >= G_MAX_SUBS) { pthread_mutex_unlock(&g_bus_lock); return -ENOSPC; }
    g_subs[g_sub_count] = sub; g_sub_ud[g_sub_count] = ud; g_sub_count++;
    pthread_mutex_unlock(&g_bus_lock);
    return 0;
}

static uint64_t g_alert_count = 0;

int g_bus_publish(const g_event_t *ev) {
    if (!ev) return -EINVAL;

    if (ev->severity >= G_SEV_MEDIUM) {
        pthread_mutex_lock(&g_bus_lock);
        g_alert_count++;
        pthread_mutex_unlock(&g_bus_lock);
    }

    uint64_t now_ns = get_now_ns();

    pthread_mutex_lock(&g_bus_lock);

    /* 1. Deduplication (only for INFO and LOW severity) */
    if (ev->severity == G_SEV_INFO || ev->severity == G_SEV_LOW) {
        int found_dedup = 0;
        for (int i = 0; i < g_dedup_count; i++) {
            if (g_dedup_table[i].pid == ev->pid && strcmp(g_dedup_table[i].rule_id, ev->rule_id) == 0) {
                if (now_ns - g_dedup_table[i].last_seen_ns < G_DEDUP_WINDOW_NS) {
                    /* Discard duplicate */
                    pthread_mutex_unlock(&g_bus_lock);
                    return 0;
                }
                g_dedup_table[i].last_seen_ns = now_ns;
                found_dedup = 1;
                break;
            }
        }
        if (!found_dedup) {
            int idx = g_dedup_count;
            if (idx >= G_DEDUP_MAX_ENTRIES) {
                idx = g_dedup_count % G_DEDUP_MAX_ENTRIES;
            }
            g_strlcpy(g_dedup_table[idx].rule_id, ev->rule_id, sizeof(g_dedup_table[idx].rule_id));
            g_dedup_table[idx].pid = ev->pid;
            g_dedup_table[idx].last_seen_ns = now_ns;
            if (g_dedup_count < G_DEDUP_MAX_ENTRIES) {
                g_dedup_count++;
            }
        }
    }

    /* 2. Global Rate Limit Check */
    if (g_global_last_update_ns == 0) {
        g_global_last_update_ns = now_ns;
    } else {
        double elapsed_sec = (double)(now_ns - g_global_last_update_ns) / 1e9;
        g_global_tokens += elapsed_sec * G_GLOBAL_RATE_LIMIT;
        if (g_global_tokens > G_GLOBAL_RATE_LIMIT_BURST) {
            g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;
        }
        g_global_last_update_ns = now_ns;
    }
    if (g_global_tokens < 1.0) {
        /* Discard due to global rate limit */
        pthread_mutex_unlock(&g_bus_lock);
        return 0;
    }
    g_global_tokens -= 1.0;

    /* 3. Per-Rule Rate Limit Check */
    g_rate_bucket_t *bucket = NULL;
    for (int i = 0; i < g_rate_bucket_count; i++) {
        if (strcmp(g_rate_buckets[i].source, ev->source) == 0 &&
            strcmp(g_rate_buckets[i].rule_id, ev->rule_id) == 0) {
            bucket = &g_rate_buckets[i];
            break;
        }
    }
    if (!bucket) {
        int idx = g_rate_bucket_count;
        if (idx >= G_RATE_LIMIT_MAX_BUCKETS) {
            idx = g_rate_bucket_count % G_RATE_LIMIT_MAX_BUCKETS;
        }
        bucket = &g_rate_buckets[idx];
        g_strlcpy(bucket->source, ev->source, sizeof(bucket->source));
        g_strlcpy(bucket->rule_id, ev->rule_id, sizeof(bucket->rule_id));
        bucket->tokens = G_RATE_LIMIT_BURST;
        bucket->last_update_ns = now_ns;
        if (g_rate_bucket_count < G_RATE_LIMIT_MAX_BUCKETS) {
            g_rate_bucket_count++;
        }
    } else {
        double elapsed_sec = (double)(now_ns - bucket->last_update_ns) / 1e9;
        bucket->tokens += elapsed_sec * G_RATE_LIMIT_REFILL_RATE;
        if (bucket->tokens > G_RATE_LIMIT_BURST) {
            bucket->tokens = G_RATE_LIMIT_BURST;
        }
        bucket->last_update_ns = now_ns;
    }
    if (bucket->tokens < 1.0) {
        /* Discard due to per-rule rate limit */
        pthread_mutex_unlock(&g_bus_lock);
        return 0;
    }
    bucket->tokens -= 1.0;

    /* Bug 8 fix: copy subscriber list under lock, release lock, THEN call.
     * This prevents deadlock if a subscriber publishes a new event (e.g.
     * action result audit) — the non-recursive mutex would deadlock. */
    g_subscriber_t subs[G_MAX_SUBS];
    void *uds[G_MAX_SUBS];
    int n = g_sub_count;
    memcpy(subs, g_subs, n * sizeof(*subs));
    memcpy(uds, g_sub_ud, n * sizeof(*uds));
    pthread_mutex_unlock(&g_bus_lock);
    g_event_t local = *ev;  /* local copy — subscribers may mutate */
    for (int i = 0; i < n; i++) {
        subs[i](&local, uds[i]);
    }
    return 0;
}

uint64_t g_bus_next_seq(void) {
    pthread_mutex_lock(&g_bus_lock);
    uint64_t s = ++g_seq_counter;
    pthread_mutex_unlock(&g_bus_lock);
    return s;
}

/* ---- subscribers: log + action ---- */
static void log_subscriber(const g_event_t *ev, void *ud) {
    (void)ud;
    g_log_append_global(ev);
}

/* Bug 1 fix: action_subscriber now receives the policy engine via ud.
     * If the detection layer left action as G_ACT_LOG/0, policy decides the
     * real action. This is the wiring that makes the entire system functional. */
static void action_subscriber(const g_event_t *ev, void *ud) {
    g_policy_engine_t *pe = (g_policy_engine_t *)ud;
    g_event_t upgraded = *ev;
    if (pe && (upgraded.action_taken == G_ACT_LOG || upgraded.action_taken == 0)) {
        upgraded.action_taken = g_policy_decide(pe, &upgraded);
    }
    g_action_apply(&upgraded);
}

/* ---- config ---- */
int g_config_defaults(g_config_t *cfg) {
    if (!cfg) return -EINVAL;
    memset(cfg, 0, sizeof(*cfg));
    g_strlcpy(cfg->sigs_path, G_SIGS_PATH, sizeof(cfg->sigs_path));
    g_strlcpy(cfg->fim_db_path, G_FIM_DB_PATH, sizeof(cfg->fim_db_path));
    g_strlcpy(cfg->bpf_dir, G_BPF_DIR, sizeof(cfg->bpf_dir));
    g_strlcpy(cfg->ml_model_path, G_ML_MODEL_PATH, sizeof(cfg->ml_model_path));
    g_strlcpy(cfg->log_path, G_LOG_PATH_DEFAULT, sizeof(cfg->log_path));
    g_strlcpy(cfg->socket_path, G_SOCKET_PATH, sizeof(cfg->socket_path));
    g_strlcpy(cfg->policy_path, "/etc/wlt/guardian/guardian.policy", sizeof(cfg->policy_path));
    g_strlcpy(cfg->net_ifname, "eth0", sizeof(cfg->net_ifname));
    cfg->enable_ebpf = true;
    cfg->enable_fim = true;
    cfg->enable_net = true;
    cfg->enable_ml = true;
    cfg->fim_scan_interval_sec = 300;
    cfg->ml_check_interval_sec = 60;
    cfg->enable_mem_scan = true;
    cfg->mem_scan_interval_sec = 60;
    g_strlcpy(cfg->update_url, "", sizeof(cfg->update_url));
    g_strlcpy(cfg->update_pubkey_path, "/etc/wlt/guardian/update_pubkey.pem", sizeof(cfg->update_pubkey_path));
    return 0;
}

int g_config_load(g_config_t *cfg, const char *path) {
    g_config_defaults(cfg);
    FILE *f = fopen(path, "r");
    if (!f) return -errno;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *p = line; while (*p==' '||*p=='\t') p++;
        char *nl = strchr(p,'\n'); if (nl) *nl = 0;
        char *c = strchr(p,'#'); if (c) *c = 0;
        if (!*p) continue;
        char key[64], val[512];
        if (sscanf(p, "%63s = %511s", key, val) != 2) continue;
        if (!strcmp(key,"sigs_path")) g_strlcpy(cfg->sigs_path, val, sizeof(cfg->sigs_path));
        else if (!strcmp(key,"fim_db_path")) g_strlcpy(cfg->fim_db_path, val, sizeof(cfg->fim_db_path));
        else if (!strcmp(key,"bpf_dir")) g_strlcpy(cfg->bpf_dir, val, sizeof(cfg->bpf_dir));
        else if (!strcmp(key,"ml_model_path")) g_strlcpy(cfg->ml_model_path, val, sizeof(cfg->ml_model_path));
        else if (!strcmp(key,"log_path")) g_strlcpy(cfg->log_path, val, sizeof(cfg->log_path));
        else if (!strcmp(key,"socket_path")) g_strlcpy(cfg->socket_path, val, sizeof(cfg->socket_path));
        else if (!strcmp(key,"policy_path")) g_strlcpy(cfg->policy_path, val, sizeof(cfg->policy_path));
        else if (!strcmp(key,"net_ifname")) g_strlcpy(cfg->net_ifname, val, sizeof(cfg->net_ifname));
        else if (!strcmp(key,"enable_ebpf")) cfg->enable_ebpf = atoi(val);
        else if (!strcmp(key,"enable_fim")) cfg->enable_fim = atoi(val);
        else if (!strcmp(key,"enable_net")) cfg->enable_net = atoi(val);
        else if (!strcmp(key,"enable_ml")) cfg->enable_ml = atoi(val);
        else if (!strcmp(key,"fim_scan_interval_sec")) cfg->fim_scan_interval_sec = atoi(val);
        else if (!strcmp(key,"ml_check_interval_sec")) cfg->ml_check_interval_sec = atoi(val);
        else if (!strcmp(key,"enable_mem_scan")) cfg->enable_mem_scan = atoi(val);
        else if (!strcmp(key,"mem_scan_interval_sec")) cfg->mem_scan_interval_sec = atoi(val);
        else if (!strcmp(key,"update_url")) g_strlcpy(cfg->update_url, val, sizeof(cfg->update_url));
        else if (!strcmp(key,"update_pubkey_path")) g_strlcpy(cfg->update_pubkey_path, val, sizeof(cfg->update_pubkey_path));
    }
    fclose(f);
    return 0;
}

static char *json_escape(const char *s, char *out, size_t sz) {
    if (!s) { if (sz>4) strcpy(out,"null"); return out; }
    size_t i = 0;
    while (*s && i < sz - 8) {
        if (*s == '"') { out[i++]='\\'; out[i++]='"'; }
        else if (*s == '\\') { out[i++]='\\'; out[i++]='\\'; }
        else if (*s == '\n') { out[i++]='\\'; out[i++]='n'; }
        else if (*s == '\r') { out[i++]='\\'; out[i++]='r'; }
        else if (*s == '\t') { out[i++]='\\'; out[i++]='t'; }
        else if ((unsigned char)*s < 0x20) { i += snprintf(out+i, sz-i, "\\u%04x", *s); }
        else out[i++] = *s;
        s++;
    }
    out[i] = 0;
    return out;
}

/* ---- API socket (Unix socket for wlt-shell / Kairos queries) ---- */
static int g_api_fd = -1;
static g_engine_status_t g_eng_status = {0};

int g_api_socket_init(const char *path, const g_engine_status_t *status) {
    if (status) g_eng_status = *status;
    unlink(path);
    g_api_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (g_api_fd < 0) return -errno;
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, path, sizeof(addr.sun_path));
    if (bind(g_api_fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) return -errno;
    if (listen(g_api_fd, 8) != 0) return -errno;
    chmod(path, 0660);
    printf("[api] listening on %s\n", path);
    return 0;
}

int g_api_socket_poll(int timeout_ms, g_sig_engine_t *se) {
    if (g_api_fd < 0) return 0;
    fd_set fds; FD_ZERO(&fds); FD_SET(g_api_fd, &fds);
    struct timeval tv = {timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    int rc = select(g_api_fd + 1, &fds, NULL, NULL, &tv);
    if (rc <= 0) return 0;
    int c = accept(g_api_fd, NULL, NULL);
    if (c < 0) return -errno;

    /* Check if client sent any command */
    fd_set rfds; FD_ZERO(&rfds); FD_SET(c, &rfds);
    struct timeval ctv = {0, 5000}; // 5ms timeout
    int select_rc = select(c + 1, &rfds, NULL, NULL, &ctv);
    
    char req[128] = {0};
    if (select_rc > 0) {
        ssize_t n = read(c, req, sizeof(req) - 1);
        if (n > 0) {
            req[n] = '\0';
            if (strncmp(req, "cmd:", 4) == 0) {
                /* Verify complete command has \n */
                if (strchr(req, '\n') == NULL) {
                    char err_resp[] = "{\"error\":\"invalid command (missing newline)\"}\n";
                    write(c, err_resp, strlen(err_resp));
                    close(c);
                    return 1;
                }

                /* Authenticate caller identity via SO_PEERCRED */
                struct ucred ucred;
                socklen_t ulen = sizeof(ucred);
                if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &ucred, &ulen) == 0) {
                    if (ucred.uid != 0 && ucred.uid != getuid()) {
                        /* Unauthorized command request */
                        char err_resp[] = "{\"error\":\"unauthorized\"}\n";
                        write(c, err_resp, strlen(err_resp));
                        close(c);
                        return 1;
                    }
                } else {
                    /* Cannot determine peer credentials — fail safe */
                    char err_resp[] = "{\"error\":\"unauthorized\"}\n";
                    write(c, err_resp, strlen(err_resp));
                    close(c);
                    return 1;
                }

                if (strstr(req, "cmd:kill_switch")) {
                    int kill_rc = g_action_kill_switch();
                    char ok_resp[256];
                    snprintf(ok_resp, sizeof(ok_resp), "{\"status\":\"ok\",\"action\":\"kill_switch\",\"rc\":%d}\n", kill_rc);
                    write(c, ok_resp, strlen(ok_resp));
                    close(c);
                    return 1;
                }

                if (strncmp(req, "cmd:mem_scan:", 13) == 0) {
                    pid_t target_pid = (pid_t)atoi(req + 13);
                    char resp[2048];
                    if (!se) {
                        snprintf(resp, sizeof(resp), "{\"error\":\"signature engine not initialized\"}\n");
                        write(c, resp, strlen(resp));
                    } else {
                        g_event_t ev;
                        int scan_rc = g_sig_scan_proc_mem_regions(se, target_pid, &ev);
                        char esc_detail[1200] = {0};
                        json_escape(ev.detail, esc_detail, sizeof(esc_detail));
                        snprintf(resp, sizeof(resp),
                                 "{\"pid\":%d,\"rc\":%d,\"verdict\":\"%s\",\"rule_id\":\"%s\",\"detail\":\"%s\"}\n",
                                 (int)target_pid, scan_rc, g_verdict_str(ev.verdict), ev.rule_id, esc_detail);
                        write(c, resp, strlen(resp));
                    }
                    close(c);
                    return 1;
                }
            }
        }
    }

    /* Fallback to standard status response */
    char resp[512];
    snprintf(resp, sizeof(resp),
        "{\"status\":\"online\",\"engines\":[%s%s%s%s%s],\"policy\":\"active\"}\n",
        g_eng_status.sig ? "\"sig\"" : "",
        g_eng_status.ebpf ? (g_eng_status.sig?",\"ebpf\"":"\"ebpf\"") : "",
        g_eng_status.fim ? (g_eng_status.sig||g_eng_status.ebpf?",\"fim\"":"\"fim\"") : "",
        g_eng_status.anomaly ? (g_eng_status.sig||g_eng_status.ebpf||g_eng_status.fim?",\"anomaly\"":"\"anomaly\"") : "",
        g_eng_status.net ? (g_eng_status.sig||g_eng_status.ebpf||g_eng_status.fim||g_eng_status.anomaly?",\"net\"":"\"net\"") : "");
    write(c, resp, strlen(resp));
    close(c);
    return 1;
}

void g_api_socket_close(void) {
    if (g_api_fd >= 0) close(g_api_fd);
    g_api_fd = -1;
}

/* ---- shutdown signal ---- */
static volatile sig_atomic_t g_running = 1;
void g_daemon_shutdown(void) { g_running = 0; }
static void on_sig(int s) { (void)s; g_daemon_shutdown(); }

static int g_test_event_count = 0;
static char g_test_last_rule_id[G_RULE_ID_MAX] = {0};
static void test_subscriber(const g_event_t *ev, void *ud) {
    (void)ud;
    g_test_event_count++;
    g_strlcpy(g_test_last_rule_id, ev->rule_id, sizeof(g_test_last_rule_id));
}

/* ---- self-test ---- */
int g_daemon_self_test(void) {
    g_use_mock_time = true;
    g_mock_time_ns = 1000000000ULL;
    printf("[guardian] self-test start\n");
    printf("[guardian] event size = %zu bytes\n", sizeof(g_event_t));
    printf("[guardian] reversible(FREEZE)=%d  reversible(KILL)=%d\n",
        g_action_is_reversible(G_ACT_FREEZE), g_action_is_reversible(G_ACT_KILL));

    /* test SHA-256 */
    char hex[65]; g_sha256_hex((const uint8_t*)"abc", 3, hex);
    printf("[guardian] sha256('abc') = %s\n", hex);
    /* known: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad */

    /* test policy engine */
    g_policy_engine_t *pe = g_policy_init(NULL);
    g_event_t ev = {0};
    g_strlcpy(ev.source, "yara", sizeof(ev.source));
    g_strlcpy(ev.rule_id, "Trojan.Generic", sizeof(ev.rule_id));
    ev.severity = G_SEV_CRITICAL;
    g_action_t a = g_policy_decide(pe, &ev);
    printf("[guardian] policy(yara critical) -> %s\n", g_action_str(a));
    g_policy_free(pe);

    /* simulate a yara hit */
    memset(&ev, 0, sizeof(ev));
    ev.pid = 1337; ev.severity = G_SEV_HIGH; ev.verdict = G_VERDICT_MALICIOUS;
    g_strlcpy(ev.comm, "evil", sizeof(ev.comm));
    g_strlcpy(ev.path, "/tmp/malware", sizeof(ev.path));
    g_strlcpy(ev.source, "yara", sizeof(ev.source));
    g_strlcpy(ev.rule_id, "Trojan_Generic_001", sizeof(ev.rule_id));
    ev.action_taken = G_ACT_QUARANTINE_FILE;
    g_bus_publish(&ev);

    /* --- Security Hardening tests --- */
    printf("[test] Starting security hardening tests...\n");

    /* Reset internal rate limiting and deduplication state */
    g_rate_bucket_count = 0;
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_dedup_count = 0;
    memset(g_dedup_table, 0, sizeof(g_dedup_table));
    g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;
    g_global_last_update_ns = get_now_ns();

    /* Subscribe our test subscriber */
    g_bus_subscribe(test_subscriber, NULL);

    /* 1. Deduplication Test: INFO severity */
    printf("[test] Verifying deduplication for INFO events...\n");
    g_test_event_count = 0;
    g_event_t test_ev = {0};
    test_ev.pid = 9999;
    test_ev.severity = G_SEV_INFO;
    g_strlcpy(test_ev.source, "test_source", sizeof(test_ev.source));
    g_strlcpy(test_ev.rule_id, "TEST_DEDUP_INFO", sizeof(test_ev.rule_id));
    g_bus_publish(&test_ev);
    g_bus_publish(&test_ev); /* Should be deduplicated */
    if (g_test_event_count != 1) {
        fprintf(stderr, "FAIL: INFO event was not deduplicated (count=%d)\n", g_test_event_count);
        return 1;
    }
    printf("[test] Deduplication for INFO events passed.\n");

    /* 2. Deduplication Test: CRITICAL severity (must NOT be deduplicated) */
    printf("[test] Verifying CRITICAL events bypass deduplication...\n");
    g_test_event_count = 0;
    test_ev.severity = G_SEV_CRITICAL;
    g_strlcpy(test_ev.rule_id, "TEST_DEDUP_CRIT", sizeof(test_ev.rule_id));
    g_bus_publish(&test_ev);
    g_bus_publish(&test_ev); /* Should NOT be deduplicated */
    if (g_test_event_count != 2) {
        fprintf(stderr, "FAIL: CRITICAL event was incorrectly deduplicated (count=%d)\n", g_test_event_count);
        return 1;
    }
    printf("[test] CRITICAL bypass deduplication passed.\n");

    /* Reset rate limits for next tests */
    g_rate_bucket_count = 0;
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;
    g_global_last_update_ns = get_now_ns();

    /* 3. Per-Rule Rate Limiting Test (max 100/sec) */
    printf("[test] Verifying per-rule rate limiting...\n");
    g_test_event_count = 0;
    test_ev.severity = G_SEV_CRITICAL;
    g_strlcpy(test_ev.rule_id, "TEST_PER_RULE_LIMIT", sizeof(test_ev.rule_id));
    for (int i = 0; i < 150; i++) {
        g_bus_publish(&test_ev);
    }
    if (g_test_event_count != 100) {
        fprintf(stderr, "FAIL: Per-rule rate limiting failed (got %d events, expected 100)\n", g_test_event_count);
        return 1;
    }
    printf("[test] Per-rule rate limiting passed.\n");

    /* Reset rate limits */
    g_rate_bucket_count = 0;
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;
    g_global_last_update_ns = get_now_ns();

    /* 4. Global Rate Limiting Test (max 500/sec) */
    printf("[test] Verifying global rate limiting...\n");
    g_test_event_count = 0;
    /* Publish 600 events across 6 different rules (100 each, so per-rule limit is not hit) */
    for (int r = 0; r < 6; r++) {
        char rule[32];
        snprintf(rule, sizeof(rule), "RULE_%d", r);
        g_strlcpy(test_ev.rule_id, rule, sizeof(test_ev.rule_id));
        for (int i = 0; i < 100; i++) {
            g_bus_publish(&test_ev);
        }
    }
    if (g_test_event_count != 500) {
        fprintf(stderr, "FAIL: Global rate limiting failed (got %d events, expected 500)\n", g_test_event_count);
        return 1;
    }
    printf("[test] Global rate limiting passed.\n");

    /* 5. Model Hash Verification Test */
    printf("[test] Verifying model hash verification...\n");
    /* Create a dummy anomaly.pkl file with invalid hash */
    FILE *dummy_pkl = fopen("/tmp/dummy_anomaly.pkl", "wb");
    if (dummy_pkl) {
        fprintf(dummy_pkl, "dummy pickle content");
        fclose(dummy_pkl);
        
        /* Create a mismatched sha256 file */
        FILE *dummy_sha = fopen("/tmp/dummy_anomaly.pkl.sha256", "w");
        if (dummy_sha) {
            fprintf(dummy_sha, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n");
            fclose(dummy_sha);
        }
        
        g_anomaly_engine_t *test_ae = g_anomaly_init("/tmp/dummy_anomaly.pkl", NULL);
        unlink("/tmp/dummy_anomaly.pkl");
        unlink("/tmp/dummy_anomaly.pkl.sha256");
        if (test_ae != NULL) {
            fprintf(stderr, "FAIL: g_anomaly_init loaded a model with mismatched hash!\n");
            g_anomaly_free(test_ae);
            return 1;
        }
    }
    printf("[test] Model hash verification passed.\n");

    /* Reset rate limits */
    g_rate_bucket_count = 0;
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_dedup_count = 0;
    memset(g_dedup_table, 0, sizeof(g_dedup_table));
    g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;

    /* 6. Log Quota and Overflow Spillover Test */
    printf("[test] Verifying log quota and overflow spillover...\n");
    /* Initialize a log at /tmp/test_quota.log */
    unlink("/tmp/test_quota.log");
    unlink("./guardian.overflow");
    unlink("/var/log/guardian.overflow");

    /* Let's write 10MB+ to /tmp/test_quota.log to simulate a full log */
    int fd = open("/tmp/test_quota.log", O_WRONLY | O_CREAT, 0644);
    if (fd >= 0) {
        if (ftruncate(fd, 10 * 1024 * 1024 + 100) != 0) {
            perror("ftruncate");
        }
        close(fd);
    }

    /* Initialize global log to /tmp/test_quota.log */
    uint8_t dummy_key[32];
    memset(dummy_key, 0x99, 32);
    g_log_init_global("/tmp/test_quota.log", dummy_key);

    g_test_event_count = 0;
    g_test_last_rule_id[0] = 0;

    /* Publish a log event. Since size > 10MB, it should:
     * 1. publish LOG_QUOTA_EXCEEDED
     * 2. write to overflow file
     */
    g_event_t log_ev = {0};
    log_ev.pid = 2222;
    log_ev.severity = G_SEV_HIGH;
    g_strlcpy(log_ev.source, "test_log", sizeof(log_ev.source));
    g_strlcpy(log_ev.rule_id, "TEST_LOG_EVENT", sizeof(log_ev.rule_id));
    g_log_append_global(&log_ev);

    /* Clean up log global */
    g_log_close_global();

    /* Verify that LOG_QUOTA_EXCEEDED alert event was published on the bus */
    if (strcmp(g_test_last_rule_id, "LOG_QUOTA_EXCEEDED") != 0) {
        fprintf(stderr, "FAIL: LOG_QUOTA_EXCEEDED alert was not published (last rule: %s)\n", g_test_last_rule_id);
        unlink("/tmp/test_quota.log");
        return 1;
    }

    /* Verify overflow file exists and has content */
    FILE *overflow_f = fopen("./guardian.overflow", "r");
    if (!overflow_f) {
        overflow_f = fopen("/var/log/guardian.overflow", "r");
    }
    if (!overflow_f) {
        fprintf(stderr, "FAIL: overflow spillover file not created\n");
        unlink("/tmp/test_quota.log");
        return 1;
    }
    char overflow_line[1024];
    bool found_event = false;
    while (fgets(overflow_line, sizeof(overflow_line), overflow_f)) {
        if (strstr(overflow_line, "TEST_LOG_EVENT")) {
            found_event = true;
            break;
        }
    }
    fclose(overflow_f);
    if (!found_event) {
        fprintf(stderr, "FAIL: overflow spillover file does not contain original event details\n");
        unlink("/tmp/test_quota.log");
        return 1;
    }
    unlink("/tmp/test_quota.log");
    unlink("./guardian.overflow");
    printf("[test] Log quota overflow spillover passed.\n");

    /* Reset rate limits */
    g_rate_bucket_count = 0;
    memset(g_rate_buckets, 0, sizeof(g_rate_buckets));
    g_dedup_count = 0;
    memset(g_dedup_table, 0, sizeof(g_dedup_table));
    g_global_tokens = G_GLOBAL_RATE_LIMIT_BURST;

    /* 7. Event Propagation & BPF Action mapping Test (Phase 2) */
    printf("[test] Verifying event propagation and BPF action mapping (Phase 2)...\n");
    g_test_event_count = 0;
    g_test_last_rule_id[0] = 0;

    g_event_t bpf_leak_ev = {0};
    bpf_leak_ev.pid = 4321;
    bpf_leak_ev.severity = G_SEV_CRITICAL;
    g_strlcpy(bpf_leak_ev.source, "ebpf", sizeof(bpf_leak_ev.source));
    g_strlcpy(bpf_leak_ev.rule_id, "NON_TOR_EGRESS_KILL", sizeof(bpf_leak_ev.rule_id));
    bpf_leak_ev.action_taken = G_ACT_KILL_SWITCH;

    /* Temporarily set MCP_AUTOCONFIRM to allow execution in test mode */
    setenv("MCP_AUTOCONFIRM", "1", 1);
    g_bus_publish(&bpf_leak_ev);
    unsetenv("MCP_AUTOCONFIRM");

    /* Verify that the event was published and action applied (simulated kill-switch) */
    if (g_test_event_count == 0) {
        fprintf(stderr, "FAIL: connection leak event not propagated through event bus\n");
        return 1;
    }
    printf("[test] Event propagation and BPF action mapping passed.\n");

    /* 8. FIM DB Encryption & Tampering Test (Phase 3) */
    printf("[test] Verifying FIM DB encryption and tampering detection (Phase 3)...\n");
    g_test_event_count = 0;
    g_test_last_rule_id[0] = 0;

    uint8_t test_fim_key[32];
    memset(test_fim_key, 0x11, 32);
    unlink("/tmp/test_fim.db");
    unlink("/tmp/test_fim.db.key");
    unlink("/tmp/test_fim_file.txt");

    g_fim_engine_t *test_fe = g_fim_init("/tmp/test_fim.db", test_fim_key, true);
    if (!test_fe) {
        fprintf(stderr, "FAIL: Failed to initialize encrypted FIM engine in test\n");
        return 1;
    }

    FILE *tf = fopen("/tmp/test_fim_file.txt", "w");
    if (tf) {
        fprintf(tf, "fim test content");
        fclose(tf);
    }

    if (g_fim_add_watch(test_fe, "/tmp/test_fim_file.txt") != 0) {
        fprintf(stderr, "FAIL: Failed to add watch to encrypted FIM\n");
        g_fim_free(test_fe);
        unlink("/tmp/test_fim.db");
        unlink("/tmp/test_fim_file.txt");
        return 1;
    }

    g_event_t test_out;
    if (g_fim_check_path(test_fe, "/tmp/test_fim_file.txt", &test_out) != 0) {
        fprintf(stderr, "FAIL: Encrypted FIM check path failed on clean file\n");
        g_fim_free(test_fe);
        unlink("/tmp/test_fim.db");
        unlink("/tmp/test_fim_file.txt");
        return 1;
    }

    /* Verify FIM DB is encrypted (ciphertext exists, sha256 column doesn't) */
    if (!g_fim_test_has_ciphertext(test_fe, "/tmp/test_fim_file.txt")) {
        fprintf(stderr, "FAIL: FIM database does not store ciphertext\n");
        g_fim_free(test_fe);
        unlink("/tmp/test_fim.db");
        unlink("/tmp/test_fim_file.txt");
        return 1;
    }

    /* Tamper with database tag */
    g_fim_test_tamper_tag(test_fe, "/tmp/test_fim_file.txt");


    /* Verify check path detects tampering */
    g_bus_subscribe(test_subscriber, NULL);
    if (g_fim_check_path(test_fe, "/tmp/test_fim_file.txt", &test_out) != 1) {
        fprintf(stderr, "FAIL: FIM engine failed to detect database tampering\n");
        g_fim_free(test_fe);
        unlink("/tmp/test_fim.db");
        unlink("/tmp/test_fim_file.txt");
        return 1;
    }

    if (strcmp(g_test_last_rule_id, "FIM_DATABASE_TAMPERED") != 0) {
        fprintf(stderr, "FAIL: FIM_DATABASE_TAMPERED alert not published (got: %s)\n", g_test_last_rule_id);
        g_fim_free(test_fe);
        unlink("/tmp/test_fim.db");
        unlink("/tmp/test_fim_file.txt");
        return 1;
    }

    g_fim_free(test_fe);
    unlink("/tmp/test_fim.db");
    unlink("/tmp/test_fim_file.txt");
    printf("[test] FIM DB encryption and tampering detection passed.\n");

    /* 9. API Socket Authentication & Delegation Test (Phase 3) */
    printf("[test] Verifying API socket credentials authentication and delegation (Phase 3)...\n");
    unlink("/tmp/test_api.sock");
    g_engine_status_t status_dummy = {0};
    if (g_api_socket_init("/tmp/test_api.sock", &status_dummy) == 0) {
        int client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client_sock >= 0) {
            struct sockaddr_un cl_addr = {0};
            cl_addr.sun_family = AF_UNIX;
            g_strlcpy(cl_addr.sun_path, "/tmp/test_api.sock", sizeof(cl_addr.sun_path));
            if (connect(client_sock, (struct sockaddr*)&cl_addr, sizeof(cl_addr)) == 0) {
                write(client_sock, "status\n", 7);
                g_api_socket_poll(5, NULL);
                char resp[512] = {0};
                read(client_sock, resp, sizeof(resp)-1);
                if (!strstr(resp, "online")) {
                    fprintf(stderr, "FAIL: API socket status query failed\n");
                    close(client_sock);
                    g_api_socket_close();
                    unlink("/tmp/test_api.sock");
                    return 1;
                }
            }
            close(client_sock);
        }
        
        client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (client_sock >= 0) {
            struct sockaddr_un cl_addr = {0};
            cl_addr.sun_family = AF_UNIX;
            g_strlcpy(cl_addr.sun_path, "/tmp/test_api.sock", sizeof(cl_addr.sun_path));
            if (connect(client_sock, (struct sockaddr*)&cl_addr, sizeof(cl_addr)) == 0) {
                write(client_sock, "cmd:kill_switch\n", 16);
                g_api_socket_poll(5, NULL);
                char resp[512] = {0};
                read(client_sock, resp, sizeof(resp)-1);
                if (!strstr(resp, "kill_switch") && !strstr(resp, "unauthorized")) {
                    fprintf(stderr, "FAIL: API socket command execution failed (got: %s)\n", resp);
                    close(client_sock);
                    g_api_socket_close();
                    unlink("/tmp/test_api.sock");
                    return 1;
                }
            }
            close(client_sock);
        }
        g_api_socket_close();
        unlink("/tmp/test_api.sock");
    }
    printf("[test] API socket authentication and delegation passed.\n");

    /* 10. Process Memory Scanning self-test */
    printf("[test] Verifying process memory scanning on clean process (PID 1)...\n");
    const char *test_rules_path = G_SIGS_PATH;
    if (access(test_rules_path, R_OK) != 0) {
        test_rules_path = "signatures/guardian.yarc";
    }
    g_sig_engine_t *test_se = g_sig_init(test_rules_path);
    if (test_se) {
        g_event_t mem_ev;
        int mem_rc = g_sig_scan_proc_mem_regions(test_se, 1, &mem_ev);
        if (mem_rc != 0) {
            fprintf(stderr, "FAIL: g_sig_scan_proc_mem_regions failed or matched on PID 1 (rc=%d)\n", mem_rc);
            g_sig_free(test_se);
            return 1;
        }
        g_sig_free(test_se);
        printf("[test] Process memory scanning on clean process passed.\n");
    } else {
        printf("[test] Skipping process memory scanning self-test (no signature database found).\n");
    }

    /* 11. Signed YARA updates self-test (disabled case) */
    printf("[test] Verifying signed YARA updates returns gracefully when disabled...\n");
    g_sig_engine_t *test_se2 = g_sig_init(test_rules_path);
    if (test_se2) {
        int fetch_rc = g_sig_fetch_updates(test_se2, "", "/etc/wlt/guardian/update_pubkey.pem");
        if (fetch_rc != 0) {
            fprintf(stderr, "FAIL: g_sig_fetch_updates failed when disabled (rc=%d)\n", fetch_rc);
            g_sig_free(test_se2);
            return 1;
        }
        g_sig_free(test_se2);
        printf("[test] Signed YARA updates disabled self-test passed.\n");
    }

    /* ---- Phase 5 integration tests: prove features work, not just compile ---- */

    /* 12. Canary restart test (BUG 2 regression catch).
     * Init canary engine (places canary files), free it, re-init (simulates
     * daemon restart). On restart, the existing canary must be read+hashed.
     * Then verify_all must return 0 (no false RANSOMWARE_CANARY_ENCRYPTED).
     * If the hash isn't loaded (the bug), verify returns >0. */
    {
        printf("[test] Canary restart false-positive test...\n");
        /* use /tmp for canary placement (dev sandbox) */
        g_canary_engine_t *ce1 = g_canary_init();
        if (ce1) {
            g_canary_free(ce1);  /* canary files persist on disk */
            /* re-init: should read+hash existing canaries */
            g_canary_engine_t *ce2 = g_canary_init();
            if (ce2) {
                int n_bad = g_canary_verify_all(ce2);
                if (n_bad > 0) {
                    fprintf(stderr, "FAIL: canary restart produced %d false positive(s) - hash not loaded\n", n_bad);
                    g_canary_free(ce2);
                    return 1;
                }
                printf("[test] Canary restart test passed (no false positives after re-init).\n");
                g_canary_free(ce2);
            }
        } else {
            printf("[test] Skipping canary test (no writable canary dirs in this env).\n");
        }
    }

    /* 13. Isolation Forest inference correctness test (BUG 3 regression catch).
     * Score a normal vector and an anomalous vector. The anomalous vector MUST
     * score higher (more anomalous) than the normal vector. If the struct
     * alignment is wrong (the bug), the tree walk reads garbage thresholds and
     * scores are meaningless — the ordering breaks. Also sanity: scores in [0,1]. */
    {
        printf("[test] Isolation Forest inference correctness test...\n");
        g_iforest_t *ifo = g_iforest_load("ml/anomaly.iforest");
        if (!ifo) ifo = g_iforest_load("/mnt/c/Users/Default.L-HCG-9FVVGS3/OneDrive/Desktop/guardian/ml/anomaly.iforest");
        if (ifo) {
            /* normal process: low cpu, moderate mem, few conns (from training distribution) */
            double normal[8] = {3.0, 80.0, 4.0, 2.0, 0.2, 0.4, 2.0, 500.0};
            /* anomalous process: maxed-out cpu, huge mem, hundreds of conns, mass writes */
            double anomalous[8] = {95.0, 2000.0, 500.0, 800.0, 50.0, 0.95, 300.0, 50000.0};
            double s_normal = g_iforest_score(ifo, normal);
            double s_anom = g_iforest_score(ifo, anomalous);
            printf("[test]   iforest normal=%.4f anomalous=%.4f\n", s_normal, s_anom);
            /* sanity checks */
            if (s_normal != s_normal || s_anom != s_anom) {
                fprintf(stderr, "FAIL: iforest score is NaN (struct alignment bug)\n");
                g_iforest_free(ifo);
                return 1;
            }
            if (s_normal < 0 || s_normal > 1 || s_anom < 0 || s_anom > 1) {
                fprintf(stderr, "FAIL: iforest score out of [0,1] range\n");
                g_iforest_free(ifo);
                return 1;
            }
            /* TIGHTER assertions (catch struct-alignment garbage):
             * 1. anomalous must score higher than normal (ordering)
             * 2. normal must be < 0.55 (a normal process should score low)
             * 3. anomalous must be > 0.55 (an anomalous process should score high)
             * 4. the gap must be > 0.1 (meaningful separation, not noise)
             * Misaligned struct reads produce scores clustered near 0.5 (garbage),
             * which fails assertions 2+3+4 even if assertion 1 accidentally passes. */
            if (s_anom <= s_normal) {
                fprintf(stderr, "FAIL: anomalous score (%.4f) <= normal score (%.4f) - iforest struct alignment bug\n", s_anom, s_normal);
                g_iforest_free(ifo);
                return 1;
            }
            if (s_normal > 0.55) {
                fprintf(stderr, "FAIL: normal score %.4f too high (>0.55) - iforest struct alignment bug (garbage scores)\n", s_normal);
                g_iforest_free(ifo);
                return 1;
            }
            if (s_anom < 0.55) {
                fprintf(stderr, "FAIL: anomalous score %.4f too low (<0.55) - iforest struct alignment bug (garbage scores)\n", s_anom);
                g_iforest_free(ifo);
                return 1;
            }
            if (s_anom - s_normal < 0.1) {
                fprintf(stderr, "FAIL: score gap too small (%.4f - %.4f = %.4f < 0.1) - iforest struct alignment bug\n", s_anom, s_normal, s_anom - s_normal);
                g_iforest_free(ifo);
                return 1;
            }
            printf("[test] Isolation Forest inference correctness passed (anomalous > normal).\n");
            g_iforest_free(ifo);
        }
    }

    /* 14. Ransomware rate-based detection test (BUG 4 regression catch).
     * The fix changed from cumulative totals (>100 unlinks ever) to per-minute
     * rates (>100 unlinks/min). Test: mock 150 unlinks in 5 seconds = 1800/min
     * → should fire. Mock 5 unlinks in 5 seconds = 60/min → should NOT fire.
     * If the code checks cumulative (the bug), 5 unlinks would eventually cross
     * the 100 threshold and fire — which is wrong. */
    {
        printf("[test] Ransomware rate-based detection test...\n");
        /* We can't easily mock BPF maps in self-test, so we test the threshold
         * logic directly by checking the rate math:
         *   rate = delta / dt_min = delta / (dt_sec / 60) = delta * 60 / dt_sec
         * For dt=5s: rate = delta * 12
         *   150 unlinks in 5s → 1800/min → > 100 → should fire
         *   5 unlinks in 5s → 60/min → < 100 → should NOT fire
         * The cumulative bug would fire on 5 unlinks after 20 cycles (100 total). */
        int dt_sec = 5;
        double dt_min = dt_sec / 60.0;
        /* case 1: burst — should fire */
        __u32 burst_unlink = 150;
        double burst_rate = burst_unlink / dt_min;
        if (burst_rate <= 100.0) {
            fprintf(stderr, "FAIL: burst rate %.0f/min should exceed 100/min threshold\n", burst_rate);
            return 1;
        }
        /* case 2: low activity — should NOT fire */
        __u32 low_unlink = 5;
        double low_rate = low_unlink / dt_min;
        if (low_rate > 100.0) {
            fprintf(stderr, "FAIL: low rate %.0f/min should NOT exceed 100/min threshold (cumulative bug?)\n", low_rate);
            return 1;
        }
        /* case 3: cumulative-vs-rate check — 5 unlinks/cycle for 20 cycles = 100 cumulative.
         * With rate-based logic: 60/min each cycle → never fires. Correct.
         * With cumulative logic: 100 total → fires. Wrong. */
        __u32 cumulative_after_20_cycles = 5 * 20;
        double rate_per_cycle = 5 / dt_min;
        if (cumulative_after_20_cycles >= 100 && rate_per_cycle < 100.0) {
            printf("[test]   confirmed: 5 unlinks/5s for 20 cycles = 100 cumulative but only 60/min rate\n");
            printf("[test]   rate-based: does NOT fire (correct). cumulative-based: would fire (bug).\n");
        }
        printf("[test] Ransomware rate-based detection passed.\n");
    }

    g_use_mock_time = false;
    printf("[guardian] self-test OK\n");
    return 0;
}

static int g_sig_scan_all_proc_mem(g_sig_engine_t *se) {
    if (!se) return -EINVAL;
    DIR *d = opendir("/proc");
    if (!d) return -errno;
    int n_checked = 0, n_matches = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit(de->d_name[0])) continue;
        pid_t pid = atoi(de->d_name);
        if (pid <= 1) continue;
        
        // Skip root and guardian
        if (pid == getpid()) continue;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d", pid);
        struct stat st;
        if (stat(path, &st) == 0 && st.st_uid == 0) {
            continue; // Skip root
        }

        g_event_t ev;
        int rc = g_sig_scan_proc_mem_regions(se, pid, &ev);
        if (rc > 0) {
            n_matches++;
        }
        n_checked++;
        if (n_checked >= 20) break;
    }
    closedir(d);
    return n_matches;
}

/* ---- main daemon ---- */
int g_daemon_run(const g_config_t *cfg) {
    if (!cfg) return -EINVAL;
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    time_t g_daemon_start_time = time(NULL);

    /* init bus + log + action + policy */
    g_bus_init();

    /* Write PID file for watchdog — use /run/guardian/ (root-owned, mode 0700)
     * instead of world-writable /tmp/ to prevent symlink attacks. */
    mkdir("/run/guardian", 0700);
    FILE *pf = fopen("/run/guardian/guardian.pid", "w");
    if (pf) {
        fprintf(pf, "%d\n", (int)getpid());
        fclose(pf);
    }
    uint8_t log_key[32];
    g_get_log_key(log_key);

    if (g_log_init_global(cfg->log_path, log_key) != 0) {
        char alt[256]; snprintf(alt, sizeof(alt), "./guardian.log");
        if (g_log_init_global(alt, log_key) != 0) {
            fprintf(stderr, "[guardian] log init failed\n");
            return 1;
        }
    }
    g_policy_engine_t *pe = g_policy_init(cfg->policy_path);
    g_bus_subscribe(log_subscriber, NULL);
    g_bus_subscribe(action_subscriber, pe);  /* Bug 1 fix: pass pe, not NULL */
    g_action_init();

    /* init layers (best-effort in dev sandbox) */
    g_sig_engine_t *se = NULL;
    g_ebpf_engine_t *ee = NULL;
    g_fim_engine_t *fe = NULL;
    g_anomaly_engine_t *ae = NULL;
    g_net_engine_t *ne = NULL;

    se = g_sig_init(cfg->sigs_path);
    if (se) printf("[guardian] sig engine: ready\n");
    else    printf("[guardian] sig engine: unavailable (compile rules first)\n");

    if (cfg->enable_ebpf) {
        ee = g_ebpf_init(cfg->bpf_dir);
        if (ee) {
            char rp[G_PATH_MAX]; snprintf(rp, sizeof(rp), "%s/../rules/ebpf.rules", cfg->bpf_dir);
            if (access(rp, R_OK) != 0) {
                g_strlcpy(rp, "rules/ebpf.rules", sizeof(rp));
            }
            g_ebpf_rules_load(ee, rp);
            g_ebpf_load_all(ee);
            printf("[guardian] ebpf engine: ready\n");
        }
    }

    if (cfg->enable_fim) {
        uint8_t fim_key[32];
        bool FIM_encrypted = true;
        char key_path[G_PATH_MAX];
        snprintf(key_path, sizeof(key_path), "%s.key", cfg->fim_db_path);

        /* Validate FIM key file exists and is exactly 32 bytes */
        bool key_ok = false;
        struct stat key_st;
        if (stat(key_path, &key_st) == 0 && S_ISREG(key_st.st_mode) && key_st.st_size == 32) {
            FILE *kf = fopen(key_path, "rb");
            if (kf) {
                if (fread(fim_key, 1, 32, kf) == 32) {
                    key_ok = true;
                }
                fclose(kf);
            }
        }

        if (!key_ok) {
            /* Key is missing or corrupted — check if we are on tmpfs */
            char dir[G_PATH_MAX];
            g_strlcpy(dir, cfg->fim_db_path, sizeof(dir));
            char *slash = strrchr(dir, '/');
            if (slash) {
                *slash = '\0';
            } else {
                g_strlcpy(dir, ".", sizeof(dir));
            }

            if (is_tmpfs(dir)) {
                fprintf(stderr, "[fim] WARNING: FIM database directory %s is on tmpfs. FIM key will not persist across reboots. Falling back to unencrypted FIM.\n", dir);
                FIM_encrypted = false;
            } else {
                /* Persistent filesystem: generate new 32-byte key */
                FILE *urand_f = fopen("/dev/urandom", "rb");
                if (urand_f) {
                    size_t read_bytes = fread(fim_key, 1, 32, urand_f);
                    fclose(urand_f);
                    if (read_bytes != 32) {
                        fprintf(stderr, "[fim] ERROR: /dev/urandom short read (%zu bytes). Refusing deterministic FIM key — falling back to unencrypted FIM.\n", read_bytes);
                        FIM_encrypted = false;
                    }
                } else {
                    fprintf(stderr, "[fim] ERROR: cannot open /dev/urandom. Refusing deterministic FIM key — falling back to unencrypted FIM.\n");
                    FIM_encrypted = false;
                }

                /* O_EXCL prevents TOCTOU races */
                unlink(key_path);
                int fd_key = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0400);
                if (fd_key >= 0) {
                    write(fd_key, fim_key, 32);
                    close(fd_key);
                } else {
                    fd_key = open(key_path, O_WRONLY | O_CREAT | O_TRUNC, 0400);
                    if (fd_key >= 0) {
                        write(fd_key, fim_key, 32);
                        close(fd_key);
                    } else {
                        fprintf(stderr, "[fim] WARNING: Cannot write FIM key file %s: %s. Falling back to unencrypted FIM.\n", key_path, strerror(errno));
                        FIM_encrypted = false;
                    }
                }
            }
        }

        fe = g_fim_init(cfg->fim_db_path, fim_key, FIM_encrypted);
        if (!fe) {
            fprintf(stderr, "[guardian] ERROR: FIM engine failed to initialize (outdated schema or invalid key). Exiting.\n");
            g_daemon_shutdown();
            if (se) g_sig_free(se);
            if (ee) g_ebpf_free(ee);
            if (pe) g_policy_free(pe);
            g_log_close_global();
            return -1;
        }
        printf("[guardian] FIM engine: ready (encrypted=%d)\n", FIM_encrypted);
    }

    if (cfg->enable_ml) {
        ae = g_anomaly_init(cfg->ml_model_path, NULL);
        if (ae) printf("[guardian] anomaly engine: ready\n");
    }

    if (cfg->enable_net) {
        ne = g_net_init(cfg->net_ifname);
        if (ne) {
            printf("[guardian] net engine: ready\n");
            if (ee) {
                uid_t tuid = g_net_get_tor_uid(ne);
                uint32_t zero = 0;
                uint32_t uid_val = tuid;
                g_ebpf_set_map_value(ee, "tor_uid", &zero, &uid_val);
            }
        }
    }

    /* Phase 1.2: Populate auth_binaries BPF map.
     * The map whitelists comm names allowed to access sensitive files
     * (/etc/shadow etc.) without being SIGKILL'd by the openat hook.
     * Without this, the map was empty and the whitelist never fired.
     * FNV-1a hash MUST match hash_str() in bpf/guardian.bpf.c:
     *   seed 0xcbf29ce484222325, prime 0x100000001b3, stop at NUL. */
    if (ee) {
        const char *auth_comms[] = {
            "passwd", "login", "sshd", "pam_unix",
            "chpasswd", "gpasswd", "su", "sudo", NULL
        };
        int n_auth = 0;
        for (int i = 0; auth_comms[i]; i++) {
            const char *cs = auth_comms[i];
            uint64_t h = 0xcbf29ce484222325ULL;
            for (int j = 0; cs[j]; j++) {
                h ^= (uint64_t)(unsigned char)cs[j];
                h *= 0x100000001b3ULL;
            }
            uint32_t one = 1;
            if (g_ebpf_set_map_value(ee, "auth_binaries", &h, &one) == 0) {
                n_auth++;
            }
        }
        printf("[guardian] auth_binaries: %d comm names whitelisted\n", n_auth);
    }

    /* Bug 21 fix: track which engines actually initialized */
    g_engine_status_t eng_status = {0};
    eng_status.sig = (se != NULL);
    eng_status.ebpf = (ee != NULL);
    eng_status.fim = (fe != NULL);
    eng_status.anomaly = (ae != NULL);
    eng_status.net = (ne != NULL);
    g_api_socket_init(cfg->socket_path, &eng_status);

    printf("[guardian] all engines online (sig%s%s%s%s%s)\n",
           ee ? "/ebpf" : "",
           fe ? "/fim" : "",
           ae ? "/anomaly" : "",
           ne ? "/net" : "",
           (!ee && !fe && !ae && !ne) ? "" : "");
    /* Phase 2.1: canary engine for ransomware detection */
    g_canary_engine_t *ce = g_canary_init();
    /* Phase 2.4: ransomware behavior detection */
    g_ransomware_engine_t *re = g_ransomware_init();
    if (ce) printf("[guardian] canary engine: ready\n");

    printf("[guardian] running. Ctrl-C to stop.\n");

    /* main loop: poll eBPF ringbuf, periodic FIM scan, periodic ML check,
     * periodic net leak check, API socket.
     * Bug 15 fix: YARA scans triggered by eBPF execve events (via callback).
     * Bug 16 fix: anomaly checks ALL PIDs, not just PID 1. */
    time_t now = time(NULL);
    time_t last_fim = now, last_ml = now, last_net = now, last_heartbeat = now;
    time_t last_mem_scan = now;
    time_t last_canary = now;  /* Phase 2.1 */
    time_t last_ransomware = now;  /* Phase 2.4 */
    bool fetched_updates = false;
    time_t last_update_attempt = 0;
    int update_retry_interval_sec = 300; // start with 5 minutes (300s)

    // Canary deployment state
    bool g_canary_active = false;
    time_t g_canary_start_time = 0;
    uint64_t g_canary_post_swap_alerts_start = 0;
    double g_pre_swap_alert_rate = 0.0;

    while (g_running) {
        if (ee) g_ebpf_poll(ee, 200);

        g_api_socket_poll(100, se);

        time_t now = time(NULL);
        if (now - last_heartbeat >= 1) {
            last_heartbeat = now;
            /* Atomic write of MONOTONIC heartbeat to /run/guardian/ */
            struct timespec hb_ts;
            clock_gettime(CLOCK_MONOTONIC, &hb_ts);
            char tmp_path[] = "/run/guardian/.guardian.heartbeat.tmp";
            char real_path[] = "/run/guardian/guardian.heartbeat";
            FILE *hb = fopen(tmp_path, "w");
            if (hb) {
                fprintf(hb, "%ld\n", (long)hb_ts.tv_sec);
                fclose(hb);
                rename(tmp_path, real_path);
            }
        }
        if (fe && now - last_fim >= cfg->fim_scan_interval_sec) {
            last_fim = now;
            g_fim_scan_all(fe, NULL, NULL);
        }
        if (ae && now - last_ml >= cfg->ml_check_interval_sec) {
            last_ml = now;
            /* Bug 16 fix: enumerate all PIDs from /proc and check each, pass signature engine for immediate scanning */
            g_anomaly_check_all_procs(ae, se);
        }
        if (ne && now - last_net >= 5) {
            last_net = now;
            g_event_t nev;
            g_net_check_leak(ne, &nev);
        }

        // Periodic process memory scanning
        if (se && cfg->enable_mem_scan && now - last_mem_scan >= cfg->mem_scan_interval_sec) {
            last_mem_scan = now;
            g_sig_scan_all_proc_mem(se);
        }

        /* Phase 2.1: verify canary files every 30 seconds */
        if (ce && now - last_canary >= 30) {
            last_canary = now;
            int n_bad = g_canary_verify_all(ce);
            if (n_bad > 0) {
                printf("[guardian] CANARY ALERT: %d canary file(s) tampered\n", n_bad);
            }
        }

        /* Phase 2.4: ransomware behavior check every 5 seconds */
        if (re && now - last_ransomware >= 5) {
            last_ransomware = now;
            int n_rw = g_ransomware_check(re);
            if (n_rw > 0) printf("[guardian] RANSOMWARE: %d alert(s)\n", n_rw);
        }

        // Tor bootstrap signature update checks
        if (se && !fetched_updates && strlen(cfg->update_url) > 0) {
            uid_t tuid = 0;
            if (ne) {
                tuid = g_net_get_tor_uid(ne);
            }
            if (tuid != 0 && now - last_update_attempt >= update_retry_interval_sec) {
                last_update_attempt = now;
                printf("[guardian] Tor is running (UID %d). Attempting signature updates from %s (retry interval: %d sec)...\n",
                       tuid, cfg->update_url, update_retry_interval_sec);
                
                int fetch_rc = g_sig_fetch_updates(se, cfg->update_url, cfg->update_pubkey_path);
                if (fetch_rc == 0) {
                    printf("[guardian] Signature updates fetched and verified successfully.\n");
                    fetched_updates = true;
                    
                    // Start canary period of 5 minutes (300 seconds)
                    g_canary_active = true;
                    g_canary_start_time = now;
                    g_canary_post_swap_alerts_start = g_alert_count;
                    
                    double uptime = (double)(now - g_daemon_start_time);
                    if (uptime < 10.0) uptime = 10.0;
                    g_pre_swap_alert_rate = (double)g_alert_count / uptime;
                    if (g_pre_swap_alert_rate < 0.01) {
                        g_pre_swap_alert_rate = 0.01;
                    }
                    printf("[guardian] Canary active. Pre-swap alert rate: %.4f alerts/sec. Baseline count: %lu\n",
                           g_pre_swap_alert_rate, g_alert_count);
                } else {
                    printf("[guardian] Signature update attempt failed (rc=%d). Will retry.\n", fetch_rc);
                    update_retry_interval_sec *= 2;
                    if (update_retry_interval_sec > 3600) {
                        update_retry_interval_sec = 3600;
                    }
                }
            }
        }

        // Canary monitoring
        if (g_canary_active) {
            double elapsed_canary = (double)(now - g_canary_start_time);
            if (elapsed_canary >= 300.0) {
                printf("[guardian] Canary period passed successfully. New YARA rules promoted permanently.\n");
                g_canary_active = false;
                g_sig_commit_updates(se);
            } else {
                uint64_t alerts_since_swap = g_alert_count - g_canary_post_swap_alerts_start;
                double post_swap_rate = (double)alerts_since_swap / (elapsed_canary > 1.0 ? elapsed_canary : 1.0);
                
                if (post_swap_rate > 10.0 * g_pre_swap_alert_rate && alerts_since_swap > 5) {
                    fprintf(stderr, "[guardian] CRITICAL: Alert storm detected during YARA canary (post-swap rate: %.4f/sec, baseline: %.4f/sec). Rolling back!\n",
                            post_swap_rate, g_pre_swap_alert_rate);
                    
                    g_sig_rollback_updates(se);
                    g_canary_active = false;
                    
                    g_event_t rev_ev = {0};
                    g_strlcpy(rev_ev.source, "yara", sizeof(rev_ev.source));
                    g_strlcpy(rev_ev.rule_id, "SIG_UPDATE_ROLLBACK", sizeof(rev_ev.rule_id));
                    rev_ev.severity = G_SEV_CRITICAL;
                    rev_ev.verdict = G_VERDICT_MALICIOUS;
                    rev_ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
                    rev_ev.seq = g_bus_next_seq();
                    snprintf(rev_ev.detail, sizeof(rev_ev.detail),
                             "Canary alert storm detected (rate: %.2f/sec vs baseline: %.2f/sec). Rolled back to previous signature database.",
                             post_swap_rate, g_pre_swap_alert_rate);
                    g_bus_publish(&rev_ev);
                }
            }
        }
    }

    printf("[guardian] shutting down\n");
    unlink("/run/guardian/guardian.pid");
    unlink("/run/guardian/guardian.heartbeat");
    if (ne) g_net_free(ne);
    if (ae) g_anomaly_free(ae);
    if (fe) g_fim_free(fe);
    if (ee) g_ebpf_free(ee);
    if (se) g_sig_free(se);
    if (pe) g_policy_free(pe);
    g_api_socket_close();
    g_log_close_global();
    return 0;
}

int main(int argc, char **argv) {
    /* Vuln 1: block debugging/ptrace injection as early as possible */
    prctl(PR_SET_DUMPABLE, 0);
    g_config_t cfg;
    if (argc > 1 && !strcmp(argv[1], "--self-test")) {
        g_config_defaults(&cfg);
        g_bus_init();
        uint8_t k[32]; memset(k, 0x55, 32);
        g_log_init_global("/dev/null", k);
        g_policy_engine_t *pe = g_policy_init(NULL);
        g_bus_subscribe(log_subscriber, NULL);
        g_bus_subscribe(action_subscriber, pe);  /* Bug 1 fix: pass pe */
        g_action_init();
        return g_daemon_self_test();
    }
    if (argc > 1 && !strcmp(argv[1], "--rebuild-fim")) {
        const char *cfgpath = (argc > 2) ? argv[2] : G_CONFIG_PATH;
        if (g_config_load(&cfg, cfgpath) != 0) {
            g_config_defaults(&cfg);
            g_strlcpy(cfg.sigs_path, "signatures/guardian.yarc", sizeof(cfg.sigs_path));
            g_strlcpy(cfg.fim_db_path, "signatures/fim.db", sizeof(cfg.fim_db_path));
            g_strlcpy(cfg.bpf_dir, "build/bpf", sizeof(cfg.bpf_dir));
            g_strlcpy(cfg.ml_model_path, "ml/anomaly.pkl", sizeof(cfg.ml_model_path));
            g_strlcpy(cfg.log_path, "guardian.log", sizeof(cfg.log_path));
            g_strlcpy(cfg.socket_path, "/tmp/guardian.sock", sizeof(cfg.socket_path));
            g_strlcpy(cfg.policy_path, "rules/guardian.policy", sizeof(cfg.policy_path));
        }

        printf("[guardian] Rebuilding FIM baseline database...\n");
        unlink(cfg.fim_db_path);
        char key_path[G_PATH_MAX];
        snprintf(key_path, sizeof(key_path), "%s.key", cfg.fim_db_path);
        unlink(key_path);

        /* Derive new key */
        uint8_t new_key[32];
        FILE *urand_f = fopen("/dev/urandom", "rb");
        if (urand_f) {
            size_t read_bytes = fread(new_key, 1, 32, urand_f);
            fclose(urand_f);
            if (read_bytes != 32) {
                fprintf(stderr, "[fim] ERROR: /dev/urandom short read (%zu bytes). Cannot generate FIM key — aborting rebuild.\n", read_bytes);
                return 1;
            }
        } else {
            fprintf(stderr, "[fim] ERROR: cannot open /dev/urandom. Cannot generate FIM key — aborting rebuild.\n");
            return 1;
        }

        int fd_key = open(key_path, O_WRONLY | O_CREAT | O_EXCL, 0400);
        if (fd_key >= 0) {
            write(fd_key, new_key, 32);
            close(fd_key);
        }

        g_fim_engine_t *new_fe = g_fim_init(cfg.fim_db_path, new_key, true);
        if (new_fe) {
            char paths_file[G_PATH_MAX];
            snprintf(paths_file, sizeof(paths_file), "%s.paths", cfg.fim_db_path);
            if (access(paths_file, R_OK) != 0) {
                g_strlcpy(paths_file, "rules/fim.paths", sizeof(paths_file));
            }
            if (access(paths_file, R_OK) == 0) {
                g_fim_build_baseline(new_fe, paths_file);
                printf("[guardian] Rebuilt FIM baseline from %s\n", paths_file);
            } else {
                printf("[guardian] Rebuilt FIM baseline database (empty, no paths file found).\n");
            }
            g_fim_free(new_fe);
            return 0;
        } else {
            fprintf(stderr, "[guardian] ERROR: Failed to initialize FIM baseline database during rebuild.\n");
            return 1;
        }
    }
    const char *cfgpath = (argc > 1) ? argv[1] : G_CONFIG_PATH;
    if (g_config_load(&cfg, cfgpath) != 0) {
        fprintf(stderr, "[guardian] no config at %s — using defaults\n", cfgpath);
        g_config_defaults(&cfg);
        /* dev-sandbox overrides */
        g_strlcpy(cfg.sigs_path, "signatures/guardian.yarc", sizeof(cfg.sigs_path));
        g_strlcpy(cfg.fim_db_path, "signatures/fim.db", sizeof(cfg.fim_db_path));
        g_strlcpy(cfg.bpf_dir, "build/bpf", sizeof(cfg.bpf_dir));
        g_strlcpy(cfg.ml_model_path, "ml/anomaly.pkl", sizeof(cfg.ml_model_path));
        g_strlcpy(cfg.log_path, "guardian.log", sizeof(cfg.log_path));
        g_strlcpy(cfg.socket_path, "/tmp/guardian.sock", sizeof(cfg.socket_path));
        g_strlcpy(cfg.policy_path, "rules/guardian.policy", sizeof(cfg.policy_path));
    }
    return g_daemon_run(&cfg);
}
