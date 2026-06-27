
/* guardian.h — WLTIOS Guardian public API (production).
 *
 * The Guardian is a Defender-style endpoint protection engine:
 *   Layer 1: YARA signature engine         (sig_engine.c)
 *   Layer 2: eBPF behavioral rules          (ebpf_engine.c, bpf/*.bpf.c)
 *   Layer 3: File integrity monitor         (fim_engine.c)
 *   Layer 4: Anomaly ML (isolation forest)  (anomaly_engine.c)
 *   Layer 5: Network IDS                    (net_engine.c)
 *   Enforcement: tiered action layer        (action_engine.c)
 *   Policy: threat→action mapping           (policy_engine.c)
 *   Forensic log: SHA-256 chained + AES-GCM (forensic_log.c)
 *
 * No always-on LLM. Deterministic code + small classical ML.
 * Optional on-demand consultant (Qwythos-9B) invoked manually only.
 *
 * Conventions:
 *   - All functions return 0 on success, negative errno on failure.
 *   - All strings are NUL-terminated UTF-8.
 *   - All timestamps are nanoseconds since boot (CLOCK_BOOTTIME).
 *   - All PIDs are kernel PIDs (not TIDs).
 */
#ifndef GUARDIAN_H
#define GUARDIAN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================ *
 *  Constants                                                   *
 * ============================================================ */

#define G_PATH_MAX        4096
#define G_COMM_MAX        16
#define G_RULE_ID_MAX     64
#define G_SOURCE_MAX      32
#define G_DETAIL_MAX      1024
#define G_HASH_HEX_MAX    65   /* 32 bytes SHA-256 = 64 hex chars + NUL */
#define G_MAX_ENGINES     8
#define G_MAX_SUBS        32
#define G_MAX_RULES       256
#define G_RINGBUF_SZ      (256 * 1024)
#define G_LOG_PATH_DEFAULT "/var/log/guardian.log"
#define G_SOCKET_PATH     "/run/guardian.sock"
#define G_CONFIG_PATH     "/etc/wlt/guardian/guardian.conf"
#define G_SIGS_PATH       "/etc/wlt/guardian/sigs/guardian.yarc"
#define G_FIM_DB_PATH     "/etc/wlt/guardian/fim.db"
#define G_BPF_DIR         "/etc/wlt/guardian/bpf/"
#define G_QUARANTINE_DIR  "/var/quarantine/"
#define G_ML_MODEL_PATH   "/etc/wlt/guardian/anomaly.pkl"
#define G_KAIROS_PORT     8080  /* llama.cpp llama-server port */

/* ============================================================ *
 *  Severity / verdict / action tiers                          *
 * ============================================================ */

typedef enum {
    G_SEV_INFO = 0,
    G_SEV_LOW = 1,
    G_SEV_MEDIUM = 2,
    G_SEV_HIGH = 3,
    G_SEV_CRITICAL = 4
} g_severity_t;

typedef enum {
    G_VERDICT_CLEAN = 0,
    G_VERDICT_SUSPICIOUS = 1,
    G_VERDICT_MALICIOUS = 2,
    G_VERDICT_UNKNOWN = 3
} g_verdict_t;

typedef enum {
    /* Tier 0 — observe only (log) */
    G_ACT_LOG = 0,
    /* Tier 1 — reversible (autonomous) */
    G_ACT_FREEZE = 1,        /* SIGSTOP / cgroup freezer */
    G_ACT_THAW = 2,          /* reverse a freeze */
    G_ACT_QUARANTINE_FILE = 3,   /* move file to /var/quarantine */
    G_ACT_RESTORE_FILE = 4,      /* restore from baseline */
    G_ACT_QUARANTINE_PROC = 5,   /* unshare CLONE_NEWNET isolation */
    G_ACT_BLOCK_NET = 6,         /* block pid's network egress */
    G_ACT_ALERT = 7,             /* notify user via compositor */
    /* Tier 2 — irreversible (HUMAN CONFIRM REQUIRED) */
    G_ACT_KILL = 10,             /* SIGKILL with forensic snapshot */
    G_ACT_DELETE = 11,           /* secure delete (3-pass + unlink) */
    G_ACT_ENCRYPT = 12,          /* Key Vault encrypt */
    G_ACT_KILL_SWITCH = 13       /* full network lockdown (SIOCDELRT) */
} g_action_t;

/* Is an action reversible? Drives autonomous-vs-human-confirm policy. */
static inline bool g_action_is_reversible(g_action_t a) {
    return a >= G_ACT_LOG && a <= G_ACT_ALERT;
}

static inline bool g_action_is_irreversible(g_action_t a) {
    return a >= G_ACT_KILL;
}

static inline const char *g_severity_str(g_severity_t s) {
    static const char *names[] = {"INFO","LOW","MEDIUM","HIGH","CRITICAL"};
    return (s <= G_SEV_CRITICAL) ? names[s] : "?";
}

static inline const char *g_verdict_str(g_verdict_t v) {
    static const char *names[] = {"CLEAN","SUSPICIOUS","MALICIOUS","UNKNOWN"};
    return (v <= G_VERDICT_UNKNOWN) ? names[v] : "?";
}

static inline const char *g_action_str(g_action_t a) {
    switch (a) {
        case G_ACT_LOG:             return "LOG";
        case G_ACT_FREEZE:          return "FREEZE";
        case G_ACT_THAW:            return "THAW";
        case G_ACT_QUARANTINE_FILE: return "QUARANTINE_FILE";
        case G_ACT_RESTORE_FILE:    return "RESTORE_FILE";
        case G_ACT_QUARANTINE_PROC: return "QUARANTINE_PROC";
        case G_ACT_BLOCK_NET:       return "BLOCK_NET";
        case G_ACT_ALERT:           return "ALERT";
        case G_ACT_KILL:            return "KILL";
        case G_ACT_DELETE:          return "DELETE";
        case G_ACT_ENCRYPT:         return "ENCRYPT";
        case G_ACT_KILL_SWITCH:     return "KILL_SWITCH";
        default: return "?";
    }
}

/* ============================================================ *
 *  Event structure (the unified internal event)               *
 * ============================================================ */

typedef struct {
    uint64_t ts_ns;            /* CLOCK_BOOTTIME nanoseconds */
    uint64_t seq;              /* monotonic sequence number */
    uint32_t pid;              /* offending pid (0 = system/global) */
    uint32_t ppid;
    uid_t     uid;
    char     comm[G_COMM_MAX];
    char     pcomm[G_COMM_MAX];   /* BUG 7: parent comm for IOA ancestry rules */
    char     path[G_PATH_MAX];
    char     detail[G_DETAIL_MAX];
    g_severity_t severity;
    g_verdict_t  verdict;
    g_action_t   action_taken;
    char     source[G_SOURCE_MAX];    /* "yara"|"ebpf"|"fim"|"anomaly"|"net"|"policy" */
    char     rule_id[G_RULE_ID_MAX];
    char     evidence_hash[G_HASH_HEX_MAX];  /* SHA-256 of supporting evidence */
} g_event_t;

/* ============================================================ *
 *  Event bus (in-process pub/sub)                             *
 * ============================================================ */

typedef void (*g_subscriber_t)(const g_event_t *ev, void *ud);

int  g_bus_init(void);
int  g_bus_publish(const g_event_t *ev);
int  g_bus_subscribe(g_subscriber_t sub, void *ud);
uint64_t g_bus_next_seq(void);   /* thread-safe sequence allocator */

/* ============================================================ *
 *  Forensic log (SHA-256 chained + AES-256-GCM encrypted)     *
 * ============================================================ */

typedef struct g_log g_log_t;

g_log_t *g_log_open(const char *path, const uint8_t key[32]);
int      g_log_append(g_log_t *log, const g_event_t *ev);
int      g_log_verify(g_log_t *log, char *out_break_at, size_t out_sz);
void     g_log_close(g_log_t *log);

/* global singleton helpers (used by the daemon) */
int  g_log_init_global(const char *path, const uint8_t key[32]);
int  g_log_append_global(const g_event_t *ev);
void g_log_close_global(void);

/* ============================================================ *
 *  Layer 1: YARA signature engine                             *
 * ============================================================ */

typedef struct g_sig_engine g_sig_engine_t;

g_sig_engine_t *g_sig_init(const char *compiled_rules_path);
void            g_sig_free(g_sig_engine_t *se);
int  g_sig_scan_file(g_sig_engine_t *se, const char *path, g_event_t *out);
int  g_sig_scan_mem(g_sig_engine_t *se, const uint8_t *buf, size_t len, g_event_t *out);
int  g_sig_scan_proc_mem(g_sig_engine_t *se, pid_t pid, g_event_t *out);
int  g_sig_scan_proc_mem_regions(g_sig_engine_t *se, pid_t pid, g_event_t *out);
int  g_sig_fetch_updates(g_sig_engine_t *se, const char *update_url, const char *pubkey_path);
void g_sig_commit_updates(g_sig_engine_t *se);
int  g_sig_rollback_updates(g_sig_engine_t *se);
int  g_sig_stats(g_sig_engine_t *se, int *out_nrules, int *out_nscans);

/* ============================================================ *
 *  Layer 2: eBPF behavioral engine                            *
 * ============================================================ */

typedef struct g_ebpf_engine g_ebpf_engine_t;

g_ebpf_engine_t *g_ebpf_init(const char *bpf_dir);
void             g_ebpf_free(g_ebpf_engine_t *ee);
int  g_ebpf_load_all(g_ebpf_engine_t *ee);   /* loads all .bpf.o in dir */
int  g_ebpf_poll(g_ebpf_engine_t *ee, int timeout_ms);  /* poll ringbuf, dispatch events */
int  g_ebpf_attach_tracepoint(g_ebpf_engine_t *ee, const char *prog_name,
                              const char *tp_category, const char *tp_name);
int  g_ebpf_enforce_kill(pid_t pid);   /* inline bpf_send_signal (Tetragon-style) */
int  g_ebpf_stats(g_ebpf_engine_t *ee, int *out_nprogs, int *out_nevents);
int  g_ebpf_set_map_value(g_ebpf_engine_t *ee, const char *map_name, const void *key, const void *val);
int  g_ebpf_get_map_value(g_ebpf_engine_t *ee, const char *map_name, const void *key, void *out);  /* Phase 2.3/2.4 */
int  g_ebpf_set_kill_switch_active(bool active);


/* Falco-style rule engine (consumes eBPF events) */
typedef struct {
    char     rule_id[G_RULE_ID_MAX];
    char     desc[G_DETAIL_MAX];
    char     condition[G_DETAIL_MAX];   /* simple expression language */
    g_severity_t severity;
    g_action_t   action;
} g_ebpf_rule_t;

int  g_ebpf_rules_load(g_ebpf_engine_t *ee, const char *rules_path);
int  g_ebpf_rules_eval(g_ebpf_engine_t *ee, const g_event_t *raw, g_event_t *out);

/* ============================================================ *
 *  Layer 3: File integrity monitor (custom, replaces AIDE)    *
 * ============================================================ */

typedef struct g_fim_engine g_fim_engine_t;

g_fim_engine_t *g_fim_init(const char *db_path, const uint8_t key[32], bool encrypt_enabled);
void            g_fim_free(g_fim_engine_t *fe);
int  g_fim_add_watch(g_fim_engine_t *fe, const char *path);
int  g_fim_build_baseline(g_fim_engine_t *fe, const char *paths_file);
int  g_fim_check_path(g_fim_engine_t *fe, const char *path, g_event_t *out);
int  g_fim_scan_all(g_fim_engine_t *fe, int (*cb)(const g_event_t *, void *), void *ud);
int  g_fim_restore(g_fim_engine_t *fe, const char *path);  /* restore from baseline */
int  g_fim_watch_inotify(g_fim_engine_t *fe, int timeout_ms,
                         int (*cb)(const g_event_t *, void *), void *ud);

/* Test helpers for Phase 3 self-test */
int  g_fim_test_has_ciphertext(g_fim_engine_t *fe, const char *path);
int  g_fim_test_tamper_tag(g_fim_engine_t *fe, const char *path);


/* ============================================================ *
 *  Layer 4: Anomaly ML (isolation forest via Python bridge)   *
 * ============================================================ */

typedef struct g_anomaly_engine g_anomaly_engine_t;

g_anomaly_engine_t *g_anomaly_init(const char *model_path, const char *py_bin);
void                g_anomaly_free(g_anomaly_engine_t *ae);
int  g_anomaly_check_proc(g_anomaly_engine_t *ae, pid_t pid, g_event_t *out);
int  g_anomaly_check_system(g_anomaly_engine_t *ae, g_event_t *out);
int  g_anomaly_check_all_procs(g_anomaly_engine_t *ae, g_sig_engine_t *se);  /* Bug 16 fix: enumerate /proc */

/* collect per-process feature vector from /proc */
int  g_anomaly_collect_features(pid_t pid, double out[8]);

/* ============================================================ *
 *  Phase 2.2: Isolation Forest inference in C (replaces Python) *
 * ============================================================ */

typedef struct g_iforest g_iforest_t;

g_iforest_t *g_iforest_load(const char *path);
void         g_iforest_free(g_iforest_t *ifo);
double       g_iforest_score(const g_iforest_t *ifo, const double *features);  /* [0,1], >0.5=anomaly */
uint32_t     g_iforest_n_features(const g_iforest_t *ifo);
double       g_iforest_threshold(const g_iforest_t *ifo);

/* ============================================================ *
 *  Phase 2.1: Canary file engine (ransomware detection)         *
 * ============================================================ */

typedef struct g_canary_engine g_canary_engine_t;

g_canary_engine_t *g_canary_init(void);
void               g_canary_free(g_canary_engine_t *ce);
int  g_canary_verify_all(g_canary_engine_t *ce);  /* returns # missing/tampered */

/* Phase 2.4: ransomware behavior detection */
typedef struct g_ransomware_engine g_ransomware_engine_t;
g_ransomware_engine_t *g_ransomware_init(void);
void                   g_ransomware_free(g_ransomware_engine_t *re);
int  g_ransomware_check(g_ransomware_engine_t *re);  /* returns # alerts emitted */

/* Phase 4.2: PMU hardware performance counters (side-channel + crypto-miner) */
typedef struct g_pmu_engine g_pmu_engine_t;
g_pmu_engine_t *g_pmu_init(void);
void            g_pmu_free(g_pmu_engine_t *pe);
int  g_pmu_check_pid(g_pmu_engine_t *pe, pid_t pid, int duration_ms);  /* 0=clean 1=sidechan 2=miner */

/* ============================================================ *
 *  Layer 5: Network IDS (af_packet sniffer, Tor-focused)      *
 * ============================================================ */

typedef struct g_net_engine g_net_engine_t;

g_net_engine_t *g_net_init(const char *ifname);
void            g_net_free(g_net_engine_t *ne);
int  g_net_capture(g_net_engine_t *ne, int duration_sec,
                   int (*cb)(const g_event_t *, void *), void *ud);
int  g_net_check_leak(g_net_engine_t *ne, g_event_t *out);  /* non-Tor egress check */
uid_t g_net_get_tor_uid(g_net_engine_t *ne);


/* ============================================================ *
 *  Action engine (enforcement execution)                      *
 * ============================================================ */

int  g_action_init(void);
int  g_action_apply(const g_event_t *ev);  /* executes ev->action_taken */
int  g_action_freeze(pid_t pid);
int  g_action_thaw(pid_t pid);
int  g_action_quarantine_file(const char *path);
int  g_action_restore_file(const char *path);
int  g_action_quarantine_proc(pid_t pid);
int  g_action_block_net(pid_t pid);
int  g_action_kill(pid_t pid, bool take_snapshot);
int  g_action_delete(const char *path);
int  g_action_kill_switch(void);

/* ============================================================ *
 *  Policy engine (threat→action mapping, deterministic)       *
 * ============================================================ */

typedef struct g_policy_engine g_policy_engine_t;

g_policy_engine_t *g_policy_init(const char *policy_path);
void               g_policy_free(g_policy_engine_t *pe);
/* decide what action to take for a given event */
g_action_t g_policy_decide(g_policy_engine_t *pe, const g_event_t *ev);
/* apply policy to an event (mutates ev->action_taken) then publishes */
int  g_policy_apply(g_policy_engine_t *pe, g_event_t *ev);

/* ============================================================ *
 *  Daemon lifecycle                                           *
 * ============================================================ */

typedef struct {
    char     sigs_path[G_PATH_MAX];
    char     fim_db_path[G_PATH_MAX];
    char     bpf_dir[G_PATH_MAX];
    char     ml_model_path[G_PATH_MAX];
    char     log_path[G_PATH_MAX];
    char     socket_path[G_PATH_MAX];
    char     policy_path[G_PATH_MAX];
    char     net_ifname[64];
    bool     enable_ebpf;
    bool     enable_fim;
    bool     enable_net;
    bool     enable_ml;
    bool     daemonize;
    int      fim_scan_interval_sec;   /* default 300 (5 min) */
    int      ml_check_interval_sec;   /* default 60 */
    bool     enable_mem_scan;         /* default true */
    int      mem_scan_interval_sec;   /* default 60 */
    char     update_url[G_PATH_MAX];
    char     update_pubkey_path[G_PATH_MAX];
} g_config_t;

int  g_config_load(g_config_t *cfg, const char *path);
int  g_config_defaults(g_config_t *cfg);

int  g_daemon_run(const g_config_t *cfg);
int  g_daemon_self_test(void);
void g_daemon_shutdown(void);   /* signal handler target */

/* API socket (Unix socket for wlt-shell / Kairos queries) */
typedef struct {
    bool sig;
    bool ebpf;
    bool fim;
    bool anomaly;
    bool net;
} g_engine_status_t;

int  g_api_socket_init(const char *path, const g_engine_status_t *status);
int  g_api_socket_poll(int timeout_ms, g_sig_engine_t *se);
void g_api_socket_close(void);

/* ============================================================ *
 *  Utility: SHA-256, hashing, safe string ops                *
 * ============================================================ */

void g_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void g_sha256_hex(const uint8_t *data, size_t len, char out[65]);
void g_sha256_init_ctx(void *ctx);
void g_sha256_update_ctx(void *ctx, const uint8_t *data, size_t len);
void g_sha256_final_ctx(void *ctx, uint8_t out[32]);

/* AES-256-GCM (uses openssl if available, else stub) */
int  g_aes_gcm_encrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *plain, size_t plain_len,
                       const uint8_t *aad, size_t aad_len,
                       uint8_t *cipher, uint8_t tag[16]);
int  g_aes_gcm_decrypt(const uint8_t *key, const uint8_t *iv, size_t iv_len,
                       const uint8_t *cipher, size_t cipher_len,
                       const uint8_t *aad, size_t aad_len,
                       const uint8_t tag[16], uint8_t *plain);

/* safe string copy that always NUL-terminates */
size_t g_strlcpy(char *dst, const char *src, size_t sz);

#ifdef __cplusplus
}
#endif
#endif /* GUARDIAN_H */
