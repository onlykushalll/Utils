
/* sig_engine.c — Layer 1: YARA signature engine.
 *
 * Loads compiled YARA rules and scans files/memory for known-bad patterns.
 * On a hit, emits a g_event_t to the bus. Millisecond-fast, deterministic.
 */
#include "guardian.h"
#include <yara.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <ctype.h>

struct g_sig_engine {
    YR_RULES *rules;
    int n_rules;
    int n_scans;
    char compiled_rules_path[G_PATH_MAX];
    
    // Canary rollback fields
    YR_RULES *backup_rules;
    int backup_n_rules;
};

typedef struct {
    g_event_t *out;
    bool matched;
} sig_scan_ctx;

static int yara_callback(YR_SCAN_CONTEXT *ctx, int msg, void *msg_data, void *ud) {
    if (msg == CALLBACK_MSG_RULE_MATCHING) {
        sig_scan_ctx *sc = (sig_scan_ctx*)ud;
        YR_RULE *r = (YR_RULE *)msg_data;
        g_strlcpy(sc->out->rule_id, r->identifier, sizeof(sc->out->rule_id));
        sc->matched = true;
        sc->out->verdict = G_VERDICT_MALICIOUS;
        /* severity heuristic from rule tags — v1: HIGH for any match */
        sc->out->severity = G_SEV_HIGH;
        sc->out->action_taken = G_ACT_LOG;  /* policy engine upgrades */
    }
    return CALLBACK_CONTINUE;
}

g_sig_engine_t *g_sig_init(const char *compiled_rules_path) {
    if (yr_initialize() != ERROR_SUCCESS) {
        fprintf(stderr, "[sig] yara initialize failed\n");
        return NULL;
    }
    g_sig_engine_t *se = calloc(1, sizeof(*se));
    if (!se) return NULL;
    
    if (compiled_rules_path) {
        g_strlcpy(se->compiled_rules_path, compiled_rules_path, sizeof(se->compiled_rules_path));
        int rc = yr_rules_load(compiled_rules_path, &se->rules);
        if (rc != ERROR_SUCCESS) {
            fprintf(stderr, "[sig] load rules '%s' failed: %d\n", compiled_rules_path, rc);
            free(se);
            return NULL;
        }
    }
    
    /* count rules */
    if (se->rules) {
        YR_RULE *r;
        yr_rules_foreach(se->rules, r) se->n_rules++;
    }
    printf("[sig] loaded %d rules from %s\n", se->n_rules, compiled_rules_path ? compiled_rules_path : "NULL");
    return se;
}

void g_sig_free(g_sig_engine_t *se) {
    if (!se) return;
    if (se->rules) yr_rules_destroy(se->rules);
    free(se);
}

int g_sig_scan_file(g_sig_engine_t *se, const char *path, g_event_t *out) {
    if (!se || !path || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    g_strlcpy(out->source, "yara", sizeof(out->source));
    g_strlcpy(out->path, path, sizeof(out->path));
    out->pid = 0;
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();

    sig_scan_ctx sc = {out, false};
    int rc = yr_rules_scan_file(se->rules, path, 0, yara_callback, &sc, 0);
    se->n_scans++;
    if (rc != ERROR_SUCCESS) {
        out->verdict = G_VERDICT_UNKNOWN;
        return -rc;
    }
    if (!sc.matched) {
        out->verdict = G_VERDICT_CLEAN;
        out->severity = G_SEV_INFO;
        return 0;  /* Bug 22 fix: don't publish CLEAN events — avoids log spam */
    }
    g_bus_publish(out);
    return 1;
}

int g_sig_scan_mem(g_sig_engine_t *se, const uint8_t *buf, size_t len, g_event_t *out) {
    if (!se || !buf || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    g_strlcpy(out->source, "yara", sizeof(out->source));
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();

    sig_scan_ctx sc = {out, false};
    int rc = yr_rules_scan_mem(se->rules, buf, len, 0, yara_callback, &sc, 0);
    se->n_scans++;
    if (rc != ERROR_SUCCESS) { out->verdict = G_VERDICT_UNKNOWN; return -rc; }
    if (!sc.matched) { out->verdict = G_VERDICT_CLEAN; return 0; }  /* Bug 22 */
    g_bus_publish(out);
    return 1;
}

int g_sig_scan_proc_mem(g_sig_engine_t *se, pid_t pid, g_event_t *out) {
    if (!se || !out) return -EINVAL;
    /* read /proc/<pid>/maps to find readable regions, then read /proc/<pid>/mem.
     * v1: scan the cmdline + environ (cheap, catches string-based sigs). */
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "rb");
    if (!f) return -errno;
    char buf[8192] = {0};
    size_t n = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    if (n == 0) return 0;
    g_strlcpy(out->path, path, sizeof(out->path));
    out->pid = pid;
    return g_sig_scan_mem(se, (uint8_t*)buf, n, out);
}

int g_sig_stats(g_sig_engine_t *se, int *out_nrules, int *out_nscans) {
    if (!se) return -EINVAL;
    if (out_nrules) *out_nrules = se->n_rules;
    if (out_nscans) *out_nscans = se->n_scans;
    return 0;
}

/* ============================================================ *
 *  Phase 4: Process Memory Scanning (Workstream A)             *
 * ============================================================ */

int g_sig_scan_proc_mem_regions(g_sig_engine_t *se, pid_t pid, g_event_t *out) {
    if (!se || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    g_strlcpy(out->source, "yara", sizeof(out->source));
    out->pid = pid;
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();

    /* Phase 4.3: precheck — scan the exe symlink via YARA file scan (cheap).
     * Catches malware where the on-disk binary itself matches a signature,
     * without needing to walk /proc/pid/maps. */
    {
        char exe_path[64];
        char exe_target[G_PATH_MAX];
        snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", pid);
        ssize_t n = readlink(exe_path, exe_target, sizeof(exe_target)-1);
        if (n > 0) {
            exe_target[n] = 0;
            g_event_t file_ev = {0};
            if (g_sig_scan_file(se, exe_target, &file_ev) > 0) {
                *out = file_ev;
                out->pid = pid;
                return 1;
            }
        }
    }

    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    
    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDONLY);
    if (mem_fd < 0) {
        // Handle gracefully: if /proc/<pid>/mem can't be opened, skip the scan.
        out->verdict = G_VERDICT_CLEAN;
        out->severity = G_SEV_INFO;
        return 0;
    }

    struct timespec start_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    bool matched = false;
    char matched_rule[G_RULE_ID_MAX] = {0};
    unsigned long match_start = 0, match_end = 0;

    /* Two-pass scan. Total timeout of 500ms is tracked per-process. */

    /* PASS 1: Priority 1 regions — Writable + Executable (rwx) */
    FILE *f = fopen(maps_path, "r");
    if (f) {
        char line[1024];
        while (fgets(line, sizeof(line), f)) {
            // Check process total timeout
            struct timespec cur_time;
            clock_gettime(CLOCK_MONOTONIC, &cur_time);
            double elapsed_ms = (cur_time.tv_sec - start_time.tv_sec) * 1000.0 +
                                (cur_time.tv_nsec - start_time.tv_nsec) / 1000000.0;
            if (elapsed_ms > 500.0) {
                printf("[sig] Memory scan for PID %d exceeded 500ms total timeout in Pass 1.\n", pid);
                break;
            }

            unsigned long start = 0, end = 0;
            char perms[5] = {0};
            int n = -1;
            int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %n", &start, &end, perms, &n);
            if (fields < 3) continue;

            // Priority 1: must be rwx
            if (strncmp(perms, "rwx", 3) != 0) continue;

            size_t size = end - start;
            if (size == 0) continue;

            // Cap region size at 64MB
            if (size > 64 * 1024 * 1024) {
                printf("[sig] Skipping large anonymous region at 0x%lx for PID %d (size: %zu MB)\n", start, pid, size / (1024 * 1024));
                continue;
            }

            uint8_t *region_buf = malloc(size);
            if (!region_buf) continue;

            ssize_t bytes_read = pread(mem_fd, region_buf, size, (off_t)start);
            if (bytes_read <= 0) {
                // TOCTOU: region unmapped mid-scan
                free(region_buf);
                continue;
            }

            sig_scan_ctx sc = {out, false};
            int rc = yr_rules_scan_mem(se->rules, region_buf, bytes_read, 0, yara_callback, &sc, 0);
            se->n_scans++;
            free(region_buf);

            if (rc == ERROR_SUCCESS && sc.matched) {
                g_strlcpy(matched_rule, out->rule_id, sizeof(matched_rule));
                match_start = start;
                match_end = end;
                matched = true;
                break;
            }
        }
        fclose(f);
    }

    /* PASS 2: Priority 2 regions — Anonymous rw- or [heap] (if time allows and no match yet) */
    if (!matched) {
        f = fopen(maps_path, "r");
        if (f) {
            char line[1024];
            while (fgets(line, sizeof(line), f)) {
                // Check process total timeout
                struct timespec cur_time;
                clock_gettime(CLOCK_MONOTONIC, &cur_time);
                double elapsed_ms = (cur_time.tv_sec - start_time.tv_sec) * 1000.0 +
                                    (cur_time.tv_nsec - start_time.tv_nsec) / 1000000.0;
                if (elapsed_ms > 500.0) {
                    printf("[sig] Memory scan for PID %d exceeded 500ms total timeout in Pass 2.\n", pid);
                    break;
                }

                unsigned long start = 0, end = 0;
                char perms[5] = {0};
                int n = -1;
                int fields = sscanf(line, "%lx-%lx %4s %*s %*s %*s %n", &start, &end, perms, &n);
                if (fields < 3) continue;

                // Priority 2: must be rw-
                if (strncmp(perms, "rw-", 3) != 0) continue;

                // Parse pathname (if any)
                char path[G_PATH_MAX] = {0};
                if (n != -1 && n < (int)strlen(line)) {
                    char *p = line + n;
                    while (*p == ' ' || *p == '\t') p++;
                    g_strlcpy(path, p, sizeof(path));
                    size_t len = strlen(path);
                    while (len > 0 && (path[len - 1] == '\n' || path[len - 1] == '\r' || path[len - 1] == ' ' || path[len - 1] == '\t')) {
                        path[len - 1] = '\0';
                        len--;
                    }
                }

                // Phase 4.3: scan anonymous + [heap] + (deleted) files + /tmp-backed
                // (deleted) regions = fileless malware loaders; /tmp = drop location
                if (strlen(path) > 0 && strcmp(path, "[heap]") != 0) {
                    bool is_deleted = (strstr(path, "(deleted)") != NULL);
                    bool is_tmp = (strncmp(path, "/tmp/", 5) == 0);
                    if (!is_deleted && !is_tmp) continue;
                }

                size_t size = end - start;
                if (size == 0) continue;

                // Cap region size at 64MB
                if (size > 64 * 1024 * 1024) {
                    printf("[sig] Skipping large anonymous region at 0x%lx for PID %d (size: %zu MB)\n", start, pid, size / (1024 * 1024));
                    continue;
                }

                uint8_t *region_buf = malloc(size);
                if (!region_buf) continue;

                ssize_t bytes_read = pread(mem_fd, region_buf, size, (off_t)start);
                if (bytes_read <= 0) {
                    // TOCTOU: region unmapped mid-scan
                    free(region_buf);
                    continue;
                }

                sig_scan_ctx sc = {out, false};
                int rc = yr_rules_scan_mem(se->rules, region_buf, bytes_read, 0, yara_callback, &sc, 0);
                se->n_scans++;
                free(region_buf);

                if (rc == ERROR_SUCCESS && sc.matched) {
                    g_strlcpy(matched_rule, out->rule_id, sizeof(matched_rule));
                    match_start = start;
                    match_end = end;
                    matched = true;
                    break;
                }
            }
            fclose(f);
        }
    }

    close(mem_fd);

    if (matched) {
        memset(out, 0, sizeof(*out));
        g_strlcpy(out->source, "yara", sizeof(out->source));
        g_strlcpy(out->rule_id, "PROC_MEM_MATCH", sizeof(out->rule_id));
        out->severity = G_SEV_HIGH;
        out->action_taken = G_ACT_FREEZE;
        out->verdict = G_VERDICT_MALICIOUS;
        out->pid = pid;
        out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
        out->seq = g_bus_next_seq();
        snprintf(out->detail, sizeof(out->detail), "YARA rule %s matched in process memory region 0x%lx-0x%lx", matched_rule, match_start, match_end);
        
        g_bus_publish(out);
        return 1;
    }

    // No match: return 0
    memset(out, 0, sizeof(*out));
    g_strlcpy(out->source, "yara", sizeof(out->source));
    out->pid = pid;
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();
    out->verdict = G_VERDICT_CLEAN;
    out->severity = G_SEV_INFO;
    return 0;
}

/* ============================================================ *
 *  Phase 4: Signed YARA Updates over Tor (Workstream B)        *
 * ============================================================ */

static bool is_valid_onion_url(const char *url) {
    if (!url) return false;
    const char *p = strstr(url, "://");
    if (!p) return false;
    p += 3; // Skip ://
    const char *end = p;
    while (*end && *end != '/' && *end != ':') {
        end++;
    }
    size_t host_len = end - p;
    if (host_len < 6) return false; // minimum length for x.onion
    if (strncmp(end - 6, ".onion", 6) != 0) {
        return false;
    }
    return true;
}

static int run_curl_fetch(const char *url, const char *out_path) {
    pid_t pid = fork();
    if (pid < 0) return -errno;
    if (pid == 0) {
        // Child
        prctl(PR_SET_PDEATHSIG, SIGKILL);
        
        // Redirect stdout/stderr to /dev/null
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        
        char *argv[] = {
            "curl",
            "--socks5-hostname", "127.0.0.1:9050",
            "-s", "-f", "-o", (char *)out_path,
            (char *)url,
            NULL
        };
        execvp("curl", argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    return -EIO;
}

static int verify_ed25519_signature(const uint8_t *data, size_t data_len,
                                    const uint8_t *sig, size_t sig_len,
                                    const char *pubkey_path) {
    FILE *f = fopen(pubkey_path, "r");
    if (!f) return -errno;
    EVP_PKEY *pubkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pubkey) return -EINVAL;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        EVP_PKEY_free(pubkey);
        return -ENOMEM;
    }

    int rc = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pubkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pubkey);
        return -EINVAL;
    }

    rc = EVP_DigestVerify(ctx, sig, sig_len, data, data_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pubkey);

    if (rc == 1) {
        return 0; // Valid
    }
    return -EACCES; // Invalid
}

static int copy_file(const char *src, const char *dst) {
    int sfd = open(src, O_RDONLY);
    if (sfd < 0) return -errno;
    int dfd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (dfd < 0) {
        close(sfd);
        return -errno;
    }
    char buf[4096];
    ssize_t n;
    while ((n = read(sfd, buf, sizeof(buf))) > 0) {
        if (write(dfd, buf, n) != n) {
            close(sfd);
            close(dfd);
            return -EIO;
        }
    }
    close(sfd);
    close(dfd);
    return 0;
}

static void write_update_status(const char *result) {
    mkdir("/run/guardian", 0700);
    FILE *f = fopen("/run/guardian/sig_update.status", "w");
    if (f) {
        fprintf(f, "{\n  \"version\": \"1.0\",\n  \"last_update_ts\": %ld,\n  \"last_update_result\": \"%s\"\n}\n",
                (long)time(NULL), result);
        fclose(f);
    }
}

int g_sig_fetch_updates(g_sig_engine_t *se, const char *update_url, const char *pubkey_path) {
    if (!se || !update_url || !pubkey_path) return -EINVAL;
    if (strlen(update_url) == 0) {
        write_update_status("disabled");
        return 0;
    }

    if (!is_valid_onion_url(update_url)) {
        fprintf(stderr, "[sig] ERROR: update URL '%s' is not a valid Tor .onion address\n", update_url);
        write_update_status("failed");
        return -EINVAL;
    }

    char dl_path[G_PATH_MAX];
    snprintf(dl_path, sizeof(dl_path), "%s.dl", se->compiled_rules_path);
    unlink(dl_path);

    int rc = run_curl_fetch(update_url, dl_path);
    if (rc != 0) {
        printf("[sig] INFO: SIG_UPDATE_FETCH_FAILED\n");
        write_update_status("failed");
        unlink(dl_path);
        return 0; // Silently keep baseline, return 0
    }

    FILE *f = fopen(dl_path, "rb");
    if (!f) {
        printf("[sig] INFO: SIG_UPDATE_FETCH_FAILED\n");
        write_update_status("failed");
        unlink(dl_path);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (sz < 64) {
        fprintf(stderr, "[sig] ERROR: fetched rule pack is too small (%ld bytes)\n", sz);
        fclose(f);
        unlink(dl_path);
        write_update_status("failed");

        g_event_t ev = {0};
        g_strlcpy(ev.source, "yara", sizeof(ev.source));
        g_strlcpy(ev.rule_id, "SIG_UPDATE_SIGNATURE_INVALID", sizeof(ev.rule_id));
        ev.severity = G_SEV_CRITICAL;
        ev.verdict = G_VERDICT_MALICIOUS;
        ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
        ev.seq = g_bus_next_seq();
        snprintf(ev.detail, sizeof(ev.detail), "Fetched signature update from %s is truncated", update_url);
        g_bus_publish(&ev);
        return -EINVAL;
    }

    size_t data_len = (size_t)sz - 64;
    uint8_t *file_buf = malloc(sz);
    if (!file_buf) {
        fclose(f);
        unlink(dl_path);
        return -ENOMEM;
    }

    if (fread(file_buf, 1, sz, f) != (size_t)sz) {
        free(file_buf);
        fclose(f);
        unlink(dl_path);
        return -EIO;
    }
    fclose(f);
    unlink(dl_path);

    uint8_t *data = file_buf;
    uint8_t *sig = file_buf + data_len;

    int sig_rc = verify_ed25519_signature(data, data_len, sig, 64, pubkey_path);
    if (sig_rc != 0) {
        free(file_buf);
        fprintf(stderr, "[sig] ERROR: SIG_UPDATE_SIGNATURE_INVALID\n");
        write_update_status("failed");

        g_event_t ev = {0};
        g_strlcpy(ev.source, "yara", sizeof(ev.source));
        g_strlcpy(ev.rule_id, "SIG_UPDATE_SIGNATURE_INVALID", sizeof(ev.rule_id));
        ev.severity = G_SEV_CRITICAL;
        ev.verdict = G_VERDICT_MALICIOUS;
        ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
        ev.seq = g_bus_next_seq();
        snprintf(ev.detail, sizeof(ev.detail), "Cryptographic signature check failed on YARA updates from %s", update_url);
        g_bus_publish(&ev);
        return -EACCES;
    }

    char temp_rules_path[G_PATH_MAX];
    snprintf(temp_rules_path, sizeof(temp_rules_path), "%s.tmp", se->compiled_rules_path);
    unlink(temp_rules_path);

    FILE *tf = fopen(temp_rules_path, "wb");
    if (!tf) {
        free(file_buf);
        return -errno;
    }
    if (fwrite(data, 1, data_len, tf) != data_len) {
        fclose(tf);
        unlink(temp_rules_path);
        free(file_buf);
        return -EIO;
    }
    fclose(tf);
    free(file_buf);

    YR_RULES *new_rules = NULL;
    int load_rc = yr_rules_load(temp_rules_path, &new_rules);
    if (load_rc != ERROR_SUCCESS) {
        fprintf(stderr, "[sig] ERROR: fetched rules failed to compile/load: %d\n", load_rc);
        unlink(temp_rules_path);
        write_update_status("failed");
        return -EINVAL;
    }

    // Backup the old file on disk first
    char backup_file_path[G_PATH_MAX];
    snprintf(backup_file_path, sizeof(backup_file_path), "%s.bak", se->compiled_rules_path);
    unlink(backup_file_path);
    copy_file(se->compiled_rules_path, backup_file_path);

    // Atomically replace on disk
    if (rename(temp_rules_path, se->compiled_rules_path) != 0) {
        yr_rules_destroy(new_rules);
        unlink(temp_rules_path);
        unlink(backup_file_path);
        write_update_status("failed");
        return -errno;
    }

    // Preserve old rules in memory as backup for canary rollback
    if (se->backup_rules) {
        yr_rules_destroy(se->backup_rules);
    }
    se->backup_rules = se->rules;
    se->backup_n_rules = se->n_rules;

    // Swap in the new rules in-memory
    se->rules = new_rules;
    se->n_rules = 0;
    YR_RULE *r;
    yr_rules_foreach(se->rules, r) se->n_rules++;

    printf("[sig] YARA signature database updated to %d rules (backup stored for canary)\n", se->n_rules);
    write_update_status("success");
    return 0;
}

void g_sig_commit_updates(g_sig_engine_t *se) {
    if (!se) return;
    if (se->backup_rules) {
        yr_rules_destroy(se->backup_rules);
        se->backup_rules = NULL;
    }
    char backup_file_path[G_PATH_MAX];
    snprintf(backup_file_path, sizeof(backup_file_path), "%s.bak", se->compiled_rules_path);
    unlink(backup_file_path);
}

int g_sig_rollback_updates(g_sig_engine_t *se) {
    if (!se || !se->backup_rules) return -EINVAL;

    char backup_file_path[G_PATH_MAX];
    snprintf(backup_file_path, sizeof(backup_file_path), "%s.bak", se->compiled_rules_path);

    if (rename(backup_file_path, se->compiled_rules_path) != 0) {
        copy_file(backup_file_path, se->compiled_rules_path);
    }
    unlink(backup_file_path);

    if (se->rules) {
        yr_rules_destroy(se->rules);
    }
    se->rules = se->backup_rules;
    se->n_rules = se->backup_n_rules;
    se->backup_rules = NULL;

    printf("[sig] successfully rolled back to previous signature database (%d rules)\n", se->n_rules);
    return 0;
}
