
/* anomaly_engine.c — Layer 4: isolation forest anomaly detection (C bridge).
 *
 * The actual model is Python (ml/anomaly.py, pickled sklearn IsolationForest).
 * This C module:
 *   1. Collects per-process feature vectors from /proc
 *   2. Spawns the Python model via subprocess (popen)
 *   3. Parses the JSON verdict
 *   4. Emits a g_event_t to the bus
 *
 * RAM: ~1MB resident (just the C bridge + /proc reads). The Python interpreter
 * is only invoked on-demand when a check runs, then exits. Model inference
 * itself is ~20MB of Python+numpy for the duration of the call.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <fcntl.h>

#define G_NFEATURES 8
static const char *FEATURE_NAMES[G_NFEATURES] = {
    "cpu_pct", "mem_mb", "net_conns", "file_writes_min",
    "fork_rate_min", "entropy_file_io", "distinct_ips_5min", "syscall_rate"
};

struct g_anomaly_engine {
    char model_path[G_PATH_MAX];
    char py_bin[256];
    double threshold;   /* below this anomaly_score → flag */
    g_iforest_t *ifo;   /* Phase 2.2: native C iforest (NULL = use Python fallback) */
    bool native;        /* true if iforest loaded */
};

/* collect features for a pid from /proc */
int g_anomaly_collect_features(pid_t pid, double out[8]) {
    memset(out, 0, sizeof(double) * G_NFEATURES);
    char path[128];

    /* mem_mb from /proc/<pid>/status VmRSS */
    snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -errno;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        if (!strncmp(line, "VmRSS:", 6)) {
            unsigned long kb = 0;
            sscanf(line+6, "%lu", &kb);
            out[1] = kb / 1024.0;  /* mem_mb */
        }
    }
    fclose(f);

    /* net_conns from /proc/<pid>/net/tcp — count lines */
    snprintf(path, sizeof(path), "/proc/%d/net/tcp", pid);
    f = fopen(path, "r");
    if (f) {
        int n = 0; char buf[256];
        (void)fgets(buf, sizeof(buf), f);  /* header */
        while (fgets(buf, sizeof(buf), f)) n++;
        fclose(f);
        out[2] = n;  /* net_conns */
    }

    /* cpu_pct, file_writes_min, fork_rate_min, entropy, distinct_ips, syscall_rate
     * require either eBPF counters or /proc sampling over time. In v1 we
     * sample /proc/<pid>/stat at two timepoints to get cpu_pct. Other
     * features fall back to 0 (model still works — it flags on mem+net alone). */
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    f = fopen(path, "r");
    if (f) {
        unsigned long utime1 = 0, stime1 = 0;
        unsigned long long start1 = 0;
        char buf[1024];
        if (fgets(buf, sizeof(buf), f)) {
            char *rp = strrchr(buf, ')');
            if (rp) {
                sscanf(rp+2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu %*d %*d %*d %*d %*d %*d %llu",
                       &utime1, &stime1, &start1);
            }
        }
        fclose(f);
        /* sample again after 100ms */
        usleep(100000);
        f = fopen(path, "r");
        if (f) {
            if (fgets(buf, sizeof(buf), f)) {
                char *rp = strrchr(buf, ')');
                unsigned long utime2 = 0, stime2 = 0;
                if (rp) {
                    sscanf(rp+2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
                           &utime2, &stime2);
                }
                /* cpu_pct = delta / 100ms * 100 (clock ticks per sec = 100) */
                long ticks_per_sec = sysconf(_SC_CLK_TCK);
                out[0] = ((utime2 + stime2) - (utime1 + stime1)) * 100.0 / (ticks_per_sec);
            }
            fclose(f);
        }
    }

    /* Phase 2.3: read eBPF feature counters (fork_count, write_bytes, syscall_count).
     * These are zero in dev sandbox (no BPF), but on WLTIOS target they provide
     * real feature[4] (fork_rate), feature[3] (file_writes), feature[7] (syscall_rate). */
    extern g_ebpf_engine_t *g_ee_global;
    if (g_ee_global) {
        __u32 fork_c = 0;
        __u64 write_b = 0;
        __u64 sys_c = 0;
        if (g_ebpf_get_map_value(g_ee_global, "fork_count", &pid, &fork_c) == 0)
            out[4] = (double)fork_c;            /* fork_rate_min */
        if (g_ebpf_get_map_value(g_ee_global, "write_bytes", &pid, &write_b) == 0)
            out[3] = (double)(write_b / 1024);  /* file_writes_min (KB) */
        if (g_ebpf_get_map_value(g_ee_global, "syscall_count", &pid, &sys_c) == 0)
            out[7] = (double)sys_c;             /* syscall_rate */
    }

    return 0;
}

static int verify_model_hash(const char *model_path) {
    char hash_path[G_PATH_MAX];
    snprintf(hash_path, sizeof(hash_path), "%s.sha256", model_path);
    FILE *hf = fopen(hash_path, "r");
    if (!hf) {
        /* Fallback: try ml/anomaly.pkl.sha256 */
        snprintf(hash_path, sizeof(hash_path), "ml/anomaly.pkl.sha256");
        hf = fopen(hash_path, "r");
    }
    if (!hf) {
        fprintf(stderr, "[anomaly] ERROR: Verification file (.sha256) not found for %s\n", model_path);
        return -ENOENT;
    }
    char expected_hex[65];
    if (fscanf(hf, "%64s", expected_hex) != 1) {
        fclose(hf);
        return -EINVAL;
    }
    fclose(hf);

    FILE *mf = fopen(model_path, "rb");
    if (!mf) {
        return -errno;
    }
    fseek(mf, 0, SEEK_END);
    long sz = ftell(mf);
    fseek(mf, 0, SEEK_SET);
    if (sz < 0) {
        fclose(mf);
        return -EIO;
    }
    uint8_t *buf = malloc(sz);
    if (!buf) {
        fclose(mf);
        return -ENOMEM;
    }
    if (fread(buf, 1, sz, mf) != (size_t)sz) {
        free(buf);
        fclose(mf);
        return -EIO;
    }
    fclose(mf);

    char computed_hex[65];
    g_sha256_hex(buf, sz, computed_hex);
    free(buf);

    if (strcmp(expected_hex, computed_hex) != 0) {
        fprintf(stderr, "[anomaly] ERROR: model hash verification failed (expected %s, got %s)!\n", expected_hex, computed_hex);
        return -EACCES;
    }

    printf("[anomaly] Model hash verification passed: %s\n", computed_hex);
    return 0;
}

g_anomaly_engine_t *g_anomaly_init(const char *model_path, const char *py_bin) {
    g_anomaly_engine_t *ae = calloc(1, sizeof(*ae));
    if (!ae) return NULL;
    g_strlcpy(ae->model_path, model_path ? model_path : G_ML_MODEL_PATH, sizeof(ae->model_path));
    g_strlcpy(ae->py_bin, py_bin ? py_bin : "python3", sizeof(ae->py_bin));
    ae->threshold = -0.15;  /* below this = anomaly (sklearn decision_function scale) */

    /* Verify the hash of the ML model before loading it (prevents Pickle RCE) */
    if (verify_model_hash(ae->model_path) != 0) {
        free(ae);
        return NULL;
    }

    /* Phase 2.2: try to load native C iforest (eliminates Python subprocess). */
    {
        char ifo_path[G_PATH_MAX];
        snprintf(ifo_path, sizeof(ifo_path), "%s.iforest", ae->model_path);
        if (access(ifo_path, R_OK) != 0) {
            g_strlcpy(ifo_path, "ml/anomaly.iforest", sizeof(ifo_path));
        }
        ae->ifo = g_iforest_load(ifo_path);
        ae->native = (ae->ifo != NULL);
        if (ae->native) printf("[anomaly] using NATIVE C iforest\n");
        else printf("[anomaly] no .iforest - falling back to Python subprocess\n");
    }

    return ae;
}

void g_anomaly_free(g_anomaly_engine_t *ae) { if (!ae) return; g_iforest_free(ae->ifo); free(ae); }

static int call_python_model(g_anomaly_engine_t *ae, double features[G_NFEATURES],
                             double *out_score, char *out_verdict, size_t verdict_sz) {
    /* Phase 2.2: native C inference fast-path (~0.1ms vs ~300ms Python) */
    if (ae->native && ae->ifo) {
        double score = g_iforest_score(ae->ifo, features);
        *out_score = score;
        g_strlcpy(out_verdict, score > g_iforest_threshold(ae->ifo) ? "anomaly" : "clean", verdict_sz);
        return 0;
    }
    /* build JSON args (Python fallback) */
    char args[512];
    int n = snprintf(args, sizeof(args), "{\"cpu_pct\":%.2f,\"mem_mb\":%.2f,\"net_conns\":%.2f,"
                     "\"file_writes_min\":%.2f,\"fork_rate_min\":%.2f,\"entropy_file_io\":%.2f,"
                     "\"distinct_ips_5min\":%.2f,\"syscall_rate\":%.2f}",
                     features[0], features[1], features[2], features[3],
                     features[4], features[5], features[6], features[7]);
    if (n < 0 || n >= (int)sizeof(args)) return -ENAMETOOLONG;

    /* find the anomaly.py next to the model */
    char script[G_PATH_MAX];
    snprintf(script, sizeof(script), "%s/../anomaly.py", ae->model_path);
    /* fallback: try a sibling anomaly.py in cwd */
    if (access(script, R_OK) != 0) {
        g_strlcpy(script, "ml/anomaly.py", sizeof(script));
    }

    int pipefd[2];
    if (pipe(pipefd) < 0) return -errno;

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -errno;
    }

    if (pid == 0) {
        /* Child process */
        /* Vuln 1: ensure child dies if parent exits */
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        /* Redirect stdout to the pipe */
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        /* Redirect stderr to /dev/null */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }

        /* Build arguments array */
        char *argv[] = { ae->py_bin, script, "--check", args, NULL };
        execvp(ae->py_bin, argv);
        /* If execvp fails, exit child */
        _exit(127);
    }

    /* Parent process */
    close(pipefd[1]);

    char output[1024] = {0};
    size_t off = 0;
    while (off < sizeof(output) - 1) {
        ssize_t got = read(pipefd[0], output + off, sizeof(output) - 1 - off);
        if (got <= 0) break;
        off += (size_t)got;
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);

    /* parse JSON: {"verdict":"anomaly","anomaly_score":-0.17,"confidence":"high"} */
    char *v = strstr(output, "\"verdict\"");
    char *s = strstr(output, "\"anomaly_score\"");
    if (v) {
        v = strchr(v, ':');
        if (v) {
            v++; while (*v==' '||*v=='"') v++;
            char *e = v;
            while (*e && *e != '"' && *e != ',' && *e != '}') e++;
            size_t L = e - v;
            if (L && verdict_sz) {
                size_t len = L < verdict_sz - 1 ? L : verdict_sz - 1;
                memcpy(out_verdict, v, len);
                out_verdict[len] = 0;
            }
        }
    } else {
        g_strlcpy(out_verdict, "unknown", verdict_sz);
    }
    if (s) {
        s = strchr(s, ':');
        if (s) { s++; *out_score = strtod(s, NULL); }
    } else {
        *out_score = 0.0;
    }
    return 0;
}

int g_anomaly_check_proc(g_anomaly_engine_t *ae, pid_t pid, g_event_t *out) {
    if (!ae || !out) return -EINVAL;
    memset(out, 0, sizeof(*out));
    double features[G_NFEATURES];
    if (g_anomaly_collect_features(pid, features) != 0) return -errno;

    g_strlcpy(out->source, "anomaly", sizeof(out->source));
    out->pid = pid;
    out->ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    out->seq = g_bus_next_seq();

    double score = 0.0;
    char verdict[32] = {0};
    if (call_python_model(ae, features, &score, verdict, sizeof(verdict)) == 0) {
        snprintf(out->detail, sizeof(out->detail),
                 "anomaly score=%.3f verdict=%s (cpu=%.1f%% mem=%.0fMB conns=%.0f)",
                 score, verdict, features[0], features[1], features[2]);
        if (!strcmp(verdict, "anomaly") || score < ae->threshold) {
            out->verdict = G_VERDICT_SUSPICIOUS;
            out->severity = (score < ae->threshold * 2) ? G_SEV_HIGH : G_SEV_MEDIUM;
            out->action_taken = G_ACT_LOG;  /* policy engine will upgrade */
            g_strlcpy(out->rule_id, "ANOMALY_ISOLATION_FOREST", sizeof(out->rule_id));
            g_bus_publish(out);
            return 1;
        }
    } else {
        g_strlcpy(out->rule_id, "ANOMALY_MODEL_UNAVAILABLE", sizeof(out->rule_id));
        out->verdict = G_VERDICT_UNKNOWN;
    }
    out->verdict = G_VERDICT_CLEAN;
    return 0;
}

int g_anomaly_check_system(g_anomaly_engine_t *ae, g_event_t *out) {
    /* system-level: sum all procs, then check. v1: just check PID 1 + a few. */
    return g_anomaly_check_proc(ae, 1, out);
}

/* Bug 16 fix: enumerate ALL PIDs from /proc and check each.
 * Old code only checked PID 1 (init), which always looks clean.
 * This scans every running process for anomalies. */
int g_anomaly_check_all_procs(g_anomaly_engine_t *ae, g_sig_engine_t *se) {
    if (!ae) return -EINVAL;
    DIR *d = opendir("/proc");
    if (!d) return -errno;
    int n_checked = 0, n_anomaly = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit(de->d_name[0])) continue;
        pid_t pid = atoi(de->d_name);
        if (pid <= 1) continue;  /* skip init */
        g_event_t ev;
        if (g_anomaly_check_proc(ae, pid, &ev) > 0) {
            n_anomaly++;
            // Immediately run a memory signature scan on the anomalous PID
            if (se) {
                g_event_t mem_ev;
                g_sig_scan_proc_mem_regions(se, pid, &mem_ev);
            }
        }
        n_checked++;
        /* Bug 17 mitigation: limit to 50 PIDs per cycle to avoid blocking the
         * daemon too long (each Python subprocess call is ~300ms). A persistent
         * Python process (Enhancement 8) would eliminate this limit. */
        if (n_checked >= 50) break;
    }
    closedir(d);
    return n_anomaly;
}
