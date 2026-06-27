/* pmu_engine.c — Phase 4.2: Hardware performance counter monitoring.
 *
 * Uses perf_event_open() to read per-process:
 *   - LLC cache misses (side-channel / Spectre detection)
 *   - instructions retired (crypto-miner detection)
 *
 * Feed these as 2 new anomaly features (distinct_ips_5min, syscall_rate were
 * stubs in v1). Also direct detection:
 *   - cache_miss_rate > 0.05 sustained > 30s -> side-channel scan alert
 *   - instructions > 10B/sec, cache_miss_rate < 0.001 sustained -> crypto-miner FREEZE
 *
 * On-demand: only attaches PMU counters to PIDs flagged by the anomaly engine.
 * Not always-on (PMU counters are a limited resource).
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <dirent.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>

struct g_pmu_engine {
    int n_monitored;
    time_t last_check;
};

/* perf_event_open syscall (not in glibc for all arches) */
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid, int cpu,
                            int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

g_pmu_engine_t *g_pmu_init(void) {
    g_pmu_engine_t *pe = calloc(1, sizeof(*pe));
    if (!pe) return NULL;
    pe->last_check = time(NULL);
    printf("[pmu] engine ready (on-demand per-process PMU counters)\n");
    return pe;
}

void g_pmu_free(g_pmu_engine_t *pe) { free(pe); }

/* Open LLC-misses + instructions counters for a PID. Returns 0 on success,
 * fills out_fds[0]=misses, out_fds[1]=instructions. */
static int open_pmu_counters(pid_t pid, int out_fds[2]) {
    out_fds[0] = out_fds[1] = -1;
    struct perf_event_attr pe = {0};
    pe.type = PERF_TYPE_HARDWARE;
    pe.size = sizeof(pe);
    pe.disabled = 1;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;

    /* instructions retired */
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    out_fds[1] = (int)perf_event_open(&pe, pid, -1, -1, 0);
    if (out_fds[1] < 0) return -errno;

    /* LLC cache misses (via PERF_TYPE_HW_CACHE) */
    struct perf_event_attr cm = {0};
    cm.type = PERF_TYPE_HW_CACHE;
    cm.size = sizeof(cm);
    cm.disabled = 1;
    cm.exclude_kernel = 1;
    cm.exclude_hv = 1;
    /* BUG 5 fix: PERF_COUNT_HW_CACHE_L1D -> PERF_COUNT_HW_CACHE_LL.
     * L1D miss rate is 10-50% for normal code (would false-positive every
     * process). LLC (last-level cache) misses are the real side-channel signal. */
    cm.config = (PERF_COUNT_HW_CACHE_LL) |
                (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                (PERF_COUNT_HW_CACHE_RESULT_MISS << 16);
    out_fds[0] = (int)perf_event_open(&cm, pid, -1, -1, 0);
    if (out_fds[0] < 0) { close(out_fds[1]); return -errno; }

    ioctl(out_fds[0], PERF_EVENT_IOC_ENABLE, 0);
    ioctl(out_fds[1], PERF_EVENT_IOC_ENABLE, 0);
    return 0;
}

static void close_pmu_counters(int fds[2]) {
    if (fds[0] >= 0) close(fds[0]);
    if (fds[1] >= 0) close(fds[1]);
    fds[0] = fds[1] = -1;
}

/* Read a PMU counter value */
static long long read_counter(int fd) {
    long long val = 0;
    if (fd >= 0 && read(fd, &val, sizeof(val)) == sizeof(val)) return val;
    return -1;
}

/* Phase 4.2: check a specific PID for side-channel or crypto-miner patterns.
 * Attaches PMU counters, samples for `duration_ms`, applies thresholds.
 * Returns 0 = clean, 1 = side-channel alert, 2 = crypto-miner alert. */
int g_pmu_check_pid(g_pmu_engine_t *pe, pid_t pid, int duration_ms) {
    if (!pe || pid <= 1) return -1;
    int fds[2];
    if (open_pmu_counters(pid, fds) != 0) return -1;

    /* sample 1 */
    long long miss1 = read_counter(fds[0]);
    long long ins1  = read_counter(fds[1]);
    if (miss1 < 0 || ins1 < 0) { close_pmu_counters(fds); return -1; }

    usleep(duration_ms * 1000);

    /* sample 2 */
    long long miss2 = read_counter(fds[0]);
    long long ins2  = read_counter(fds[1]);
    close_pmu_counters(fds);

    long long dmiss = miss2 - miss1;
    long long dins  = ins2 - ins1;
    if (dins <= 0) return 0;

    double cache_miss_rate = (double)dmiss / (double)dins;
    double ins_per_sec = (double)dins * 1000.0 / (double)duration_ms;

    /* crypto-miner: very high instruction rate, very low cache-miss rate */
    if (ins_per_sec > 10e9 && cache_miss_rate < 0.001) {
        g_event_t ev = {0};
        g_strlcpy(ev.source, "pmu", sizeof(ev.source));
        g_strlcpy(ev.rule_id, "PMU_CRYPTO_MINER", sizeof(ev.rule_id));
        ev.pid = pid;
        ev.severity = G_SEV_HIGH;
        ev.verdict = G_VERDICT_SUSPICIOUS;
        ev.action_taken = G_ACT_FREEZE;
        ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
        ev.seq = g_bus_next_seq();
        snprintf(ev.detail, sizeof(ev.detail),
                 "PID %u: %.2fB ins/s, cache_miss_rate=%.4f (crypto-miner pattern)",
                 pid, ins_per_sec/1e9, cache_miss_rate);
        g_bus_publish(&ev);
        return 2;
    }

    /* side-channel: high cache-miss rate sustained */
    if (cache_miss_rate > 0.05) {
        g_event_t ev = {0};
        g_strlcpy(ev.source, "pmu", sizeof(ev.source));
        g_strlcpy(ev.rule_id, "PMU_SIDE_CHANNEL", sizeof(ev.rule_id));
        ev.pid = pid;
        ev.severity = G_SEV_MEDIUM;
        ev.verdict = G_VERDICT_SUSPICIOUS;
        ev.action_taken = G_ACT_LOG;
        ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
        ev.seq = g_bus_next_seq();
        snprintf(ev.detail, sizeof(ev.detail),
                 "PID %u: cache_miss_rate=%.4f (possible side-channel scan)",
                 pid, cache_miss_rate);
        g_bus_publish(&ev);
        return 1;
    }

    return 0;
}
