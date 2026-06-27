/* ransomware_engine.c — Phase 2.4: ransomware behavior detection.
 *
 * Reads the BPF counter maps (unlink_count, rename_count, write_bytes) and
 * applies behavioral thresholds to detect ransomware patterns:
 *   - bulk delete: >100 unlink/min  -> BULK_DELETE_SUSPICIOUS (FREEZE)
 *   - rename storm: >10 rename/min  -> RENAME_STORM_SUSPICIOUS (HIGH)
 *   - high-write + (entropy handled in anomaly_engine): RANSOMWARE_IO_PATTERN (CRITICAL)
 *
 * Called every 5 seconds from the daemon main loop.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>

/* we read BPF maps via the ebpf engine's helper */
#ifdef G_HAVE_LIBBPF
#include <bpf/bpf.h>
#endif

struct g_ransomware_engine {
    /* previous counters per pid (for delta computation) — simple fixed table */
    struct {
        __u32 pid;
        __u32 prev_unlink;
        __u32 prev_rename;
        __u64 prev_write;
        time_t first_seen;
    } slots[64];
    int n;
    time_t last_check;
};

g_ransomware_engine_t *g_ransomware_init(void) {
    g_ransomware_engine_t *re = calloc(1, sizeof(*re));
    if (!re) return NULL;
    re->last_check = time(NULL);
    printf("[ransomware] engine ready (5s polling)\n");
    return re;
}

void g_ransomware_free(g_ransomware_engine_t *re) { free(re); }

/* read a u32 BPF map value by pid key; returns 0 on success */
static int read_u32_map(const char *map_name, __u32 pid, __u32 *out) {
    /* This would use g_ebpf_get_map_value on the global engine. For now,
     * the daemon passes the ebpf engine; we use a global pointer. */
    extern g_ebpf_engine_t *g_ee_global;
    if (!g_ee_global) return -1;
    return g_ebpf_get_map_value(g_ee_global, map_name, &pid, out);
}

static int read_u64_map(const char *map_name, __u32 pid, __u64 *out) {
    extern g_ebpf_engine_t *g_ee_global;
    if (!g_ee_global) return -1;
    return g_ebpf_get_map_value(g_ee_global, map_name, &pid, out);
}

static void emit_event(const char *rule, g_severity_t sev, g_action_t act,
                       __u32 pid, const char *detail) {
    g_event_t ev = {0};
    g_strlcpy(ev.source, "ransomware", sizeof(ev.source));
    g_strlcpy(ev.rule_id, rule, sizeof(ev.rule_id));
    ev.pid = pid;
    ev.severity = sev;
    ev.verdict = (sev >= G_SEV_HIGH) ? G_VERDICT_MALICIOUS : G_VERDICT_SUSPICIOUS;
    ev.action_taken = act;
    ev.ts_ns = (uint64_t)time(NULL) * 1000000000ULL;
    ev.seq = g_bus_next_seq();
    snprintf(ev.detail, sizeof(ev.detail), "%s", detail);
    g_bus_publish(&ev);
}

/* BUG 4 fix: find-or-create a slot for a pid in the prev-counters table.
 * Returns the slot index, or -1 if the table is full. */
static int find_slot(g_ransomware_engine_t *re, __u32 pid) {
    for (int i = 0; i < re->n; i++) {
        if (re->slots[i].pid == pid) return i;
    }
    if (re->n < 64) {
        re->slots[re->n].pid = pid;
        re->slots[re->n].prev_unlink = 0;
        re->slots[re->n].prev_rename = 0;
        re->slots[re->n].prev_write = 0;
        re->slots[re->n].first_seen = time(NULL);
        return re->n++;
    }
    return -1;
}

/* Scan /proc for PIDs, read their BPF counters, apply RATE thresholds.
 * BUG 4 fix: old code checked cumulative totals (unlink > 100) which
 * false-positived on any long-running process (apt clean, log rotators).
 * Now: compute delta since last check, scale to per-minute rate. */
int g_ransomware_check(g_ransomware_engine_t *re) {
    if (!re) return -1;
    time_t now = time(NULL);
    int dt = (int)(now - re->last_check);
    if (dt < 1) dt = 1;
    re->last_check = now;
    int n_alerts = 0;
    double dt_min = dt / 60.0;

    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (!isdigit(de->d_name[0])) continue;
        __u32 pid = (__u32)atoi(de->d_name);
        if (pid <= 1) continue;

        __u32 unlink = 0, rename = 0;
        __u64 writeb = 0;
        read_u32_map("unlink_count", pid, &unlink);
        read_u32_map("rename_count", pid, &rename);
        read_u64_map("write_bytes", pid, &writeb);

        int si = find_slot(re, pid);
        if (si < 0) continue;

        /* compute deltas (this check - last check) */
        __u32 d_unlink = (unlink > re->slots[si].prev_unlink) ? (unlink - re->slots[si].prev_unlink) : 0;
        __u32 d_rename = (rename > re->slots[si].prev_rename) ? (rename - re->slots[si].prev_rename) : 0;
        __u64 d_write  = (writeb > re->slots[si].prev_write) ? (writeb - re->slots[si].prev_write) : 0;

        /* update prev for next cycle */
        re->slots[si].prev_unlink = unlink;
        re->slots[si].prev_rename = rename;
        re->slots[si].prev_write = writeb;

        /* skip if no activity this interval */
        if (d_unlink == 0 && d_rename == 0 && d_write == 0) continue;

        /* per-minute rates */
        double unlink_per_min = d_unlink / dt_min;
        double rename_per_min = d_rename / dt_min;
        double write_per_min  = (double)d_write / dt_min;

        char detail[256];
        /* bulk delete: >100 unlinks/min (was: cumulative — false positive) */
        if (unlink_per_min > 100.0) {
            snprintf(detail, sizeof(detail),
                     "PID %u: %.0f file deletions/min (bulk delete — possible ransomware)", pid, unlink_per_min);
            emit_event("BULK_DELETE_SUSPICIOUS", G_SEV_CRITICAL, G_ACT_FREEZE, pid, detail);
            n_alerts++;
        }
        /* rename storm: >10 renames/min with extension changes (heuristic) */
        if (rename_per_min > 10.0) {
            snprintf(detail, sizeof(detail),
                     "PID %u: %.0f renames/min (rename storm — possible extension-changing ransomware)", pid, rename_per_min);
            emit_event("RENAME_STORM_SUSPICIOUS", G_SEV_HIGH, G_ACT_FREEZE, pid, detail);
            n_alerts++;
        }
        /* high write rate: >1MB/min (entropy check would need /proc/pid/mem sampling) */
        if (write_per_min > (1024.0 * 1024.0)) {
            snprintf(detail, sizeof(detail),
                     "PID %u: %.1f MB written/min (high I/O — ransomware pattern check)", pid, write_per_min/(1024*1024));
            emit_event("RANSOMWARE_IO_PATTERN", G_SEV_CRITICAL, G_ACT_FREEZE, pid, detail);
            n_alerts++;
        }
    }
    closedir(d);
    return n_alerts;
}
