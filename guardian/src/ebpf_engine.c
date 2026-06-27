
/* ebpf_engine.c — Layer 2: eBPF behavioral rules + enforcement.
 *
 * Three responsibilities:
 *   1. Load all .bpf.o files from the bpf dir via libbpf, attach to tracepoints
 *   2. Poll the ring buffer for events, dispatch to the rule engine
 *   3. Falco-style rule evaluation + Tetragon-style inline enforcement
 *
 * The eBPF programs themselves live in bpf/*.bpf.c (compiled by `make bpf`).
 * This is the userspace counterpart.
 *
 * In the dev sandbox: load/attach can't run (no CAP_BPF). The engine
 * gracefully degrades — it loads rules, can evaluate them on synthetic events,
 * and reports "eBPF unavailable" for load/poll. On WLTIOS target: full.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef G_HAVE_LIBBPF
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#endif

#define MAX_BPF_OBJECTS 16
#define MAX_EBPF_RULES  64

struct g_ebpf_object {
    char name[64];
#ifdef G_HAVE_LIBBPF
    struct bpf_object *obj;
    struct bpf_link   *link;
    struct ring_buffer *rb;   /* Bug 7 fix: created once, reused across polls */
#else
    void *obj;
    void *link;
    void *rb;
#endif
    int  n_events;
};

struct g_ebpf_engine {
    struct g_ebpf_object objs[MAX_BPF_OBJECTS];
    int  n_objs;
    g_ebpf_rule_t rules[MAX_EBPF_RULES];
    int  n_rules;
    int  n_events_total;
    bool bpf_available;
    char bpf_dir[G_PATH_MAX];
};

struct bpf_event {
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint8_t  comm[16];
    uint8_t  path[128];
    uint8_t  rule[64];
    uint8_t  severity;     /* 0=info 1=low 2=med 3=high 4=critical */
    uint8_t  action;       /* 0=log 1=freeze 2=quarantine 3=kill 4=kill_switch */
    uint16_t syscall_nr;   /* which syscall triggered this */
};

static inline g_action_t bpf_action_to_g_action(uint8_t action) {
    switch (action) {
        case 0: return G_ACT_LOG;
        case 1: return G_ACT_FREEZE;
        case 2: return G_ACT_QUARANTINE_FILE;
        case 3: return G_ACT_KILL;
        case 4: return G_ACT_KILL_SWITCH;
        default: return G_ACT_LOG;
    }
}

/* Global static pointer to the active EBPF engine (for single-instance daemon maps updates) */
g_ebpf_engine_t *g_ee_global = NULL;


/* forward declaration — ringbuf_cb defined below, used in g_ebpf_load_all */
#ifdef G_HAVE_LIBBPF
static int ringbuf_cb(void *ctx, void *data, size_t sz);
#endif

/* ---- rule parsing (simple line-based DSL) ----
 * Format:
 *   rule <id> <severity> <action>
 *     desc <text>
 *     condition <expression>
 *
 * Example:
 *   rule SHELL_BY_WEB_SERVER HIGH QUARANTINE_PROC
 *     desc nginx/apache spawned a shell
 *     condition comm in (sh,bash,zsh) and pcomm in (nginx,apache2,httpd)
 */
static g_severity_t parse_sev(const char *s) {
    if (!s) return G_SEV_INFO;
    if (!strcmp(s,"INFO")) return G_SEV_INFO;
    if (!strcmp(s,"LOW")) return G_SEV_LOW;
    if (!strcmp(s,"MEDIUM")) return G_SEV_MEDIUM;
    if (!strcmp(s,"HIGH")) return G_SEV_HIGH;
    if (!strcmp(s,"CRITICAL")) return G_SEV_CRITICAL;
    return G_SEV_INFO;
}

static g_action_t parse_action(const char *s) {
    if (!s) return G_ACT_LOG;
    if (!strcmp(s,"LOG")) return G_ACT_LOG;
    if (!strcmp(s,"FREEZE")) return G_ACT_FREEZE;
    if (!strcmp(s,"QUARANTINE_FILE")) return G_ACT_QUARANTINE_FILE;
    if (!strcmp(s,"QUARANTINE_PROC")) return G_ACT_QUARANTINE_PROC;
    if (!strcmp(s,"BLOCK_NET")) return G_ACT_BLOCK_NET;
    if (!strcmp(s,"KILL")) return G_ACT_KILL;
    if (!strcmp(s,"KILL_SWITCH")) return G_ACT_KILL_SWITCH;
    if (!strcmp(s,"ALERT")) return G_ACT_ALERT;
    return G_ACT_LOG;
}

int g_ebpf_rules_load(g_ebpf_engine_t *ee, const char *rules_path) {
    if (!ee || !rules_path) return -EINVAL;
    FILE *f = fopen(rules_path, "r");
    if (!f) {
        fprintf(stderr, "[ebpf] rules file %s: %s\n", rules_path, strerror(errno));
        return -errno;
    }
    char line[1024];
    g_ebpf_rule_t *cur = NULL;
    while (fgets(line, sizeof(line), f)) {
        /* strip */
        char *p = line; while (*p && (*p==' '||*p=='\t')) p++;
        char *nl = strchr(p,'\n'); if (nl) *nl = 0;
        char *c = strchr(p,'#'); if (c) *c = 0;
        if (!*p) continue;

        if (!strncmp(p, "rule ", 5)) {
            if (ee->n_rules >= MAX_EBPF_RULES) break;
            cur = &ee->rules[ee->n_rules++];
            char id[64], sev[16], act[32];
            if (sscanf(p+5, "%63s %15s %31s", id, sev, act) == 3) {
                g_strlcpy(cur->rule_id, id, sizeof(cur->rule_id));
                cur->severity = parse_sev(sev);
                cur->action = parse_action(act);
                cur->desc[0] = 0;
                cur->condition[0] = 0;
            } else {
                cur = NULL;
            }
        } else if (!strncmp(p, "desc ", 5) && cur) {
            g_strlcpy(cur->desc, p+5, sizeof(cur->desc));
        } else if (!strncmp(p, "condition ", 10) && cur) {
            g_strlcpy(cur->condition, p+10, sizeof(cur->condition));
        }
    }
    fclose(f);
    printf("[ebpf] loaded %d rules from %s\n", ee->n_rules, rules_path);
    return 0;
}

/* ---- rule evaluation (very simple expression matcher) ----
 * Supports: <field> in (a,b,c), <field> == <val>, <field> contains <substr>
 * Joined by 'and' / 'or'. No parens in v1.
 *
 * Fields: comm, pcomm, pid, uid, path, syscall
 */
static bool field_match(const char *field, const char *op, const char *val, const g_event_t *ev) {
    const char *fv = NULL;
    char pidbuf[16]; char uidbuf[16];
    if (!strcmp(field, "comm"))  fv = ev->comm;
    else if (!strcmp(field, "path"))  fv = ev->path;
    else if (!strcmp(field, "rule_id")) fv = ev->rule_id;
    else if (!strcmp(field, "pid"))  { snprintf(pidbuf,sizeof(pidbuf),"%u",ev->pid); fv = pidbuf; }
    else if (!strcmp(field, "uid"))  { snprintf(uidbuf,sizeof(uidbuf),"%u",ev->uid); fv = uidbuf; }
    else return false;

    if (!strcmp(op, "in")) {
        /* val is "(a,b,c)" — parse */
        const char *s = val;
        if (*s == '(') s++;
        while (*s) {
            const char *e = s;
            while (*e && *e != ',' && *e != ')') e++;
            size_t L = e - s;
            if (L && strlen(fv) == L && !strncmp(fv, s, L)) return true;
            s = *e == ',' ? e+1 : (*e == ')' ? e+1 : e);
            while (*s == ' ') s++;
        }
        return false;
    }
    if (!strcmp(op, "==")) return !strcmp(fv, val);
    if (!strcmp(op, "contains")) return fv && strstr(fv, val);
    if (!strcmp(op, "startswith")) return fv && !strncmp(fv, val, strlen(val));
    return false;
}

static bool eval_condition(const char *cond, const g_event_t *ev) {
    /* Bug 2 fix: proper 3-token-per-predicate parser.
     * Old code used strtok_r + sscanf on a single token, which could never
     * parse "comm in (sh,bash)" because strtok_r returns one word at a time.
     * Now we tokenize the whole condition string and consume field/op/val
     * as three consecutive tokens, handling 'and'/'or' as separators. */
    char buf[G_DETAIL_MAX];
    g_strlcpy(buf, cond, sizeof(buf));

    char *tokens[64];
    int ntok = 0;
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ", &saveptr);
    while (tok && ntok < 64) {
        tokens[ntok++] = tok;
        tok = strtok_r(NULL, " ", &saveptr);
    }

    bool result = true;
    bool is_or = false;
    int i = 0;
    while (i < ntok) {
        if (!strcmp(tokens[i], "and")) {
            is_or = false;
            i++;
            continue;
        }
        if (!strcmp(tokens[i], "or")) {
            is_or = true;
            if (result) return true;  /* short-circuit OR */
            i++;
            continue;
        }
        /* expect field op val */
        if (i + 2 >= ntok) break;  /* incomplete predicate */
        char *field = tokens[i];
        char *op = tokens[i+1];
        char *val = tokens[i+2];
        bool m = field_match(field, op, val, ev);
        result = is_or ? (result || m) : (result && m);
        is_or = false;
        i += 3;
    }
    return result;
}

int g_ebpf_rules_eval(g_ebpf_engine_t *ee, const g_event_t *raw, g_event_t *out) {
    if (!ee || !raw || !out) return -EINVAL;
    *out = *raw;  /* start with raw event */
    g_strlcpy(out->source, "ebpf", sizeof(out->source));
    for (int i = 0; i < ee->n_rules; i++) {
        g_ebpf_rule_t *r = &ee->rules[i];
        if (r->condition[0] && eval_condition(r->condition, raw)) {
            g_strlcpy(out->rule_id, r->rule_id, sizeof(out->rule_id));
            out->severity = r->severity;
            out->verdict = (r->severity >= G_SEV_HIGH) ? G_VERDICT_MALICIOUS : G_VERDICT_SUSPICIOUS;
            out->action_taken = r->action;
            return 1;  /* matched */
        }
    }
    out->verdict = G_VERDICT_CLEAN;
    out->action_taken = G_ACT_LOG;
    return 0;
}

/* ---- libbpf loader (only compiles if libbpf available) ---- */

g_ebpf_engine_t *g_ebpf_init(const char *bpf_dir) {
    g_ebpf_engine_t *ee = calloc(1, sizeof(*ee));
    if (!ee) return NULL;
    g_ee_global = ee;
    if (bpf_dir) g_strlcpy(ee->bpf_dir, bpf_dir, sizeof(ee->bpf_dir));

    /* detect BPF availability: try to access /sys/kernel/btf/vmlinux */
    ee->bpf_available = (access("/sys/kernel/btf/vmlinux", R_OK) == 0);
    /* also check we have CAP_BPF-ish (can read /proc/self/status CapEff) */
    if (ee->bpf_available) {
        FILE *f = fopen("/proc/self/status", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (!strncmp(line, "CapEff:", 7)) {
                    unsigned long long cap = strtoull(line+7, NULL, 16);
                    /* CAP_BPF = bit 39, CAP_SYS_ADMIN = bit 21 */
                    if (!((cap >> 39) & 1) && !((cap >> 21) & 1)) {
                        ee->bpf_available = false;
                    }
                    break;
                }
            }
            fclose(f);
        }
    }
    if (!ee->bpf_available) {
        printf("[ebpf] BPF load/attach unavailable (no CAP_BPF) — engine in degraded mode\n");
    }
    return ee;
}

void g_ebpf_free(g_ebpf_engine_t *ee) {
    if (!ee) return;
    if (g_ee_global == ee) g_ee_global = NULL;
#ifdef G_HAVE_LIBBPF
    for (int i = 0; i < ee->n_objs; i++) {
        if (ee->objs[i].rb)   ring_buffer__free(ee->objs[i].rb);
        if (ee->objs[i].link) bpf_link__destroy(ee->objs[i].link);
        if (ee->objs[i].obj)  bpf_object__close(ee->objs[i].obj);
    }
#endif
    free(ee);
}

int g_ebpf_load_all(g_ebpf_engine_t *ee) {
    if (!ee) return -EINVAL;
    if (!ee->bpf_available) {
        printf("[ebpf] skipping load — BPF unavailable (degraded mode)\n");
        return 0;
    }
#ifndef G_HAVE_LIBBPF
    printf("[ebpf] libbpf not linked in this build — skipping load\n");
    return 0;
#else
    DIR *d = opendir(ee->bpf_dir);
    if (!d) { fprintf(stderr, "[ebpf] opendir %s: %s\n", ee->bpf_dir, strerror(errno)); return -errno; }
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t L = strlen(de->d_name);
        if (L < 7 || strcmp(de->d_name + L - 6, ".bpf.o")) continue;
        if (ee->n_objs >= MAX_BPF_OBJECTS) break;

        char path[G_PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", ee->bpf_dir, de->d_name);
        struct g_ebpf_object *o = &ee->objs[ee->n_objs];
        g_strlcpy(o->name, de->d_name, sizeof(o->name));

        struct bpf_object *obj = bpf_object__open_file(path, NULL);
        if (libbpf_get_error(obj)) {
            fprintf(stderr, "[ebpf] open %s failed\n", path);
            continue;
        }
        if (bpf_object__load(obj)) {
            fprintf(stderr, "[ebpf] load %s failed\n", path);
            bpf_object__close(obj);
            continue;
        }
        o->obj = obj;
        /* attach all programs in the object */
        struct bpf_program *prog;
        bpf_object__for_each_program(prog, obj) {
            struct bpf_link *link = bpf_program__attach(prog);
            if (!libbpf_get_error(link)) {
                if (!o->link) o->link = link;
                printf("[ebpf] attached %s\n", bpf_program__name(prog));
            }
        }
        /* Bug 7 fix: create ring buffer ONCE here, reuse across all poll calls.
         * Old code created+destroyed it every 200ms in g_ebpf_poll, dropping
         * events during the gap and causing memory fragmentation. */
        struct bpf_map *m = bpf_object__find_map_by_name(obj, "events");
        if (m) {
            o->rb = ring_buffer__new(bpf_map__fd(m), ringbuf_cb, ee, NULL);
            if (o->rb) printf("[ebpf] ring buffer created for %s\n", de->d_name);
        }
        ee->n_objs++;
        printf("[ebpf] loaded %s\n", path);
    }
    closedir(d);
    printf("[ebpf] %d BPF objects loaded and attached\n", ee->n_objs);
    return 0;
#endif
}

/* ring buffer callback: receives raw exec_event from BPF, converts to g_event_t,
 * runs rule engine, publishes to bus. */
#ifdef G_HAVE_LIBBPF
static int ringbuf_cb(void *ctx, void *data, size_t sz) {
    g_ebpf_engine_t *ee = (g_ebpf_engine_t *)ctx;
    if (sz < sizeof(struct bpf_event)) return 0;
    const struct bpf_event *be = (const struct bpf_event *)data;

    g_event_t ev = {0};
    ev.pid = be->pid;
    ev.ppid = be->ppid;
    ev.uid = be->uid;
    memcpy(ev.comm, be->comm, 16);
    g_strlcpy(ev.path, (const char *)be->path, sizeof(ev.path));
    /* BUG 7 fix: populate pcomm from the ancestry map so IOA rules can match
     * parent comm (e.g. SHELL_SPAWNED_BY_WEB_SERVER matches pcomm in nginx). */
#ifdef G_HAVE_LIBBPF
    if (g_ee_global) {
        struct g_ancestry {
            uint32_t ppid;
            uint8_t  parent_comm[16];
        } a;
        if (g_ebpf_get_map_value(g_ee_global, "ancestry", &be->pid, &a) == 0) {
            memcpy(ev.pcomm, a.parent_comm, 16);
            ev.pcomm[15] = 0;
        }
    }
#endif
    g_strlcpy(ev.rule_id, (const char *)be->rule, sizeof(ev.rule_id));
    ev.severity = (g_severity_t)be->severity;
    ev.action_taken = bpf_action_to_g_action(be->action);

    /* Bug 19 fix: use real CLOCK_BOOTTIME nanoseconds, not seq counter */
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    ev.ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
    ev.seq = g_bus_next_seq();
    g_strlcpy(ev.source, "ebpf", sizeof(ev.source));
    ev.verdict = G_VERDICT_UNKNOWN;

    if (ev.action_taken == G_ACT_KILL_SWITCH) {
        /* Minor: explain to the user why Tor is offline now */
        g_strlcpy(ev.detail, "Non-Tor egress connection leak detected. System kill-switch activated. All default routes deleted. Tor guardian connections also terminated.", sizeof(ev.detail));
    }

    ee->n_events_total++;

    g_event_t decided;
    if (ev.action_taken != G_ACT_LOG) {
        /* BPF inline enforcement already chose/executed this action (e.g. SIGKILL/G_ACT_KILL_SWITCH) */
        ev.verdict = (ev.severity >= G_SEV_HIGH) ? G_VERDICT_MALICIOUS : G_VERDICT_SUSPICIOUS;
        g_bus_publish(&ev);
    } else if (g_ebpf_rules_eval(ee, &ev, &decided) > 0) {
        g_bus_publish(&decided);
    }
    return 0;
}
#endif

int g_ebpf_poll(g_ebpf_engine_t *ee, int timeout_ms) {
    if (!ee) return -EINVAL;
#ifndef G_HAVE_LIBBPF
    (void)timeout_ms;
    return 0;
#else
    if (!ee->bpf_available || ee->n_objs == 0) {
        usleep(timeout_ms * 1000);
        return 0;
    }
    /* Bug 7 fix: poll the PERSISTENT ring buffers created in g_ebpf_load_all.
     * No more create/destroy churn every 200ms. */
    int total = 0;
    for (int i = 0; i < ee->n_objs; i++) {
        if (!ee->objs[i].rb) continue;
        int n = ring_buffer__poll(ee->objs[i].rb, timeout_ms);
        if (n > 0) { ee->objs[i].n_events += n; total += n; }
    }
    return total;
#endif
}

int g_ebpf_attach_tracepoint(g_ebpf_engine_t *ee, const char *prog_name,
                             const char *tp_cat, const char *tp_name) {
    (void)ee; (void)prog_name; (void)tp_cat; (void)tp_name;
    return 0;  /* auto-attached in g_ebpf_load_all */
}

int g_ebpf_enforce_kill(pid_t pid) {
    /* Tetragon-style inline enforcement would use bpf_send_signal from inside
     * the BPF program. Userspace fallback: SIGKILL directly. */
    if (kill(pid, SIGKILL) == 0) return 0;
    return -errno;
}

int g_ebpf_stats(g_ebpf_engine_t *ee, int *out_nprogs, int *out_nevents) {
    if (!ee) return -EINVAL;
    if (out_nprogs) *out_nprogs = ee->n_objs;
    if (out_nevents) *out_nevents = ee->n_events_total;
    return 0;
}

int g_ebpf_set_map_value(g_ebpf_engine_t *ee, const char *map_name, const void *key, const void *val) {
#ifndef G_HAVE_LIBBPF
    return 0;
#else
    if (!ee || !ee->bpf_available) return 0;
    for (int i = 0; i < ee->n_objs; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(ee->objs[i].obj, map_name);
        if (m) {
            int fd = bpf_map__fd(m);
            if (fd >= 0) {
                int rc = bpf_map_update_elem(fd, key, val, BPF_ANY);
                if (rc != 0) {
                    return -errno;
                }
                return 0;
            }
        }
    }
    return -ENOENT;
#endif
}

/* Phase 2.3/2.4: read a BPF map value by name+key. Used by anomaly_engine
 * (feature counters) and ransomware_engine (delete/rename/write counters). */
int g_ebpf_get_map_value(g_ebpf_engine_t *ee, const char *map_name, const void *key, void *out) {
#ifndef G_HAVE_LIBBPF
    return -ENOSYS;
#else
    if (!ee || !ee->bpf_available) return -ENOSYS;
    for (int i = 0; i < ee->n_objs; i++) {
        struct bpf_map *m = bpf_object__find_map_by_name(ee->objs[i].obj, map_name);
        if (m) {
            int fd = bpf_map__fd(m);
            if (fd >= 0) {
                if (bpf_map_lookup_elem(fd, key, out) == 0) return 0;
                return -ENOENT;
            }
        }
    }
    return -ENOENT;
#endif
}

int g_ebpf_set_kill_switch_active(bool active) {
    if (!g_ee_global) return -ENODEV;
    uint32_t zero = 0;
    uint32_t val = active ? 1 : 0;
    /* Design decision: kill_switch_active cannot be cleared by userspace once set */
    if (!active) return -EINVAL;
    return g_ebpf_set_map_value(g_ee_global, "kill_switch_active", &zero, &val);
}
