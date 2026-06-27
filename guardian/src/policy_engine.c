/* policy_engine.c — deterministic threat→action mapping.
 *
 * Rules-based, NOT LLM. Given an event (from any layer), decide the action:
 *   - signature hit for known-critical malware → KILL_SWITCH or QUARANTINE
 *   - signature hit for known malware → QUARANTINE_FILE
 *   - eBPF rule with HIGH severity → FREEZE + ALERT
 *   - eBPF rule with CRITICAL severity → KILL (with snapshot)
 *   - FIM violation on critical path (/etc/passwd, /bin/*, torrc) → RESTORE + ALERT
 *   - FIM violation on other path → LOG + ALERT
 *   - anomaly ML score < -0.15 (high anomaly) → FREEZE + escalate
 *   - net IDS non-Tor egress → KILL_SWITCH
 *
 * Policy file format (guardian.policy):
 *   # source rule_id_glob severity_glob -> action
 *   yara *Malware* CRITICAL -> QUARANTINE_FILE
 *   ebpf * HIGH -> FREEZE
 *   fim * HIGH -> RESTORE_FILE
 *   net * CRITICAL -> KILL_SWITCH
 *
 * Falls back to built-in defaults if no policy file.
 */
#include "guardian.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fnmatch.h>
#include <errno.h>

#define MAX_POLICY_RULES 64

typedef struct {
    char     source_glob[G_SOURCE_MAX];
    char     rule_glob[G_RULE_ID_MAX];
    int      min_severity;       /* match if event.severity >= this */
    g_action_t action;
} g_policy_rule;

struct g_policy_engine {
    g_policy_rule rules[MAX_POLICY_RULES];
    int n_rules;
};

static g_action_t default_action(const g_event_t *ev) {
    /* built-in defaults when no policy rule matches */
    if (!strcmp(ev->source, "yara")) {
        if (ev->severity >= G_SEV_CRITICAL) return G_ACT_QUARANTINE_FILE;
        if (ev->severity >= G_SEV_HIGH)     return G_ACT_QUARANTINE_FILE;
        return G_ACT_LOG;
    }
    if (!strcmp(ev->source, "ebpf")) {
        if (ev->severity >= G_SEV_CRITICAL) return G_ACT_KILL;
        if (ev->severity >= G_SEV_HIGH)     return G_ACT_FREEZE;
        return G_ACT_LOG;
    }
    if (!strcmp(ev->source, "fim")) {
        /* critical paths: /etc/passwd, /etc/shadow, /bin/*, /sbin/*, /usr/bin/*,
         * torrc, seL4 config */
        const char *critical_paths[] = {
            "/etc/passwd", "/etc/shadow", "/etc/tor/torrc",
            "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/lib/",
            NULL
        };
        for (int i = 0; critical_paths[i]; i++) {
            if (strstr(ev->path, critical_paths[i])) return G_ACT_RESTORE_FILE;
        }
        return G_ACT_ALERT;
    }
    if (!strcmp(ev->source, "anomaly")) {
        if (ev->severity >= G_SEV_HIGH) return G_ACT_FREEZE;
        return G_ACT_LOG;
    }
    if (!strcmp(ev->source, "net")) {
        if (ev->severity >= G_SEV_CRITICAL) return G_ACT_KILL_SWITCH;
        return G_ACT_BLOCK_NET;
    }
    return G_ACT_LOG;
}

static int parse_sev_int(const char *s) {
    if (!s) return G_SEV_INFO;
    if (!strcmp(s,"INFO")) return G_SEV_INFO;
    if (!strcmp(s,"LOW")) return G_SEV_LOW;
    if (!strcmp(s,"MEDIUM")) return G_SEV_MEDIUM;
    if (!strcmp(s,"HIGH")) return G_SEV_HIGH;
    if (!strcmp(s,"CRITICAL")) return G_SEV_CRITICAL;
    return G_SEV_INFO;
}

static g_action_t parse_action_str(const char *s) {
    if (!s) return G_ACT_LOG;
    if (!strcmp(s,"LOG")) return G_ACT_LOG;
    if (!strcmp(s,"FREEZE")) return G_ACT_FREEZE;
    if (!strcmp(s,"THAW")) return G_ACT_THAW;
    if (!strcmp(s,"QUARANTINE_FILE")) return G_ACT_QUARANTINE_FILE;
    if (!strcmp(s,"RESTORE_FILE")) return G_ACT_RESTORE_FILE;
    if (!strcmp(s,"QUARANTINE_PROC")) return G_ACT_QUARANTINE_PROC;
    if (!strcmp(s,"BLOCK_NET")) return G_ACT_BLOCK_NET;
    if (!strcmp(s,"ALERT")) return G_ACT_ALERT;
    if (!strcmp(s,"KILL")) return G_ACT_KILL;
    if (!strcmp(s,"DELETE")) return G_ACT_DELETE;
    if (!strcmp(s,"ENCRYPT")) return G_ACT_ENCRYPT;
    if (!strcmp(s,"KILL_SWITCH")) return G_ACT_KILL_SWITCH;
    return G_ACT_LOG;
}

g_policy_engine_t *g_policy_init(const char *policy_path) {
    g_policy_engine_t *pe = calloc(1, sizeof(*pe));
    if (!pe) return NULL;

    if (policy_path) {
        FILE *f = fopen(policy_path, "r");
        if (f) {
            char line[512];
            while (fgets(line, sizeof(line), f) && pe->n_rules < MAX_POLICY_RULES) {
                char *p = line; while (*p==' '||*p=='\t') p++;
                char *nl = strchr(p,'\n'); if (nl) *nl = 0;
                char *c = strchr(p,'#'); if (c) *c = 0;
                if (!*p) continue;
                /* format: <src_glob> <rule_glob> <sev> -> <action> */
                char sg[G_SOURCE_MAX], rg[G_RULE_ID_MAX], sv[16], arrow[4], act[32];
                if (sscanf(p, "%31s %63s %15s %3s %31s", sg, rg, sv, arrow, act) == 5
                    && !strcmp(arrow, "->")) {
                    g_policy_rule *r = &pe->rules[pe->n_rules++];
                    g_strlcpy(r->source_glob, sg, sizeof(r->source_glob));
                    g_strlcpy(r->rule_glob, rg, sizeof(r->rule_glob));
                    r->min_severity = parse_sev_int(sv);
                    r->action = parse_action_str(act);
                }
            }
            fclose(f);
            printf("[policy] loaded %d rules from %s\n", pe->n_rules, policy_path);
        } else {
            printf("[policy] no policy file at %s — using built-in defaults\n", policy_path);
        }
    }
    return pe;
}

void g_policy_free(g_policy_engine_t *pe) {
    free(pe);
}

g_action_t g_policy_decide(g_policy_engine_t *pe, const g_event_t *ev) {
    if (!pe || !ev) return G_ACT_LOG;

    /* check policy rules in order, first match wins */
    for (int i = 0; i < pe->n_rules; i++) {
        g_policy_rule *r = &pe->rules[i];
        if (fnmatch(r->source_glob, ev->source, 0) != 0) continue;
        if (fnmatch(r->rule_glob, ev->rule_id, 0) != 0) continue;
        if (ev->severity < r->min_severity) continue;
        return r->action;
    }
    return default_action(ev);
}

int g_policy_apply(g_policy_engine_t *pe, g_event_t *ev) {
    if (!pe || !ev) return -EINVAL;
    /* if the source layer didn't already set an action, decide it */
    if (ev->action_taken == G_ACT_LOG || ev->action_taken == 0) {
        ev->action_taken = g_policy_decide(pe, ev);
    }
    /* publish to bus (enforcement + log subscribe) */
    g_bus_publish(ev);
    return 0;
}
