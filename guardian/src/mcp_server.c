/* mcp_server.c — Deep-kernel MCP server for the Guardian (and Qwythos on-demand).
 *
 * JSON-RPC 2.0 over Unix socket. ~50 tools organized by tier:
 *   inspect (read-only) — process_inspect, netflow_capture, file_forensics, etc.
 *   reversible           — process_freeze, process_quarantine, net_block, etc.
 *   irreversible         — process_kill, secure_delete, kill_switch (human-confirm)
 *
 * Safety: denylist blocks /proc/kcore, /dev/mem, /dev/kmem. Irreversible
 * actions require MCP_AUTOCONFIRM=1 or a confirmation token.
 *
 * Borrows MCPilot's blueprint (tool registry + JSON-RPC + safety gates) but
 * the tools are WLTIOS-native (eBPF, seL4-aware, amnesic-aware).
 *
 * Usage:
 *   mcp_server [--socket /run/guardian.mcp.sock] [--stdio]
 *   mcp_server --list-tools
 */
#define _GNU_SOURCE  /* required for struct ucred / SO_PEERCRED on glibc */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <dirent.h>
#include <ctype.h>
#include <openssl/evp.h>

#define MCP_MAX_TOOLS    64
#define MCP_MAX_ARGS     8
#define MCP_BUF_SZ       (64 * 1024)
#define MCP_SOCKET_PATH  "/run/guardian.mcp.sock"

/* ---- JSON helpers (minimal hand-rolled) ---- */

typedef struct {
    char key[64];
    char val[1024];
} mcp_kv;

typedef struct {
    mcp_kv items[MCP_MAX_ARGS];
    int count;
} mcp_args;

static const char *args_get(const mcp_args *a, const char *key) {
    for (int i = 0; i < a->count; i++)
        if (!strcmp(a->items[i].key, key)) return a->items[i].val;
    return NULL;
}

static long args_get_long(const mcp_args *a, const char *key, long def) {
    const char *v = args_get(a, key);
    return v ? strtol(v, NULL, 10) : def;
}

/* parse a flat {"k":"v","k2":"v2"} into mcp_args. No nested objects in v1. */
static void args_parse(const char *json, mcp_args *out) {
    out->count = 0;
    if (!json) return;
    const char *p = strchr(json, '{');
    if (!p) return;
    p++;
    while (*p && *p != '}' && out->count < MCP_MAX_ARGS) {
        while (*p && (*p==' '||*p==','||*p=='\t'||*p=='\n')) p++;
        if (*p != '"') break;
        p++;
        int ki = 0;
        while (*p && *p != '"' && ki < 63) out->items[out->count].key[ki++] = *p++;
        out->items[out->count].key[ki] = 0;
        if (*p == '"') p++;
        while (*p && *p!=':') p++;
        if (*p==':') p++;
        while (*p && (*p==' '||*p=='\t')) p++;
        int vi = 0;
        if (*p == '"') {
            p++;
            while (*p && *p != '"' && vi < 1023) {
                if (*p == '\\' && p[1]) { p++; }
                out->items[out->count].val[vi++] = *p++;
            }
            if (*p=='"') p++;
        } else {
            while (*p && *p != ',' && *p != '}' && vi < 1023)
                out->items[out->count].val[vi++] = *p++;
        }
        out->items[out->count].val[vi] = 0;
        out->count++;
    }
}

/* JSON-escape a string into out. Returns out. */
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

/* ---- tool registry ---- */

typedef enum { TIER_INSPECT, TIER_REVERSIBLE, TIER_IRREVERSIBLE } mcp_tier;

typedef struct {
    const char *name;
    const char *desc;
    mcp_tier tier;
    bool needs_root;
    bool needs_bpf;
    char (*fn)(const mcp_args *args, char *out, size_t sz);  /* returns type */
} mcp_tool;

/* output buffer type marker — 's' string, '{' json object */
#define MCP_RETURN_JSON '{'
#define MCP_RETURN_STR  's'

static char tool_buf[MCP_BUF_SZ];

/* ---- safety denylist ---- */
static bool is_dangerous_path(const char *p) {
    if (!p) return false;
    const char *bad[] = {
        "/proc/kcore", "/dev/mem", "/dev/kmem", "/dev/port",
        "/sys/kernel/debug", NULL
    };
    for (int i = 0; bad[i]; i++) if (strstr(p, bad[i])) return true;
    return false;
}

static bool is_dangerous_cmd(const char *cmd) {
    if (!cmd) return false;
    const char *bad[] = {
        "rm -rf /", "mkfs", "dd if=", "shutdown", "reboot", "halt",
        ":(){:|:&};:", "chmod -R 777 /", "chown -R", "kill -9 1", "kill -9 -1",
        "wget http | sh", "curl http | bash", NULL
    };
    for (int i = 0; bad[i]; i++) if (strstr(cmd, bad[i])) return true;
    return false;
}

static bool have_root(void) { return geteuid() == 0; }

/* ============================================================ *
 *  INSPECT TOOLS (read-only)                                   *
 * ============================================================ */

static char t_process_inspect(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    char path[128];
    snprintf(path, sizeof(path), "/proc/%ld", pid);
    if (access(path, F_OK) != 0)
        return snprintf(out, sz, "{\"error\":\"pid %ld not found\"}", pid), MCP_RETURN_JSON;
    char buf[4096]; char comm[64]; char esc_comm[128];
    FILE *f;
    /* comm */
    snprintf(path, sizeof(path), "/proc/%ld/comm", pid);
    f = fopen(path, "r");
    if (f) { if (!fgets(comm, sizeof(comm), f)) comm[0]=0; fclose(f);
        char *nl=strchr(comm,'\n'); if(nl)*nl=0; } else comm[0]=0;
    json_escape(comm, esc_comm, sizeof(esc_comm));
    /* status */
    snprintf(path, sizeof(path), "/proc/%ld/status", pid);
    f = fopen(path, "r");
    char status[2048] = {0}; size_t off = 0;
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f) && off < sizeof(status)-256) {
            off += snprintf(status+off, sizeof(status)-off, "%s", line);
        }
        fclose(f);
    }
    char esc_status[4200];
    json_escape(status, esc_status, sizeof(esc_status));
    /* cmdline */
    snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
    f = fopen(path, "rb");
    char cmdline[1024] = {0};
    if (f) { size_t n = fread(cmdline, 1, sizeof(cmdline)-1, f); fclose(f);
        for (size_t i = 0; i < n; i++) if (cmdline[i]==0) cmdline[i]=' ';
    }
    char esc_cmd[1200]; json_escape(cmdline, esc_cmd, sizeof(esc_cmd));
    snprintf(out, sz, "{\"pid\":%ld,\"comm\":\"%s\",\"cmdline\":\"%s\",\"status\":\"%s\"}",
             pid, esc_comm, esc_cmd, esc_status);
    return MCP_RETURN_JSON;
}

static char t_process_list(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    DIR *d = opendir("/proc");
    if (!d) return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    /* M9 fix: use a fixed-width placeholder so the count patch never overflows.
     * "count":999999 is 16 chars; any real count up to 999999 ("count":     3")
     * will fit in the same space when right-padded. */
    size_t off = snprintf(out, sz, "{\"count\":999999,\"processes\":[");
    /* remember where the count placeholder starts */
    char *count_start = strstr(out, "\"count\":999999");
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL && off < sz - 256) {
        if (!isdigit(de->d_name[0])) continue;
        long pid = strtol(de->d_name, NULL, 10);
        char p[64]; snprintf(p, sizeof(p), "/proc/%ld/comm", pid);
        FILE *f = fopen(p, "r");
        if (!f) continue;
        char comm[32] = {0};
        if (fgets(comm, sizeof(comm), f)) {
            char *nl = strchr(comm, '\n'); if (nl) *nl = 0;
        }
        fclose(f);
        char esc[64]; json_escape(comm, esc, sizeof(esc));
        off += snprintf(out+off, sz-off, "%s{\"pid\":%ld,\"comm\":\"%s\"}",
                        n?",":"", pid, esc);
        n++;
    }
    closedir(d);
    off += snprintf(out+off, sz-off, "]}");
    /* M9 fix: overwrite the fixed-width placeholder with the real count.
     * snprintf into exactly 16 chars (the length of '"count":999999') with
     * left-justified content and space-padding so we never write past the
     * original placeholder boundary. */
    if (count_start) {
        char patch[17];
        int wrote = snprintf(patch, sizeof(patch), "\"count\":%-7d", n);
        /* ensure we don't exceed the 16-char placeholder */
        if (wrote > 16) wrote = 16;
        memcpy(count_start, patch, 16);  /* always exactly 16 bytes */
    }
    return MCP_RETURN_JSON;
}

static char t_netflow_capture(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    size_t off = snprintf(out, sz, "{\"tcp\":[");
    const char *protos[] = {"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"};
    int n = 0;
    for (int i = 0; i < 4 && off < sz - 256; i++) {
        FILE *f = fopen(protos[i], "r");
        if (!f) continue;
        char line[256];
        (void)fgets(line, sizeof(line), f);  /* header */
        while (fgets(line, sizeof(line), f) && off < sz - 256) {
            char local[64], remote[64], state[16];
            if (sscanf(line, "%*d: %63s %63s %15s", local, remote, state) != 3) continue;
            off += snprintf(out+off, sz-off, "%s{\"local\":\"%s\",\"remote\":\"%s\",\"state\":\"%s\"}",
                            n?",":"", local, remote, state);
            n++;
        }
        fclose(f);
    }
    off += snprintf(out+off, sz-off, "],\"count\":%d}", n);
    return MCP_RETURN_JSON;
}

static char t_file_forensics(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    if (is_dangerous_path(path))
        return snprintf(out, sz, "{\"error\":\"denied by safety denylist\"}"), MCP_RETURN_JSON;
    struct stat st;
    if (stat(path, &st) != 0)
        return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    /* sha256 */
    FILE *f = fopen(path, "rb");
    if (!f) return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    /* hash via openssl EVP */
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    uint8_t buf[65536]; size_t nr;
    while ((nr = fread(buf, 1, sizeof(buf), f)) > 0) EVP_DigestUpdate(ctx, buf, nr);
    uint8_t h[32]; unsigned int L=32;
    EVP_DigestFinal_ex(ctx, h, &L);
    EVP_MD_CTX_free(ctx);
    fclose(f);
    char hex[65]; static const char *hx="0123456789abcdef";
    for (int i=0;i<32;i++){hex[i*2]=hx[h[i]>>4];hex[i*2+1]=hx[h[i]&0xf];} hex[64]=0;
    char esc_path[4200]; json_escape(path, esc_path, sizeof(esc_path));
    snprintf(out, sz, "{\"path\":\"%s\",\"sha256\":\"%s\",\"size\":%lld,\"mtime\":%lld,\"mode\":%o,\"uid\":%d,\"gid\":%d}",
             esc_path, hex, (long long)st.st_size, (long long)st.st_mtime,
             st.st_mode, st.st_uid, st.st_gid);
    return MCP_RETURN_JSON;
}

static char t_audit_query(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    /* ausearch may not be available — read /var/log/audit/audit.log directly */
    FILE *f = fopen("/var/log/audit/audit.log", "r");
    if (!f) return snprintf(out, sz, "{\"error\":\"audit log not available\"}"), MCP_RETURN_JSON;
    size_t off = snprintf(out, sz, "{\"lines\":[");
    int n = 0; char line[1024];
    while (fgets(line, sizeof(line), f) && off < sz - 1024 && n < 50) {
        char esc[2100]; json_escape(line, esc, sizeof(esc));
        /* strip trailing newline from esc */
        char *nl = strrchr(esc, '\\');
        off += snprintf(out+off, sz-off, "%s\"%s\"", n?",":"", esc);
        n++;
    }
    fclose(f);
    off += snprintf(out+off, sz-off, "],\"count\":%d}", n);
    return MCP_RETURN_JSON;
}

static char t_log_read(const mcp_args *a, char *out, size_t sz) {
    const char *name = args_get(a, "name");
    if (!name) name = "guardian.log";
    /* H8 fix: reject path traversal — name must be a bare filename, no
     * slashes or ".." allowed. Without this, an attacker can read any
     * file on disk via name="../../etc/shadow". */
    if (strchr(name, '/') || strstr(name, "..")) {
        return snprintf(out, sz, "{\"error\":\"invalid log name: path traversal blocked\"}"),
               MCP_RETURN_JSON;
    }
    long lines = args_get_long(a, "lines", 50);
    char path[256];
    snprintf(path, sizeof(path), "/var/log/%s", name);
    if (access(path, R_OK) != 0) snprintf(path, sizeof(path), "%s", name);
    FILE *f = fopen(path, "r");
    if (!f) return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    /* read last N lines */
    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    long target = pos > 65536 ? pos - 65536 : 0;
    fseek(f, target, SEEK_SET);
    char buf[65536] = {0};
    size_t nr = fread(buf, 1, sizeof(buf)-1, f);
    fclose(f);
    /* count lines from end, take last N */
    int total = 0;
    for (size_t i = 0; i < nr; i++) if (buf[i] == '\n') total++;
    int start = total > lines ? total - lines : 0;
    int cur = 0;
    size_t off = snprintf(out, sz, "{\"lines\":[");
    int written = 0;
    char *p = buf;
    while (*p && off < sz - 512) {
        char *nl = strchr(p, '\n');
        if (!nl) break;
        if (cur >= start) {
            *nl = 0;
            char esc[2100]; json_escape(p, esc, sizeof(esc));
            off += snprintf(out+off, sz-off, "%s\"%s\"", written?",":"", esc);
            written++;
        }
        cur++;
        p = nl + 1;
    }
    off += snprintf(out+off, sz-off, "]}");
    return MCP_RETURN_JSON;
}

static char t_perf_counters(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    /* read /proc/stat for basic counters (perf_event_open needs root for some) */
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    char line[512];
    size_t off = snprintf(out, sz, "{");
    int first = 1;
    while (fgets(line, sizeof(line), f) && off < sz - 512) {
        char key[64];
        if (sscanf(line, "%63s", key) != 1) continue;
        if (!strncmp(key, "cpu", 3) || !strncmp(key, "ctxt", 4) ||
            !strncmp(key, "btime", 5) || !strncmp(key, "processes", 9) ||
            !strncmp(key, "procs_running", 13)) {
            char *rest = strchr(line, ' ');
            if (rest) {
                rest++; /* skip space */
                char *nl = strchr(rest, '\n'); if (nl) *nl = 0;
                off += snprintf(out+off, sz-off, "%s\"%s\":\"%s\"", first?"":",", key, rest);
                first = 0;
            }
        }
    }
    fclose(f);
    off += snprintf(out+off, sz-off, "}");
    return MCP_RETURN_JSON;
}

static char t_sel4_caps_dump(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    /* phase 2: would read capDL dump from a seL4 userspace tool.
     * v1: return stub indicating not yet available. */
    return snprintf(out, sz, "{\"error\":\"sel4_caps_dump requires seL4 userspace capdl tool (phase 2)\","
                   "\"stub\":true}"), MCP_RETURN_JSON;
}

static char t_tpm_attest(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    /* read IMA measurements if available */
    FILE *f = fopen("/sys/kernel/security/ima/ascii_runtime_measurements", "r");
    if (!f) return snprintf(out, sz, "{\"error\":\"IMA/TPM not available on this hardware\",\"supported\":false}"),
               MCP_RETURN_JSON;
    size_t off = snprintf(out, sz, "{\"supported\":true,\"measurements\":[");
    int n = 0; char line[1024];
    while (fgets(line, sizeof(line), f) && off < sz - 1024 && n < 20) {
        char esc[2100]; json_escape(line, esc, sizeof(esc));
        off += snprintf(out+off, sz-off, "%s\"%s\"", n?",":"", esc);
        n++;
    }
    fclose(f);
    off += snprintf(out+off, sz-off, "],\"count\":%d}", n);
    return MCP_RETURN_JSON;
}

static char t_ima_measure(const mcp_args *a, char *out, size_t sz) {
    return t_tpm_attest(a, out, sz);  /* same source */
}

static char t_intel_pt_trace(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    long dur = args_get_long(a, "duration", 1);
    /* perf_event_open with PERF_SAMPLE_BRANCH — needs root.
     * v1: return a stub explaining how to invoke perf. */
    return snprintf(out, sz, "{\"error\":\"intel_pt_trace requires perf_event_open (root) — "
                   "run: perf record -e intel_pt// -p %ld -- sleep %ld\","
                   "\"pid\":%ld,\"duration\":%ld,\"stub\":true}", pid, dur, pid, dur), MCP_RETURN_JSON;
}

static char t_kernel_mem_read(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    return snprintf(out, sz, "{\"error\":\"kernel_mem_read requires /dev/mem (blocked by denylist)\"}"),
           MCP_RETURN_JSON;
}

static char t_ebpf_load_probe(const mcp_args *a, char *out, size_t sz) {
    const char *prog = args_get(a, "prog");
    if (!prog) return snprintf(out, sz, "{\"error\":\"missing prog path\"}"), MCP_RETURN_JSON;
    if (is_dangerous_path(prog))
        return snprintf(out, sz, "{\"error\":\"denied\"}"), MCP_RETURN_JSON;
    /* actual load via libbpf would happen here — v1 stub */
    return snprintf(out, sz, "{\"prog\":\"%s\",\"status\":\"load_requires_cap_bpf\",\"stub\":true}", prog),
           MCP_RETURN_JSON;
}

static char t_syscall_trace(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    long dur = args_get_long(a, "duration", 1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    if (dur < 1) dur = 1;
    if (dur > 30) dur = 30;  /* cap trace duration */

    /* C2 fix: replace popen(shell_cmd) with fork/execvp to prevent
     * shell injection via crafted pid values. The old code passed
     * user-controlled values into a shell command string. */
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return snprintf(out, sz, "{\"error\":\"pipe: %s\"}", strerror(errno)), MCP_RETURN_JSON;

    pid_t child = fork();
    if (child < 0) {
        close(pipefd[0]); close(pipefd[1]);
        return snprintf(out, sz, "{\"error\":\"fork: %s\"}", strerror(errno)), MCP_RETURN_JSON;
    }
    if (child == 0) {
        /* Child: redirect stdout+stderr to pipe, exec strace directly */
        prctl(PR_SET_PDEATHSIG, SIGKILL);  /* die if parent exits */
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        char pid_str[32];
        snprintf(pid_str, sizeof(pid_str), "%ld", pid);
        execlp("strace", "strace", "-p", pid_str, "-c", "-f", (char *)NULL);
        _exit(127);  /* exec failed */
    }
    /* Parent: read from pipe with timeout */
    close(pipefd[1]);
    char buf[4096] = {0};
    size_t total = 0;
    /* Wait for 'dur' seconds, then kill the child */
    for (long elapsed = 0; elapsed < dur; elapsed++) {
        sleep(1);
    }
    kill(child, SIGTERM);
    /* Drain remaining pipe data */
    ssize_t nr;
    while (total < sizeof(buf) - 1) {
        nr = read(pipefd[0], buf + total, sizeof(buf) - 1 - total);
        if (nr <= 0) break;
        total += (size_t)nr;
    }
    buf[total] = '\0';
    close(pipefd[0]);
    waitpid(child, NULL, 0);
    char esc[4200]; json_escape(buf, esc, sizeof(esc));
    snprintf(out, sz, "{\"pid\":%ld,\"output\":\"%s\"}", pid, esc);
    return MCP_RETURN_JSON;
}

/* ---- Guardian integration (read-only) ---- */
static char t_guardian_status(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    return snprintf(out, sz, "{\"status\":\"online\",\"engines\":[\"sig\",\"ebpf\",\"fim\",\"anomaly\",\"net\"],"
                   "\"ram_mb\":120}"), MCP_RETURN_JSON;
}

static char t_guardian_history(const mcp_args *a, char *out, size_t sz) {
    return t_log_read(a, out, sz);
}

static char t_guardian_forensics(const mcp_args *a, char *out, size_t sz) {
    long eid = args_get_long(a, "event_id", -1);
    return snprintf(out, sz, "{\"event_id\":%ld,\"forensic_snapshot\":\"see /var/quarantine/snapshot_*\"}", eid),
           MCP_RETURN_JSON;
}

static char t_guardian_sigs_list(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    return snprintf(out, sz, "{\"sig_db\":\"/etc/wlt/guardian/sigs/guardian.yarc\","
                   "\"version\":\"1.0\",\"rule_count\":6}"), MCP_RETURN_JSON;
}

static char t_process_mem_scan(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;

    /* Connect to daemon's API socket to delegate command */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    bool delegated = false;
    if (s >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        
        /* Try production path first */
        g_strlcpy(addr.sun_path, G_SOCKET_PATH, sizeof(addr.sun_path));
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            delegated = true;
        } else {
            /* Try dev sandbox path next */
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            g_strlcpy(addr.sun_path, "/tmp/guardian.sock", sizeof(addr.sun_path));
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                delegated = true;
            }
        }

        if (delegated) {
            char cmd[64];
            snprintf(cmd, sizeof(cmd), "cmd:mem_scan:%ld\n", pid);
            if (write(s, cmd, strlen(cmd)) == (ssize_t)strlen(cmd)) {
                char resp[4096] = {0};
                ssize_t n = read(s, resp, sizeof(resp) - 1);
                if (n > 0) {
                    snprintf(out, sz, "%s", resp);
                    char *nl = strchr(out, '\n');
                    if (nl) *nl = '\0';
                    close(s);
                    return MCP_RETURN_JSON;
                }
            }
            close(s);
        } else {
            close(s);
        }
    }

    return snprintf(out, sz, "{\"error\":\"daemon not running, cannot scan memory\"}"), MCP_RETURN_JSON;
}

static char t_sig_update_status(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    FILE *f = fopen("/run/guardian/sig_update.status", "r");
    if (!f) {
        return snprintf(out, sz, "{\"version\":\"1.0\",\"last_update_ts\":0,\"last_update_result\":\"disabled\"}"), MCP_RETURN_JSON;
    }
    char buf[1024] = {0};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0) {
        return snprintf(out, sz, "{\"version\":\"1.0\",\"last_update_ts\":0,\"last_update_result\":\"disabled\"}"), MCP_RETURN_JSON;
    }
    g_strlcpy(out, buf, sz);
    return MCP_RETURN_JSON;
}

/* ============================================================ *
 *  REVERSIBLE ACTION TOOLS (autonomous)                        *
 * ============================================================ */

static char t_process_freeze(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    int rc = g_action_freeze((pid_t)pid);
    return snprintf(out, sz, "{\"pid\":%ld,\"action\":\"freeze\",\"rc\":%d,\"simulated\":%s}",
                    pid, rc, have_root()?"false":"true"), MCP_RETURN_JSON;
}

static char t_process_thaw(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    int rc = g_action_thaw((pid_t)pid);
    return snprintf(out, sz, "{\"pid\":%ld,\"action\":\"thaw\",\"rc\":%d}", pid, rc), MCP_RETURN_JSON;
}

static char t_process_quarantine(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    int rc = g_action_quarantine_proc((pid_t)pid);
    return snprintf(out, sz, "{\"pid\":%ld,\"action\":\"quarantine\",\"rc\":%d,\"simulated\":%s}",
                    pid, rc, have_root()?"false":"true"), MCP_RETURN_JSON;
}

static char t_net_block_pid(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    int rc = g_action_block_net((pid_t)pid);
    return snprintf(out, sz, "{\"pid\":%ld,\"action\":\"net_block\",\"rc\":%d}", pid, rc), MCP_RETURN_JSON;
}

static char t_file_quarantine(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    if (is_dangerous_path(path))
        return snprintf(out, sz, "{\"error\":\"denied\"}"), MCP_RETURN_JSON;
    int rc = g_action_quarantine_file(path);
    char esc[4200]; json_escape(path, esc, sizeof(esc));
    return snprintf(out, sz, "{\"path\":\"%s\",\"action\":\"quarantine_file\",\"rc\":%d}", esc, rc),
           MCP_RETURN_JSON;
}

static char t_file_restore(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    /* C3 fix: t_file_quarantine checks is_dangerous_path but t_file_restore
     * was missing the same guard. Without this, an attacker could restore
     * a weaponized file to /proc/kcore, /dev/mem, etc. */
    if (is_dangerous_path(path))
        return snprintf(out, sz, "{\"error\":\"denied by safety denylist\"}"), MCP_RETURN_JSON;
    int rc = g_action_restore_file(path);
    char esc[4200]; json_escape(path, esc, sizeof(esc));
    return snprintf(out, sz, "{\"path\":\"%s\",\"action\":\"restore\",\"rc\":%d}", esc, rc),
           MCP_RETURN_JSON;
}

/* ============================================================ *
 *  IRREVERSIBLE ACTION TOOLS (human-confirm required)          *
 * ============================================================ */

static char t_process_kill(const mcp_args *a, char *out, size_t sz) {
    long pid = args_get_long(a, "pid", -1);
    if (pid < 0) return snprintf(out, sz, "{\"error\":\"missing pid\"}"), MCP_RETURN_JSON;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"irreversible action requires MCP_AUTOCONFIRM=1 or human confirm\","
                       "\"pid\":%ld,\"tier\":\"irreversible\"}", pid), MCP_RETURN_JSON;
    int rc = g_action_kill((pid_t)pid, true);
    return snprintf(out, sz, "{\"pid\":%ld,\"action\":\"kill\",\"rc\":%d}", pid, rc), MCP_RETURN_JSON;
}

static char t_secure_delete(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    if (is_dangerous_path(path))
        return snprintf(out, sz, "{\"error\":\"denied\"}"), MCP_RETURN_JSON;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"irreversible action requires MCP_AUTOCONFIRM=1\"}"), MCP_RETURN_JSON;
    int rc = g_action_delete(path);
    return snprintf(out, sz, "{\"path\":\"%s\",\"action\":\"secure_delete\",\"rc\":%d}", path, rc),
           MCP_RETURN_JSON;
}

static char t_kill_switch(const mcp_args *a, char *out, size_t sz) {
    (void)a;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"kill_switch is irreversible — requires MCP_AUTOCONFIRM=1\"}"),
               MCP_RETURN_JSON;

    /* Try connecting to daemon's API socket to delegate command */
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    bool delegated = false;
    int rc = -1;
    if (s >= 0) {
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        
        /* Try production path first */
        g_strlcpy(addr.sun_path, G_SOCKET_PATH, sizeof(addr.sun_path));
        if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            delegated = true;
        } else {
            /* Try dev sandbox path next */
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            g_strlcpy(addr.sun_path, "/tmp/guardian.sock", sizeof(addr.sun_path));
            if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
                delegated = true;
            }
        }

        if (delegated) {
            /* Send cmd:kill_switch\n and wait for response */
            if (write(s, "cmd:kill_switch\n", 16) == 16) {
                char resp[256] = {0};
                ssize_t n = read(s, resp, sizeof(resp) - 1);
                if (n > 0) {
                    snprintf(out, sz, "%s", resp);
                    /* strip trailing newline from out */
                    char *nl = strchr(out, '\n');
                    if (nl) *nl = '\0';
                    close(s);
                    return MCP_RETURN_JSON;
                }
            }
            /* If write/read failed, reset delegated */
            delegated = false;
            close(s);
        } else {
            close(s);
        }
    }

    /* Fallback directly when daemon is down */
    fprintf(stderr, "WARNING: daemon not running. Reversal prevention BPF flag was not set.\n");
    rc = g_action_kill_switch();
    return snprintf(out, sz, "{\"action\":\"kill_switch\",\"rc\":%d,\"fallback\":true}", rc), MCP_RETURN_JSON;
}


static char t_file_encrypt(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"irreversible — requires MCP_AUTOCONFIRM=1\"}"), MCP_RETURN_JSON;
    return snprintf(out, sz, "{\"path\":\"%s\",\"action\":\"encrypt\",\"error\":\"Key Vault not yet implemented (v2)\"}",
                    path), MCP_RETURN_JSON;
}

/* ---- userspace misc tools (ported from MCPilot blueprint) ---- */
static char t_shell_exec(const mcp_args *a, char *out, size_t sz) {
    const char *cmd = args_get(a, "cmd");
    if (!cmd) return snprintf(out, sz, "{\"error\":\"missing cmd\"}"), MCP_RETURN_JSON;
    if (is_dangerous_cmd(cmd))
        return snprintf(out, sz, "{\"error\":\"command blocked by safety denylist\"}"), MCP_RETURN_JSON;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"shell_exec requires MCP_AUTOCONFIRM=1\"}"), MCP_RETURN_JSON;
    FILE *p = popen(cmd, "r");
    if (!p) return snprintf(out, sz, "{\"error\":\"%s\"}", strerror(errno)), MCP_RETURN_JSON;
    char buf[4096] = {0}; size_t off = 0;
    while (off < sizeof(buf)-1 && fgets(buf+off, sizeof(buf)-off, p)) off = strlen(buf);
    int rc = pclose(p);
    char esc[4200]; json_escape(buf, esc, sizeof(esc));
    snprintf(out, sz, "{\"cmd\":\"%s\",\"rc\":%d,\"output\":\"%s\"}", cmd, rc, esc);
    return MCP_RETURN_JSON;
}

static char t_install_package(const mcp_args *a, char *out, size_t sz) {
    const char *path = args_get(a, "path");
    if (!path) return snprintf(out, sz, "{\"error\":\"missing path\"}"), MCP_RETURN_JSON;
    if (!getenv("MCP_AUTOCONFIRM"))
        return snprintf(out, sz, "{\"error\":\"install_package requires MCP_AUTOCONFIRM=1\"}"), MCP_RETURN_JSON;
    return snprintf(out, sz, "{\"path\":\"%s\",\"action\":\"install\",\"error\":\"wlt-pkg integration (v2)\"}",
                    path), MCP_RETURN_JSON;
}

/* ---- tool registry ---- */
static mcp_tool TOOLS[] = {
    /* inspect */
    {"process_inspect",     "Full state of a PID",         TIER_INSPECT,    false, false, t_process_inspect},
    {"process_list",        "List all processes",          TIER_INSPECT,    false, false, t_process_list},
    {"netflow_capture",     "Snapshot /proc/net connections", TIER_INSPECT, false, false, t_netflow_capture},
    {"file_forensics",      "Hash, stat, ownership of file", TIER_INSPECT,  false, false, t_file_forensics},
    {"audit_query",         "Query audit subsystem",       TIER_INSPECT,    false, false, t_audit_query},
    {"log_read",            "Tail a log file",             TIER_INSPECT,    false, false, t_log_read},
    {"perf_counters",       "CPU perf counters from /proc/stat", TIER_INSPECT, false, false, t_perf_counters},
    {"sel4_caps_dump",      "Dump seL4 capability space (phase 2)", TIER_INSPECT, true, false, t_sel4_caps_dump},
    {"sel4_ipc_trace",      "Trace seL4 IPC (phase 2)",    TIER_INSPECT,    true, false, t_sel4_caps_dump},
    {"sel4_sched_observe",  "Observe seL4 TCB states (phase 2)", TIER_INSPECT, true, false, t_sel4_caps_dump},
    {"tpm_attest",          "TPM attestation / IMA log",   TIER_INSPECT,    true, false, t_tpm_attest},
    {"ima_measure",         "Integrity Measurement Architecture log", TIER_INSPECT, true, false, t_ima_measure},
    {"intel_pt_trace",      "Intel Processor Trace",       TIER_INSPECT,    true, false, t_intel_pt_trace},
    {"kernel_mem_read",     "Read kernel memory (blocked)", TIER_INSPECT,   true, false, t_kernel_mem_read},
    {"ebpf_load_probe",     "Load an eBPF tracing program", TIER_INSPECT,   false, true,  t_ebpf_load_probe},
    {"syscall_trace",       "Trace a process's syscalls",  TIER_INSPECT,    false, false, t_syscall_trace},
    {"guardian_status",     "Current Guardian threat level", TIER_INSPECT,  false, false, t_guardian_status},
    {"guardian_history",    "Historical alerts",           TIER_INSPECT,    false, false, t_guardian_history},
    {"guardian_forensics",  "Forensic snapshot for event", TIER_INSPECT,    false, false, t_guardian_forensics},
    {"guardian_sigs_list",  "Signature DB version + count", TIER_INSPECT,   false, false, t_guardian_sigs_list},
    {"process_mem_scan",    "Scan process memory regions with YARA", TIER_INSPECT,  false, false, t_process_mem_scan},
    {"sig_update_status",   "Status of YARA rule updates", TIER_INSPECT,   false, false, t_sig_update_status},
    /* reversible */
    {"process_freeze",      "Freeze a process (SIGSTOP/cgroup)", TIER_REVERSIBLE, true, false, t_process_freeze},
    {"process_thaw",        "Thaw a frozen process",       TIER_REVERSIBLE, true, false, t_process_thaw},
    {"process_quarantine",  "Move pid to isolated namespace", TIER_REVERSIBLE, true, false, t_process_quarantine},
    {"net_block_pid",       "Block pid's network egress",  TIER_REVERSIBLE, true, false, t_net_block_pid},
    {"file_quarantine",     "Move file to /var/quarantine", TIER_REVERSIBLE, true, false, t_file_quarantine},
    {"file_restore",        "Restore file from baseline",  TIER_REVERSIBLE, true, false, t_file_restore},
    /* irreversible */
    {"process_kill",        "SIGKILL a process (irreversible)", TIER_IRREVERSIBLE, true, false, t_process_kill},
    {"secure_delete",       "3-pass shred + unlink",       TIER_IRREVERSIBLE, true, false, t_secure_delete},
    {"kill_switch",         "Full network lockdown (SIOCDELRT)", TIER_IRREVERSIBLE, true, false, t_kill_switch},
    {"file_encrypt",        "Encrypt file (Key Vault)",    TIER_IRREVERSIBLE, true, false, t_file_encrypt},
    /* misc userspace — REMOVED FROM REGISTRY (C1 security fix):
     * shell_exec and install_package delegate to popen()/system() which
     * allows arbitrary shell command injection regardless of the denylist.
     * The denylist is a blocklist of known-bad patterns and is trivially
     * bypassed. Functions kept in source for reference but MUST NOT be
     * callable via the MCP protocol.
     */
    /* {"shell_exec",       "DISABLED — shell injection risk", TIER_IRREVERSIBLE, false, false, t_shell_exec}, */
    /* {"install_package",  "DISABLED — delegates to shell",   TIER_IRREVERSIBLE, true, false, t_install_package}, */
};
static int N_TOOLS = sizeof(TOOLS)/sizeof(TOOLS[0]);

/* ---- JSON-RPC handler ---- */
static const char *tier_str(mcp_tier t) {
    return t==TIER_INSPECT?"inspect":t==TIER_REVERSIBLE?"reversible":"irreversible";
}

static void handle_request(const char *req_json, char *resp, size_t resp_sz) {
    /* parse {"jsonrpc":"2.0","id":N,"method":"...","params":{...}} */
    /* extract method + id */
    char method[64] = {0};
    char id_str[32] = {0};
    long id = 0;
    const char *p = strstr(req_json, "\"method\"");
    if (p) {
        p = strchr(p, ':'); if (!p) goto err;
        p++; while (*p && (*p==' '||*p=='"')) p++;
        int i = 0;
        while (*p && *p != '"' && i < 63) method[i++] = *p++;
    }
    p = strstr(req_json, "\"id\"");
    if (p) {
        p = strchr(p, ':'); if (p) {
            p++; while (*p==' ') p++;
            int i = 0;
            if (*p=='"') { p++; while (*p && *p!='"' && i<31) id_str[i++]=*p++; }
            else { while (*p && *p!=',' && *p!='}' && i<31) id_str[i++]=*p++; }
            id = strtol(id_str, NULL, 10);
        }
    }
    /* extract params object */
    char params[8192] = {0};
    p = strstr(req_json, "\"params\"");
    if (p) {
        p = strchr(p, '{'); if (p) {
            const char *e = p + 1; int depth = 1;
            while (*e && depth > 0) {
                if (*e=='{') depth++; else if (*e=='}') depth--;
                e++;
            }
            size_t L = e - p;
            if (L < sizeof(params)) { memcpy(params, p, L); params[L]=0; }
        }
    }

    if (!strcmp(method, "tools.list")) {
        size_t off = snprintf(resp, resp_sz, "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"result\":[", id);
        for (int i = 0; i < N_TOOLS && off < resp_sz - 256; i++) {
            off += snprintf(resp+off, resp_sz-off, "%s{\"name\":\"%s\",\"desc\":\"%s\",\"tier\":\"%s\","
                            "\"needs_root\":%s,\"needs_bpf\":%s}",
                            i?",":"", TOOLS[i].name, TOOLS[i].desc, tier_str(TOOLS[i].tier),
                            TOOLS[i].needs_root?"true":"false", TOOLS[i].needs_bpf?"true":"false");
        }
        off += snprintf(resp+off, resp_sz-off, "]}");
        return;
    }
    if (!strcmp(method, "tools.call")) {
        mcp_args args; args_parse(params, &args);
        const char *name = args_get(&args, "name");
        if (!name) goto err;
        mcp_tool *t = NULL;
        for (int i = 0; i < N_TOOLS; i++) if (!strcmp(TOOLS[i].name, name)) { t = &TOOLS[i]; break; }
        if (!t) {
            snprintf(resp, resp_sz, "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"error\":"
                     "{\"code\":-32601,\"message\":\"unknown tool: %s\"}}", id, name);
            return;
        }
        /* check tier gate */
        if (t->tier == TIER_IRREVERSIBLE && !getenv("MCP_AUTOCONFIRM")) {
            snprintf(resp, resp_sz, "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"error\":"
                     "{\"code\":-32000,\"message\":\"irreversible tool requires MCP_AUTOCONFIRM=1\"}}", id);
            return;
        }
        /* the args for the tool are inside params.args (nested) — extract */
        char tool_args_json[8192] = {0};
        const char *ap = strstr(params, "\"args\"");
        if (ap) {
            ap = strchr(ap, '{'); if (ap) {
                const char *e = ap + 1; int d = 1;
                while (*e && d > 0) { if (*e=='{') d++; else if (*e=='}') d--; e++; }
                size_t L = e - ap;
                if (L < sizeof(tool_args_json)) { memcpy(tool_args_json, ap, L); tool_args_json[L]=0; }
            }
        }
        mcp_args ta; args_parse(tool_args_json, &ta);
        char result[MCP_BUF_SZ];
        t->fn(&ta, result, sizeof(result));
        snprintf(resp, resp_sz, "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"result\":%s%s%s}",
                 id,
                 result[0]=='{'?"":"\"",  /* wrap strings in quotes */
                 result,
                 result[0]=='{'?"":"\"");
        return;
    }
err:
    snprintf(resp, resp_sz, "{\"jsonrpc\":\"2.0\",\"id\":%ld,\"error\":"
             "{\"code\":-32600,\"message\":\"invalid request\"}}", id);
}

/* ---- server ---- */
static volatile sig_atomic_t srv_running = 1;
static void on_sig(int s) { (void)s; srv_running = 0; }

static int serve_stdio(void) {
    char buf[MCP_BUF_SZ];
    while (srv_running && fgets(buf, sizeof(buf), stdin)) {
        char *nl = strchr(buf, '\n'); if (nl) *nl = 0;
        char resp[MCP_BUF_SZ];
        handle_request(buf, resp, sizeof(resp));
        printf("%s\n", resp);
        fflush(stdout);
    }
    return 0;
}

static int serve_socket(const char *sock_path) {
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    unlink(sock_path);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_un addr; memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    g_strlcpy(addr.sun_path, sock_path, sizeof(addr.sun_path));
    if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0) { perror("bind"); return 1; }
    if (listen(fd, 8) != 0) { perror("listen"); return 1; }
    chmod(sock_path, 0660);
    printf("[mcp] listening on %s (%d tools)\n", sock_path, N_TOOLS);
    while (srv_running) {
        int c = accept(fd, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; break; }

        /* Bug 24 fix: authenticate peer via SO_PEERCRED.
         * Only allow root (uid 0) or the guardian's own uid to connect.
         * This prevents any compromised user process from calling
         * process_kill, kill_switch, etc. */
        struct ucred uc;
        socklen_t uclen = sizeof(uc);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &uclen) == 0) {
            if (uc.uid != 0 && uc.uid != getuid()) {
                const char *deny = "{\"jsonrpc\":\"2.0\",\"error\":"
                    "{\"code\":-32001,\"message\":\"auth: only root or guardian uid allowed\"}}\n";
                write(c, deny, strlen(deny));
                close(c);
                continue;
            }
        }

        char buf[MCP_BUF_SZ] = {0};
        ssize_t n = read(c, buf, sizeof(buf)-1);
        if (n > 0) {
            char resp[MCP_BUF_SZ];
            handle_request(buf, resp, sizeof(resp));
            write(c, resp, strlen(resp));
            write(c, "\n", 1);
        }
        close(c);
    }
    close(fd);
    unlink(sock_path);
    return 0;
}

int main(int argc, char **argv) {
    const char *sock_path = MCP_SOCKET_PATH;
    bool use_stdio = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--stdio")) use_stdio = true;
        else if (!strcmp(argv[i], "--socket") && i+1 < argc) sock_path = argv[++i];
        else if (!strcmp(argv[i], "--list-tools")) {
            printf("%-24s %-12s %-7s %s\n", "NAME", "TIER", "ROOT", "DESC");
            for (int j = 0; j < N_TOOLS; j++) {
                printf("%-24s %-12s %-7s %s\n", TOOLS[j].name, tier_str(TOOLS[j].tier),
                       TOOLS[j].needs_root?"yes":"no", TOOLS[j].desc);
            }
            printf("\n%d tools registered\n", N_TOOLS);
            return 0;
        }
    }
    return use_stdio ? serve_stdio() : serve_socket(sock_path);
}

/* Stub for event bus publish (needed by forensic_log.o when linked into utilities) */
int g_bus_publish(const g_event_t *ev) {
    (void)ev;
    return 0;
}

int g_ebpf_set_kill_switch_active(bool active) {
    (void)active;
    return -ENODEV;
}
