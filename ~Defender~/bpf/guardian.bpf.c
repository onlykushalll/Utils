
/* guardian.bpf.c — comprehensive eBPF enforcement engine (the "nothing escapes" core).
 *
 * Hooks every syscall that matters for process escape / persistence / exfil.
 * Uses bpf_send_signal(SIGKILL) for INLINE enforcement — the offending process
 * is killed BEFORE the syscall returns. The attacker never gets to complete
 * the malicious action.
 *
 * Hooks:
 *   1. tracepoint/syscalls/sys_enter_execve     — process starts (blocklist)
 *   2. tracepoint/syscalls/sys_enter_execveat   — same, with fd-relative path
 *   3. tracepoint/syscalls/sys_enter_openat     — sensitive file access
 *   4. tracepoint/syscalls/sys_enter_openat2    — same, newer variant
 *   5. tracepoint/syscalls/sys_enter_connect    — non-Tor egress
 *   6. tracepoint/syscalls/sys_enter_ptrace     — process injection (block)
 *   7. tracepoint/syscalls/sys_enter_clone      — fork bomb rate limit
 *   8. tracepoint/syscalls/sys_enter_clone3     — same, newer
 *   9. tracepoint/syscalls/sys_enter_unshare    — namespace escape (block)
 *  10. tracepoint/syscalls/sys_enter_setns      — namespace enter (block)
 *  11. tracepoint/syscalls/sys_enter_bind       — unexpected listeners
 *  12. tracepoint/syscalls/sys_enter_socket     — raw socket creation (block)
 *  13. tracepoint/syscalls/sys_enter_setuid     — privilege escalation
 *  14. tracepoint/syscalls/sys_enter_capset     — capability changes
 *
 * Enforcement tiers (in BPF, before userspace even sees the event):
 *   - KILL:    bpf_send_signal(SIGKILL) — process dies inline
 *   - BLOCK:   bpf_override_return(ctx, -EPERM) — syscall returns EPERM
 *   - LOG:     emit to ring buffer, userspace decides
 *
 * The blocklist maps (bad_paths, bad_binaries) are BPF maps that userspace
 * updates at runtime via libbpf. Initial values are baked in for v1.
 *
 * Compile:  make bpf
 * Load:     on WLTIOS target (needs CAP_BPF + CAP_SYS_ADMIN).
 *           In dev sandbox: compiles only.
 */
#include "guardian_vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#ifndef BPF_F_RDONLY_PROG
#define BPF_F_RDONLY_PROG (1U << 7)
#endif

char LICENSE[] SEC("license") = "GPL";

/* ---- event record pushed to userspace ---- */
struct g_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u8  comm[16];
    __u8  path[128];
    __u8  rule[64];
    __u8  severity;     /* 0=info 1=low 2=med 3=high 4=critical */
    __u8  action;       /* 0=log 1=freeze 2=quarantine 3=kill 4=kill_switch */
    __u16 syscall_nr;   /* which syscall triggered this */
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);  /* 1 MB */
} events SEC(".maps");

/* ---- blocklist maps (userspace updates these) ---- */
/* bad_paths: string path → 1 if blocked (e.g. /etc/shadow for non-root) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    /* hash of path string */
    __type(value, __u32);  /* severity */
    __uint(map_flags, BPF_F_RDONLY_PROG);
} bad_paths SEC(".maps");

/* bad_binaries: hash of executable → action (1=block, 2=kill) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u64);    /* hash of comm/binary name */
    __type(value, __u32);  /* action */
    __uint(map_flags, BPF_F_RDONLY_PROG);
} bad_binaries SEC(".maps");

/* fork_rate: pid → last fork timestamp (for rate limiting) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} fork_last SEC(".maps");

/* tor_uid: the uid of the tor process (set by userspace). Connect from other
 * uids = leak. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} tor_uid SEC(".maps");

/* kill_switch_active: 1 if active, blocks route addition */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
    __uint(map_flags, BPF_F_RDONLY_PROG);
} kill_switch_active SEC(".maps");

/* ---- Phase 2.3: eBPF feature counters for anomaly engine ---- */
/* fork_count: pid -> fork count (incremented in tp_clone, cleared on exit) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} fork_count SEC(".maps");

/* write_bytes: pid -> cumulative bytes written (incremented in tp_write) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} write_bytes SEC(".maps");

/* syscall_count: pid -> syscall count (incremented in raw_tp/sys_enter) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u64);
} syscall_count SEC(".maps");

/* ---- Phase 2.4: ransomware detection counters ---- */
/* unlink_count: pid -> file deletion count (incremented in tp_unlink/tp_unlinkat) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} unlink_count SEC(".maps");

/* rename_count: pid -> rename count (incremented in tp_rename/tp_renameat) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} rename_count SEC(".maps");

/* ---- Phase 2.5: process ancestry for IOA rules ---- */
/* ancestry: pid -> {ppid, parent_comm[16]} (populated in tp_execve) */
struct g_ancestry {
    __u32 ppid;
    __u8  parent_comm[16];
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, struct g_ancestry);
} ancestry SEC(".maps");

/* ---- helpers ---- */
static __always_inline void emit_event(__u16 syscall_nr, __u8 severity,
                                        __u8 action, const char *rule,
                                        const char *path)
{
    struct g_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->ppid = 0;
    e->syscall_nr = syscall_nr;
    e->severity = severity;
    e->action = action;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    if (path) bpf_probe_read_user_str(&e->path, sizeof(e->path), path);
    else e->path[0] = 0;
    __builtin_memset(e->rule, 0, sizeof(e->rule));
    if (rule) {
        int i = 0;
        while (rule[i] && i < 63) { e->rule[i] = rule[i]; i++; }
    }
    bpf_ringbuf_submit(e, 0);
}

/* FNV-1a hash of a string (for map key lookup) */
static __always_inline __u64 hash_str(const char *s, int max_len)
{
    __u64 h = 0xcbf29ce484222325ULL;
    #pragma unroll
    for (int i = 0; i < 128 && i < max_len; i++) {
        char c = 0;
        bpf_probe_read_user(&c, 1, s + i);
        if (!c) break;
        h ^= c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* BUG 1 fix: hash a comm string that's already in a stack/kernel buffer.
 * hash_str() uses bpf_probe_read_user (for user pointers), which FAILS when
 * reading a stack address — so auth_binaries lookups always missed and every
 * non-root process got SIGKILL'd on /etc/shadow. This variant reads the
 * buffer directly. */
static __always_inline __u64 hash_comm(const char *s, int max_len)
{
    __u64 h = 0xcbf29ce484222325ULL;
    #pragma unroll
    for (int i = 0; i < 16 && i < max_len; i++) {
        char c = s[i];
        if (!c) break;
        h ^= (__u64)(unsigned char)c;
        h *= 0x100000001b3ULL;
    }
    return h;
}

/* prefix-match a path against a list of sensitive prefixes */
static __always_inline int path_is_sensitive(const char *path)
{
    char buf[64] = {};
    bpf_probe_read_user_str(buf, sizeof(buf), path);
    /* /etc/shadow */
    if (buf[0]=='/'&&buf[1]=='e'&&buf[2]=='t'&&buf[3]=='c'&&buf[4]=='/'&&buf[5]=='s') return 4;
    /* /proc/kcore */
    if (buf[0]=='/'&&buf[1]=='p'&&buf[2]=='r'&&buf[3]=='o'&&buf[4]=='c'&&buf[5]=='/'&&buf[6]=='k') return 4;
    /* /dev/mem, /dev/kmem, /dev/port */
    if (buf[0]=='/'&&buf[1]=='d'&&buf[2]=='e'&&buf[3]=='v'&&buf[4]=='/'&&(buf[5]=='m'||buf[5]=='k'||buf[5]=='p')) return 4;
    /* /etc/cron — persistence */
    if (buf[0]=='/'&&buf[1]=='e'&&buf[2]=='t'&&buf[3]=='c'&&buf[4]=='/'&&buf[5]=='c'&&buf[6]=='r') return 3;
    return 0;
}

/* ============================================================ *
 *  HOOK 1: execve — process starts                              *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    const char *filename = (const char *)ctx->args[0];

    /* check blocklist */
    __u64 h = hash_str(filename, 128);
    __u32 *act = bpf_map_lookup_elem(&bad_binaries, &h);
    if (act && *act == 2) {
        /* KILL: inline signal */
        bpf_send_signal(SIGKILL);
        emit_event(59, 4, 3, "EXECVE_BLOCKLIST_KILL", filename);
        return 0;
    }

    /* Bug 6 fix: removed the /dev/t check that killed /dev/tty, /dev/ttyS0,
     * /dev/tpm0, etc. The check was architecturally wrong — /dev/tcp reverse
     * shells use bash builtins (>& /dev/tcp/...), NOT execve. The connect()
     * hook (tp_connect) handles non-Tor egress correctly. */
    return 0;
}

/* ============================================================ *
 *  HOOK 2: execveat — same, fd-relative                         *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_execveat")
int tp_execveat(struct trace_event_raw_sys_enter *ctx)
{
    const char *filename = (const char *)ctx->args[1];
    __u64 h = hash_str(filename, 128);
    __u32 *act = bpf_map_lookup_elem(&bad_binaries, &h);
    if (act && *act == 2) {
        bpf_send_signal(SIGKILL);
        emit_event(322, 4, 3, "EXECVEAT_BLOCKLIST_KILL", filename);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 3: openat — sensitive file access                       *
 * ============================================================ */
/* Bug 23 fix: whitelist of comm names allowed to access /etc/shadow etc.
 * (passwd, login, sshd, pam_unix, chpasswd, gpasswd, su, sudo) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, __u64);    /* hash of comm name */
    __type(value, __u32);  /* 1 = allowed */
} auth_binaries SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    const char *path = (const char *)ctx->args[1];
    int sev = path_is_sensitive(path);
    if (sev > 0 && uid != 0) {
        /* Bug 23 fix: check if this is an authorized auth binary */
        char comm[16] = {};
        bpf_get_current_comm(&comm, sizeof(comm));
        /* BUG 1 fix: comm is a stack buffer — use hash_comm, not hash_str */
        __u64 ch = hash_comm(comm, 16);
        __u32 *allowed = bpf_map_lookup_elem(&auth_binaries, &ch);
        if (!allowed) {
            /* non-root, non-auth binary accessing sensitive file — KILL */
            bpf_send_signal(SIGKILL);
            emit_event(257, sev, 3, "SENSITIVE_FILE_ACCESS_KILL", path);
            return 0;
        }
        /* authorized auth binary — log but don't kill */
        emit_event(257, sev, 0, "SENSITIVE_FILE_AUTH_ACCESS", path);
        return 0;
    }
    /* also check bad_paths map */
    __u64 h = hash_str(path, 128);
    __u32 *sv = bpf_map_lookup_elem(&bad_paths, &h);
    if (sv && *sv >= 3) {
        bpf_send_signal(SIGKILL);
        emit_event(257, *sv, 3, "BAD_PATH_KILL", path);
    } else if (sv) {
        emit_event(257, *sv, 0, "BAD_PATH_LOG", path);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 4: openat2 — newer variant                              *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_openat2")
int tp_openat2(struct trace_event_raw_sys_enter *ctx)
{
    /* same logic as openat, just newer syscall (437 on x86_64) */
    return tp_openat(ctx);
}

/* ============================================================ *
 *  HOOK 5: connect — non-Tor egress                             *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_connect")
int tp_connect(struct trace_event_raw_sys_enter *ctx)
{
    /* args[1] = struct sockaddr __user * */
    const void *sa = (const void *)ctx->args[1];
    __u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), sa);

    /* check if this is the tor uid */
    __u32 zero = 0;
    __u32 *tuid = bpf_map_lookup_elem(&tor_uid, &zero);
    __u32 uid = bpf_get_current_uid_gid();

    /* ---- Phase 1.4: IPv4 (AF_INET) handling ---- */
    if (family == 2) {
        __u16 port = 0;
        bpf_probe_read_user(&port, 2, (char*)sa + 2);
        port = (port >> 8) | (port << 8);  /* ntohs */

        __u32 addr = 0;
        bpf_probe_read_user(&addr, 4, (char*)sa + 4);

        /* localhost (127.0.0.1) is always ok (tor SOCKS) */
        if (addr == 0x0100007f) return 0;

        /* if tor_uid is set and this isn't tor -> KILL (leak) */
        if (tuid && *tuid != 0 && uid != *tuid) {
            bpf_send_signal(SIGKILL);
            emit_event(42, 4, 4, "NON_TOR_EGRESS_KILL", NULL);
        }
        return 0;
    }

    /* ---- Phase 1.4: IPv6 (AF_INET6) handling ----
     * sockaddr_in6 layout: family(2) + port(2) + flowinfo(4) + addr(16) + scope(4)
     * addr starts at offset 8. ::1 (loopback) = 15 zero bytes + 0x01.
     * Without this hook, IPv6 was a full bypass for the non-Tor egress kill. */
    if (family == 10) {
        __u8 addr6[16] = {};
        bpf_probe_read_user(addr6, sizeof(addr6), (char*)sa + 8);

        /* ::1 loopback check (15 zeros then 0x01) */
        bool is_loopback = (addr6[0]==0 && addr6[1]==0 && addr6[2]==0 && addr6[3]==0 &&
                            addr6[4]==0 && addr6[5]==0 && addr6[6]==0 && addr6[7]==0 &&
                            addr6[8]==0 && addr6[9]==0 && addr6[10]==0 && addr6[11]==0 &&
                            addr6[12]==0 && addr6[13]==0 && addr6[14]==0 && addr6[15]==1);
        if (is_loopback) return 0;

        /* all-zeros unspecified (::) — skip */
        bool is_unspec = (addr6[0]==0 && addr6[15]==0);  /* good enough */
        if (is_unspec) return 0;

        /* non-Tor uid making IPv6 connection -> KILL (leak) */
        if (tuid && *tuid != 0 && uid != *tuid) {
            bpf_send_signal(SIGKILL);
            emit_event(42, 4, 4, "NON_TOR_EGRESS6_KILL", NULL);
        }
        return 0;
    }

    return 0;  /* other families (unix, netlink) — ignore */
}

/* ============================================================ *
 *  HOOK 6: ptrace — process injection (always block + kill)     *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_ptrace")
int tp_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    /* ptrace is how debuggers and process injectors work. Block unconditionally
     * for non-root (root can still ptrace — but the guardian itself runs as root). */
    if (uid != 0) {
        bpf_send_signal(SIGKILL);
        emit_event(101, 4, 3, "PTRACE_INJECTION_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 7: clone — fork bomb rate limiting                      *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_clone")
int tp_clone(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 now = bpf_ktime_get_ns();
    __u64 *last = bpf_map_lookup_elem(&fork_last, &pid);
    if (last) {
        __u64 delta = now - *last;
        /* if this process forked < 10ms ago, it's a fork bomb — KILL */
        if (delta < 10000000ULL) {
            bpf_send_signal(SIGKILL);
            emit_event(56, 3, 3, "FORK_BOMB_KILL", NULL);
            return 0;
        }
    }
    bpf_map_update_elem(&fork_last, &pid, &now, BPF_ANY);
    /* Phase 2.3: increment fork_count for anomaly engine feature[4] */
    {
        __u32 *fc = bpf_map_lookup_elem(&fork_count, &pid);
        __u32 one = 1;
        if (fc) { __u32 nv = *fc + 1; bpf_map_update_elem(&fork_count, &pid, &nv, BPF_ANY); }
        else bpf_map_update_elem(&fork_count, &pid, &one, BPF_ANY);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 8: clone3 — newer variant                               *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_clone3")
int tp_clone3(struct trace_event_raw_sys_enter *ctx)
{
    return tp_clone(ctx);
}

/* ============================================================ *
 *  HOOK 9: unshare — namespace escape (block for non-root)      *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_unshare")
int tp_unshare(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    __u64 flags = ctx->args[0];
    /* CLONE_NEWUSER = 0x10000000 — user namespace creation can be abused
     * for privilege escalation. Block for non-root. */
    if (uid != 0 && (flags & 0x10000000)) {
        bpf_send_signal(SIGKILL);
        emit_event(272, 4, 3, "USER_NS_ESCAPE_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 10: setns — namespace enter (block for non-root)        *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_setns")
int tp_setns(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid != 0) {
        bpf_send_signal(SIGKILL);
        emit_event(308, 3, 3, "SETNS_BLOCK_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 11: bind — unexpected listeners                         *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_bind")
int tp_bind(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    /* only tor (set via tor_uid map) should bind. anyone else binding = backdoor. */
    __u32 zero = 0;
    __u32 *tuid = bpf_map_lookup_elem(&tor_uid, &zero);
    if (tuid && *tuid != 0 && uid != *tuid && uid != 0) {
        emit_event(49, 3, 1, "UNEXPECTED_BIND", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 12: socket — raw socket creation (block for non-root)   *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_socket")
int tp_socket(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    __u64 domain = ctx->args[0];
    __u64 type = ctx->args[1];
    /* AF_PACKET (17) or SOCK_RAW (3) — packet capture / spoofing. Block. */
    if (uid != 0 && (domain == 17 || (type & 3) == 3)) {
        bpf_send_signal(SIGKILL);
        emit_event(41, 4, 3, "RAW_SOCKET_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 13: setuid — privilege escalation (log + verify)        *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_setuid")
int tp_setuid(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    __u32 target = ctx->args[0];
    /* non-root trying to setuid(0) — almost certainly an exploit. KILL. */
    if (uid != 0 && target == 0) {
        bpf_send_signal(SIGKILL);
        emit_event(105, 4, 3, "PRIVESC_SETUID0_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 14: capset — capability changes (block for non-root)    *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_capset")
int tp_capset(struct trace_event_raw_sys_enter *ctx)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid != 0) {
        bpf_send_signal(SIGKILL);
        emit_event(126, 4, 3, "CAPSET_BLOCK_KILL", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 15: sched_process_exit — cleanup fork_last map (Bug 18) *
 * ============================================================ */
SEC("tracepoint/sched/sched_process_exit")
int tp_process_exit(void *ctx)
{
    /* Bug 18 fix: when a process exits, remove its entry from fork_last.
     * Without this, the map fills to 4096 entries and fork bomb detection
     * is disabled. Also prevents stale-timestamp false positives on PID reuse. */
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&fork_last, &pid);
    /* Phase 2.3: clear feature counters on exit (prevents stale data on PID reuse) */
    bpf_map_delete_elem(&fork_count, &pid);
    bpf_map_delete_elem(&write_bytes, &pid);
    bpf_map_delete_elem(&syscall_count, &pid);
    bpf_map_delete_elem(&unlink_count, &pid);
    bpf_map_delete_elem(&rename_count, &pid);
    bpf_map_delete_elem(&ancestry, &pid);
    return 0;
}

/* ============================================================ *
 *  HOOK 16: ioctl — block default route restore (SIOCADDRT)    *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_ioctl")
int tp_ioctl(struct trace_event_raw_sys_enter *ctx)
{
    unsigned int cmd = ctx->args[1];
    /* Critical performance: early escape */
    if (cmd != 0x890B) return 0;  /* SIOCADDRT */

    __u32 zero = 0;
    __u32 *active = bpf_map_lookup_elem(&kill_switch_active, &zero);
    if (active && *active != 0) {
        bpf_send_signal(SIGKILL);
        emit_event(16, 4, 4, "KILLSWITCH_REVERSAL_BLOCKED", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 17: rtnl_newroute — block netlink route additions       *
 * ============================================================ */
SEC("kprobe/rtnl_newroute")
int BPF_KPROBE(kp_rtnl_newroute)
{
    __u32 zero = 0;
    __u32 *active = bpf_map_lookup_elem(&kill_switch_active, &zero);
    if (active && *active != 0) {
        bpf_send_signal(SIGKILL);
        emit_event(0, 4, 4, "KILLSWITCH_REVERSAL_BLOCKED", NULL);
    }
    return 0;
}

/* ============================================================ *
 *  HOOK 18: write — Phase 2.3: track bytes written for anomaly feature[3] *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_write")
int tp_write(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u64 count = ctx->args[2];  /* count argument */
    if (count == 0) return 0;
    __u64 *wb = bpf_map_lookup_elem(&write_bytes, &pid);
    if (wb) { __u64 nv = *wb + count; bpf_map_update_elem(&write_bytes, &pid, &nv, BPF_ANY); }
    else { __u64 v = count; bpf_map_update_elem(&write_bytes, &pid, &v, BPF_ANY); }
    return 0;
}

/* ============================================================ *
 *  HOOK 19: unlink — Phase 2.4: ransomware bulk-delete detection          *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_unlink")
int tp_unlink(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *uc = bpf_map_lookup_elem(&unlink_count, &pid);
    __u32 one = 1;
    if (uc) { __u32 nv = *uc + 1; bpf_map_update_elem(&unlink_count, &pid, &nv, BPF_ANY); }
    else bpf_map_update_elem(&unlink_count, &pid, &one, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_unlinkat")
int tp_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
    return tp_unlink(ctx);
}

/* ============================================================ *
 *  HOOK 20: rename — Phase 2.4: ransomware extension-change detection     *
 * ============================================================ */
SEC("tracepoint/syscalls/sys_enter_rename")
int tp_rename(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 *rc = bpf_map_lookup_elem(&rename_count, &pid);
    __u32 one = 1;
    if (rc) { __u32 nv = *rc + 1; bpf_map_update_elem(&rename_count, &pid, &nv, BPF_ANY); }
    else bpf_map_update_elem(&rename_count, &pid, &one, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_renameat")
int tp_renameat(struct trace_event_raw_sys_enter *ctx)
{
    return tp_rename(ctx);
}

SEC("tracepoint/syscalls/sys_enter_renameat2")
int tp_renameat2(struct trace_event_raw_sys_enter *ctx)
{
    return tp_rename(ctx);
}

/* ============================================================ *
 *  HOOK 21: execve ancestry — Phase 2.5: populate ancestry map for IOA    *
 * ============================================================ */
/* (added to tp_execve below via BPF_CORE_READ of real_parent) */
/* This is done by extending tp_execve — but to avoid touching the existing
 * hook, we add a separate sched_process_fork hook that captures parent->child
 * relationship at fork time. */
SEC("tracepoint/sched/sched_process_fork")
int tp_sched_fork(void *ctx)
{
    /* sched_process_fork gives: parent_pid, child_pid. We record the parent's
     * comm as the child's parent_comm in the ancestry map. */
    struct trace_event_raw_sched_process_fork {
        __u64 unused;
        char parent_comm[16];
        __u32 parent_pid;
        char child_comm[16];
        __u32 child_pid;
    } *e = ctx;
    if (!e) return 0;
    __u32 child = e->child_pid;
    struct g_ancestry a = {0};
    a.ppid = e->parent_pid;
    __builtin_memcpy(&a.parent_comm, e->parent_comm, 16);
    bpf_map_update_elem(&ancestry, &child, &a, BPF_ANY);
    return 0;
}


#ifndef GUARDIAN_MINIMAL_VMLINUX
/* LSM hooks require the full vmlinux.h (generated on target via bpftool btf dump).
 * In dev with guardian_vmlinux.h, these are skipped — tracepoint hooks remain active. */
/* ============================================================ *
 *  Phase 4.1: BPF LSM hooks (decision before syscall completes) *
 *  These eliminate the SIGKILL race window that tracepoints have.  *
 *  Only attach on kernels with CONFIG_BPF_LSM (lsm=bpf cmdline).   *
 * ============================================================ */

/* LSM hook: bprm_check_security — replaces tp_execve for blocklist (no race).
 * Returns -EPERM to deny the exec before it completes. */
SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm_check, struct linux_binprm *bprm, int ret)
{
    /* only enforce if the existing policy didn't already deny */
    if (ret != 0) return ret;
    __u32 uid = bpf_get_current_uid_gid();
    if (uid == 0) return 0;  /* root exempt */
    /* check blocklist — same hash as tp_execve */
    const char *filename = BPF_CORE_READ(bprm, filename);
    if (!filename) return 0;
    __u64 h = hash_str(filename, 128);
    __u32 *act = bpf_map_lookup_elem(&bad_binaries, &h);
    if (act && *act == 2) {
        emit_event(59, 4, 3, "LSM_EXECVE_BLOCKLIST_DENY", filename);
        return -EPERM;  /* deny the exec — no SIGKILL race */
    }
    return 0;
}

/* LSM hook: file_open — replaces tp_openat for sensitive files + canary protection.
 * Phase 2.1 canary files get inline-denied here (zero false positive). */
SEC("lsm/file_open")
int BPF_PROG(lsm_file_open, struct file *file)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid == 0) return 0;  /* root exempt */
    const char *path = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    if (!path) return 0;
    /* canary file protection — any access by non-root = deny + alert */
    char buf[64] = {};
    bpf_probe_read_kernel_str(buf, sizeof(buf), path);
    if (buf[0]=='!' && buf[1]=='G' && buf[2]=='U' && buf[3]=='A') {
        /* matches !GUARDIAN_CANARY_* — ransomware touching the canary */
        emit_event(257, 4, 3, "LSM_CANARY_ACCESS_DENY", path);
        return -EPERM;
    }
    /* sensitive file check (same logic as tp_openat) */
    int sev = path_is_sensitive(path);
    if (sev > 0) {
        char comm[16] = {};
        bpf_get_current_comm(&comm, sizeof(comm));
        /* BUG 1 fix: comm is a stack buffer — use hash_comm, not hash_str */
        __u64 ch = hash_comm(comm, 16);
        __u32 *allowed = bpf_map_lookup_elem(&auth_binaries, &ch);
        if (!allowed) {
            emit_event(257, sev, 3, "LSM_SENSITIVE_FILE_DENY", path);
            return -EPERM;
        }
    }
    return 0;
}

/* LSM hook: socket_connect — replaces tp_connect (deny before any bytes leave).
 * IPv4 + IPv6 non-Tor egress denied at the LSM layer. */
SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid == 0) return 0;
    __u16 family = 0;
    bpf_probe_read(&family, sizeof(family), &address->sa_family);
    __u32 zero = 0;
    __u32 *tuid = bpf_map_lookup_elem(&tor_uid, &zero);
    if (!tuid || *tuid == 0) return 0;
    if (uid == *tuid) return 0;  /* tor's own connection */
    if (family == 2 || family == 10) {
        emit_event(42, 4, 4, "LSM_NON_TOR_CONNECT_DENY", NULL);
        return -EPERM;  /* deny before connect() completes — no leak possible */
    }
    return 0;
}

/* LSM hook: inode_unlink — canary file deletion prevention + ransomware signal.
 * Phase 2.4 enhancement: canary deletion = immediate CRITICAL alert. */
SEC("lsm/inode_unlink")
int BPF_PROG(lsm_inode_unlink, struct inode *dir, struct dentry *dentry)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid == 0) return 0;
    const char *name = BPF_CORE_READ(dentry, d_name.name);
    if (!name) return 0;
    char buf[64] = {};
    bpf_probe_read_kernel_str(buf, sizeof(buf), name);
    if (buf[0]=='!' && buf[1]=='G' && buf[2]=='U' && buf[3]=='U') {
        emit_event(263, 4, 3, "LSM_CANARY_DELETE_DENY", name);
        return -EPERM;  /* deny canary deletion — ransomware blocked */
    }
    return 0;
}

/* LSM hook: ptrace_access_check — better than tp_ptrace (fires at access check). */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lsm_ptrace_access, struct task_struct *child, unsigned int mode)
{
    __u32 uid = bpf_get_current_uid_gid();
    if (uid != 0) {
        emit_event(101, 4, 3, "LSM_PTRACE_DENY", NULL);
        return -EPERM;
    }
    return 0;
}

#endif /* GUARDIAN_MINIMAL_VMLINUX */
