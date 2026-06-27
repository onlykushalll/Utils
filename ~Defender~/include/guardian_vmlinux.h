/* guardian_vmlinux.h — minimal type definitions for Guardian BPF programs.
 *
 * On the WLTIOS TARGET, replace this with a full vmlinux.h generated via:
 *     bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
 * (BTF is kernel-version-specific, so generation happens on the target.)
 *
 * In this dev sandbox we define just enough to compile BPF programs:
 *   - fundamental types (__u8..__u64, __s8..__s64)
 *   - the tracepoint sys_enter context struct
 *   - bool / common macros
 */
#ifndef GUARDIAN_VMLINUX_H
#define GUARDIAN_VMLINUX_H
#define GUARDIAN_MINIMAL_VMLINUX 1

/* ---- fundamental integer types (x86_64 uapi) ---- */
typedef unsigned char       __u8;
typedef unsigned short      __u16;
typedef unsigned int        __u32;
typedef unsigned long       __u64;
typedef signed char         __s8;
typedef short               __s16;
typedef int                 __s32;
typedef long                __s64;

typedef __u8  u8;
typedef __u16 u16;
typedef __u32 u32;
typedef __u64 u64;
typedef __s8  s8;
typedef __s16 s16;
typedef __s32 s32;
typedef __s64 s64;

typedef __u64 __le64;
typedef __u32 __le32;
typedef __u16 __le16;
typedef __u64 __be64;
typedef __u32 __be32;
typedef __u16 __be16;

/* kernel checksum types (referenced by bpf_helper_defs.h) */
typedef __u32 __wsum;
typedef __u16 __sum16;

/* forward declarations of kernel structs used (by pointer) in helper sigs */
struct __sk_buff;
struct bpf_perf_event_data;
struct bpf_perf_event_value;
struct bpf_cgroup_storage;
struct bpf_cgroup_storage_key;
struct pt_regs;
struct bpf_sock;
struct bpf_sock_addr;
struct bpf_sock_ops;
struct sk_msg_md;
struct xdp_md;
struct bpf_perf_event;
struct bpf_map;
struct bpf_timer;

#ifndef bool
typedef _Bool bool;
#endif
#define true 1
#define false 0

/* ---- tracepoint context for sys_enter_* (from /sys/kernel/debug/tracing) ----
 * The tracepoint args for syscalls/sys_enter_execve etc. expose:
 *   args[0..5] = the 6 syscall arguments.
 */
struct trace_event_raw_sys_enter {
    __u64 unused;     /* tracepoint common fields (skipped) */
    __u64 args[6];
};

/* ---- minimal task_struct fields used by BPF_CORE_READ (would be in full vmlinux.h) ---- */
struct task_struct {
    __u32 pid;
    __u32 tgid;
    struct task_struct *real_parent;
};

/* ---- BPF map types (subset; from linux/bpf.h enum bpf_map_type) ----
 * Defined here so BPF programs don't need to include <linux/bpf.h> (which
 * drags in the fragile asm/types.h multiarch chain). On target with a full
 * vmlinux.h these come for free. */
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC  = 0,
    BPF_MAP_TYPE_HASH    = 1,
    BPF_MAP_TYPE_ARRAY   = 2,
    BPF_MAP_TYPE_PERCPU_HASH = 5,
    BPF_MAP_TYPE_PERCPU_ARRAY = 6,
    BPF_MAP_TYPE_LRU_HASH = 9,
    BPF_MAP_TYPE_RINGBUF = 27,
};

/* ---- BPF map update flags (from uapi/linux/bpf.h) ---- */
#define BPF_ANY     0
#define BPF_NOEXIST 1
#define BPF_EXIST   2

/* ---- signal numbers (from uapi/asm-generic/signal.h) ---- */
#define SIGHUP     1
#define SIGINT     2
#define SIGQUIT    3
#define SIGKILL    9
#define SIGSTOP    19
#define SIGTERM    15

/* ---- socket families / types (from uapi/linux/socket.h) ---- */
#define AF_INET    2
#define AF_INET6   10
#define AF_PACKET  17
#define SOCK_STREAM 1
#define SOCK_DGRAM  2
#define SOCK_RAW    3

/* ---- clone flags (from uapi/linux/sched.h) ---- */
#define CLONE_NEWUSER  0x10000000
#define CLONE_NEWNET   0x40000000
#define CLONE_NEWNS    0x00020000
#define CLONE_NEWPID   0x20000000

#endif /* GUARDIAN_VMLINUX_H */
