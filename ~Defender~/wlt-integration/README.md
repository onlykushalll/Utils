# WLTIOS Guardian Integration — Handoff Document

**Phase 3 of the Guardian roadmap.** This folder contains guardian-side
artifacts and precise patches for the WLTIOS tree so Guardian runs as a
first-class WLTIOS component (PID 3, after the watchdog at PID 2).

The WLTIOS source files themselves live in a sibling repo and are NOT edited
here — this document gives the exact diffs to apply there.

---

## 3.1 Boot order (wlt-init)

**File:** `WLTIOS/src/userspace/wlt-init/init-minimal.c`

Boot order MUST be:

```
PID 1: wlt-init
PID 2: wlt-guardian-watchdog   (monitors guardian heartbeat, triggers kill switch on death)
PID 3: wlt-guardian            (the daemon — needs network for Tor UID detection)
PID 4: tor                     (started after guardian so guardian detects its UID)
PID 5: wlt-compositor
PID 6: wlt-shell
```

**Patch (apply to init-minimal.c, after the existing wlt-net setup):**

```c
/* Start guardian watchdog BEFORE guardian so it monitors from first heartbeat */
if (fork() == 0) { execl("/usr/sbin/wlt-guardian-watchdog", "wlt-guardian-watchdog", NULL); _exit(1); }
usleep(200000);  /* let watchdog claim PID 2 */

/* Start guardian daemon — receives /etc/wlt/guardian/guardian.conf path */
if (fork() == 0) {
    execl("/usr/sbin/wlt-guardian", "wlt-guardian",
          "--config", "/etc/wlt/guardian/guardian.conf", NULL);
    _exit(1);
}
usleep(500000);  /* let guardian claim PID 3 and init engines */

/* THEN start tor — guardian's net engine detects tor's UID at init */
if (fork() == 0) { execl("/usr/sbin/tor", "tor", "-f", "/etc/tor/torrc", NULL); _exit(1); }
usleep(1000000);  /* tor bootstrap */

/* compositor + shell after tor */
```

## 3.2 Initramfs bundle (build-initramfs64.sh)

**File:** `WLTIOS/scripts/build-initramfs64.sh`

Source the bundled snippet `build-initramfs-snippet.sh` from this folder, OR
add these lines to build-initramfs64.sh after the existing bundle step:

```bash
# Guardian bundle
source /path/to/guardian/wlt-integration/build-initramfs-snippet.sh
```

The snippet copies into the initramfs:
- `build/guardian` → `/usr/sbin/wlt-guardian` (static)
- `build/guardian_watchdog` → `/usr/sbin/wlt-guardian-watchdog` (static)
- `build/mcp_server` → `/usr/sbin/wlt-mcp-server` (static)
- `build/bpf/guardian.bpf.o` → `/etc/wlt/guardian/guardian.bpf.o`
- `signatures/guardian.yarc` → `/etc/wlt/guardian/guardian.yarc`
- `signatures/fim.db` → `/etc/wlt/guardian/fim.db` (baseline built at image time)
- `ml/anomaly.iforest` → `/etc/wlt/guardian/anomaly.iforest`
- `rules/guardian.policy`, `rules/ebpf.rules`, `update_pubkey.pem`
- `baseline/` directory (clean originals for FIM restore)

**Static build command (for the initramfs, all binaries must be static):**

```bash
make all CC=gcc DAEMON_LDFLAGS="-static -lyara -lssl -lcrypto -lsqlite3 -lbpf -lz -lpthread -ldl"
```

## 3.3 vmlinux.h generation (on the 64-bit QEMU target)

In the running WLTIOS guest (after Phase 3.1 integration):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > /etc/wlt/guardian/vmlinux.h
```

Then in `bpf/guardian.bpf.c`, replace:
```c
#include "guardian_vmlinux.h"
```
with:
```c
#include "vmlinux.h"
```

Recompile BPF on the target:
```bash
clang -target bpf -g -O2 -D__TARGET_ARCH_x86 -I/etc/wlt/guardian/ \
  -c bpf/guardian.bpf.c -o build/bpf/guardian.bpf.o
```

## 3.4 Kill switch unification

**File:** `WLTIOS/src/userspace/wlt-shell/shell.c` — `cmd_killswitch()`

Currently wlt-shell calls SIOCDELRT directly. It MUST instead delegate to
Guardian so both manual and automatic kill-switch activations go through the
same code path (Guardian's BPF `kill_switch_active` map then blocks
SIOCADDRT regardless of source).

**Patch:**

```c
/* OLD: direct ioctl SIOCDELRT */
/* NEW: delegate to guardian's Unix socket */
int cmd_killswitch(int argc, char **argv) {
    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "/run/guardian.sock", sizeof(addr.sun_path)-1);
    if (connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "killswitch: cannot reach guardian (is it running?)\n");
        return 1;
    }
    /* SO_PEERCRED auth happens guardian-side; we run as root so it passes */
    write(s, "cmd:kill_switch\n", 16);
    char buf[256];
    int n = read(s, buf, sizeof(buf)-1);
    if (n > 0) { buf[n] = 0; printf("%s", buf); }
    close(s);
    return 0;
}
```

## 3.5 Integration tests

See `tests/run_all.sh` for the new WLTIOS integration test block (gated on
`$WLTIOS_MODE` env var so they skip in dev sandbox).

---

## File layout of this folder

```
wlt-integration/
├── README.md                       (this file)
├── guardian.service                (init script template for wlt-init)
├── build-initramfs-snippet.sh      (sourced by build-initramfs64.sh)
├── guardian.conf                   (default guardian config for WLTIOS)
└── guardian-cgroup.conf            (cgroup memory/CPU limits — Phase 5.2)
```
