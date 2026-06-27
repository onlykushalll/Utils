# WLTIOS Guardian — Defender-Class Endpoint Protection

A minimal, amnesic, eBPF-native endpoint protection engine built for the WLTIOS
security OS. Defender-style layered architecture without the cloud dependency.

## Architecture

```
ALWAYS-ON CORE (~120 MB, deterministic + small ML)
  Layer 1: YARA signature engine         (sig_engine.c)      millisecond
  Layer 2: eBPF behavioral rules         (ebpf_engine.c + bpf/guardian.bpf.c)  real-time, inline kill
  Layer 3: File integrity monitor        (fim_engine.c)      SHA-256 + sqlite3
  Layer 4: Anomaly ML (isolation forest) (anomaly_engine.c + iforest.c)  native C, no Python
  Layer 5: Network IDS                   (net_engine.c)      Tor-focused
  + Canary engine                        (canary_engine.c)   ransomware detection
  + Ransomware behavior                  (ransomware_engine.c)  rate-based
  + PMU hardware counters                (pmu_engine.c)      side-channel + miner detection
  Enforcement: tiered action layer       (action_engine.c)   reversible=auto, irreversible=confirm
  Policy: threat→action mapping          (policy_engine.c)   deterministic
  Forensic log: SHA-256 chain + AES-GCM  (forensic_log.c)    tamper-evident
```

## The 14+ BPF syscall hooks (inline enforcement)

Each hook can fire `bpf_send_signal(SIGKILL)` — the process dies BEFORE the
syscall returns. The attacker never completes the malicious action.

| Hook | Syscall | What it blocks |
|---|---|---|
| 1 | execve | blocklist match |
| 2 | execveat | blocklist match (fd-relative) |
| 3 | openat | /etc/shadow, /proc/kcore, /dev/mem (non-root) |
| 4 | openat2 | same, newer variant |
| 5 | connect | non-Tor egress (IPv4 + IPv6) |
| 6 | ptrace | process injection |
| 7 | clone | fork bombs (<10ms between forks) |
| 8 | clone3 | same, newer variant |
| 9 | unshare | CLONE_NEWUSER namespace escape |
| 10 | setns | namespace enter |
| 11 | bind | unexpected listeners |
| 12 | socket | AF_PACKET/SOCK_RAW creation |
| 13 | setuid | non-root setuid(0) privesc |
| 14 | capset | non-root capability changes |
| 15 | sched_process_exit | cleanup fork_last map |
| 16 | ioctl | SIOCADDRT kill-switch reversal block |
| 17 | rtnl_newroute | kprobe route addition block |
| 18 | write | bytes-written counter (anomaly feature) |
| 19-21 | unlink/unlinkat | ransomware bulk-delete counter |
| 22-25 | rename/renameat/renameat2 | ransomware rename-storm counter |
| 26 | sched_process_fork | ancestry map (IOA parent tracking) |

**Phase 4.1 BPF LSM hooks** (5 additional, gated behind `GUARDIAN_MINIMAL_VMLINUX`):
`lsm/bprm_check_security`, `lsm/file_open`, `lsm/socket_connect`,
`lsm/inode_unlink`, `lsm/ptrace_access_check` — decision BEFORE syscall
completes, no SIGKILL race window.

## Build

```bash
cd guardian
source activate.sh          # sets up clang/libbpf/yara env
make all                    # rebuild everything from source
make test                   # run integration tests
./build/guardian --self-test
```

### On the WLTIOS target

1. Generate vmlinux.h: `bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h`
2. Replace `#include "guardian_vmlinux.h"` with `#include "vmlinux.h"` in `bpf/guardian.bpf.c`
3. Build statically: `make all CC=gcc DAEMON_LDFLAGS="-static ..."`
4. See `wlt-integration/README.md` for boot order + initramfs bundling

## Self-test

The self-test verifies **feature correctness, not just compile correctness**:
- Canary restart (no false positives after daemon restart)
- Isolation Forest inference (anomalous > normal, 4 assertions)
- Ransomware rate-based detection (rate not cumulative)

Each test was regression-verified: temporarily reverting the fix confirms the
test fails (the tests have teeth).

## RAM budget

- Idle: ~120 MB (core engine)
- During investigation: +6 GB (if Qwythos consultant spins up — on-demand only)
- After investigation: back to ~120 MB

## Documentation

- `docs/RESEARCH_BRIEF.md` — 12-topic deep research (Defender, Falco, Tetragon, libbpf, AIDE, seL4, Intel PT, TPM, isolation forest, Tor IDS, MCP)
- `docs/THREAT_MODEL.md` — 5-layer bypass analysis + residual risks
- `docs/MEMORY_SAFETY_AUDIT.md` — per-file audit, no critical vulns
- `docs/RACE_AUDIT.md` — lock-ordering analysis (Bug 8 fix prevents ABBA deadlock)
- `docs/TPM_KEY_SEALING.md` — TPM PCR-bound key derivation plan
- `docs/adr/09-guardian.md` — Defender-style decision rationale
- `wlt-integration/README.md` — WLTIOS integration handoff (boot order, initramfs, kill switch)

## License

See `LICENSE` file. Source-available, dual-license for evaluation and WLTIOS integration.

## Threat model

Guardian is purpose-built for WLTIOS — a minimal, amnesic, Tor-only OS where
the threat model is **targeted surveillance**, not mass malware. For that
specific threat model, eBPF inline enforcement + a network kill switch +
tamper-evident amnesic logging + signed updates over Tor + zero cloud
dependency is the right architecture.
