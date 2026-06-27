# WLTIOS Guardian — Research Brief

**Date:** 2026-06-26
**Purpose:** Consolidated research driving the Guardian build. Sources cited inline.

## 1. Windows Defender Engine Internals

Defender's detection engine is layered and **does NOT use an LLM** in the detection loop:

1. **Signature DB** — `.vdm` files (Virtual Device Drivers, PE-format). Hash + pattern matching against known malware. The "Security Intelligence Updates" ship as 4 core `.vdm` files parsed into an in-memory `gktab` structure. [retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world]
2. **Heuristic engine** — analyzes API usage patterns, memory allocation behavior, not just static signatures. [medium yua_mikanana19]
3. **Memory scanning** — scans the memory space of running processes to expose obfuscated behavior. [learn.microsoft.com/defender-endpoint/adv-tech-of-mdav]
4. **Cloud-delivered protection** — heavy lifting on Microsoft's cloud (NOT on-device). The LLM "Security Copilot" is a separate paid analyst product, not in the detection loop.
5. **RAM footprint** — typically 100-200MB idle. Reddit/sysadmin reports of runaway RAM are exceptions, not baseline.

**Takeaway for Guardian:** Defender proves a deterministic signature+heuristic+small-ML engine catches 95%+ of threats at ~100-200MB. Our 5-layer architecture (YARA + eBPF + FIM + isolation forest + net IDS) mirrors this exactly.

## 2. Falco (eBPF Runtime Security)

- **Architecture:** eBPF driver hooks tracepoints (syscalls, sched, net) → userspace daemon (`falco`) evaluates rules → alerts. [falco.org/blog/adaptive-syscalls-selection]
- **Rule syntax** (from falcosecurity/rules repo):
  ```yaml
  - rule: Shell Spawned by Web Server
    desc: A web server process (nginx/apache) spawned a shell
    condition: >
      evt.type in (execve, execveat) and
      proc.name in (nginx, apache2, httpd) and
      proc.pname in (sh, bash, zsh)
    output: "Suspicious shell spawn (pid=%proc.pid comm=%proc.name)"
    priority: WARNING
  ```
- **Adaptive syscall selection** — Falco 0.36+ lets you pick which syscalls to monitor, reducing overhead. [falco.org/blog/adaptive-syscalls-selection]
- **Lowest RAM** of all eBPF security tools per benchmarks. Typically ~30-50MB.
- **Alerts only** — Falco does NOT enforce. That's Tetragon's job.

**For Guardian:** Write a Falco-style rule engine in C that consumes eBPF events from our `trace_execve.bpf.c` probe and evaluates rule conditions. Rules stored as a simple DSL (YAML-like, parsed at boot). ~15-20 baseline rules covering the threat model.

## 3. Tetragon (eBPF Enforcement)

- **Key difference from Falco:** Tetragon **enforces**, not just alerts. [tetragon.io/docs/concepts/enforcement/persistent-enforcement]
- **Enforcement mechanism:** BPF program returns an action (Sigkill, Override, Unfollow). The kernel helper `bpf_send_signal(SIGKILL)` kills the offending process inline, before the syscall completes.
- **Persistent enforcement:** policies pinned in `/sys/fs/bpf/tetragon` survive tetragon restarts. [tetragon.io]
- **CPU overhead:** <2% per Isovalent benchmarks. [youtube zzokbANVuE4]
- **Hook points:** kprobes (any kernel function) + tracepoints + LSM hooks. [tetragon.io/docs/concepts/tracing-policy/hooks]

**Tetragon enforcement example (kills any process touching /tmp/tetragon):**
```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata: { name: "enforcement" }
spec:
  kprobes:
  - call: "fd_install"
    syscall: false
    args:
    - { index: 0, type: int }
    - { index: 1, type: "file" }
    selectors:
    - matchArgs:
      - { index: 1, operator: "Equal", values: ["/tmp/tetragon"] }
      matchActions:
      - { action: Sigkill }
```

**For Guardian:** Add `bpf_send_signal(SIGKILL)` and `bpf_override_return()` to our eBPF programs for inline enforcement. The userspace policy engine decides which rule triggers which enforcement action (kill vs freeze vs log).

## 4. libbpf Userspace Loader Patterns

The canonical C userspace loader pattern: [docs.ebpf.io/ebpf-library/libbpf/userspace/bpf_object__open]

```c
#include <bpf/libbpf.h>

int main() {
    struct bpf_object *obj = bpf_object__open_file("prog.bpf.o", NULL);
    if (libbpf_get_error(obj)) return 1;
    
    if (bpf_object__load(obj)) {  // loads programs + maps into kernel
        bpf_object__close(obj);
        return 1;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "trace_execve");
    struct bpf_link *link = bpf_program__attach(prog);  // attaches to tracepoint
    
    // ring buffer poll
    struct ring_buffer *rb = ring_buffer__new(
        bpf_object__find_map_by_name(obj, "events"),
        handle_event, NULL, NULL);
    
    while (running) {
        ring_buffer__poll(rb, 100 /*timeout_ms*/);
    }
    
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
```

Key APIs: `bpf_object__open_file`, `bpf_object__load`, `bpf_program__attach`, `ring_buffer__new`, `ring_buffer__poll`, `bpf_link__destroy`. [libbpf.readthedocs.io/en/latest/api.html]

**For Guardian:** `ebpf_engine.c` implements exactly this pattern. Loads all `.bpf.o` files from `/etc/wlt/guardian/bpf/`, attaches them, polls the ring buffer, dispatches events to the rule engine.

## 5. AIDE (File Integrity Monitoring)

- **Database:** binary DB at `/var/lib/aide/aide.db` storing filename + hash (sha256/md5) + perm/uid/gid/size/mtime/ctime/inode/linkcount.
- **Config syntax:** `/etc/aide.conf` with regex path selectors + attributes to track:
  ```
  /etc        p+i+n+u+g+s+m+c+sha256
  /bin        p+i+n+u+g+s+m+c+sha256
  /usr/bin    p+i+n+u+g+s+m+c+sha256
  ```
  [aide.github.io, access.redhat.com/articles]
- **Baseline:** generated at build time with `aide --init`, stored read-only. Checked with `aide --check`.
- **Comparison:** any attribute mismatch = alert.

**For Guardian:** Our custom FIM (fim.c) already does this with sqlite3 + SHA-256. We extend it with: (a) config file listing watched paths + attributes, (b) periodic scan (every 5 min per spec), (c) on-write inotify hook for instant detection, (d) quarantine + restore-from-baseline action.

## 6. Tamper-Evident Logging

**Weak (don't do):** FNV-1a chain (what my v1 had) — trivially forgeable, no cryptographic binding.

**Strong (do this):** SHA-256 hash chain with prev-hash + timestamp + sequence number:
```
entry[n] = {
  seq: n,
  ts: iso8601,
  prev_hash: sha256(entry[n-1]),
  event: <json>,
  entry_hash: sha256(seq || ts || prev_hash || event)
}
```
Any modification to entry[k] breaks entry[k+1].prev_hash → cascades to all subsequent entries. [Cryptographic Audit Trail pattern, several implementations on github]

**Even stronger:** Merkle tree (batch entries, root hash published). Certificate Transparency uses this. Overkill for our use case.

**Encryption:** AES-256-GCM for confidentiality. Key derived from a per-boot secret (stored in kernel keyring or TPM if available). Amnesic mode = key wiped on reboot = log unreadable across reboots (acceptable: real-time monitoring is the value, not historical retention).

**For Guardian:** Rewrite forensic_log.c with SHA-256 chain (bundle a minimal SHA-256 impl — we already have one in fim.c). Add AES-256-GCM encryption with libsodium or openssl. Log entries are JSON. The chain hash covers the entire JSON blob.

## 7. seL4 Capability Monitoring (Phase 2)

- seL4 is capability-based: every kernel object (TCB, endpoint, page, etc.) is referenced by capabilities in capability spaces (CSpaces). [sel4.systems whitepaper]
- CapDL (Capability Description Language) specifies which objects/entities have access to which capabilities. [Trustworthy Systems PDF]
- **sel4_caps_dump:** would require a userspace component with access to the CSpace root cap to walk all caps and dump them. The capDL tool already does this for static analysis.
- **sel4_ipc_trace:** seL4 IPC is synchronous — tracepoint would need a kernel-side instrumentation hook (not standard). Realistic only if we ship a patched seL4.
- **Realistic for phase 2:** sel4_caps_dump via a debug capdl export. IPC trace and fault inject are research-grade.

**For Guardian MCP:** Implement `sel4_caps_dump` as a tool that reads a capDL dump file (generated at boot by a seL4 userspace tool). Stub the IPC trace / fault inject tools as "not implemented in v1".

## 8. Intel PT and Perf Counters for Malware Detection

- **Intel PT:** records every branch executed. Captured via `perf_event_open` with `PERF_SAMPLE_BRANCH_*`. [perf-intel-pt(1) man7.org]
- **CPU overhead:** low, but **memory bandwidth** significant. Not suitable for always-on; use on-demand for forensic analysis of a specific suspicious PID. [easyperf.net]
- **Malware signatures in PT:** control-flow patterns of unpacking routines, ROP chains, code reuse attacks. Active research area.
- **Perf counters:** cache-miss rate, branch-mispredict rate, IPC (instructions per cycle). Malware (especially crypto-mining, packing) has distinctive signatures. Capture via `perf_event_open` with hardware counters.

**For Guardian MCP:** `intel_pt_trace(pid, duration)` and `perf_counters(cpu)` tools. On-demand only (not always-on). Uses `perf_event_open` syscall.

## 9. TPM Attestation and IMA

- **IMA (Integrity Measurement Architecture):** kernel subsystem that hashes every executed file and extends the hash into a TPM PCR (Platform Configuration Register). [LWN.net IMA article]
- **IMA log:** `/sys/kernel/security/ima/ascii_runtime_measurements` — ordered list of file hashes + PCRs. [Intel Trust Authority docs]
- **TPM attestation:** PCR values are quoteable (signed by TPM). Remote verifier can confirm the system booted a known-good state.
- **Realistic for WLTIOS:** if the target hardware has a TPM (most x86 since ~2015 do), `ima_measure()` just reads the IMA log file. `tpm_attest()` needs `tpm2-tools` or direct `/dev/tpm0` access.

**For Guardian MCP:** `ima_measure()` reads the IMA log. `tpm_attest()` quotes PCR values. Both are read-only inspection tools. If no TPM, return "unsupported on this hardware".

## 10. Isolation Forest for Anomaly Detection

- **Algorithm:** isolates observations by randomly selecting a feature + random split. Anomalies need fewer splits to isolate → shorter path length → higher anomaly score. [scikit-learn IsolationForest docs]
- **Key params:** `n_estimators=80-100`, `contamination=0.01-0.05` (expected anomaly fraction), `max_samples=256` (subsample size).
- **Feature engineering for security:** per-process (cpu_pct, mem_mb, net_conns, file_writes_min, fork_rate, distinct_ips, syscall_rate, entropy_io). Per-system (total proc count, net flow count, disk I/O rate).
- **Concept drift in amnesic mode:** model trained at build time on benign workload. No online learning (amnesic = no persistent state). Re-train at each USB rebuild.
- **C inference:** either (a) bundle a C isolation-forest impl (simple — just tree traversal), or (b) subprocess to Python with pickled model. (b) is simpler and what we have.

**For Guardian:** Keep the Python model (`ml/anomaly.py`) for training + inference via subprocess. Add `anomaly_engine.c` that builds the features vector from /proc stats, calls the Python model via popen, parses the JSON verdict.

## 11. Network IDS for Tor-Only Traffic

Attacks that matter when all traffic is Tor:
1. **DNS leaks** — app makes DNS query outside Tor (bypassing the SOCKS proxy). Detect: any UDP/53 traffic not from the Tor process.
2. **Non-Tor egress** — any TCP connection not from Tor. Kill switch already handles this (route-based).
3. **Tor protocol anomalies** — malformed cells, unexpected circuit extends. Hard to detect without deep Tor protocol parsing.
4. **Guard rotation attacks** — adversary forces guard changes to de-anonymize. Detect: guard changes faster than expected (Tor rotates every few months normally).
5. **Consensus attacks** — adversary poisons the consensus. Detect: consensus diff > threshold.
6. **Tor DNS cache timing attacks** — [timeless timing attacks paper] adversary can determine if a domain is cached.

**For Guardian net_engine:** af_packet sniffer on the e1000 interface. Rules:
- non-Tor process opens socket → alert + kill switch
- UDP/53 from non-Tor → instant kill switch (DNS leak)
- Tor process traffic only to known Tor directory authorities + guard nodes (whitelist from consensus)
- Anything else = alert

## 12. MCPilot / MCP Architecture

- **Tool registry:** map of tool_name → function pointer + metadata (tier, needs_root, needs_bpf).
- **JSON-RPC 2.0:** `{"jsonrpc":"2.0","id":N,"method":"tools.call","params":{"name":"...","args":{...}}}` → `{"jsonrpc":"2.0","id":N,"result":{...}}`.
- **Safety denylist:** regex/prefix list of forbidden paths/commands (`/proc/kcore`, `/dev/mem`, `rm -rf /`, etc).
- **User-confirm gates:** irreversible actions (kill, delete, encrypt, kill_switch) require explicit `MCP_AUTOCONFIRM=1` env var OR a confirmation token from the UI.

**For Guardian MCP:** Rewrite `mcp_server.py` in C as `mcp_server.c`. ~50 tools organized by tier (inspect/reversible/irreversible). Unix socket server (not TCP — local only, more secure). Safety denylist + confirm gates ported from MCPilot.

---

## Recommended Approach Summary

| Layer | Tool/Approach | RAM | Status in v1 sandbox |
|---|---|---|---|
| L1 Signatures | YARA 4.5.2 + custom rules + hash module | 5-20MB | ✅ built, need hash module fix + more rules |
| L2 Behavioral | Custom eBPF + Falco-style C rule engine + Tetragon-style enforcement | 30-50MB | ⚠️ BPF prog done, need ebpf_engine.c loader + rule engine |
| L3 FIM | Custom sqlite3 + SHA-256 (replaces AIDE, fewer deps) | 5MB | ✅ built, need config + inotify + periodic scan |
| L4 Anomaly | sklearn isolation forest + C subprocess bridge | 10-20MB | ⚠️ Python model done, need anomaly_engine.c |
| L5 Net IDS | af_packet sniffer + Tor-focused rules | 20-40MB | ❌ need net_engine.c |
| Enforcement | action_engine.c (cgroup freezer/SIGSTOP/SIGKILL/unshare/route) | <1MB | ⚠️ enforce.c done, need real impl |
| Policy | policy_engine.c (rules-based, deterministic) | <1MB | ❌ need policy_engine.c |
| Forensic log | forensic_log.c (SHA-256 chain + AES-256-GCM) | <1MB | ⚠️ chain done, need SHA-256 + encryption |
| MCP | mcp_server.c (C, ~50 tools, Unix socket) | <1MB | ⚠️ Python proto done, need C rewrite |
| Kairos | cli + loader + agent + instruction.md | 0 (on-demand) | ❌ need all |
| ADR-09 | docs/adr/09-guardian.md | 0 | ❌ need |

**Build priority (in order):**
1. Expand guardian.h to full production API (the contract)
2. ebpf_engine.c (highest value — unblocks L2)
3. policy_engine.c + forensic_log.c (correctness + security)
4. anomaly_engine.c + net_engine.c (complete the layers)
5. mcp_server.c in C with ~50 tools
6. kairos (cli/loader/agent/instruction.md)
7. ADR-09, expanded YARA rules, integration tests
8. Build, verify, document
