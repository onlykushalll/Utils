# Guardian Threat Model Review — Phase 5.4

**Question:** Can a process bypass ALL 5 detection layers simultaneously?
What does that attack look like, and what catches it?

---

## The 5 detection layers

| Layer | What it detects | Bypass attempt | What catches the bypass |
|---|---|---|---|
| L1 YARA sigs | known-bad file/memory patterns | polymorphic/fileless malware | L2 (behavior) + L4 (anomaly) |
| L2 eBPF behavioral | syscall patterns (execve/openat/connect) | use syscalls eBPF doesn't hook | L2 LSM hooks (Phase 4.1) cover the gaps |
| L3 FIM | file tampering | modify file via syscall FIM doesn't watch | inotify + periodic SHA-256 scan |
| L4 Anomaly ML | novel process behavior | stay within training distribution | canary files (Phase 2.1) catch mass ops |
| L5 Net IDS | non-Tor egress | IPv6, DNS leak, Tor protocol abuse | IPv6 hook (Phase 1.4) + consensus (4.4) |

## Attack scenario: bypass all 5 layers

**Attacker goal:** exfiltrate data without triggering any layer.

### Attempt 1: Use a novel fileless loader
- L1 (YARA): no file to scan -> **bypass**
- L2 (eBPF execve hook): loader runs via `memfd_create` + execveat
  -> execveat hook catches it (HOOK 2)
- **CAUGHT at L2**

### Attempt 2: Use only syscalls not hooked by eBPF
- Hooks cover: execve, execveat, openat, openat2, connect, ptrace, clone,
  clone3, unshare, setns, bind, socket, setuid, capset, write, unlink,
  unlinkat, rename, renameat, renameat2, ioctl, sched_process_fork, sched_process_exit
- Gaps: `mmap` (no hook), `sendfile` (no hook), `splice` (no hook)
- Attacker uses `sendfile` to exfiltrate via an existing Tor connection
- L5 (Net IDS): connection is from Tor UID -> **bypass**
- L4 (Anomaly): sendfile to Tor socket is unusual -> high syscall_rate
  -> flagged as anomaly -> **CAUGHT at L4**
- **CAUGHT at L4** (but only if anomaly model was trained on this pattern)

### Attempt 3: Stay within anomaly training distribution
- Attacker mimics normal process behavior (low CPU, low mem, low forks)
- L4 (Anomaly): looks normal -> **bypass**
- L2 (eBPF write hook): exfiltrating data = high write_bytes
  -> ransomware module flags RANSOMWARE_IO_PATTERN -> **CAUGHT at L2/Phase 2.4**
- **CAUGHT at ransomware module**

### Attempt 4: Slow exfiltration (low write rate)
- Attacker sends 1KB/s — below all thresholds
- L4 (Anomaly): within distribution -> **bypass**
- L5 (Net IDS): Tor UID -> **bypass**
- L2 (eBPF): no single syscall threshold crossed -> **bypass**
- **GAP: slow data exfiltration via Tor is the hardest to detect.**
  Mitigation: Phase 4.4 Tor consensus tracking (if destination isn't a known
  guard, flag). Also: total-volume anomaly detection (future work).

## Attack scenario: kill the guardian itself

### Attempt: SIGKILL the guardian daemon
- Guardian runs as root; attacker is non-root -> cannot signal
- Attacker with root: ptrace hook kills them before they can act
- Guardian watchdog (PID 2) detects guardian death within 5s -> triggers
  network kill switch (deletes default route)
- **CAUGHT by watchdog + kill switch** (attacker loses network too)

### Attempt: corrupt the forensic log
- Log is AES-256-GCM encrypted + SHA-256 chained
- Any modification breaks the GCM auth tag or the hash chain
- `g_log_verify()` detects tampering at the first broken entry
- **CAUGHT by chain verification**

### Attempt: poison the YARA signature DB
- Updates are Ed25519-signed (Phase 4 sig_engine.c)
- Unsigned updates rejected with SIG_UPDATE_SIGNATURE_INVALID event
- Canary rollback: if a bad update ships, `g_sig_rollback_updates()` restores
  the previous DB from `.bak`
- **CAUGHT by signature verification + rollback**

## Attack scenario: exploit the guardian itself

### Memory safety
- C code with fixed-size buffers. Audited in MEMORY_SAFETY_AUDIT.md.
- Key risks: snprintf truncation (warnings, not vulnerabilities),
  /proc parsing (bounded by sscanf field widths).
- MCP server Unix socket: SO_PEERCRED auth + denylist.

### Race conditions
- See RACE_AUDIT.md. Key finding: log lock + bus lock + FIM lock interact.
- The bus subscriber copy-then-release pattern (Bug 8 fix) prevents the
  main ABBA deadlock.

## Residual risks (accepted)

1. **Slow Tor exfiltration** (Attempt 4) — requires volume-based anomaly
   detection (future work, not in v1).
2. **Kernel exploit** — if the attacker gets ring 0, eBPF can be unloaded.
   Mitigation: Guardian watches its own BPF programs via bpftool (future).
3. **Physical access** — TPM sealing (Phase 5.1) protects keys at rest, but
   a hardware attacker with a soldering iron can extract TPM secrets.

## Conclusion

Guardian catches the vast majority of attacks through layered defense.
The main residual gap is **low-and-slow exfiltration via Tor**, which
requires volume-anomaly detection to close (recommended for v2).
