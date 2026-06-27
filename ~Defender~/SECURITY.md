# WLTIOS Guardian — Security Model

## Threat Model

The Guardian daemon is an endpoint protection engine running as PID 2 on WLTIOS
(amnesic Tails-like OS). It defends against:

1. **Malware execution** — detected by YARA signatures (Layer 1) and BPF syscall
   hooks (Layer 2) that inline-kill known-bad patterns
2. **File tampering** — detected by AES-256-GCM encrypted FIM baseline (Layer 3)
3. **Anomalous behavior** — detected by isolation forest ML (Layer 4)
4. **Network leaks** — non-Tor egress detected by BPF connect hook + `/proc/net`
   parsing (Layer 5)
5. **Daemon compromise** — self-protection via `PR_SET_DUMPABLE(0)`, watchdog PID 3,
   and BPF ptrace hook that blocks tracing of the Guardian PID

## Trust Boundaries

```
┌──────────────────────────────────────────────┐
│  KERNEL (BPF hooks — 14 syscall tracepoints) │  ← trusted
├──────────────────────────────────────────────┤
│  GUARDIAN DAEMON (PID 2, root)               │  ← trusted
│    ├── API socket: /run/guardian.sock         │
│    │   └── SO_PEERCRED: root or guardian UID  │
│    └── Forensic log: AES-256-GCM + SHA chain │
├──────────────────────────────────────────────┤
│  MCP SERVER (separate binary, root)          │  ← trusted
│    ├── MCP socket: SO_PEERCRED authenticated │
│    ├── Irreversible tools: MCP_AUTOCONFIRM   │
│    └── cmd:kill_switch → delegates to daemon │
├──────────────────────────────────────────────┤
│  WATCHDOG (PID 3, root)                      │  ← trusted
│    └── Monitors /run/guardian/guardian.heartbeat
├──────────────────────────────────────────────┤
│  USER PROCESSES                              │  ← untrusted
│    └── Cannot connect to daemon/MCP sockets  │
│    └── Cannot ptrace Guardian (BPF hook)     │
│    └── Cannot add routes (ioctl + netlink    │
│        hooks block during kill switch)       │
└──────────────────────────────────────────────┘
```

## Authentication

- **API socket** (`/run/guardian.sock`): `SO_PEERCRED` check on `cmd:*` commands.
  Status queries (no `cmd:` prefix) are open to any peer. Only root or the
  guardian's own UID may issue commands.
- **MCP socket**: `SO_PEERCRED` check on all connections. Only root or guardian UID.
- **Irreversible actions** (KILL, DELETE, KILL_SWITCH): require `MCP_AUTOCONFIRM=1`
  environment variable. In production, the human-confirmation token mechanism
  (Phase 3) is the primary gate.

## Closed Vulnerabilities

### Phase 1 (v1.1 → v1.2): Foundation
| Vuln | Description | Fix |
|------|-------------|-----|
| 1 | No self-protection — daemon ptrace-able | `PR_SET_DUMPABLE(0)` + BPF ptrace hook |
| 10 | No rate limiting — event bus flood | Per-rule (100/s) + global (500/s) + dedup |
| 8 | Pickle deserialization RCE in ML model | SHA-256 hash verification before load |

### Phase 2 (v1.2 → v1.3): Kill Switch
| Vuln | Description | Fix |
|------|-------------|-----|
| 6 | 5-second kill switch latency gap | BPF→ringbuf→userspace in microseconds |
| 9 | Kill switch reversible (attacker re-adds route) | ioctl SIOCADDRT + netlink rtnl_newroute BPF hooks |

### Phase 3 (v1.3): Defense in Depth
| Vuln | Description | Fix |
|------|-------------|-----|
| 2 | FIM baseline stored in plaintext | AES-256-GCM with path-bound AAD |
| 4 | BPF maps writable from BPF programs | `BPF_F_RDONLY_PROG` on security-critical maps |
| 5 | FIM key not bound to hardware | TPM2 PCR binding documented (deployment step) |

### Final Audit (v1.4): Stress Test
| ID | Severity | Description | Fix |
|----|----------|-------------|-----|
| C1 | CRITICAL | shell_exec/install_package — shell injection | Removed from tool registry |
| C2 | CRITICAL | t_syscall_trace popen — shell injection | fork/execlp with PR_SET_PDEATHSIG |
| C3 | CRITICAL | t_file_restore — no path validation | is_dangerous_path() guard added |
| C4 | CRITICAL | Overflow log — JSON injection | escape_json_field() escaping |
| C5 | CRITICAL | g_sha256 — NULL deref on OOM | NULL check + zero-fill fallback |
| H3 | HIGH | PID/heartbeat in /tmp/ — symlink attack | Moved to /run/guardian/ (0700) |
| H4 | HIGH | time(NULL) in watchdog — NTP race | CLOCK_MONOTONIC |
| H7 | HIGH | FIM key fallback 0xAA — deterministic | Degrade to unencrypted or abort |
| H8 | HIGH | t_log_read — path traversal | Reject / and .. in name |
| L5 | CRITICAL | FIM IV fallback rand() — GCM broken | Return -EIO, refuse to encrypt |
| M3 | MEDIUM | Secure delete write() unchecked | Return -EIO on short write |
| M7 | MEDIUM | Quarantine counter race | __sync_add_and_fetch (atomic) |
| M8 | MEDIUM | fwrite() unchecked in log append | Return -EIO on failure |
| M9 | MEDIUM | process_list count memcpy overflow | Fixed-width 16-char placeholder |

## Known Architectural Debt (v2)

These are NOT exploitable in current deployment but should be addressed long-term:

| ID | Issue | Mitigation |
|----|-------|------------|
| H1 | args_parse JSON parser has no key escape handling | MCP peers are SO_PEERCRED authenticated |
| H2 | params extraction unbounded depth loop | Bounded by 64KB input buffer |
| H5 | MCP_AUTOCONFIRM env var inheritable | Phase 3 token mechanism is primary gate |
| L4 | BPF connect hook IPv4 only | IPv6 support planned for v2 |

## FIM Key Management

- **Key location**: `<fim_db_path>.key` (e.g., `/etc/wlt/guardian/fim.db.key`)
- **Key generation**: 32 bytes from `/dev/urandom`, file mode 0400
- **Key rotation**: `guardian --rebuild-fim` deletes old key + DB, generates new
- **tmpfs degradation**: if FIM DB directory is on tmpfs, encryption is disabled
  (key won't persist across reboots) with a warning
- **Failure mode**: if `/dev/urandom` fails, daemon refuses to use deterministic
  key — falls back to unencrypted FIM or aborts rebuild
