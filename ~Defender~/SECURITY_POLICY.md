# Guardian Security Policy

## Reporting a vulnerability

If you discover a security vulnerability in Guardian, please report it
responsibly. Do NOT open a public GitHub issue.

## Threat model

Guardian is designed to defend a minimal, amnesic, Tor-only OS against
**targeted surveillance**. See `docs/THREAT_MODEL.md` for the full
5-layer bypass analysis and residual risks.

## Security features

- **eBPF inline enforcement**: processes are SIGKILL'd before the malicious
  syscall completes (not after)
- **BPF LSM hooks** (Phase 4.1): decision before syscall completes, no race
- **Tamper-evident forensic log**: SHA-256 chain + AES-256-GCM encryption
- **Signed YARA updates**: Ed25519 signature verification over Tor
- **Kill switch**: deletes default route + blocks SIOCADDRT at kernel level
- **Model hash verification**: ML model SHA-256 checked at load (prevents pickle RCE)
- **SO_PEERCRED auth**: MCP Unix socket verifies caller identity
- **Confirmation tokens**: irreversible actions require explicit confirmation

## Known limitations

- Slow Tor exfiltration (low-and-slow data theft) is not detected — requires
  volume-based anomaly detection (future work)
- Kernel exploit (ring 0) can unload BPF programs — Guardian watches its own
  programs but a determined kernel attacker can evade
- Physical access with hardware tools can extract TPM-sealed keys (when TPM
  mode is implemented)

## Hardening audit

- `docs/MEMORY_SAFETY_AUDIT.md` — per-file C code audit
- `docs/RACE_AUDIT.md` — pthread mutex lock-ordering analysis
- `tests/fuzz_mcp.py` — MCP JSON-RPC parser fuzzer
