# ADR-09: WLTIOS Guardian — Defender-Style Security Engine

**Date:** 2026-06-26
**Status:** Accepted
**Supersedes:** ADR-08 (Kairos — LLM-first security, partially)

## Context

WLTIOS needs an always-on security engine to defend against malware, behavioral
anomalies, file tampering, network attacks, and process escapes. The original
design (ADR-08) proposed an LLM-first approach (Llama 3 8B / Phi-3) doing
security reasoning in the always-on loop.

During design review we rejected the LLM-first approach for four reasons:

1. **RAM cost.** A 9B model uses ~6 GB active. The entire WLTIOS 32-bit guest
   uses 150 MB. The AI would consume 40× more RAM than the OS itself.
2. **Speed.** LLMs generate ~50 tokens/sec. Defender-class detection needs
   millisecond response. An LLM cannot keep up with raw kernel events.
3. **Hallucination risk.** A security AI that hallucinates is catastrophic —
   it either triggers the kill switch on phantom threats (locking the user out)
   or lets real malware run. A system prompt saying "don't hallucinate" doesn't
   work; hallucination is architectural in LLMs.
4. **Defender proves it's unnecessary.** Windows Defender — the most widely-
   deployed security product on Earth — does NOT use an LLM in its detection
   loop. Its engine is signature DB + heuristic rules + small classical ML
   classifiers (gradient-boosted trees, kilobytes to megabytes). The LLM
   "Security Copilot" is a separate paid product for analysts, not part of
   detection.

## Decision

Build **WLTIOS Guardian** — a Defender-style core engine with an optional
on-demand AI consultant.

### Architecture

```
ALWAYS-ON CORE (~80-150 MB, defender-style, deterministic + small ML)
  Layer 1: YARA signature engine         (sig_engine.c)
  Layer 2: eBPF behavioral rules          (ebpf_engine.c, bpf/*.bpf.c)
  Layer 3: File integrity monitor         (fim_engine.c)
  Layer 4: Anomaly ML (isolation forest)  (anomaly_engine.c)
  Layer 5: Network IDS                    (net_engine.c)
  Enforcement: tiered action layer        (action_engine.c)
  Policy: threat→action mapping           (policy_engine.c)
  Forensic log: SHA-256 chained + AES-GCM (forensic_log.c)
        │
        │ flagged event (rare, novel, ambiguous — <5% of cases)
        ▼
ON-DEMAND CONSULTANT (optional, NOT automatic, user-launched)
  Qwythos-9B-Claude-Mythos-5-1M (Q4_K_M, 5.24 GB)
  - Spins up ONLY when user invokes `kairos investigate <event>`
  - Ingests context, reasons about novel/complex attacks
  - Suggests action → user confirms → core engine executes
  - Spins DOWN after → RAM returns to baseline
```

### RAM Budget

- Idle: ~80-150 MB (core engine) + 20 MB (Kairos daemon) = ~100-170 MB total
- During investigation: +6 GB (Qwythos) = ~6.1 GB
- After investigation: back to ~100-170 MB
- <4 GB RAM targets: no consultant (Guardian-only mode)
- <8 GB RAM targets: Qwen2.5-1.5B as consultant fallback

### Design Principles

1. **Deterministic code + small classical ML only** in the always-on loop. No LLM.
2. **eBPF, not kernel modules.** The 64-bit guest can't load .ko files; eBPF
   programs load via the BPF syscall and JIT-compile in-kernel.
3. **Custom FIM, not AIDE.** AIDE pulls too many deps for a minimal OS. Our
   custom FIM uses sqlite3 + SHA-256, same capability, fewer deps.
4. **Hybrid signatures.** Frozen baseline on USB (works offline, day-zero) +
   fresh rules fetched over Tor on boot when network available.
5. **Tiered enforcement.** Reversible actions (freeze, quarantine, block-net)
   execute autonomously. Irreversible actions (kill, delete, kill-switch)
   require human confirmation. This is the architectural anti-hallucination
   guarantee — a buggy rule or false positive can't cause irreversible damage.
6. **Tamper-evident log.** Every event is recorded to a SHA-256 hash-chained,
   AES-256-GCM encrypted append-only log. Modifying any past entry breaks the
   chain. The key is per-boot (wiped on reboot — acceptable for amnesic mode).

### Threat Model

**In scope:** known malware (signatures), behavioral anomalies (eBPF rules),
file tampering (FIM), network attacks (net IDS), data exfiltration, process
escapes, resource exhaustion, persistence attempts, Tor circuit compromise,
seL4 cap-space violations (phase 2).

**Out of scope (v1):** physical attacks (mitigated by amnesic + USB read-only),
side-channel attacks (hardware), seL4 zero-days (seL4 is formally verified),
supply-chain attacks (future reproducible builds).

### Enforcement Tiers

| Action | Reversibility | Autonomous? |
|---|---|---|
| Log + alert | N/A | yes |
| Freeze process | yes | yes |
| Quarantine file | yes | yes |
| Quarantine process | yes | yes |
| Block network flow | yes | yes |
| Kill process | no | critical-only (with forensic snapshot) |
| Kill switch | no | critical-only |
| Delete file | no | never (human confirm always) |
| Encrypt file | no | never (human confirm always) |

### Model Choices

- **Always-on:** NO LLM. Deterministic code + small classical ML.
- **On-demand consultant:** Qwythos-9B-Claude-Mythos-5-1M (Q4_K_M, 5.24 GB).
  Native function calling, 1M token context, self-corrects with tools,
  cybersecurity-trained, uncensored for legitimate security ops.
- **Fallback (low-RAM):** Qwen2.5-1.5B-Instruct (Q4, 1.4 GB). Native function
  calling, conservative — declines what it can't handle.
- **DROPPED:** VibeThinker-3B. Brilliant at verifiable reasoning (math, code)
  but explicitly not trained for tool-calling or agents — wrong tool class.

### MCP (Deep-Kernel Tool Layer)

A separate JSON-RPC server (`wlt-mcp`) exposes ~50 deep-kernel inspection and
action tools for the Kairos consultant to use when invoked. Tool registry with
safety denylist + tier-based confirm gates (port from MCPilot blueprint, tools
are WLTIOS-native). Categories: userspace (12), Linux kernel/eBPF (7), seL4
(4, phase 2), hardware (2), Guardian integration (4).

### Anti-Hallucination Guardrails (when Qwythos is invoked)

Architectural, not prompt-only:
1. Grounding rule: every claim MUST cite evidence (PID, log line, packet hash)
2. Verification loop: before any action, re-verify via an MCP tool
3. Confidence threshold: below 70% → recommend human review, don't act
4. Reversibility tiers: reversible = autonomous; irreversible = always confirm
5. Self-correction: act → observe → confirm → if not, self-correct

## Consequences

**Positive:**
- RAM budget fits the target (150 MB 32-bit, 512 MB 64-bit)
- Millisecond detection (signatures + eBPF rules are deterministic code)
- 95%+ of threats caught by the cheap always-on core
- No hallucination risk in the detection loop (it's code, not an LLM)
- Tamper-evident log provides forensic chain
- AI consultant available when genuinely needed, without the always-on cost

**Negative:**
- More C code to maintain than a single LLM call (9 engine modules)
- Custom FIM means we own the bug surface (vs AIDE's battle-tested code)
- eBPF loader is fragile across kernel versions (mitigated by CO-RE + BTF)
- Signature DB can go stale in amnesic mode (mitigated by Tor-fetched updates)
- The consultant, when invoked, can still hallucinate — mitigated by
  architectural guardrails (grounding, verification, confidence, tiers)

**Neutral:**
- Supersedes ADR-08's always-on LLM. ADR-08's MCP tool design is preserved
  and extended (12 → ~50 tools) in the new wlt-mcp module.

## Verification

Every feature must be verified in QEMU with serial output showing the
detection/action. "It compiles" is not done. "QEMU serial shows
'Guardian: threat detected, process 1234 quarantined'" is done.

Success criteria (all 10) are in section 8 of the master build specification.
