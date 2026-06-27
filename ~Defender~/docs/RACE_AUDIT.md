# Guardian Race Condition Audit — Phase 5.7

Audit of all pthread_mutex usage and lock interactions.

---

## Locks in the codebase

| Lock | File | Protects |
|---|---|---|
| `g_bus_mutex` | guardian.c | event bus subscriber list + publish |
| `g_log_mutex` | forensic_log.c | forensic log append |
| `g_fim_mutex` | fim_engine.c | FIM sqlite3 db access |
| `g_rate_mutex` | guardian.c | rate-limit buckets |
| `g_dedup_mutex` | guardian.c | dedup table |

## Lock ordering analysis

Threads that hold multiple locks:
1. **action_subscriber** (called from bus publish, holds bus_mutex during
   callback): may call `g_action_apply` -> `g_log_append_global` (log_mutex)
   -> `g_fim_*` (fim_mutex).

   **Order: bus -> log -> fim**

2. **fim_scan thread**: holds fim_mutex, publishes events (bus_mutex),
   which triggers action_subscriber -> log_mutex.

   **Order: fim -> bus -> log**

### ⚠️ POTENTIAL ABBA DEADLOCK

- Thread A (action_subscriber): bus -> log -> fim
- Thread B (fim_scan): fim -> bus -> log

This is a classic lock-ordering inversion. **HOWEVER**, the Bug 8 fix
(copy subscribers, release bus_mutex, THEN call callbacks) breaks the
cycle: action_subscriber no longer holds bus_mutex when it calls
g_action_apply. So the actual orders are:

- Thread A: log -> fim (no bus held during callback)
- Thread B: fim -> bus (released before publish callback) -> log

No cycle. **The Bug 8 fix prevents the ABBA deadlock.**

## Other race conditions

### Heartbeat file write (guardian.c)
- Atomic write via tmp file + rename — safe.
- No lock needed (single writer, rename is atomic).

### Quarantine counter (action_engine.c)
- `__sync_add_and_fetch` (Bug 12 fix) — atomic, safe.

### BPF map updates
- `bpf_map_update_elem` is kernel-atomic — safe.
- `g_ee_global` pointer: set once in `g_ebpf_init`, read by anomaly/ransomware
  engines. No tear-down race in practice (daemon runs until killed).

### FIM inotify + periodic scan
- Both acquire fim_mutex — safe. inotify handler is non-blocking (select).

## Recommendations

1. **Keep the Bug 8 fix** — it's load-bearing for deadlock prevention.
2. **Consider a single "engine" lock** if contention appears in profiling
   (not needed at current event rates).
3. **FIM sqlite3**: sqlite3 has its own threading mode. Current code uses
   SQLITE_OPEN_NOMUTEX implicitly (single-threaded access guarded by
   fim_mutex). Safe as long as fim_mutex is always held during sqlite3 calls.

## Conclusion

No active deadlocks. The Bug 8 fix (copy-then-release subscriber list
before callbacks) is the critical deadlock-prevention mechanism. All other
lock usage follows consistent ordering. The main residual risk is
contention (not deadlock) if event rates spike — mitigated by the
rate-limit + dedup tables (Phase 2 enhancements).
