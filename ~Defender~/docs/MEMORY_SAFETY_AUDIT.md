# Guardian Memory Safety Audit — Phase 5.5

Audit of all C source for: buffer overflows, use-after-free, integer overflow,
format string issues, scanf without limits.

---

## Findings by file

### src/guardian.c (1323 lines)
- **snprintf truncation warnings** (lines 371-418 write() calls, 1333):
  These are warnings, not vulnerabilities. All snprintf calls use `sizeof()`
  bounds. No overflow possible.
- **write() return values ignored** (API socket responses): safe — best-effort
  writes to a socket that may have closed. Not a security issue.
- **FIX NEEDED**: none. All buffers bounded.

### src/fim_engine.c
- `g_strlcpy` used consistently for path copies — safe.
- inotify event path: now bounded by `sizeof(ev.path)` via snprintf (Phase 1.1 fix).
- `hash_file`: reads in 64KB chunks, no unbounded read.
- **FIX NEEDED**: none.

### src/action_engine.c
- `g_action_quarantine_file`: quarantine path uses snprintf with sizeof — safe.
- `g_action_delete`: write loop checks return (Bug 13/M3 fix) — safe.
- `g_action_freeze`: snprintf warnings (format-truncation) but bounded — safe.
- `baseline_escape` (Phase 1.3): loop bounded by `out_sz` — safe.
- **FIX NEEDED**: none.

### src/sig_engine.c
- YARA callback: `g_strlcpy` for rule_id — safe.
- `g_sig_scan_proc_mem_regions`: region size capped at 64MB, malloc checked.
- `g_sig_fetch_updates`: file size checked (>= 64), malloc checked.
- **FIX NEEDED**: none.

### src/anomaly_engine.c
- `call_python_model`: args buffer 512B, snprintf checked — safe.
- feature collection: fixed 8-element double array — safe.
- **FIX NEEDED**: none.

### src/ebpf_engine.c
- rule parsing: `fgets(line, sizeof(line), f)` — bounded.
- `g_strlcpy` for rule fields — safe.
- **FIX NEEDED**: none.

### src/mcp_server.c (43KB)
- JSON-RPC parser: **AUDIT PENDING** — this is the largest attack surface
  (accepts external input via Unix socket).
- Recommendations: ensure all sscanf/fgets bounded, denylist enforced.
- **FIX NEEDED**: audit JSON parser for malformed-input crashes.

### src/canary_engine.c (Phase 2.1)
- canary path: snprintf with sizeof — safe.
- RAND_bytes return checked — safe.
- **FIX NEEDED**: none.

### src/ransomware_engine.c (Phase 2.4)
- /proc enumeration: `atoi(de->d_name)` — safe (isdigit check first).
- detail buffer: snprintf with sizeof — safe.
- **FIX NEEDED**: none.

### src/pmu_engine.c (Phase 4.2)
- perf_event_attr: stack-allocated, zeroed — safe.
- read() return checked — safe.
- **FIX NEEDED**: none.

## Integer overflow risks

- `g_action_delete`: `off_t sz` from fstat, loop `off += sizeof(buf)` — no
  overflow (off_t is 64-bit).
- FIM metadata `int64_t mtime/size` — safe.
- BPF map sizes: fixed at compile time — no runtime overflow.

## Format string issues

- All printf/fprintf/snprintf use **constant format strings** — no `%n` or
  user-controlled format strings. Safe.

## Recommendations for v2

1. **MCP server JSON parser**: full fuzz pass (see tests/fuzz_mcp.py).
2. **Replace raw C arrays with bounds-checked helpers** where practical
   (g_strlcpy already used; consider g_snprintf wrapper).
3. **Static analysis**: run `cppcheck` and `clang --analyze` on the tree.
4. **Address sanitizer build**: compile with `-fsanitize=address` for testing.

## Conclusion

No critical memory-safety vulnerabilities found in the audited files.
The MCP server JSON parser is the remaining audit item (largest input
surface). All buffer operations use bounded snprintf/g_strlcpy. No
user-controlled format strings. No use-after-free patterns (all mallocs
paired with frees, no dangling pointers in hot paths).
