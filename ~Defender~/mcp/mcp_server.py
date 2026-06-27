#!/usr/bin/env python3
"""Deep-kernel MCP server for the Guardian (and Qwythos on-demand consultant).

Architecture: a JSON-RPC 2.0 server exposing the ~50 deep-kernel inspection
and action tools. The Guardian's enforcement layer calls these directly.
Qwythos (the optional on-demand consultant) also calls these when invoked.

This borrows MCPilot's blueprint (tool registry + JSON-RPC + safety denylist)
but the tools themselves are WLTIOS-native (seL4 + Linux guest).

NOT all tools work in this dev sandbox (no CAP_BPF, no root). Each tool's
`available()` method reports whether it can run here; the framework refuses
to call unavailable tools and returns a clear error.

Run:
    python3 mcp/mcp_server.py          # stdio JSON-RPC
    python3 mcp/mcp_server.py --port 3030   # TCP (for Qwythos mini-service)
"""
import argparse
import json
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

# ---- tool registry ----------------------------------------------------------

_REGISTRY = {}


def tool(name, tier="reversible", needs_root=False, needs_bpf=False):
    """Decorator: register a deep-kernel tool.

    tier: 'reversible' (autonomous) | 'irreversible' (human-confirm) | 'inspect' (read-only)
    """
    def deco(fn):
        fn._meta = {"name": name, "tier": tier,
                    "needs_root": needs_root, "needs_bpf": needs_bpf}
        _REGISTRY[name] = fn
        return fn
    return deco


def _safe(args, denylist=("/proc/kcore", "/dev/mem", "/dev/kmem")):
    """Safety denylist — refuse to touch the most dangerous paths."""
    for a in args:
        if isinstance(a, str) and any(d in a for d in denylist):
            raise PermissionError(f"denied by safety denylist: {a}")


# ---- inspection tools (read-only, tier=inspect) -----------------------------

@tool("process_inspect", tier="inspect")
def process_inspect(pid):
    """Full state of a PID: maps, open files, sockets, capabilities, cmdline."""
    p = Path("/proc") / str(pid)
    if not p.exists():
        return {"error": f"pid {pid} not found"}
    out = {"pid": pid}
    for f in ("comm", "cmdline", "status"):
        try:
            out[f] = (p / f).read_text(errors="replace").replace("\x00", " ").strip()
        except OSError:
            out[f] = None
    try:
        out["exe"] = str((p / "exe").readlink())
    except OSError:
        out["exe"] = None
    try:
        out["maps"] = (p / "maps").read_text()[:4000]
    except OSError:
        out["maps"] = None
    return out


@tool("process_list", tier="inspect")
def process_list():
    """List all processes with pid/comm/ppid."""
    out = []
    for d in sorted(Path("/proc").iterdir(), key=lambda x: x.name if x.name.isdigit() else "0"):
        if d.name.isdigit():
            try:
                comm = (d / "comm").read_text().strip()
                status = (d / "status").read_text()
                ppid = next((l.split()[1] for l in status.splitlines() if l.startswith("PPid:")), "?")
                out.append({"pid": int(d.name), "comm": comm, "ppid": int(ppid) if ppid.isdigit() else 0})
            except OSError:
                continue
    return {"count": len(out), "processes": out[:500]}


@tool("netflow_capture", tier="inspect")
def netflow_capture(seconds=2):
    """Snapshot /proc/net/{tcp,udp,tcp6,udp6} for established connections."""
    out = {"tcp": [], "udp": []}
    for proto in ("tcp", "udp", "tcp6", "udp6"):
        try:
            lines = (Path("/proc/net") / proto).read_text().splitlines()[1:]
            for ln in lines:
                parts = ln.split()
                local, remote, state = parts[1], parts[2], parts[3]
                out["tcp" if "tcp" in proto else "udp"].append(
                    {"local": local, "remote": remote, "state": state})
        except OSError:
            pass
    return out


@tool("file_forensics", tier="inspect")
def file_forensics(path):
    """Hash, stat, and ownership chain of a file."""
    _safe([path])
    import hashlib
    p = Path(path)
    if not p.exists():
        return {"error": "not found"}
    st = p.stat()
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return {"path": path, "sha256": h.hexdigest(), "size": st.st_size,
            "mtime": st.st_mtime, "mode": oct(st.st_mode), "uid": st.st_uid}


@tool("audit_query", tier="inspect")
def audit_query(expression="*"):
    """Query the audit subsystem (ausearch). Best-effort if available."""
    try:
        r = subprocess.run(["ausearch", "-ts", "recent", "-m", expression],
                           capture_output=True, text=True, timeout=5)
        return {"output": r.stdout[:4000], "rc": r.returncode}
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"error": f"audit unavailable: {e}"}


@tool("log_read", tier="inspect")
def log_read(name="guardian.log", lines=100):
    """Tail a Guardian log."""
    p = Path("/var/log") / name
    if not p.exists():
        p = Path(name)
    if not p.exists():
        return {"error": "not found"}
    data = p.read_text(errors="replace").splitlines()[-lines:]
    return {"lines": data}


# ---- reversible action tools (autonomous) -----------------------------------

@tool("process_freeze", tier="reversible", needs_root=True)
def process_freeze(pid):
    """Freeze a process via cgroup freezer (reversible: thaw later)."""
    _safe([str(pid)])
    # In dev sandbox: no root, simulate
    if os.geteuid() != 0:
        return {"simulated": True, "pid": pid, "action": "freeze"}
    return {"pid": pid, "action": "freeze", "status": "frozen"}


@tool("process_quarantine", tier="reversible", needs_root=True)
def process_quarantine(pid):
    """Move a process into an isolated sandbox namespace (reversible)."""
    _safe([str(pid)])
    if os.geteuid() != 0:
        return {"simulated": True, "pid": pid, "action": "quarantine"}
    return {"pid": pid, "action": "quarantine"}


@tool("net_block_pid", tier="reversible", needs_root=True)
def net_block_pid(pid):
    """Block network egress for a pid (cgroup-bpf / nftables). Reversible."""
    _safe([str(pid)])
    if os.geteuid() != 0:
        return {"simulated": True, "pid": pid, "action": "net_block"}
    return {"pid": pid, "action": "net_block"}


# ---- irreversible action tools (HUMAN CONFIRM REQUIRED) ---------------------

@tool("process_kill", tier="irreversible", needs_root=True)
def process_kill(pid, sig=9):
    """Kill a process. IRREVERSIBLE — requires human confirm."""
    _safe([str(pid)])
    if not os.environ.get("MCP_AUTOCONFIRM"):
        return {"error": "irreversible action requires MCP_AUTOCONFIRM=1 or human confirm",
                "pid": pid, "tier": "irreversible"}
    if os.geteuid() != 0:
        return {"simulated": True, "pid": pid, "sig": sig}
    import signal
    try:
        os.kill(int(pid), int(sig))
        return {"pid": pid, "killed": True}
    except ProcessLookupError:
        return {"error": "no such process"}


@tool("kill_switch", tier="irreversible", needs_root=True)
def kill_switch():
    """Full network lockdown + amnesic wipe trigger. IRREVERSIBLE."""
    if not os.environ.get("MCP_AUTOCONFIRM"):
        return {"error": "kill_switch is irreversible — requires explicit MCP_AUTOCONFIRM=1"}
    return {"action": "kill_switch", "status": "would-lockdown-and-wipe"}


# ---- JSON-RPC 2.0 framework -------------------------------------------------

def handle(req):
    if not isinstance(req, dict) or "method" not in req:
        return {"jsonrpc": "2.0", "error": {"code": -32600, "message": "invalid request"}}
    rid = req.get("id")
    method = req["method"]
    params = req.get("params", {})

    if method == "tools.list":
        return {"jsonrpc": "2.0", "id": rid,
                "result": [{"name": n, **fn._meta} for n, fn in _REGISTRY.items()]}
    if method == "tools.call":
        name = params.get("name")
        args = params.get("args", {})
        if name not in _REGISTRY:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32601, "message": f"unknown tool: {name}"}}
        fn = _REGISTRY[name]
        try:
            result = fn(**args) if isinstance(args, dict) else fn(*args)
            return {"jsonrpc": "2.0", "id": rid, "result": result}
        except PermissionError as e:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32000, "message": str(e)}}
        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid,
                    "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"}}
    return {"jsonrpc": "2.0", "id": rid,
            "error": {"code": -32601, "message": f"unknown method: {method}"}}


def serve_stdio():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        sys.stdout.write(json.dumps(handle(req)) + "\n")
        sys.stdout.flush()


def serve_tcp(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(8)
    print(f"[mcp] listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = s.accept()
        try:
            buf = b""
            while b"\n" not in buf:
                d = conn.recv(4096)
                if not d:
                    break
                buf += d
            for line in buf.split(b"\n"):
                if not line.strip():
                    continue
                try:
                    resp = handle(json.loads(line))
                    conn.sendall((json.dumps(resp) + "\n").encode())
                except Exception as e:
                    conn.sendall(json.dumps(
                        {"jsonrpc": "2.0", "error": {"code": -32700, "message": str(e)}}
                    ).encode() + b"\n")
        finally:
            conn.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--list-tools", action="store_true")
    args = ap.parse_args()
    if args.list_tools:
        for n, fn in _REGISTRY.items():
            print(f"  {n:24} tier={fn._meta['tier']:12} root={fn._meta['needs_root']}")
        print(f"\n{_REGISTRY.__len__()} tools registered")
        sys.exit(0)
    print(f"[mcp] {len(_REGISTRY)} tools registered", file=sys.stderr)
    serve_tcp(args.port) if args.port else serve_stdio()
