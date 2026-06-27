#!/usr/bin/env python3
"""Phase 5.6: fuzz_mcp.py — fuzz the Guardian MCP server JSON-RPC parser.

Sends malformed JSON to the MCP Unix socket to find crashes.
Run AFTER starting build/mcp_server (which listens on /run/guardian.sock).

Usage:
    python3 tests/fuzz_mcp.py [--socket /run/guardian.sock] [--n 10000]
"""
import socket, json, random, string, argparse, sys, time

def random_junk(n):
    """Generate random byte strings that might crash a JSON parser."""
    choice = random.randint(0, 8)
    if choice == 0:  # valid JSON, huge string
        return json.dumps({"jsonrpc":"2.0","id":1,"method":"tools.call",
                           "params":{"name":"x"*100000,"args":{}}})
    if choice == 1:  # truncated JSON
        s = json.dumps({"jsonrpc":"2.0","id":1,"method":"tools.call"})
        return s[:random.randint(1, len(s)-1)]
    if choice == 2:  # deeply nested
        d = {}
        for _ in range(500): d = {"a": d}
        return json.dumps(d)
    if choice == 3:  # null bytes
        return json.dumps({"jsonrpc":"2.0","id":1}) + "\x00\x00\x00"
    if choice == 4:  # huge array
        return json.dumps([0]*1000000)
    if choice == 5:  # random bytes
        return bytes(random.randint(0,255) for _ in range(random.randint(1,4096)))
    if choice == 6:  # unicode edge cases
        return '{"jsonrpc":"2.0","id":1,"method":"\udce0\udc80"}'
    if choice == 7:  # method with null
        return '{"jsonrpc":"2.0","id":1,"method":null,"params":null}'
    if choice == 8:  # integer overflow in id
        return '{"jsonrpc":"2.0","id":99999999999999999999,"method":"x"}'

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--socket', default='/run/guardian.sock')
    ap.add_argument('--n', type=int, default=10000)
    args = ap.parse_args()

    crashes = 0
    sent = 0
    for i in range(args.n):
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(args.socket)
            payload = random_junk(i)
            if isinstance(payload, str): payload = payload.encode()
            s.sendall(payload)
            try: s.recv(4096)
            except socket.timeout: pass
            s.close()
            sent += 1
        except (ConnectionRefusedError, FileNotFoundError):
            print(f"[fuzz] socket unavailable — is mcp_server running?")
            sys.exit(1)
        except Exception as e:
            crashes += 1
            print(f"[fuzz] crash at iter {i}: {e}")
        if i % 1000 == 0:
            print(f"[fuzz] {i}/{args.n} sent, {crashes} crashes")
    print(f"\n[fuzz] DONE: {sent} sent, {crashes} crashes")

if __name__ == '__main__':
    main()
