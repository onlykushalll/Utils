# WLTIOS Guardian — Dev Environment Inventory

This documents exactly what was installed in the sandbox to develop the
Guardian, how it was installed (no root — everything userspace), and what runs
here vs on the WLTIOS target.

## Sandbox constraints

- **No root** (`sudo` requires a password). Everything installed userspace.
- **OS**: Debian 13 (trixie), kernel 5.10.134, 8 GB RAM, 8 GB disk, 4 CPU.
- **Approach**: `micromamba` (conda-forge) for the C toolchain + building
  YARA/libbpf from source into the env prefix.

## Installed toolchain (all in `/home/z/local/mamba/envs/guardian/`)

| Component        | Version   | Source                | Purpose                          |
|------------------|-----------|-----------------------|----------------------------------|
| clang/llvm       | 18.1.8    | conda-forge           | Compile eBPF programs (`-target bpf`) |
| lld              | 18.x      | conda-forge           | BPF linker                       |
| cmake/ninja      | latest    | conda-forge           | Build system                     |
| libbpf           | 1.8.0     | built from source     | eBPF userspace loader lib        |
| libelf           | 0.194     | conda-forge (elfutils)| libbpf dependency                |
| libpcap          | latest    | conda-forge           | Network capture (Layer 5)        |
| YARA             | 4.5.2     | built from source     | Layer 1 signature engine         |
| openssl/libcrypto| latest    | conda-forge           | YARA crypto backend              |
| sqlite3          | 3.53.2    | conda-forge           | FIM baseline DB                  |
| kernel uapi hdrs | 6.12.90   | linux-libc-dev .deb   | linux/bpf.h, linux/types.h       |
| Python ML stack  | sklearn 1.5.2, numpy 2.1.3, pandas 2.2.3 | pip/venv | Layer 4 anomaly ML |
| gcc (system)     | 14.x      | Debian base           | Daemon compilation (native)      |

## What works here vs on WLTIOS target

| Capability            | Dev sandbox           | WLTIOS target |
|-----------------------|-----------------------|---------------|
| Compile eBPF programs | YES (verified)        | YES           |
| Load/attach eBPF      | NO (no CAP_BPF)       | YES           |
| YARA scan             | YES (verified)        | YES           |
| FIM                   | YES (limited paths)   | YES           |
| Anomaly ML (train+check) | YES (verified)     | YES           |
| Enforcement actions   | simulated (no root)   | YES           |
| vmlinux.h generation  | NO (needs bpftool)    | YES (on target)|
| MCP deep-kernel tools | inspect tier works; action tier simulated | YES |

## How the toolchain was built (reproducible)

```bash
# 1. micromamba + conda env
curl -Ls https://micro.mamba.pm/api/micromamba/linux-64/latest | tar -xvj bin/micromamba
micromamba create -n guardian -c conda-forge clang=18.* llvm=18.* lld=18.* \
  cmake pkg-config make ninja sqlite libpcap zlib elfutils openssl

# 2. libbpf from source
git clone https://github.com/libbpf/libbpf && cd libbpf/src
make && make install PREFIX=$ENVPREFIX   # lands in lib64/

# 3. YARA from source (with crypto)
git clone https://github.com/VirusTotal/yara && cd yara && ./bootstrap.sh
LDFLAGS="-L$ENVPREFIX/lib" CPPFLAGS="-I$ENVPREFIX/include" LIBS="-lcrypto" \
  ./configure --prefix=$ENVPREFIX --disable-shared --enable-static
make && make install

# 4. kernel uapi headers (for linux/bpf.h, linux/types.h)
apt-get download linux-libc-dev    # no root needed
dpkg-deb -x linux-libc-dev*.deb /tmp/libc-dev
cp -r /tmp/libc-dev/usr/include/linux $ENVPREFIX/include-linux/
```

## Known issues / notes for GLM 5.2 (the builder)

1. **YARA hash module**: built with `-DHASH_MODULE` and `HAVE_LIBCRYPTO=1`, but
   the hash module object isn't being linked into libyara.a (the
   `module_list` registration isn't taking effect at link time). String/heuristic
   rules work fine. For production hash-based signatures, debug the YARA build
   so the hash module registers — likely needs `modules.c` recompiled after
   `make clean` with `HASH_MODULE` in CFLAGS, or a fresh `make` without `clean`.

2. **vmlinux.h**: not generated here (no bpftool). BPF programs use a minimal
   `include/guardian_vmlinux.h` with hand-defined types. On the WLTIOS target,
   generate the full vmlinux.h:
   ```bash
   bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
   ```
   then replace `#include "guardian_vmlinux.h"` with `#include "vmlinux.h"`.

3. **eBPF load/attach**: can't be tested here (no CAP_BPF). The compiled
   `.bpf.o` objects are valid eBPF ELF. On WLTIOS, write a `bpf_loader.c` that
   uses libbpf's `bpf_object__open_file()` + `bpf_object__load()` +
   `bpf_object__attach()` to load and attach the programs, then poll the
   ringbuf via `ring_buffer__poll()`.

4. **Daemon can't write /var/log/guardian.log** without root — it falls back to
   `./guardian.log` in cwd. On WLTIOS the daemon runs as root.

5. **Makefile recipe lines need tabs** — the Write tool saves spaces. If the
   Makefile is regenerated, run `sed -i 's/^        /\t/' Makefile`.

6. **BPF include chain**: don't include `<linux/bpf.h>` directly in BPF programs
   — it pulls the fragile `asm/types.h` multiarch chain. The hand-written
   `include/guardian_vmlinux.h` provides all needed types (u8..u64, __wsum,
   __sum16, enum bpf_map_type, struct task_struct, struct trace_event_raw_sys_enter,
   forward decls of kernel structs used by bpf_helper_defs.h).

## Build commands

```bash
cd /home/z/guardian
source activate.sh        # sets up the env
make all                  # bpf + sigs + guardian + ml
make test                 # daemon self-test
```

## Verified working (2026-06-26)

- `make bpf` -> `build/bpf/trace_execve.bpf.o` (valid eBPF ELF, 11 KB)
- `make sigs` -> `signatures/guardian.yarc` (9 KB, 6 rules)
- `make guardian` -> `build/guardian` (links conda static libs)
- `make ml` -> `ml/anomaly.pkl` (1 MB isolation forest, 4000 training samples)
- `./build/guardian --self-test` -> 9 self-tests pass (dedup, rate limiting,
  model hash, log quota, BPF action mapping, FIM encryption + tamper, API auth)
- `python3 ml/anomaly.py --check` -> correctly flags anomaly (score -0.17) vs clean (score +0.19)
- `python3 mcp/mcp_server.py` -> 11 tools, JSON-RPC process_list + file_forensics verified live
- `build/mcp_server --list-tools` -> 30 C tools (shell_exec + install_package
  removed in v1.4 security fix — see SECURITY.md)

## Security hardening history

| Version | Agent | Changes |
|---------|-------|---------|
| v1.0 | GLM 5.2 | Full skeleton: 5 layers + BPF + MCP + Kairos |
| v1.1 | Sonnet 4.6 | 25 bugs fixed (policy wiring, condition parser, forensic log) |
| v1.2 | Flash 3.5 | Phase 1: self-protection, rate limiting, pickle RCE |
| v1.3 | Flash 3.5 | Phase 2-3: kill switch latency, FIM encryption, BPF map hardening |
| v1.4 | Opus 4.6 | 14 fixes from stress-test audit (5 CRITICAL, 4 HIGH, 5 MEDIUM) |

See `SECURITY.md` in project root for full vulnerability registry.

