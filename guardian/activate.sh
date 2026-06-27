#!/usr/bin/env bash
# Guardian dev environment activation script.
# Source this:  source activate.sh
# Sets up the micromamba `guardian` env (clang, libbpf, yara, etc.) + kernel uapi headers.

export MAMBA_ROOT_PREFIX=/home/z/local/mamba
GUARDIAN_ENV=/home/z/local/mamba/envs/guardian

if [ ! -d "$GUARDIAN_ENV" ]; then
  echo "ERROR: guardian env not found at $GUARDIAN_ENV" >&2
  echo "Run the setup first." >&2
  return 1 2>/dev/null || exit 1
fi

# Put env tools on PATH
export PATH="$GUARDIAN_ENV/bin:$PATH"

# Toolchain
export CC=clang
export CXX=clang++
export AR=llvm-ar
export NM=llvm-nm
export RANLIB=llvm-ranlib

# Include / lib search paths
export GUARDIAN_PREFIX="$GUARDIAN_ENV"
export CFLAGS="-I$GUARDIAN_ENV/include -I$GUARDIAN_ENV/include-linux -I$GUARDIAN_ENV/include-linux/linux -I$GUARDIAN_ENV/include-linux/asm-generic -I$GUARDIAN_PREFIX/include -O2 -g -Wall"
export CXXFLAGS="$CFLAGS"
export LDFLAGS="-L$GUARDIAN_ENV/lib -L$GUARDIAN_ENV/lib64"
export PKG_CONFIG_PATH="$GUARDIAN_ENV/lib/pkgconfig:$GUARDIAN_ENV/lib64/pkgconfig"

# Convenience
export GUARDIAN_ROOT=/home/z/guardian

echo "[guardian] env active"
echo "[guardian]   clang:      $(clang --version | head -1)"
echo "[guardian]   yara:       $(yara --version 2>/dev/null || echo n/a)"
echo "[guardian]   libbpf:     $(ls $GUARDIAN_ENV/lib/libbpf.a 2>/dev/null && echo static || echo missing)"
echo "[guardian]   BTF source: /sys/kernel/btf/vmlinux ($(du -h /sys/kernel/btf/vmlinux 2>/dev/null | cut -f1 || echo n/a))"
echo "[guardian]   root:       $GUARDIAN_ROOT"
