#!/usr/bin/env bash
set -e
mkdir -p /tmp/clang-download
cd /tmp/clang-download
rm -f *.deb
apt-get download clang-18 libclang-cpp18 libllvm18 libclang-common-18-dev llvm-18-linker-tools libclang1-18
mkdir -p /mnt/c/Users/Default.L-HCG-9FVVGS3/OneDrive/Desktop/guardian/local-deps
for deb in *.deb; do
  dpkg-deb -x "$deb" /mnt/c/Users/Default.L-HCG-9FVVGS3/OneDrive/Desktop/guardian/local-deps
done
echo "Clang extraction completed successfully."
