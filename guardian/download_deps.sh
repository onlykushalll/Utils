#!/usr/bin/env bash
set -e
mkdir -p /tmp/apt-download
cd /tmp/apt-download
rm -f *.deb
apt-get download libbpf-dev libyara-dev libelf-dev zlib1g-dev libsqlite3-dev libssl-dev
mkdir -p /mnt/c/Users/Default.L-HCG-9FVVGS3/OneDrive/Desktop/guardian/local-deps
for deb in *.deb; do
  dpkg-deb -x "$deb" /mnt/c/Users/Default.L-HCG-9FVVGS3/OneDrive/Desktop/guardian/local-deps
done
echo "Extraction completed successfully."
