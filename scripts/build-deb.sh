#!/usr/bin/env bash
# Build the Debian package. Run from anywhere inside the repo.
#   sudo apt install debhelper maven default-jdk-headless
set -euo pipefail
cd "$(dirname "$0")/.."

missing=()
command -v dpkg-buildpackage >/dev/null || missing+=(dpkg-dev)
command -v dh >/dev/null || missing+=(debhelper)
command -v mvn >/dev/null || missing+=(maven)
command -v javac >/dev/null || missing+=(default-jdk-headless)
if ((${#missing[@]})); then
    echo "Missing build tools. Fix with:  sudo apt install ${missing[*]}" >&2
    exit 1
fi

# -us -uc: unsigned; -b: binary only. dpkg-buildpackage drops the .deb in
# the PARENT of the repo. Skip the tests with DEB_BUILD_OPTIONS=nocheck.
dpkg-buildpackage -us -uc -b

deb=$(ls -t ../jnkpu_*.deb | head -1)
echo
echo "Built:   $deb"
echo "Install: sudo apt install $(cd "$(dirname "$deb")" && pwd)/$(basename "$deb")"
