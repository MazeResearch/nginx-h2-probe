#!/bin/sh
# Generates the lab's runtime artifacts (never committed):
#   lab/certs/{cert,key}.pem  -- throwaway self-signed cert
#   lab/html/big.bin          -- 16 MiB test file
#   lab/html/index.html
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$HERE/certs" "$HERE/html"
[ -f "$HERE/certs/cert.pem" ] || openssl req -x509 -newkey rsa:2048 \
    -keyout "$HERE/certs/key.pem" -out "$HERE/certs/cert.pem" \
    -days 30 -nodes -subj "/CN=probe-lab.local" 2>/dev/null
[ -f "$HERE/html/big.bin" ] || dd if=/dev/urandom \
    of="$HERE/html/big.bin" bs=1048576 count=16 2>/dev/null
echo "lab is a one-line placeholder page" > "$HERE/html/index.html"
echo "lab ready: certs + html generated in $HERE"
