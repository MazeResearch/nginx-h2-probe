#!/bin/sh
# Builds the ground-truth "patched" nginx: 1.31.8 source + the official
# h2 fix extracted from the release-1.31.8...release-1.31.9 diff
# (v2-fix.patch: the send_queued accounting + reusable-connection fix).
# The result still reports "nginx/1.31.8" in its banner -- deliberately,
# so it models a backported distro build for probe validation.
#
# Run inside a container with the lab mounted at /src, e.g.:
#   docker run -v "$PWD:/src" debian:bookworm-slim sh /src/build.sh
set -ex
cd /tmp

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    ca-certificates curl build-essential libpcre2-dev zlib1g-dev \
    libssl-dev patch >/dev/null

curl -fsSLO http://nginx.org/download/nginx-1.31.8.tar.gz
tar xzf nginx-1.31.8.tar.gz
cd nginx-1.31.8

# the h2 fix MUST apply cleanly -- a silently unpatched "patched" build
# would poison the validation matrix
patch -p1 --fuzz=1 < /src/v2-fix.patch

# and the patched check must be present in the built sources
grep -q "send_queued" src/http/v2/ngx_http_v2.c \
    || { echo "FATAL: v2 patch did not apply (ngx_http_v2.c)"; exit 1; }
grep -q "send_queued" src/http/v2/ngx_http_v2_filter_module.c \
    || { echo "FATAL: v2 patch did not apply (filter module)"; exit 1; }

./configure --with-http_v2_module --with-http_ssl_module \
    --with-cc-opt="-O2" >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
/usr/local/nginx/sbin/nginx -v
echo "GROUND TRUTH BUILD OK: 1.31.8 + official h2 fix (banner says 1.31.8)"
