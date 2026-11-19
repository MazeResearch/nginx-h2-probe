# Validation lab

Reproduces the probe's validation matrix, including the misbehaviour
cases external reviewers care about. Artifacts (certs, the big test
file, built binaries) are generated locally by `setup.sh` and never
committed.

## One-time setup

```sh
./setup.sh          # self-signed cert + 16 MiB test file
```

## Validation targets

```sh
# vulnerable (official image) and patched (official image):
docker run -d --name nginx-vuln  -p 8443:443 \
  -v "$PWD/conf/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/certs:/etc/nginx/certs:ro" -v "$PWD/html:/usr/share/nginx/html:ro" \
  nginx:1.31.8
docker run -d --name nginx-patched -p 9443:443 \
  -v "$PWD/conf/nginx.conf:/etc/nginx/nginx.conf:ro" \
  -v "$PWD/certs:/etc/nginx/certs:ro" -v "$PWD/html:/usr/share/nginx/html:ro" \
  nginx:1.31.9

# ground truth: 1.31.8 source + the official h2 fix. The banner still
# says "nginx/1.31.8", deliberately modelling a backported distro build.
docker run -d --name nginx-srcbuild -v "$PWD:/src" \
  debian:bookworm-slim sh /src/build.sh
docker commit nginx-srcbuild nginx1318patched
docker run -d --name nginx-realpatched -p 10443:443 \
  -v "$PWD/conf/nginx.conf:/usr/local/nginx/conf/nginx.conf:ro" \
  -v "$PWD/certs:/etc/nginx/certs:ro" \
  -v "$PWD/html:/usr/share/nginx/html:ro" \
  nginx1318patched /usr/local/nginx/sbin/nginx -g "daemon off;"

# reviewer case: catch-all proxy_pass to a 3-second backend on a
# VULNERABLE front (must NOT produce a false "not vulnerable"):
docker run -d --name slow-backend -v "$PWD/slow_backend.py:/srv/sb.py:ro" \
  python:3-alpine python3 /srv/sb.py --sleep 3            # add --mimic for
SB_IP=$(docker inspect -f '{{.NetworkSettings.Networks}}{{.IPAddress}}' slow-backend)
sed "s|SLOW_BACKEND|$SB_IP|" conf/nginx-slowproxy.conf.template > /tmp/sp.conf
docker run -d --name nginx-slowproxy -p 12443:443 \
  -v /tmp/sp.conf:/etc/nginx/nginx.conf:ro \
  -v "$PWD/certs:/etc/nginx/certs:ro" nginx:1.31.8
```

## Running the probe (from inside the docker network only!)

Docker Desktop / NAT relays break TCP backpressure; the probe needs a
direct veth path, or results become INCONCLUSIVE (never wrong):

```sh
VULN_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nginx-vuln)
RP_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nginx-realpatched)
SP_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' nginx-slowproxy)

cd ..   # repo root
docker run --rm -v "$PWD:/work" -w /work python:3-alpine \
  python3 nginx-h2-probe.py check $VULN_IP --insecure    # -> VULNERABLE, exit 1
docker run --rm -v "$PWD:/work" -w /work python:3-alpine \
  python3 nginx-h2-probe.py check $RP_IP --insecure     # -> not vulnerable, exit 0
docker run --rm -v "$PWD:/work" -w /work python:3-alpine \
  python3 nginx-h2-probe.py check $SP_IP --insecure     # -> VULNERABLE via
                                                        #    TRACE (exit 1)
```

## Expected results (validated 2026-11-19)

| Target | Expected |
|---|---|
| nginx:1.31.8 (official) | VULNERABLE, over-max reproduced, exit 1 |
| nginx:1.31.9 / 1.30.7 (official) | not vulnerable, exit 0 |
| 1.31.8 source + official fix (banner "1.31.8") | not vulnerable, exit 0 |
| 1.31.8 behind catch-all proxy to 3s backend | VULNERABLE via TRACE, exit 1 (no false "patched") |
| same, backend mimics built-in pages | same (latency gate rejects the mimic) |
| HTTP/2 disabled | not exposed, exit 0 |
| unreachable host / cert failure | error (connection failed), exit 3 |

The misbehaviour cases (lax non-nginx servers, flood-guard kills, bare
closes, backend pages) are additionally pinned by unit tests with modelled
accountings (`tests/test_fake_server.py`), since real servers cannot
produce them on demand.

`staller.py` parks a backpressured connection for socket inspection
(`ss -tnm` from a `--network container:nginx-vuln` sidecar);
`exp_probe_seq.py` is a frame-level debug harness for the exact probe
sequence.
