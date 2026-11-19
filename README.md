# nginx-h2-probe

**Safe remote scanner for CVE-2026-123007, the 2026 nginx HTTP/2 flow-control RCE.** It also flags CVE-2026-123633 (the HTTP/2 use-after-free RCE) from version and config, but does not actively probe it (see [Which CVE is actively probed](#which-cve-is-actively-probed)).

The active behavioral test is for **CVE-2026-123007**. One command tells you whether an endpoint runs the vulnerable code, even when the version banner lies (distro backports keep the old version string) or is hidden. The test can't crash or exploit a server. It reproduces the vulnerability's bookkeeping precondition in a bounded way, not anything memory-unsafe (details below).

> **Before you run it:** it's a single file, so read it first. Only probe hosts you're authorized to test. The active test is safe by design (see [Why this is safe to run on production](#why-this-is-safe-to-run-on-production)), but it does send a few MB of crafted HTTP/2 traffic.

```sh
$ nginx-h2-probe check www.example.com
[*] www.example.com: active test selected -- this sends a few MB of safe,
    non-exploiting test traffic and takes 1-8 minutes.
[.] active attempt 4/14: prefill 128000 pings
[.] active attempt 7/14: prefill 152000 pings
[.] attempt 152000 pings: over-maximum window state reproduced

target: www.example.com:443
ALPN h2 negotiated : True
Server banner      : nginx/1.31.8
CVE-2026-123007 behavior : VULNERABLE (flow-control validation matches unfixed
                            1.9.5-1.31.8 code)
send_window exceeded 2^31-1: YES -- CVE precondition reproduced (bounded, safe)

RESULT: VULNERABLE to CVE-2026-123007 on this endpoint.  (exit code 1)
```

## Run it (no install needed)

Pure Python 3.8+, zero third-party dependencies. The whole tool is the single file `nginx-h2-probe.py`, so there is nothing to install.

```sh
# clone and run (simplest):
git clone https://github.com/MazeResearch/nginx-h2-probe
python3 nginx-h2-probe/nginx-h2-probe.py check www.example.com

# or download just the one file and run it anywhere:
curl -fsSL -O https://raw.githubusercontent.com/MazeResearch/nginx-h2-probe/main/nginx-h2-probe.py
python3 nginx-h2-probe.py check www.example.com
```

Two optional extras. `pip install .` from a clone puts a `nginx-h2-probe` command on your PATH (the examples below use that short form; `python3 nginx-h2-probe.py` works identically). Docker is handy when you need to run from a host that can reach the origin:

```sh
docker build -t nginx-h2-probe .
docker run --rm --network host nginx-h2-probe check www.example.com
```

Passive-only triage (instant, zero active traffic): add `--passive`. JSON output for CI: add `--json`.

## Use it with an AI agent

Point a coding agent at this repo and let it run the check. It reads [AGENTS.md](AGENTS.md), which tells it to stay read-only by default, warn you before anything that sends traffic, and only probe hosts you've said you're allowed to test.

Copy-paste prompt:

> Clone https://github.com/MazeResearch/nginx-h2-probe and read its AGENTS.md. Check whether `HOST` is vulnerable to the 2026 nginx HTTP/2 RCE (CVE-2026-123007). Start passive and read-only, and warn me before you send any active traffic or probe anything you're not sure I'm allowed to test.

## Which CVE is actively probed

* **CVE-2026-123007** (HTTP/2 flow-control integer underflow, affects nginx 1.9.5-1.31.8): **actively probed.** The behavioral test returns a VULNERABLE / not-vulnerable verdict based on how the server handles the flow-control sequence, independent of the version banner.
* **CVE-2026-123633** (HTTP/2 connection use-after-free, affects 1.19.7-1.31.8): **not probed remotely.** Triggering it means exhausting the server's connection slots, which is the DoS/UAF itself. It is reported from the banner version and, with the `local` subcommand, the reverse-proxy config. If a host is vulnerable to 123007 and reverse-proxies (`proxy_pass` etc.), treat 123633 as exposed too.

Both fixed in nginx 1.30.7 (stable) and 1.31.9 (mainline).

## Why this is safe to run on production

The memory corruption in CVE-2026-123007 only becomes reachable once the connection flow-control window is driven to values near 2^63. This probe drives the window to about 2^31 (the RFC 9113 maximum) plus a small overshoot, well below that range, and uses only ordinary HTTP/2 frames (GET, PING, WINDOW_UPDATE, RST_STREAM). It targets the bookkeeping precondition, not the corruption itself. On a patched server the effect should be ordinary FLOW_CONTROL_ERROR handling, the same as any non-conforming client.

It is still live traffic to someone's server: a few MB per run, 2-8 minutes (worst ~15, up to 14 calibration attempts), and some benign log noise ("http2 flood detected", "client violated connection flow control"). Read the code first, test in a lab if you can, and only run it against hosts you are authorized to test.

## What it reports

| Verdict | Meaning | Exit |
|---|---|---|
| `VULNERABLE` | flow-control validation matches unfixed 1.9.5-1.31.8 code; the bounded over-maximum precondition was reproduced | 1 |
| `not-vulnerable/not-exposed` | validation matches fixed code | 0 |
| `not-exposed (HTTP/2 not enabled)` | HTTP/2 was not negotiated for the name tested, so the CVEs are not reachable here | 0 |
| `INCONCLUSIVE` | could not obtain a decisive answer (notes explain what to change) | 2 |
| `assessment-only` | passive mode: banner/ALPN/version ranges only | 0 |

The verdict above is for CVE-2026-123007. CVE-2026-123633 is reported as a version/config assessment only (see [Which CVE is actively probed](#which-cve-is-actively-probed)); the `local` subcommand, run on the nginx host, checks the proxy configuration directly.

## Commands

```sh
nginx-h2-probe check HOST [options]   # remote check (default command)
    --port 443  --sni SNI  --path /x  --passive  --json  --insecure
    --flood-multiplier 2   # retry hint for INCONCLUSIVE results
nginx-h2-probe local                 # on-the-nginx-host checks
nginx-h2-probe serve [--token S]      # HTTP wrapper (curl-friendly)
```

A bare target works too: `nginx-h2-probe example.com`. The package also runs as a module: `python -m nginx_h2_probe check example.com`.

### Library use

```python
from nginx_h2_probe import check

result = check("origin.example.com", active=True)
result["verdict"]             # "VULNERABLE" | "not-vulnerable/not-exposed" | "inconclusive"
result["over_max_confirmed"]  # was the CVE-2026-123007 precondition reproduced?
```

### Scanner service (for systems with nothing but curl)

```sh
nginx-h2-probe serve --listen 127.0.0.1 --port 8080 --token SECRET
curl 'http://scanner:8080/probe?token=SECRET&target=origin.example.com&active=1'
# -> {"verdict": "VULNERABLE", "over_max_confirmed": true, ...}
```

Probes run one at a time. Protect the service with `--token`, and only point it at targets you are authorized to test.

## Limitations

* Test the origin directly. A CDN or WAF that terminates HTTP/2 (or rewrites its control frames) makes the probe test the edge, not your nginx, and may return INCONCLUSIVE.
* Run from a host with a direct TCP path. NAT or relay paths (Docker Desktop on macOS, some container networks) break the backpressure the test needs and return INCONCLUSIVE, not a wrong answer; `docker run --network host` on Linux avoids it.
* HTTP/2 is per virtual host since nginx 1.25.1, so a bare IP only tests the default server block. Pass `--sni` per hostname.
* The probe needs a response nginx generates itself; it falls back to TRACE, and returns INCONCLUSIVE if even that is intercepted rather than guessing. Use `--path` or `local` for awkward proxy chains.
* Banner/version assessment can be wrong either way (backports, `server_tokens off`); the active test is what resolves it.
* NGINX Plus uses its own build numbers, so `local` declines a version verdict for it (exit 2) and points to F5's advisories; the remote active check still works.

## How it works

The official fix (1.30.7/1.31.9) changed nginx's connection WINDOW_UPDATE check from `MAX - send_window` to `MAX - send_window - send_queued`, so fixed code counts queued-but-unsent DATA when enforcing the 2^31−1 maximum. The probe stages a state where vulnerable and fixed code must disagree on a legal update: buffers pre-filled with PING ACKs, a small in-memory response queued but unwritten, connection window at exactly 2^31−1. Then a WINDOW_UPDATE of 3/2×B (vulnerable accepts, fixed rejects), an RST_STREAM (the credit refund crosses 2^31−1 only on unfixed code, the CVE's precondition, bounded), and a final update of 2×B (accepted only via the underflowed check). Marker PINGs classify which step any rejection came from, and an auto-calibrating flood adapts the buffer fill to the target. Full detail is in `src/nginx_h2_probe/core.py`, which is heavily commented and whose docstring contains the complete safety analysis.

Why not curl/requests/httpx? No HTTP client library can emit the custom WINDOW_UPDATE increments, burst-paced PINGs and timed RST_STREAM this needs. The probe is a protocol conformance instrument (like a TLS scanner), not an API client, and is stdlib-only by design.

## Development

```sh
python -m unittest discover -s tests -v   # unit tests
python scripts/build_standalone.py        # regenerate the single-file build
docker build -t nginx-h2-probe .          # build the image
```

Contributions welcome. The safety invariants are documented in [CONTRIBUTING.md](CONTRIBUTING.md).

## References

* Maze write-up: <https://mazehq.com/blog/nginx-http2-rce>
* Wiz: <https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities>
* Rapid7: <https://www.rapid7.com/blog/post/ve-cve-2026-123007-critical-nginx-http-2-integer-underflow-leads-to-rce-fixed/>
* Xint (nginx2root): <https://xint.io/blog/nginx2root-remote-code-execution>
* nginx.org advisories: <https://nginx.org/en/security_advisories.html>
* F5: K000163926 (123007), K000163928 (123633)

## License

MIT, provided as is with no warranty. See [LICENSE](LICENSE).
