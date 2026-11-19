# AGENTS.md

Instructions for an AI agent pointed at this repo. A user will say something
like "check whether my nginx is vulnerable to the 2026 HTTP/2 RCE." Read this
file, then do it. The tool is one stdlib-only Python file, so there is nothing
to install: run `python3 nginx-h2-probe.py ...` (or `nginx-h2-probe ...` if it
is on PATH).

## What the tool does

Detects the 2026 nginx HTTP/2 RCEs.

* CVE-2026-123007 (HTTP/2 flow-control integer underflow) is actively probed.
  The tool sends a crafted-but-safe HTTP/2 sequence and reads how the server
  handles it, so the verdict holds even when the version banner is backported
  or hidden.
* CVE-2026-123633 (HTTP/2 connection use-after-free) is assessed from version
  and config only. It is never probed remotely, because triggering it is the
  DoS itself.

## The one rule that matters

Only probe hosts the user is authorized to test, and warn before doing anything
that sends traffic. If you are not certain the user owns or is allowed to test a
target, ask before any active probe. Passive and local checks are read-only and
need no warning.

## What you may run without asking

* `python3 nginx-h2-probe.py local` reads the local nginx version and config
  (`nginx -T`, may use `sudo -n`, never prompts). Read-only. Run this first when
  you are on the nginx host.
* `python3 nginx-h2-probe.py check HOST --passive --json` returns banner, ALPN
  and version ranges only. Zero active traffic.
* Reading the source, and `python3 -m unittest discover -s tests`.

## What you must warn the user about first

* The active check (`check HOST --json`, without `--passive`). Warn that it sends
  a few MB of crafted HTTP/2 traffic, takes 2 to 8 minutes, and leaves benign
  log lines on the target ("http2 flood detected", "client violated connection
  flow control"). Confirm the target is theirs, and take extra care with
  production. It is safe by design, since it never reaches the memory-corruption
  state, but it is still traffic to someone's server. Run it from a host with a
  direct TCP path to the target. NAT or relay paths (Docker Desktop on macOS,
  some container networks) break the backpressure the test relies on and give
  INCONCLUSIVE rather than a wrong answer; `docker run --network host` on Linux
  avoids this.
* `serve` on a non-loopback address. This stands up a service that will probe
  arbitrary targets. Only run it bound to `127.0.0.1`, or with `--token` if it
  must listen wider. Never expose it open.
* `--insecure`, which skips TLS certificate verification. Labs and self-signed
  origins only. Say so when you use it.

## Never do this

* Sweep IP ranges or probe hosts the user has not named and authorized.
* Expose `serve` to a network without a token.
* Present a passive version verdict as final. Backports and `server_tokens off`
  make the banner unreliable, so say the active test is what resolves it.
* Claim CVE-2026-123633 was confirmed remotely. It is version/config only.

## Recommended flow

1. On the nginx host? Run `local`. If it is conclusive, report and stop.
2. Otherwise run `check HOST --passive --json` and report version and ALPN.
3. If the version is in range, hidden, or uncertain, offer the active test. Warn
   (traffic, time, log lines), confirm authorization, then on an explicit yes
   run `check HOST --json`.
4. Read the result from JSON (keys below) and the exit code, not the prose.
5. If the host is vulnerable to 123007 and reverse-proxies (`proxy_pass` etc.),
   also flag CVE-2026-123633, and confirm it with `local` on the host.
6. If the result is VULNERABLE, give the remediation below.

## Reading the result

Use `--json`. Act on `exit_code`. The key fields are:

* `verdict`: one of `VULNERABLE`, `not-vulnerable/not-exposed`,
  `not-exposed (HTTP/2 not enabled on this endpoint)`, `INCONCLUSIVE`,
  `assessment-only (active test not run)`, `error (connection failed)`.
* `behavior_123007`: `vulnerable`, `patched`, `inconclusive`, or `null`.
* `over_max_confirmed`: true when the 123007 precondition was reproduced.
* `version`, `version_123007`, `version_123633`, `alpn_h2`, `notes`.

Exit codes:

| Code | Meaning | What to do |
|---|---|---|
| 0 | not vulnerable, or HTTP/2 not enabled | report safe; if passive, note the active test is stronger |
| 1 | VULNERABLE to CVE-2026-123007 | report and give remediation |
| 2 | INCONCLUSIVE | read `notes`; try `--path` at an endpoint nginx answers itself, `--flood-multiplier 2`, or `local`. If many hosts come back INCONCLUSIVE, you are probably behind NAT or Docker Desktop: run from a host with a direct TCP path to the targets |
| 3 | error (unreachable / TLS failure) | not a "safe" result; check reachability, `--sni`, or `--insecure` for labs |

## Remediation to hand the user

* Upgrade to nginx 1.30.7 (stable) or 1.31.9 (mainline). NGINX Plus: 37.0.8.1 or
  37.3.0.1 for 123007, and 37.0.7.1 or 37.2.0.1 for 123633.
* If you can't upgrade yet (nginx 1.25.1+): set `http2 off;` and drop `http2`
  from `listen` directives as a stopgap. This closes 123007 and 123633.
* After patching, restart nginx rather than reload it. A reload keeps the old
  worker binary serving existing connections.

Full detail is in the README and in `src/nginx_h2_probe/core.py`.
