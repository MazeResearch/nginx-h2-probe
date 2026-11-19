# Changelog

## 1.0.0 (2026-11-19)

First public release.

* Active behavioral detection of CVE-2026-123007 (nginx HTTP/2 flow-control
  integer underflow). The probe stages the flow-control state where patched and
  unpatched code diverge, so the verdict holds even when the version banner is
  backported or hidden. It stays near the 2^31 protocol maximum, well below the
  ~2^63 range where memory corruption starts, and sends only ordinary HTTP/2
  frames. Ambiguous cases are reported as INCONCLUSIVE rather than guessed, and
  an over-maximum control check rules out non-nginx HTTP/2 stacks.
* CVE-2026-123633 (HTTP/2 connection use-after-free) is assessed from version
  and config only. It is never probed remotely, since triggering it is the
  DoS/UAF itself.
* Branch-aware version assessment (fixed in 1.30.7 stable and 1.31.9 mainline).
  NGINX Plus is detected and its OSS-incompatible version is not judged; the
  remote behavioral check still works on Plus.
* Modes: remote `check` (active, or `--passive` for instant triage), on-host
  `local` (version, HTTP/2 module, listeners, reverse-proxy config), and `serve`
  (an HTTP wrapper for hosts that have only curl; token-protected, refuses to
  bind non-loopback without a token).
* Results as exit codes (0/1/2/3) and `--json`; the JSON verdict separates
  "patched" from "HTTP/2 not enabled".
* Stdlib-only Python 3.8+. Runs from a clone, as a single file, as a Docker
  image, or as `python -m nginx_h2_probe`.
* An AGENTS.md so a coding agent can run the checks with read-only defaults and
  warn before anything that sends traffic.
* Validated against official nginx 1.31.8 (vulnerable), 1.31.9 and 1.30.7
  (patched), and a 1.31.8 source build with the official fix whose banner still
  reads 1.31.8 (patched, modelling a distro backport). Reviewer misbehaviour
  cases are pinned by unit tests.
