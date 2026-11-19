"""nginx-h2-probe command line interface.

    nginx-h2-probe check example.com          # definitive verdict (default)
    nginx-h2-probe check example.com --passive # instant triage only
    nginx-h2-probe local                      # on-the-nginx-host checks
    nginx-h2-probe serve [--token SECRET]     # curl-friendly wrapper

For convenience the subcommand may be omitted for a plain target:

    nginx-h2-probe example.com               # same as: check example.com

Exit codes: 0 not vulnerable / not exposed, 1 vulnerable, 2 inconclusive,
3 error.
"""

import argparse
import json
import os
import sys

from nginx_h2_probe.core import run, result_dict, VERSION

_VERSION = VERSION

# ----------------------------------------------------------------------------
# pretty printing
# -----------------------------------------------------------------------------

def _use_color():
    if os.environ.get("NO_COLOR"):
        return False
    try:
        return os.isatty(sys.stdout.fileno())
    except Exception:
        return False


def _c(text, code, enabled):
    if not enabled:
        return text
    return "\033[%dm%s\033[0m" % (code, text)


def _verdict_color(res, code):
    if code == 1:
        return 31   # red
    if code == 2:
        return 33   # yellow
    return 32       # green


def recommendation(res, colored=True):
    b = res.behavior_123007
    if getattr(res, "connection_error", None):
        s = ("RESULT: ERROR -- could not complete TLS with the target.\n"
             "  No verdict is possible for this host. This is NOT a\n"
             "  \"not exposed\" result. See the notes (unreachable host,\n"
             "  or certificate validation failed: probe the real hostname\n"
             "  or pass --sni; use --insecure for lab targets).")
        return _c(s, 31, colored) if colored else s
    if b == "vulnerable" or res.over_max_confirmed:
        s = ("RESULT: VULNERABLE to CVE-2026-123007 on this endpoint.\n"
             "  The bounded over-maximum-window precondition of the\n"
             "  vulnerability was reproduced. Upgrade to nginx 1.30.7+\n"
             "  (stable), 1.31.9+ (mainline) or your vendor's backported\n"
             "  release. Until then disable HTTP/2 on this listener.\n"
             "  For CVE-2026-123633 (no safe remote probe exists): if this\n"
             "  server reverse-proxies and its version was in 1.19.7-\n"
             "  1.31.8, patch it too.")
        return _c(s, 31, colored) if colored else s
    if b == "patched":
        s = ("RESULT: NOT VULNERABLE to CVE-2026-123007 on this endpoint\n"
             "  (flow-control validation matches the fixed code).\n"
             "  For CVE-2026-123633: no safe remote probe exists; if this\n"
             "  server is a reverse proxy, verify the 1.30.7/1.31.9 fix\n"
             "  locally ('nginx-h2-probe local' or your vendor advisory).")
        return _c(s, 32, colored) if colored else s
    if b == "inconclusive":
        s = ("RESULT: INCONCLUSIVE for CVE-2026-123007.\n"
             "  See the notes above; usually fixed by re-running, using\n"
             "  --path with an endpoint the nginx answers itself (e.g. a\n"
             "  built-in error page), or --flood-multiplier 2.\n"
             "  The version/config assessment above still applies.")
        return _c(s, 33, colored) if colored else s
    if res.alpn_h2 is False:
        s = ("RESULT: HTTP/2 not enabled on this endpoint (for the\n"
             "  hostname/SNI tested) -> neither CVE-2026-123007 nor\n"
             "  CVE-2026-123633 is reachable here for this name.\n"
             "  HTTP/2 is enabled per virtual host since nginx 1.25.1:\n"
             "  test each hostname or pass --sni for full coverage.")
        return _c(s, 32, colored) if colored else s
    s = ("RESULT: version/config assessment only (active test not run).\n"
         "  Re-run without --passive for a behavioural verdict.")
    return _c(s, 33, colored) if colored else s


# ----------------------------------------------------------------------------
# subcommands
# -----------------------------------------------------------------------------

def cmd_check(args):
    ns = argparse.Namespace(
        target=args.target,
        port=args.port,
        sni=args.sni,
        path=args.path,
        active=not args.passive,
        flood_multiplier=args.flood_multiplier,
        flood_pings=args.flood_pings,
        insecure=args.insecure,
    )

    if ns.active and not args.json:
        print("[*] %s: active test selected -- this sends a few MB of safe, "
              "non-exploiting test traffic and takes 1-8 minutes."
              % ns.target, file=sys.stderr)
        print("[*] use --passive for an instant version-only triage; "
              "the README has the full safety analysis.",
              file=sys.stderr)

    if not args.json:
        ns.progress = lambda msg: print("[.] %s" % msg, file=sys.stderr)

    res, code = run(ns)

    if args.json:
        print(json.dumps(result_dict(res, code), indent=2))
    else:
        print()
        print(res.summary())
        print()
        print(recommendation(res, colored=_use_color()))
    return code


def cmd_local(_args):
    from nginx_h2_probe.local import run_local_checks
    return run_local_checks()


def cmd_serve(args):
    from nginx_h2_probe.server import serve_main
    argv = ["--listen", args.listen, "--port", str(args.port)]
    if args.token:
        argv += ["--token", args.token]
    serve_main(argv)
    return 0


# -----------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="nginx-h2-probe",
        description="Safe, reliable exposure check for the 2026 nginx "
                    "HTTP/2 RCEs (CVE-2026-123007, CVE-2026-123633). "
                    "Run only against systems you are authorized to test.",
        epilog="The active test is safe by design: it never creates the "
               "oversized-window state needed for memory corruption (see "
               "the README). Examples:\n"
               "  nginx-h2-probe check example.com\n"
               "  nginx-h2-probe check example.com --passive\n"
               "  nginx-h2-probe local\n"
               "  nginx-h2-probe serve --token SECRET\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="version",
                  version="nginx-h2-probe %s" % _VERSION)

    sub = p.add_subparsers(dest="cmd")

    c = sub.add_parser(
        "check", help="check a remote nginx endpoint (default command)",
        description="Checks a remote nginx endpoint for CVE-2026-123007 "
                    "(behavioural by default) plus a passive banner/version "
                    "assessment for both CVEs.")
    c.add_argument("target", help="hostname or IP of the nginx server")
    c.add_argument("--port", type=int, default=443)
    c.add_argument("--sni", default=None,
                   help="SNI / Host header (defaults to the target)")
    c.add_argument("--path", default=None,
                   help="path to request (default: a random nonexistent "
                        "path, using the server's built-in 404 page as a "
                        "small in-memory response)")
    c.add_argument("--passive", action="store_true",
                   help="instant passive triage only (banner, ALPN, "
                        "version ranges); skip the 1-8 min active test")
    c.add_argument("--insecure", action="store_true",
                   help="skip TLS certificate verification (labs only)")
    c.add_argument("--flood-multiplier", type=float, default=1.0,
                   help="scale the prefill flood (try 2 if INCONCLUSIVE "
                        "due to large server buffers)")
    c.add_argument("--flood-pings", type=int, default=None,
                   help="override the prefill flood size exactly (debug)")
    c.add_argument("--json", action="store_true",
                   help="machine-readable JSON output")
    c.set_defaults(func=cmd_check)

    l = sub.add_parser(
        "local", help="on-the-nginx-host checks (version, config, proxying)",
        description="Run on the nginx host itself: checks the binary "
                    "version, HTTP/2 module and listeners, HTTP/3 listeners "
                    "and reverse-proxy configuration. Definitive including "
                    "configuration.")
    l.set_defaults(func=cmd_local)

    s = sub.add_parser(
        "serve", help="run as an HTTP service (curl-friendly wrapper)",
        description="Exposes the probe over HTTP so any system can get a "
                    "verdict with plain curl: "
                    "GET /probe?target=HOST[&active=1]. Protect with "
                    "--token; run on a host with a direct TCP path to the "
                    "targets.")
    s.add_argument("--listen", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8080)
    s.add_argument("--token", default=None,
                   help="require &token=... on every request")
    s.set_defaults(func=cmd_serve)

    return p


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # convenience: a bare target is shorthand for "check <target>"
    known = {"check", "local", "serve", "-h", "--help", "--version"}
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        argv.insert(0, "check")

    p = build_parser()
    args = p.parse_args(argv)

    if not getattr(args, "cmd", None):
        p.print_help()
        return 3

    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())