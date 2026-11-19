"""HTTP wrapper mode: lets any system get the definitive verdict with
nothing but curl or a plain HTTP client (see nginx-h2_probe.cli `serve`).

    ./nginx-h2-probe.py serve --listen 127.0.0.1 --port 8080 --token SECRET
    curl 'http://localhost:8080/probe?token=SECRET&target=example.com'

The frame-level HTTP/2 test must run from a host with a direct TCP path
to the target (Docker Desktop / NAT relays in between will make active
results inconclusive rather than wrong). stdlib only.
"""

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from nginx_h2_probe.core import run, result_dict, FLOOD_MIN, FLOOD_MAX, VERSION

# active probes mutate the module-global flood size during calibration;
# serialise them so concurrent requests cannot interfere
_LOCK = threading.Lock()


class RequestError(Exception):
    pass


def _run_probe(params):
    target = params.get("target")
    if not target:
        raise RequestError("missing required parameter: target")
    try:
        port = int(params.get("port", ["443"])[0])
    except ValueError:
        raise RequestError("port must be an integer")
    try:
        flood_multiplier = float((params.get("flood_multiplier")
                                  or ["1"])[0])
    except ValueError:
        raise RequestError("flood_multiplier must be a number")
    flood_pings = None
    if "flood_pings" in params:
        try:
            flood_pings = int(params["flood_pings"][0])
        except ValueError:
            raise RequestError("flood_pings must be an integer")
        flood_pings = max(FLOOD_MIN, min(flood_pings, FLOOD_MAX))

    ns = argparse.Namespace(
        target=target[0].strip(),
        port=port,
        sni=(params.get("sni") or [None])[0],
        path=(params.get("path") or [None])[0],
        active=params.get("active", ["1"])[0] not in ("0", "false", "no"),
        flood_multiplier=flood_multiplier,
        flood_pings=flood_pings,
        insecure=params.get("insecure", ["0"])[0] in ("1", "true", "yes"),
    )

    started = time.time()
    # bounded wait: a second active check can take ~10 minutes; refuse
    # rather than pile up a thread per request
    if not _LOCK.acquire(timeout=30):
        return 503, {"error": "scanner busy: another active check is "
                     "running; retry shortly"}
    try:
        res, code = run(ns)
    except Exception as e:  # never leak a stack trace to the client
        return 500, {"error": "probe failed: %s" % str(e)[:200],
                     "target": ns.target}
    finally:
        _LOCK.release()

    out = result_dict(res, code)
    out["elapsed_seconds"] = round(time.time() - started, 1)
    return 200, out


def make_handler(token):
    class Handler(BaseHTTPRequestHandler):
        server_version = "nginx-h2-probe/%s" % VERSION
        protocol_version = "HTTP/1.1"

        def _send_json(self, status, obj):
            body = json.dumps(obj, indent=2).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            u = urlparse(self.path)
            params = parse_qs(u.query)

            if token and params.get("token", [""])[0] != token:
                self._send_json(403, {"error": "bad or missing token"})
                return

            if u.path == "/health":
                self._send_json(200, {"status": "ok",
                                      "active_probe_busy": _LOCK.locked()})
                return

            if u.path == "/probe":
                try:
                    status, obj = _run_probe(params)
                except RequestError as e:
                    self._send_json(400, {"error": str(e)})
                    return
                self._send_json(status, obj)
                return

            self._send_json(404,
                            {"error": "unknown path; use /probe or /health"})

        def log_message(self, fmt, *args):
            # never log query strings: they carry the token
            path = self.path.split("?", 1)[0]
            sys.stderr.write("[%s] %s %s\n" % (self.log_date_time_string(),
                                              self.client_address[0],
                                              path))

    return Handler


def serve_main(args=None):
    """Entry point for the `serve` subcommand."""
    ap = argparse.ArgumentParser(
        prog="nginx-h2-probe serve",
        description="HTTP wrapper for the probe (see module docstring)")
    ap.add_argument("--listen", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--token", default=None,
                    help="if set, every request must pass &token=...")
    ns = ap.parse_args(args)

    # a service that triggers deliberate traffic against arbitrary hosts
    # must not be reachable without an access token when it is not
    # loopback-only
    loopback = ns.listen in ("127.0.0.1", "::1", "localhost",
                             "", "*")
    if not loopback and not ns.token:
        sys.exit("refusing to listen on %s without --token: anyone able "
                 "to reach this service could use it to probe arbitrary "
                 "hosts. Pass --token SECRET (or bind 127.0.0.1)."
                 % ns.listen)

    httpd = ThreadingHTTPServer((ns.listen, ns.port),
                                 make_handler(ns.token))
    print("[*] probe server on http://%s:%d/probe?target=HOST[&active=1]"
          % (ns.listen, ns.port), file=sys.stderr)
    if ns.token:
        print("[*] token required on every request", file=sys.stderr)
    print("[*] only test targets you are authorized to test",
          file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass