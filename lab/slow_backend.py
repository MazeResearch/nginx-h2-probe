#!/usr/bin/env python3
"""Deliberately slow backend for lab testing of catch-all proxy_pass.

GET /*  -> sleeps SLEEP seconds, then returns a small 404-ish page.
The page body is configurable to mimic nginx's built-in error pages
(testing the front-vs-backend discrimination of the probe).

    python3 slow_backend.py [--sleep 3] [--mimic] [--port 8080]
"""
import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MIMIC_PAGE = (b"<html>\r\n<head><title>404 Not Found</title></head>\r\n"
              b"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
              b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        time.sleep(self.server.sleep_s)
        body = MIMIC_PAGE if self.server.mimic else (
            b"<html><head><title>slow app</title></head>"
            b"<body>slow application page, not nginx, " * 6 +
            b"</body></html>\n")
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_TRACE = do_GET   # only reached if the FRONT proxies TRACE

    def log_message(self, fmt, *args):
        pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sleep", type=float, default=3.0)
    ap.add_argument("--mimic", action="store_true")
    ap.add_argument("--port", type=int, default=8080)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    srv.sleep_s = args.sleep
    srv.mimic = args.mimic
    print("slow backend on :%d sleep=%.1fs mimic=%s"
          % (args.port, args.sleep, args.mimic), flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()