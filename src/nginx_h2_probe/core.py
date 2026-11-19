"""
nginx_h2_probe.core -- the CVE-2026-123007 differential probe.

Safe, reliable detection of the 2026 nginx HTTP/2 RCE family
(CVE-2026-123007 and, as a version/config assessment, CVE-2026-123633)
on endpoints reachable over TLS.

The logic in this module is the validated original implementation; it is
deliberately stdlib-only (socket + ssl + struct) so the tool can be run
as a single file, installed as a package, or shipped in a container
without any third-party dependencies.

How it works (CVE-2026-123007):

  The official fix (1.30.7 / 1.31.9) changed nginx's connection-level
  WINDOW_UPDATE validation from

      if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window)

  to

      if (window > NGX_HTTP_V2_MAX_WINDOW - h2c->send_window
                                                    - h2c->send_queued)

  i.e. fixed nginx counts queued-but-unsent DATA reservations when
  enforcing the 2^31-1 flow-control maximum, and rejects updates that
  would exceed it (FLOW_CONTROL_ERROR). Unfixed nginx ignores queued DATA
  and accepts them. The probe creates a state where the two disagree on
  a legal update, and classifies the server's reaction:

   1. Preflight GET of a random nonexistent path: nginx's built-in 404
      page is a small in-memory body; its size B is measured normally.
   2. The connection window is raised to exactly 2^31-1 (RFC 9113 legal)
      and a burst-limited PING flood fills the server's TLS and TCP send
      buffers with PING ACKs (control frames), so the probe response is
      created but cannot be written out.
   3. A WINDOW_UPDATE of 3/2*B: at that point send_window is 2^31-1-2*B;
      unfixed code always accepts (it ignores queued DATA), fixed code
      rejects it as long as fewer than B/2 response bytes were written,
      which the prefill guarantees.
   4. RST_STREAM: the credit refund pushes send_window past 2^31-1 only
      on unfixed code -- the exact CVE-2026-123007 precondition, in a
      bounded way (the window stays near 2^31; the memory corruption
      path of the real exploit needs ~2^63, a factor of ~4e9 away).
   5. A WINDOW_UPDATE of 2*B: unfixed code's bounds check has now
      underflowed and accepts anything; any implementation whose
      accounting stayed within bounds rejects it. Marker PINGs between
      the steps classify which update a rejection came from.

  The prefill flood size is auto-calibrated per target by bisection:
  too small and the response still gets written (ambiguous, retry
  bigger), too big and ACK frames exceed nginx's 10000-frame guard and
  kill the connection (retry smaller). Ambiguous outcomes return
  INCONCLUSIVE, never a guess. Unfixed code can never reject step 3
  (3/2*B <= 2*B), so a rejection there is conclusive for fixed code;
  acceptance of both steps 3 and 5 proves the over-maximum state.

Safety properties:

  * Never creates the oversized-window state used for memory corruption
    (window stays near 2^31, corruption needs ~2^63).
  * Only ordinary frames: GET, PING, WINDOW_UPDATE, RST_STREAM, GOAWAY.
  * Traffic: a few MB per attempt; a full run typically 10-60 MB, worst
    case (14 calibration attempts at the maximum prefill) ~250 MB.
    Typical duration 2-8 minutes, worst case ~15.
  * Expected target log noise: the prefill can trip nginx's "http2 flood
    detected" guard during calibration, and a rejected test update logs
    "client violated connection flow control" -- both are normal probe
    noise, not attacks.
  * On a patched server the only effect is standard, RFC-mandated
    FLOW_CONTROL_ERROR handling.
  * Validated against nginx 1.31.8 (vulnerable, deterministic), 1.31.9
    and 1.30.7 official images, and a source build of 1.31.8 with the
    official patch (all patched), plus an HTTP/2-disabled endpoint.

CVE-2026-123633 (HTTP/2 reuse UAF) is deliberately NOT probed remotely:
triggering it requires exhausting the server's free connection slots and
an allocation failure -- i.e. the DoS/UAF itself. The tool reports a
version/config assessment only; use the ``local`` checks on the host for
the reverse-proxy question.
"""

import argparse  # only for the Namespace-based run() interface
import ipaddress
import json
import random
import re
import socket
import ssl
import struct
import time

VERSION = "1.0.0"

MAX_WINDOW = (1 << 31) - 1          # 0x7fffffff, NGX_HTTP_V2_MAX_WINDOW
DEFAULT_WINDOW = 65535

# HTTP/2 frame types
FRAME_DATA = 0x0
FRAME_HEADERS = 0x1
FRAME_RST_STREAM = 0x3
FRAME_SETTINGS = 0x4
FRAME_PING = 0x6
FRAME_GOAWAY = 0x7
FRAME_WINDOW_UPDATE = 0x8

# h2 error codes
ERR_NO_ERROR = 0x0
ERR_FLOW_CONTROL_ERROR = 0x3
ERR_CANCEL = 0x8

FLAG_END_STREAM = 0x1
FLAG_ACK = 0x1
FLAG_END_HEADERS = 0x4

HTTP2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

FLOOD_TAG = b"pr0befl0"      # PING payload, exactly 8 bytes
MARK_PRE = b"p1-mark-"       # sent between the first update and the RST
MARK_FINAL = b"pA-mark-"     # sent after the second update

# Flood sizing: the goal is to fill the server's TLS buffer (16 KB class)
# + TCP send buffer (Linux autotunes to ~4 MB) + our own receive buffer.
# Each PING yields a 17-byte ACK. Two nginx guards bound the flood:
#   - 10000 concurrently allocated frames per h2 connection (hence
#     bursts, so ACK frames are recycled as they drain into the socket)
#   - the 8:1 input/output flood detector (~8 MB input budget)
FLOOD_PINGS = 64000          # read-only default; never mutated at runtime
FLOOD_BURST = 2000
FLOOD_BURST_GAP = 0.02
FLOOD_MIN = 4000
FLOOD_MAX = 480000

PREFLIGHT_READ_CAP = 256 * 1024
MIN_BODY = 32
DRAIN_BUDGET_BYTES = 32 * 1024 * 1024
DRAIN_BUDGET_SECONDS = 45.0

# A verdict is only issued when the probe response is generated by the
# FRONT server itself, synchronously, in memory. nginx's built-in error
# pages satisfy this: small, contain "<center>nginx", and (for methods
# nginx rejects before location handling, like TRACE) cannot come from a
# backend at all. Everything else -> INCONCLUSIVE, never a guess.
BUILTIN_MARKER = b"<center>nginx"
MAX_BUILTIN_BODY = 4096
PREFLIGHT_MAX_LATENCY = 2.5    # front-generated pages arrive in ~RTT;
                               # a slow backend (proxying) does not

# candidate request methods, in order. GET first (validated path, innocuous);
# TRACE as fallback: nginx answers it itself with a built-in 405 before
# location/proxy handling, so it defeats catch-all proxy_pass and slow or
# mimicking backends. Each candidate runs on a fresh connection so the
# window arithmetic stays exactly the validated form.
CANDIDATE_METHODS = ("GET", "TRACE")

VULN_RANGE_123007 = ((1, 9, 5), (1, 31, 8))   # mainline progression
VULN_RANGE_123633 = ((1, 19, 7), (1, 31, 8))
# NOTE: the ranges are branch-aware in reality -- nginx maintains a
# mainline and a stable branch cut from it. Officially fixed releases are
# 1.31.9+ (mainline) and 1.30.7+ (stable 1.30.x). A version like 1.30.7
# falls numerically inside 1.9.5-1.31.8 but is PATCHED, so the plain
# tuple range must not be used directly for assessment.


def version_vulnerable(v, first_affected):
    """Branch-aware vulnerable-code check for the 2026-11-18 nginx h2
    security fixes (123007/123633 shipped together in 1.31.9 / 1.30.7)."""
    if v >= (1, 31, 9):                      # mainline fixed
        return False
    if (1, 30, 7) <= v < (1, 31, 0):         # stable 1.30.x fixed
        return False
    return v >= first_affected


def _no_progress(_msg):
    pass


# ---------------------------------------------------------------------------
# result object
# ---------------------------------------------------------------------------

class ProbeResult:
    def __init__(self):
        self.target = None
        self.alpn_h2 = None
        self.server_banner = None
        self.version = None
        self.version_123007 = None
        self.version_123633 = None
        self.probe_path = None
        self.probe_method = None
        self.body_size = None
        self.probe_increment = None
        self.data_before_goaway = None
        self.behavior_123007 = None     # vulnerable|patched|inconclusive|None
        self.over_max_confirmed = None  # True|False|None
        self.connection_error = None    # True if TLS/TCP to target failed
        self.notes = []

    def to_json(self):
        return json.dumps(self.__dict__, indent=2, default=str)

    def summary(self):
        L = []
        L.append("target: %s" % self.target)
        L.append("ALPN h2 negotiated : %s" % self.alpn_h2)
        L.append("Server banner      : %s" % (self.server_banner or "(none)"))
        if self.version:
            L.append("banner version     : %s (may be backported or hidden)"
                     % self.version)
        if self.version_123007:
            L.append("CVE-2026-123007 version range: %s" % self.version_123007)
        if self.version_123633:
            L.append("CVE-2026-123633 version range: %s" % self.version_123633)
        if self.probe_path:
            L.append("probe request     : %s %s" % (self.probe_method or "GET",
                                                    self.probe_path))
        if self.body_size is not None:
            L.append("response body size : %s bytes" % self.body_size)
        if self.probe_increment is not None:
            L.append("test WINDOW_UPDATE : %s bytes" % self.probe_increment)
        if self.data_before_goaway is not None:
            L.append("response bytes already sent at rejection: %s"
                     % self.data_before_goaway)
        L.append("CVE-2026-123007 behavior  : %s" % fmt_behaviour(
            self.behavior_123007))
        if self.over_max_confirmed is not None:
            L.append("send_window exceeded 2^31-1: %s"
                     % ("YES -- CVE precondition reproduced (bounded, safe)"
                        if self.over_max_confirmed else "no"))
        for n in self.notes:
            L.append("note: %s" % n)
        return "\n".join(L)


def fmt_behaviour(b):
    return {
        "vulnerable": ("VULNERABLE (flow-control validation matches unfixed "
                       "1.9.5-1.31.8 code)"),
        "patched": ("PATCHED / RFC-correct (connection terminated with "
                    "FLOW_CONTROL_ERROR; matches 1.30.7/1.31.9+)"),
        "inconclusive": "INCONCLUSIVE",
        None: "not tested",
    }[b]


def version_assessment(version):
    v = tuple(int(x) for x in version.split("."))
    a = ("in vulnerable range (1.9.5-1.31.8, excluding the fixed 1.30.7+ "
         "stable branch) -- treat as vulnerable unless a vendor backport "
         "is confirmed"
         if version_vulnerable(v, VULN_RANGE_123007[0])
         else "not in vulnerable range")
    b = ("in vulnerable range (1.19.7-1.31.8, excluding 1.30.7+)"
         if version_vulnerable(v, VULN_RANGE_123633[0])
         else "not in vulnerable range")
    return a, b


def in_range(v, lo, hi):
    return lo <= v <= hi


def result_dict(res, code):
    """Common machine-readable view of a finished probe run."""
    out = json.loads(res.to_json())
    out["exit_code"] = code
    if getattr(res, "connection_error", None):
        out["verdict"] = "error (connection failed)"
    elif getattr(res, "alpn_h2", None) is False:
        # HTTP/2 was not negotiated: the CVEs are not reachable on this
        # endpoint for the name tested. Distinct from "patched" so
        # automation does not read it as "the active test passed".
        out["verdict"] = "not-exposed (HTTP/2 not enabled on this endpoint)"
    elif out.get("behavior_123007") is None:
        out["verdict"] = "assessment-only (active test not run)"
    else:
        out["verdict"] = {0: "not-vulnerable/not-exposed",
                          1: "VULNERABLE",
                          2: "inconclusive"}.get(code, "error")
    return out


# ---------------------------------------------------------------------------
# tiny HTTP/2 framing layer (deliberately hand-rolled: no HTTP client
# library can emit the custom WINDOW_UPDATE/PING/RST frames this test
# needs -- see module docstring)
# ---------------------------------------------------------------------------

def h2_frame(ftype, flags, stream_id, payload=b""):
    return (struct.pack(">I", len(payload))[1:] +
            bytes([ftype, flags]) +
            struct.pack(">I", stream_id & 0x7FFFFFFF) +
            payload)


def hpack_int(value, prefix_bits):
    """RFC 7541 section 5.1 integer encoding (prefix bits assumed zero)."""
    out = b""
    max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        return bytes([value])
    out += bytes([max_prefix])
    value -= max_prefix
    while value >= 128:
        out += bytes([(value & 0x7F) | 0x80])
        value >>= 7
    out += bytes([value])
    return out


def hpack_request(headers):
    """Literal header field without indexing, no huffman."""
    out = b""
    for name, value in headers:
        name = name.encode()
        value = value.encode()
        out += b"\x00"
        out += hpack_int(len(name), 7) + name
        out += hpack_int(len(value), 7) + value
    return out


def send_headers(sock, stream_id, headers):
    payload = hpack_request(headers)
    sock.sendall(h2_frame(FRAME_HEADERS,
                          FLAG_END_HEADERS | FLAG_END_STREAM, stream_id,
                          payload))


def send_window_update(sock, stream_id, increment):
    if increment <= 0 or increment > MAX_WINDOW:
        raise ValueError("bad window update increment %d" % increment)
    sock.sendall(h2_frame(FRAME_WINDOW_UPDATE, 0, stream_id,
                          struct.pack(">I", increment)))


def send_ping(sock, payload):
    sock.sendall(h2_frame(FRAME_PING, 0, 0, payload.ljust(8, b"0")[:8]))


def send_ping_ack(sock, payload):
    sock.sendall(h2_frame(FRAME_PING, FLAG_ACK, 0, payload[:8]))


def send_rst_stream(sock, stream_id, err):
    sock.sendall(h2_frame(FRAME_RST_STREAM, 0, stream_id, struct.pack(">I", err)))


def send_goaway(sock, last_stream_id, err=ERR_NO_ERROR):
    sock.sendall(h2_frame(FRAME_GOAWAY, 0, 0,
                          struct.pack(">II", last_stream_id & 0x7FFFFFFF, err)))


class ConnectionClosed(Exception):
    pass


class FrameReader:
    """Buffered TLS-stream reader yielding (type, flags, stream_id, payload)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self, timeout):
        self.sock.settimeout(timeout)
        try:
            chunk = self.sock.recv(262144)
        except socket.timeout:
            return False
        except (ConnectionResetError, ssl.SSLError, OSError) as e:
            raise ConnectionClosed(str(e))
        if not chunk:
            raise ConnectionClosed("connection closed by remote")
        self.buf += chunk
        return True

    def next_frame(self, timeout):
        while True:
            if len(self.buf) >= 9:
                length = int.from_bytes(self.buf[0:3], "big")
                if len(self.buf) >= 9 + length:
                    ftype = self.buf[3]
                    flags = self.buf[4]
                    stream_id = int.from_bytes(self.buf[5:9], "big") & 0x7FFFFFFF
                    payload = self.buf[9:9 + length]
                    self.buf = self.buf[9 + length:]
                    return ftype, flags, stream_id, payload
            if not self._fill(timeout):
                return None


# ---------------------------------------------------------------------------
# TLS plumbing
# ---------------------------------------------------------------------------

def tls_connect(host, port, sni, insecure, alpn):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(alpn)

    s = socket.create_connection((host, port), timeout=20)
    try:
        # Small receive buffer so our kernel stops advertising TCP window
        # quickly; this bounds how much response data can flow to us.
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 16 * 1024)
    except OSError:
        pass
    s.settimeout(20)
    return ctx.wrap_socket(s, server_hostname=sni or host)


def h2_handshake(sock):
    """Send preface + SETTINGS; read and ACK server SETTINGS. Returns reader."""
    sock.sendall(HTTP2_PREFACE)
    sock.sendall(h2_frame(FRAME_SETTINGS, 0, 0))
    reader = FrameReader(sock)
    ftype, flags, sid, payload = reader.next_frame(10)
    if ftype != FRAME_SETTINGS:
        raise RuntimeError("expected server SETTINGS, got frame type %d"
                           % ftype)
    sock.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0))
    return reader


# ---------------------------------------------------------------------------
# probe steps
# ---------------------------------------------------------------------------

def get_banner_http1(host, port, sni, insecure, path="/"):
    banner = None
    try:
        sock = tls_connect(host, port, sni, insecure, ["http/1.1"])
        req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: nginx-h2-probe\r\n"
               "Connection: close\r\n\r\n" % (path, sni or host)).encode()
        sock.sendall(req)
        data = b""
        while len(data) < 64 * 1024:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
        sock.close()
        head = data.split(b"\r\n\r\n", 1)[0].decode("latin1", "replace")
        for line in head.split("\r\n"):
            if line.lower().startswith("server:"):
                banner = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return banner


def preflight_measure(sock, reader, method, path, host_header):
    """Well-behaved request of the probe path on stream 1. Returns
    (body_size, is_builtin, elapsed_seconds).

    is_builtin is True when the body is recognisably one of nginx's own
    error pages (contains "<center>nginx") and is small: those pages are
    generated by the front server itself, synchronously, in memory, which
    is the property the verdict arithmetic depends on (the whole body is
    charged to the connection window at frame-creation time). Backend-
    generated or file-backed bodies do not have that property and must
    not be used for a verdict.

    Replenishes flow-control windows exactly as data is consumed, so it
    is RFC-legal on every implementation."""
    received = 0
    pending = 0
    prefix = b""
    done = False
    started = time.time()

    send_headers(sock, 1, [
        (":method", method), (":scheme", "https"),
        (":authority", host_header), (":path", path),
    ])

    while not done and received < PREFLIGHT_READ_CAP:
        frame = reader.next_frame(10)
        if frame is None:
            raise RuntimeError("preflight timed out")
        ftype, flags, sid, payload = frame
        if ftype == FRAME_SETTINGS and not (flags & FLAG_ACK):
            sock.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0))
        elif ftype == FRAME_PING and not (flags & FLAG_ACK):
            send_ping_ack(sock, payload)
        elif ftype == FRAME_GOAWAY:
            raise RuntimeError("server sent GOAWAY during preflight")
        elif ftype == FRAME_RST_STREAM and sid == 1:
            raise RuntimeError("stream reset during preflight")
        elif ftype == FRAME_DATA and sid == 1:
            received += len(payload)
            if len(prefix) < MAX_BUILTIN_BODY:
                prefix += payload[:MAX_BUILTIN_BODY - len(prefix)]
            pending += len(payload)
            if pending >= 32768:
                send_window_update(sock, 0, pending)
                send_window_update(sock, 1, pending)
                pending = 0
            if flags & FLAG_END_STREAM:
                done = True
        elif ftype == FRAME_HEADERS and sid == 1 and (flags & FLAG_END_STREAM):
            done = True

    if not done and received >= PREFLIGHT_READ_CAP:
        # body larger than the cap: fine, per-stream queueing is capped by
        # the default stream window anyway
        send_rst_stream(sock, 1, ERR_NO_ERROR)

    is_builtin = (BUILTIN_MARKER in prefix
                  and received <= MAX_BUILTIN_BODY)
    return received, is_builtin, time.time() - started


def ping_flood(sock, npings=None):
    """Burst-limited PING flood. Deliberately does not read: the server's
    TLS buffer, TCP send buffer and our receive buffer fill with ACKs, so
    that subsequently produced DATA frames cannot be pulled into the socket.
    Bursts + gaps keep the server's 10000-frame allocation guard happy.
    Returns True if the flood completed, False if the connection died
    (flood too large for this server's buffers)."""
    n = FLOOD_PINGS if npings is None else npings
    ping = h2_frame(FRAME_PING, 0, 0, FLOOD_TAG)
    sent = 0
    try:
        while sent < n:
            burst = min(FLOOD_BURST, n - sent)
            sock.sendall(ping * burst)
            sent += burst
            if sent < n:
                time.sleep(FLOOD_BURST_GAP)
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError, OSError):
        return False
    return True


def drain_and_classify(sock, reader, flood_tag, markers, budget_bytes,
                       budget_seconds, grace_seconds=4.0):
    """Read frames until one of `markers` resolves. Returns dict with:
       goaway_err, data_total, data_before_goaway (response DATA bytes seen
       before a GOAWAY), markers hit, closed flag.
       After all markers are found, keeps reading for `grace_seconds` more:
       nginx queues control frames LIFO at the head of its output queue, so
       a GOAWAY can be parked BEHIND a later marker PING-ACK and must not
       be missed. Also ACKs server PINGs during long drains."""
    res = {
        "goaway_err": None,
        "data_total": 0,
        "data_before_goaway": 0,
        "saw_flood_ack": False,
        "markers": {},
        "closed": False,
    }
    deadline = time.time() + budget_seconds
    budget = budget_bytes
    marker_payloads = {m[1]: m[0] for m in markers}
    markers_done_at = None
    while time.time() < deadline and budget > 0:
        if markers_done_at is not None and \
                time.time() - markers_done_at > grace_seconds:
            break
        try:
            frame = reader.next_frame(1.0)
        except ConnectionClosed:
            res["closed"] = True
            break
        if frame is None:
            continue
        ftype, flags, sid, payload = frame
        budget -= 9 + len(payload)

        if ftype == FRAME_GOAWAY:
            res["goaway_err"] = (int.from_bytes(payload[4:8], "big")
                                 if len(payload) >= 8 else -1)
            res["data_before_goaway"] = res["data_total"]
            break
        if ftype == FRAME_PING:
            if flags & FLAG_ACK:
                if payload[:8] == flood_tag:
                    res["saw_flood_ack"] = True
                else:
                    name = marker_payloads.get(payload[:8])
                    if name and name not in res["markers"]:
                        res["markers"][name] = True
                        if all(k in res["markers"] for k, _ in markers):
                            markers_done_at = time.time()
            else:
                try:
                    send_ping_ack(sock, payload)
                except OSError:
                    pass
        elif ftype == FRAME_DATA:
            res["data_total"] += len(payload)
        elif ftype == FRAME_SETTINGS and not (flags & FLAG_ACK):
            try:
                sock.sendall(h2_frame(FRAME_SETTINGS, FLAG_ACK, 0))
            except OSError:
                pass
    return res


def flood_control_survives(sock, reader, method, path, host_header, npings):
    """Control connection for the 'bare close' signature: identical load
    (window raise, PING prefill, probe request) but NO test updates. If
    this connection survives long enough to deliver our marker PING-ACK,
    the flood size is not lethal by itself -- so a death in the real
    attempt was caused by the test update (fixed code rejecting it). If
    this control dies too, the flood is lethal (frame-guard kill) and the
    size search must shrink. Returns True if the control survived."""
    try:
        send_window_update(sock, 0, MAX_WINDOW - DEFAULT_WINDOW)
        if not ping_flood(sock, npings):
            return False
        if not ping_flood(sock, 4000):
            return False
        time.sleep(0.5)
        send_headers(sock, 3, [
            (":method", method), (":scheme", "https"),
            (":authority", host_header), (":path", path),
        ])
        time.sleep(1.5)
        send_ping(sock, MARK_PRE)
        out = drain_and_classify(sock, reader, FLOOD_TAG,
                                 [("m", MARK_PRE)],
                                 DRAIN_BUDGET_BYTES, DRAIN_BUDGET_SECONDS)
        return "m" in out["markers"] and out["goaway_err"] is None
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError):
        return False


def overmax_control_rejects(sock, reader):
    """Sanity control for the VULNERABLE verdict: on a clean connection
    with nothing queued, an update that pushes the window past the 2^31-1
    protocol maximum MUST be rejected with FLOW_CONTROL_ERROR by any
    implementation that enforces the maximum -- both vulnerable and fixed
    nginx do. A server that accepts it (or closes without a GOAWAY) is not
    behaving like nginx and cannot be certified for CVE-2026-123007.
    Returns True only on a clean FLOW_CONTROL_ERROR rejection."""
    try:
        send_window_update(sock, 0, MAX_WINDOW)
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError):
        return False
    _try_send(sock, h2_frame(FRAME_PING, 0, 0, MARK_PRE))  # best effort:
    # the server may already have closed after rejecting; its GOAWAY can
    # still be queued
    try:
        out = drain_and_classify(sock, reader, FLOOD_TAG,
                                 [("m", MARK_PRE)],
                                 256 * 1024, 15.0)
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError):
        return False
    if out["goaway_err"] == ERR_FLOW_CONTROL_ERROR:
        return True
    return False


def preflight_usable(body, is_builtin, elapsed):
    """Decides whether a preflight response can anchor a verdict:
    it must be one of nginx's own small error pages (front-generated,
    in-memory, synchronously produced) and arrive quickly (front-
    generated pages take ~RTT; a proxied backend does not). Returns
    (usable, reason)."""
    if not is_builtin:
        return False, ("response is not one of nginx's own error pages "
                       "(backend- or file-generated; the verdict "
                       "arithmetic requires a response the front server "
                       "generates itself)")
    if body > MAX_BUILTIN_BODY:
        return False, "response too large (%d bytes)" % body
    if body < MIN_BODY:
        return False, "response too small (%d bytes)" % body
    if elapsed > PREFLIGHT_MAX_LATENCY:
        return False, ("response arrived after %.1fs (slow backend; the "
                       "verdict arithmetic requires a front-generated "
                       "response)" % elapsed)
    return True, "ok"


def _try_send(sock, data):
    """Best-effort send for frames AFTER the test update: a server that
    rejected the update may already have closed, but the frames it wrote
    before closing (e.g. its GOAWAY) are still classifiable -- never let
    a late send failure abort the drain."""
    try:
        sock.sendall(data)
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError):
        pass


def probe_pass(sock, reader, method, path, host_header, res, npings,
               progress=_no_progress):
    """One probe attempt on a fresh connection using the given candidate
    request method. Returns 'vulnerable' | 'patched' |
    'patched_unconfirmed' (bare close; run_active must cross-check with a
    control connection) | 'retry_more' | 'retry_less' | 'retry_candidate'
    (the response for this method is not front-generated/usable) |
    'inconclusive'."""
    try:
        body, is_builtin, elapsed = preflight_measure(sock, reader, method,
                                                       path, host_header)
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError, RuntimeError) as e:
        res.notes.append("candidate %s: preflight failed (%s); trying the "
                         "next candidate" % (method, str(e)[:60]))
        return "retry_candidate"

    res.body_size = body
    res.probe_method = method
    usable, why = preflight_usable(body, is_builtin, elapsed)
    if not usable:
        res.notes.append("candidate %s unusable: %s" % (method, why))
        return "retry_candidate"

    d_eff = min(body, DEFAULT_WINDOW)   # per-stream queueing is capped by
    eps = max(12, 3 * d_eff // 2)       # the default stream window anyway
    eps2 = 2 * d_eff
    res.probe_increment = eps

    try:
        return _probe_pass_inner(sock, reader, method, path, host_header,
                                 res, npings, body, d_eff, eps, eps2,
                                 progress)
    except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
            ssl.SSLError, OSError) as e:
        # the connection died mid-attempt: treat as flood overflow
        res.notes.append("attempt (flood %d): connection died mid-attempt "
                         "(%s); reducing the flood size."
                         % (npings, str(e)[:60]))
        return "retry_less"


def _probe_pass_inner(sock, reader, method, path, host_header, res, npings,
                      body, d_eff, eps, eps2, progress):
    # Connection window to the protocol maximum (legal everywhere: nothing
    # is queued yet, so the increment exactly fills the remaining room).
    send_window_update(sock, 0, MAX_WINDOW - DEFAULT_WINDOW)

    if not ping_flood(sock, npings):
        res.notes.append(
            "attempt (flood %d): connection died during the prefill flood; "
            "reducing the flood size." % npings)
        return "retry_less"

    # second, fixed small flood: absorbs whatever residual space was left
    # in the server's TLS buffer by the first flood, so the queued response
    # cannot be pulled into it while we are still testing
    if not ping_flood(sock, 4000):
        return "retry_less"

    time.sleep(0.5)

    send_headers(sock, 3, [
        (":method", method), (":scheme", "https"),
        (":authority", host_header), (":path", path),
    ])

    time.sleep(1.5)   # response queues as DATA frames; buffers stay full

    # eps = 3/2 * B: the bookkeeping at this point is
    #   send_window = MAX - 2*B   (preflight body B + probe body B, both
    #                              deducted at frame-creation time)
    #   vulnerable code accepts iff eps <= 2*B (it ignores queued-but-unsent
    #   DATA), so eps = 3/2*B is always within bounds for vulnerable code.
    #   fixed code accepts iff eps <= B + F, where F <= B are the probe
    #   response bytes it has already written out; the prefill keeps F
    #   small, so fixed code rejects this update.
    send_window_update(sock, 0, eps)
    time.sleep(0.3)
    _try_send(sock, h2_frame(FRAME_PING, 0, 0, MARK_PRE))  # if a GOAWAY
    # precedes this ACK, eps was rejected

    _try_send(sock, h2_frame(FRAME_RST_STREAM, 0, 3,
                             struct.pack(">I", ERR_CANCEL)))
    time.sleep(0.3)

    # eps2 = 2*B: on unfixed code the RST refund pushed send_window past
    # 2^31-1 (bounded overshoot: about eps + refund - 2*B <= B bytes), so
    # the bounds check has underflowed and accepts anything. Any code whose
    # accounting stayed within bounds rejects this.
    _try_send(sock, h2_frame(FRAME_WINDOW_UPDATE, 0, 0,
                             struct.pack(">I", eps2)))
    time.sleep(0.2)
    _try_send(sock, h2_frame(FRAME_PING, 0, 0, MARK_FINAL))

    out = drain_and_classify(
        sock, reader, FLOOD_TAG,
        [("pre", MARK_PRE), ("confirm", MARK_FINAL)],
        DRAIN_BUDGET_BYTES, DRAIN_BUDGET_SECONDS)

    res.data_before_goaway = out["data_before_goaway"]

    if "confirm" in out["markers"] and out["goaway_err"] is None:
        # both updates accepted: the bounds check underflowed, which happens
        # only when send_window exceeded 2^31-1 (the CVE precondition)
        res.over_max_confirmed = True
        progress("attempt %d pings: over-maximum window state reproduced"
                 % npings)
        return "vulnerable"

    if out["goaway_err"] is not None:
        if out["goaway_err"] != ERR_FLOW_CONTROL_ERROR:
            res.notes.append(
                "attempt (flood %d): connection terminated with GOAWAY "
                "error 0x%x; the PING flood exceeded the server's "
                "frame/buffer capacity; reducing the flood size."
                % (npings, out["goaway_err"]))
            return "retry_less"
        if "pre" in out["markers"]:
            # eps was accepted (pre-marker ACKed) but eps2 rejected: the
            # window never crossed the maximum, i.e. the server had already
            # written out too much of the probe response for the prefill to
            # hold. Ambiguous between fixed and unfixed code; retry bigger.
            res.notes.append(
                "attempt (flood %d): first update accepted but the "
                "post-cancel update was rejected (%d of %d body bytes were "
                "already sent); the prefill did not hold; increasing the "
                "flood size."
                % (npings, out["data_before_goaway"], d_eff))
            return "retry_more"
        # eps itself was rejected (no pre-marker ACK): vulnerable code can
        # never reject eps = 3/2*B <= 2*B, so this is fixed code enforcing
        # the maximum including in-flight reservations
        progress("attempt %d pings: clean rejection (fixed code)" % npings)
        return "patched"

    if out["closed"] and out["goaway_err"] is None:
        if "pre" in out["markers"]:
            # first update accepted, connection later closed with an
            # undeliverable GOAWAY: ambiguous, retry bigger
            res.notes.append(
                "attempt (flood %d): first update accepted but the "
                "connection later closed with an undeliverable GOAWAY; "
                "ambiguous; increasing the flood size." % npings)
            return "retry_more"
        # bare close at the first update. Two causes produce this signature:
        # fixed code rejecting the update on a saturated connection (the
        # GOAWAY cannot be written), and a PING-flood frame-guard kill
        # (whose GOAWAY equally cannot be written). They are
        # indistinguishable here -- run_active must confirm with a
        # control connection before trusting this as "patched".
        res.over_max_confirmed = False
        progress("attempt %d pings: closed at first update (needs control)"
                 % npings)
        return "patched_unconfirmed"

    res.notes.append("attempt (flood %d): no confirmation PING ACK and no "
                     "GOAWAY received" % npings)
    return "inconclusive"


def run_active(target, port, sni, insecure, res, progress=_no_progress,
               initial_flood=None):
    """Runs the active probe, bisecting the PING flood size to the target's
    buffer capacity. Returns the final behavior verdict.

    The prefill must fill the server's TLS + TCP send buffers completely:
    - too small: the probe response still gets written out and the result
      is ambiguous (retry with a bigger flood)
    - too big: ACK frames queue past nginx's 10000-frame guard and the
      connection dies (retry with a smaller flood)
    Between the two, the probe response stays queued and the differential
    resolves cleanly. The death threshold is a precise upper bound, and
    the guard only trips ~10000 ACKs past true capacity, so bisection
    converges.

    Verdicts are only issued when (a) a candidate request (GET, falling
    back to TRACE) yielded a small, fast response the front server itself
    generated (nginx built-in error page), (b) any bare-connection-close
    implicating a "patched" verdict was confirmed by a control connection,
    and (c) before reporting VULNERABLE, the target rejected an over-max
    update on a clean connection the way nginx does. Everything else is
    INCONCLUSIVE, never a guess.
    """
    host_header = sni or target
    path = res.probe_path

    lo = None   # largest flood that stayed alive (too small or clean)
    hi = None   # smallest flood that killed the connection (too big)
    flood = initial_flood or FLOOD_PINGS
    known_method = None          # usable candidate found in an earlier attempt
    tried_candidates = set()
    outcome = None
    attempt_method = None

    for attempt in range(14):
        # ---- candidate selection (cheap preflight, fresh connection) ----
        if known_method:
            attempt_method = known_method
        else:
            remaining = [m for m in CANDIDATE_METHODS
                         if m not in tried_candidates]
            if not remaining:
                res.notes.append(
                    "no candidate request yields a small, fast response the "
                    "front server generates itself (nginx built-in error "
                    "page). Common with catch-all proxying where TRACE is "
                    "also intercepted, or custom error pages for every "
                    "candidate. The window arithmetic cannot be guaranteed "
                    "for this path; use --path to point at an endpoint the "
                    "nginx answers itself, or run the on-host checks "
                    "('nginx-h2-probe local').")
                return "inconclusive"
            attempt_method = remaining[0]

        progress("active attempt %d/14: %s %s, prefill %d pings"
                 % (attempt + 1, attempt_method, path, flood))
        sock = tls_connect(target, port, sni, insecure, ["h2"])
        try:
            reader = h2_handshake(sock)
            outcome = probe_pass(sock, reader, attempt_method, path,
                                 host_header, res, flood, progress)
        except (ConnectionClosed, ConnectionResetError, BrokenPipeError,
                ssl.SSLError, OSError, RuntimeError) as e:
            res.notes.append("attempt (flood %d): connection died early "
                             "(%s); reducing the flood size."
                             % (flood, str(e)[:60]))
            outcome = "retry_less"
        finally:
            try:
                sock.close()
            except Exception:
                pass

        if outcome == "retry_candidate":
            if known_method is None:
                tried_candidates.add(attempt_method)
            # else: transient preflight failure of a known-good method;
            # just retry on the next attempt
            continue        # fresh connection; the flood has not started,
                            # so this is cheap

        if known_method is None:
            known_method = attempt_method
            if attempt_method != "GET":
                res.notes.append(
                    "GET responses for the probe path are backend- or file-"
                    "generated; the verdict is based on %s, which nginx "
                    "answers itself before location handling." %
                    attempt_method)

        if outcome == "vulnerable":
            # sanity control: a lax (non-nginx) server that ignores the
            # 2^31-1 maximum would also accept both updates -- confirm the
            # target rejects an over-max update the way nginx does
            sock = tls_connect(target, port, sni, insecure, ["h2"])
            try:
                reader = h2_handshake(sock)
                if not overmax_control_rejects(sock, reader):
                    res.over_max_confirmed = None
                    res.notes.append(
                        "the test updates were both accepted, but the target "
                        "did NOT reject an over-maximum update on a clean "
                        "connection with FLOW_CONTROL_ERROR as nginx does; "
                        "the target may not be nginx (CDN edge or other "
                        "HTTP/2 implementation). Result not attributable "
                        "to CVE-2026-123007.")
                    return "inconclusive"
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            return "vulnerable"

        if outcome == "patched":
            return "patched"

        if outcome == "patched_unconfirmed":
            # bare close: either fixed code rejecting the update on a
            # saturated connection, or a flood-guard kill. Cross-check with
            # a control connection carrying the same load but no updates.
            sock = tls_connect(target, port, sni, insecure, ["h2"])
            try:
                reader = h2_handshake(sock)
                survived = flood_control_survives(sock, reader,
                                                  attempt_method, path,
                                                  host_header, flood)
            except (ConnectionClosed, OSError, ssl.SSLError):
                survived = False
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
            if survived:
                progress("control connection survived the same flood: "
                         "the close was caused by the rejected update")
                return "patched"
            res.notes.append(
                "attempt (flood %d): the control connection died under the "
                "same flood without any test update, so the earlier close "
                "was a flood-guard kill, not a rejection; reducing the "
                "flood size." % flood)
            outcome = "retry_less"     # fall through into the size search

        if outcome == "retry_less":
            # connection died: flood exceeded capacity + ~10000 ACK frames
            if hi is None or flood < hi:
                hi = flood
        elif outcome in ("retry_more", "inconclusive"):
            if lo is None or flood > lo:
                lo = flood
        else:
            if lo is None or flood > lo:
                lo = flood

        if outcome == "inconclusive":
            # drain produced neither marker nor GOAWAY: nothing the size
            # search can fix
            return "inconclusive"

        if lo is not None and hi is not None and hi - lo <= 4000:
            # bracketed: the usable window is [capacity, capacity + ~10000];
            # if we have not resolved inside it, the flood cannot hold on
            # this server -- report honestly
            if outcome == "retry_more":
                res.notes.append("prefill window bracketed (%d..%d pings) "
                                 "without a clean result" % (lo, hi))
                return "inconclusive"
            flood = (lo + hi) // 2
            continue

        if outcome == "retry_more":
            if hi is not None:
                flood = (lo + hi) // 2 if lo is not None else hi // 2
            else:
                flood = min(flood * 2, FLOOD_MAX)
                if flood <= lo or flood > FLOOD_MAX:
                    res.notes.append("flood already at maximum; cannot size "
                                     "up; this server's buffers are larger "
                                     "than the prefill budget")
                    return "inconclusive"
        elif outcome == "retry_less":
            if lo is not None:
                flood = (lo + hi) // 2
            else:
                flood = max(FLOOD_MIN, flood // 2)

    res.notes.append("prefill sizing did not converge")
    return "inconclusive"


# ---------------------------------------------------------------------------
# top-level run
# ---------------------------------------------------------------------------

def run(args):
    """Run the probe according to an argparse-like namespace. Returns
    (ProbeResult, exit_code). Exit codes: 0 not vulnerable / not exposed,
    1 vulnerable, 2 inconclusive, 3 error."""
    res = ProbeResult()
    res.target = "%s:%s" % (args.target, args.port)
    res.probe_path = args.path or ("/nginx-h2-probe-%d"
                                   % random.randrange(1 << 30))

    progress = getattr(args, "progress", None) or _no_progress

    exit_code = 0

    try:
        # ---- passive part: banner + version ranges -----------------------
        banner = get_banner_http1(args.target, args.port, args.sni,
                                  args.insecure)
        if banner:
            res.server_banner = banner
            m = re.search(r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", banner)
            if m:
                res.version = m.group(1)
                res.version_123007, res.version_123633 = version_assessment(
                    res.version)

        # ---- TLS / ALPN check --------------------------------------------
        try:
            sock = tls_connect(args.target, args.port, args.sni, args.insecure,
                               ["h2"])
        except Exception as e:
            # a connection/TLS failure is NOT "h2 not enabled"; never
            # report the green not-exposed message for an unreachable host
            res.connection_error = True
            res.alpn_h2 = None
            note = "TLS connection failed: %s" % e
            if "CERTIFICATE_VERIFY_FAILED" in str(e).upper() \
                    or "certificate" in str(e).lower():
                note += (" (certificate validation failed: probe the real "
                         "hostname instead of a bare IP, pass --sni, or "
                         "use --insecure for lab targets)")
            res.notes.append(note)
            return res, 3
        res.alpn_h2 = (sock.selected_alpn_protocol() == "h2")
        try:
            sock.close()
        except Exception:
            pass
        if not res.alpn_h2:
            res.notes.append("HTTP/2 not negotiated on this endpoint for "
                             "the hostname/SNI tested. If it is not "
                             "enabled on any listener, CVE-2026-123007 "
                             "and CVE-2026-123633 are not reachable here.")
            return res, 0

        # HTTP/2 is enabled per virtual host since nginx 1.25.1; probing a
        # bare IP only tests the default server block for that listener
        try:
            ipaddress_used = bool(ipaddress.ip_address(args.target))
        except ValueError:
            ipaddress_used = False
        if ipaddress_used and not args.sni:
            res.notes.append(
                "target is a bare IP: only the DEFAULT server block for "
                "that listener was tested. HTTP/2 is enabled per virtual "
                "host since nginx 1.25.1 -- test each hostname, or pass "
                "--sni, for full coverage.")

        # ---- active part ---------------------------------------------------
        if not args.active:
            res.notes.append("Active behavioral test skipped (passive mode). "
                             "Version ranges above may be wrong if your "
                             "vendor backported fixes; the active test "
                             "checks actual code behaviour.")
            return res, 0

        initial_flood = int(FLOOD_PINGS * getattr(args, "flood_multiplier",
                                                  1.0))
        if getattr(args, "flood_pings", None) is not None:
            initial_flood = max(FLOOD_MIN,
                                min(int(args.flood_pings), FLOOD_MAX))

        res.behavior_123007 = run_active(args.target, args.port, args.sni,
                                         args.insecure, res, progress,
                                         initial_flood=initial_flood)

        if res.behavior_123007 == "vulnerable":
            exit_code = 1
        elif res.behavior_123007 == "patched":
            exit_code = 0
        else:
            exit_code = 2
    except (RuntimeError, ConnectionClosed, OSError) as e:
        res.notes.append("active test interrupted: %s" % e)
        if res.behavior_123007 is None:
            res.behavior_123007 = "inconclusive"
        return res, 2
    return res, exit_code


def check(target, port=443, sni=None, path=None, active=True,
          insecure=False, flood_multiplier=1.0, progress=None):
    """One-call library API. Returns the probe result as a dict.

        from nginx_h2_probe import check
        result = check("origin.example.com", active=True)
        print(result["verdict"])

    Keys include: verdict, behavior_123007, over_max_confirmed,
    server_banner, version, version_123007, version_123633, notes,
    exit_code (0 not vulnerable/not exposed, 1 vulnerable, 2 inconclusive).

    Note: an HTTP client library (requests/httpx) cannot implement this
    test -- the frame-level operations involved are not exposed by any
    HTTP client API -- which is why this module talks socket+ssl directly.
    """
    ns = argparse.Namespace(
        target=target, port=port, sni=sni, path=path, active=active,
        flood_multiplier=flood_multiplier, flood_pings=None,
        insecure=insecure, progress=progress,
    )
    res, code = run(ns)
    return result_dict(res, code)