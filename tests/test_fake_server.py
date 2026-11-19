"""Fake-server tests for the probe's core decision logic.

A FakeH2Server speaks just enough HTTP/2 to drive probe_pass / run_active
end-to-end without a real nginx, and models the accountings that matter:

  * vulnerable  -- send_window tracked with the unfixed check (no
                   in-flight counting; refund on RST; unsigned-wrap room)
  * fixed       -- send_window + send_queued tracked with the patched
                   check; rejects the eps update with GOAWAY(FC)
  * lax         -- accepts everything, including over-max on a clean
                   connection (must be reported INCONCLUSIVE)
  * silent_reject -- fixed accounting but rejects by closing without a
                   GOAWAY (the "bare close" case needing the control)
  * die_after_pings -- flood-guard death with no test update (must be
                   retried as sizing, never reported patched)
  * backend answers -- non-built-in preflight bodies (candidate must be
                   rejected, never verdicted; TRACE fallback must recover)

These tests pin the classifier's safety properties; the real lab cannot
easily produce the misbehaviour cases.
"""

import os
import struct
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from nginx_h2_probe import core  # noqa: E402
from nginx_h2_probe import local  # noqa: E402

MAX = core.MAX_WINDOW
MOD = 1 << 64

BUILTIN_404 = (b"<html>\r\n<head><title>404 Not Found</title></head>\r\n"
               b"<body>\r\n<center><h1>404 Not Found</h1></center>\r\n"
               b"<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
BACKEND_PAGE = (b"<html><head><title>slow app</title></head>"
                b"<body>backend page, not nginx</body></html>\n")


def goaway(err):
    return core.h2_frame(core.FRAME_GOAWAY, 0, 0, struct.pack(">II", 0, err))


def ping_ack(payload):
    return core.h2_frame(core.FRAME_PING, core.FLAG_ACK, 0, payload[:8])


class FakeH2Server:
    """Models nginx's connection-level send accounting, vulnerable or fixed."""

    def __init__(self, policy):
        self.p = policy
        self.out = core.h2_frame(core.FRAME_SETTINGS, 0, 0, b"")
        self.inbuf = b""
        self.saw_preface = False
        self.closed = False
        self.pings = 0
        self.W = core.DEFAULT_WINDOW      # h2c->send_window
        self.sq = 0                       # h2c->send_queued (fixed only)
        self.last_charged = 0             # body size of the last response

    # -- frame parsing ------------------------------------------------------

    @staticmethod
    def _parse_literal_hpack(block):
        headers = {}
        i = 0
        while i < len(block) and block[i] == 0x00:
            i += 1                      # literal-without-indexing flag
            nlen = block[i]
            i += 1
            name = block[i:i + nlen].decode()
            i += nlen
            vlen = block[i]
            i += 1
            value = block[i:i + vlen].decode()
            i += vlen
            headers[name] = value
        return headers

    def feed(self, data):
        self.inbuf += data
        if not self.saw_preface and \
                self.inbuf.startswith(core.HTTP2_PREFACE):
            self.inbuf = self.inbuf[len(core.HTTP2_PREFACE):]
            self.saw_preface = True
        while len(self.inbuf) >= 9:
            ln = int.from_bytes(self.inbuf[0:3], "big")
            if len(self.inbuf) < 9 + ln:
                return
            ftype = self.inbuf[3]
            flags = self.inbuf[4]
            sid = int.from_bytes(self.inbuf[5:9], "big") & 0x7FFFFFFF
            payload = self.inbuf[9:9 + ln]
            self.inbuf = self.inbuf[9 + ln:]
            self._on_frame(ftype, flags, sid, payload)

    # -- modelled behaviours --------------------------------------------------

    def _charge(self, n):
        # DATA frame creation: deducted from the window at queue time
        self.W -= n
        self.last_charged = n
        if self.p.get("mode") == "fixed":
            self.sq += n

    def _refund(self, n):
        # RST cleanup refund
        self.W += n
        if self.p.get("mode") == "fixed":
            self.sq -= n

    def _on_window_update(self, inc):
        mode = self.p.get("mode", "vulnerable")
        if mode == "lax":
            return                      # accepts everything
        sq = self.sq if mode == "fixed" else 0
        room = (MAX - self.W - sq) % MOD
        if inc > room:
            if self.p.get("silent_reject"):
                self.closed = True      # GOAWAY undeliverable: bare close
                self.out = b""
                return
            self.out += goaway(core.ERR_FLOW_CONTROL_ERROR)
            self.closed = True
            return
        self.W += inc

    def _on_frame(self, ftype, flags, sid, payload):
        p = self.p
        if ftype == core.FRAME_SETTINGS and not (flags & core.FLAG_ACK):
            self.out += core.h2_frame(core.FRAME_SETTINGS, core.FLAG_ACK,
                                      0, b"")
        elif ftype == core.FRAME_PING and not (flags & core.FLAG_ACK):
            self.pings += 1
            if p.get("die_after_pings") and self.pings >= p["die_after_pings"]:
                self.closed = True
                self.out = b""
                return
            if p.get("ack_pings", True) and not self.closed:
                self.out += ping_ack(payload)
        elif ftype == core.FRAME_WINDOW_UPDATE:
            if not self.closed:
                self._on_window_update(int.from_bytes(payload[0:4], "big"))
        elif ftype == core.FRAME_HEADERS:
            if self.closed:
                return
            hdrs = self._parse_literal_hpack(payload)
            body, status = p["answer"](hdrs.get(":method", "GET"),
                                       hdrs.get(":path", "/"))
            if body is not None:
                self.out += core.h2_frame(core.FRAME_HEADERS,
                                          core.FLAG_END_HEADERS, sid, b"")
                self.out += core.h2_frame(
                    core.FRAME_DATA, core.FLAG_END_STREAM, sid, body)
                self._charge(len(body))
        elif ftype == core.FRAME_RST_STREAM:
            if not self.closed and self.p.get("refund_body"):
                self._refund(self.last_charged)


class FakeSock:
    def __init__(self, server):
        self.server = server

    def settimeout(self, t):
        pass

    def sendall(self, data):
        if self.server.closed:
            raise ConnectionResetError("fake: connection closed")
        self.server.feed(data)

    def recv(self, n):
        out, self.server.out = self.server.out[:n], self.server.out[n:]
        if out:
            return out
        # nothing left: emulate an idle-then-close so drains terminate
        self.server.closed = True
        return b""

    def close(self):
        self.server.closed = True

    def selected_alpn_protocol(self):
        return "h2"


def connect_factory(policy):
    def _connect(host, port, sni, insecure, alpn):
        return FakeSock(FakeH2Server(policy))
    return _connect


def builtin(body=BUILTIN_404):
    return lambda method, path: (body, b"404")


def method_answer(get_body, trace_body=BUILTIN_404):
    def answer(method, path):
        if method == "TRACE":
            return trace_body, b"405"
        return get_body, b"404"
    return answer


class ProbeTestCase(unittest.TestCase):
    def setUp(self):
        p = mock.patch("nginx_h2_probe.core.time.sleep", lambda s: None)
        p.start()
        self.addCleanup(p.stop)

    def _run(self, policy, initial_flood=200):
        res = core.ProbeResult()
        res.probe_path = "/x"
        with mock.patch.object(core, "tls_connect", connect_factory(policy)):
            verdict = core.run_active("fake", 443, None, True, res,
                                      progress=lambda m: None,
                                      initial_flood=initial_flood)
        return verdict, res


class TestRunActive(ProbeTestCase):
    def test_vulnerable_builtin(self):
        policy = {"mode": "vulnerable", "answer": builtin(),
                  "refund_body": True}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "vulnerable")
        self.assertTrue(res.over_max_confirmed)

    def test_fixed_rejects_first_update(self):
        policy = {"mode": "fixed", "answer": builtin()}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "patched")
        self.assertFalse(res.over_max_confirmed)

    def test_lax_server_is_inconclusive(self):
        # accepts everything including over-max on a clean connection:
        # must NOT be reported VULNERABLE
        policy = {"mode": "lax", "answer": builtin()}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "inconclusive")
        self.assertIsNone(res.over_max_confirmed)
        self.assertTrue(any("did NOT reject an over-maximum" in n
                            for n in res.notes))

    def test_backend_page_is_never_verdicted(self):
        # every candidate's response is backend-generated (catch-all
        # proxying, TRACE also intercepted): INCONCLUSIVE, never a verdict
        policy = {"mode": "vulnerable",
                  "answer": lambda m, p: (BACKEND_PAGE, b"200")}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "inconclusive")
        self.assertTrue(any("no candidate request" in n for n in res.notes))

    def test_trace_fallback_recovers_verdict(self):
        # GET is backend-generated; the front answers TRACE itself
        policy = {"mode": "vulnerable", "refund_body": True,
                  "answer": method_answer(get_body=BACKEND_PAGE)}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "vulnerable")
        self.assertTrue(any("based on TRACE" in n for n in res.notes))

    def test_bare_close_needs_surviving_control(self):
        # fixed accounting, but rejects by closing silently (GOAWAY
        # undeliverable on a saturated connection); the control has no
        # test update and must survive -> "patched"
        policy = {"mode": "fixed", "silent_reject": True,
                  "answer": builtin()}
        verdict, res = self._run(policy)
        self.assertEqual(verdict, "patched")
        self.assertFalse(res.over_max_confirmed)

    def test_flood_death_is_never_patched(self):
        # the flood itself kills the connection before any update; both
        # the real attempt and the control die -> size search -> never
        # "patched"
        policy = {"mode": "vulnerable", "answer": builtin(),
                  "die_after_pings": 150}
        verdict, res = self._run(policy, initial_flood=200)
        self.assertEqual(verdict, "inconclusive")


class TestPreflightUsable(unittest.TestCase):
    def test_builtin_small_fast(self):
        ok, _ = core.preflight_usable(153, True, 0.05)
        self.assertTrue(ok)

    def test_backend_page_rejected(self):
        ok, why = core.preflight_usable(507, False, 3.1)
        self.assertFalse(ok)
        self.assertIn("front server", why)

    def test_mimic_but_slow_rejected(self):
        # looks like a built-in page but arrives after a slow backend
        ok, why = core.preflight_usable(157, True, 3.05)
        self.assertFalse(ok)
        self.assertIn("slow backend", why)

    def test_too_small(self):
        ok, why = core.preflight_usable(16, True, 0.05)
        self.assertFalse(ok)
        self.assertIn("too small", why)

    def test_too_large(self):
        ok, why = core.preflight_usable(99999, True, 0.05)
        self.assertFalse(ok)
        self.assertIn("too large", why)


class TestConnectionErrorVerdict(unittest.TestCase):
    def test_error_verdict_not_green(self):
        res = core.ProbeResult()
        res.connection_error = True
        res.alpn_h2 = None
        d = core.result_dict(res, 3)
        self.assertEqual(d["verdict"], "error (connection failed)")
        self.assertNotIn("assessment-only", d["verdict"])

    def test_normal_assessment_still_works(self):
        res = core.ProbeResult()
        d = core.result_dict(res, 0)
        self.assertEqual(d["verdict"], "assessment-only (active test not run)")


class TestLocalRegexes(unittest.TestCase):
    def test_listen_legacy_http2(self):
        self.assertRegex("listen 443 ssl http2;", local.HTTP2_LISTEN_RE)

    def test_listen_ipv6_legacy_http2(self):
        self.assertRegex("listen [::]:443 ssl http2;", local.HTTP2_LISTEN_RE)

    def test_listen_plain_ssl_no_http2(self):
        self.assertNotRegex("listen 443 ssl;", local.HTTP2_LISTEN_RE)
        self.assertNotRegex("listen [::]:443 ssl;", local.HTTP2_LISTEN_RE)

    def test_listen_quic_is_not_http2(self):
        self.assertNotRegex("listen 443 quic reuseport;", local.HTTP2_LISTEN_RE)
        self.assertRegex("listen 443 quic reuseport;", local.HTTP3_RE)

    def test_http2_on_directive(self):
        self.assertRegex("http2 on;", local.HTTP2_ON_RE)
        self.assertNotRegex("http2 off;", local.HTTP2_ON_RE)

    def test_full_config_snippet(self):
        conf = ("server {\n    listen 443 ssl;\n"
                "    listen [::]:443 ssl http2;\n    http2 on;\n}\n")
        nc = "\n".join(line.split("#", 1)[0] for line in conf.splitlines())
        self.assertEqual(len(local.HTTP2_LISTEN_RE.findall(nc)), 1)
        self.assertEqual(len(local.HTTP2_ON_RE.findall(nc)), 1)

    def test_commented_out_is_ignored(self):
        conf = "listen 443 ssl; # http2 was here\n"
        nc = "\n".join(line.split("#", 1)[0] for line in conf.splitlines())
        self.assertNotRegex(nc, local.HTTP2_LISTEN_RE)


if __name__ == "__main__":
    unittest.main()