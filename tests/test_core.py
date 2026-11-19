"""Unit tests for nginx-h2-probe (stdlib unittest; run with
`python -m unittest discover -s tests` or pytest)."""

import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from nginx_h2_probe import core  # noqa: E402


class TestHpack(unittest.TestCase):
    def test_hpack_int_short(self):
        self.assertEqual(core.hpack_int(0, 7), b"\x00")
        self.assertEqual(core.hpack_int(10, 7), b"\x0a")
        self.assertEqual(core.hpack_int(126, 7), b"\x7e")

    def test_hpack_int_at_prefix_boundary(self):
        # 127 == max 7-bit prefix -> two bytes per RFC 7541
        self.assertEqual(core.hpack_int(127, 7), b"\x7f\x00")
        self.assertEqual(core.hpack_int(128, 7), b"\x7f\x01")

    def test_hpack_int_long(self):
        # RFC 7541 appendix C example: 1337 with 5-bit prefix
        self.assertEqual(core.hpack_int(1337, 5), b"\x1f\x9a\x0a")

    def test_hpack_request(self):
        out = core.hpack_request([(":method", "GET")])
        # literal-without-indexing (0x00), 7-byte name, ":method", 3-byte value
        self.assertEqual(out, b"\x00\x07:method\x03GET")

    def test_hpack_request_long_value(self):
        # values >= 127 bytes must use multi-byte HPACK integers
        long_val = "x" * 200
        out = core.hpack_request([("x-hdr", long_val)])
        self.assertEqual(out[0], 0x00)
        self.assertEqual(out[1], 5)                       # len("x-hdr")
        self.assertEqual(out[2:7], b"x-hdr")
        self.assertEqual(out[7], 127)                     # 200 -> prefix then 73
        self.assertEqual(out[8], 200 - 127)
        self.assertEqual(len(out), 1 + 1 + 5 + 2 + 200)
        self.assertTrue(out.endswith(b"x" * 200))


class TestFraming(unittest.TestCase):
    def test_h2_frame_layout(self):
        f = core.h2_frame(0x8, 0x00, 0x1234, b"\x00\x00\x00\x01")
        # 3-byte length, type, flags, 4-byte stream id, payload
        self.assertEqual(f[:3], b"\x00\x00\x04")
        self.assertEqual(f[3], 0x8)
        self.assertEqual(f[4], 0)
        self.assertEqual(f[5:9], b"\x00\x00\x12\x34")
        self.assertEqual(f[9:], b"\x00\x00\x00\x01")

    def test_h2_frame_stream_id_mask(self):
        f = core.h2_frame(0x4, 0, 0xFFFFFFFF, b"")
        self.assertEqual(f[5:9], b"\x7f\xff\xff\xff")

    def test_send_window_update_rejects_bad_increment(self):
        class FakeSock:
            def sendall(self, _):
                pass
        with self.assertRaises(ValueError):
            core.send_window_update(FakeSock(), 0, 0)
        with self.assertRaises(ValueError):
            core.send_window_update(FakeSock(), 0, 1 << 32)

    def test_ping_payload_is_exactly_8_bytes(self):
        class FakeSock:
            def __init__(self):
                self.sent = b""
            def sendall(self, data):
                self.sent += data
        s = FakeSock()
        core.send_ping(s, b"pr0befl0d")     # 9 bytes -> truncated
        self.assertEqual(len(s.sent), 9 + 8)
        self.assertEqual(s.sent[9:], b"pr0befl0")


class TestFrameReader(unittest.TestCase):
    class FakeSock:
        def __init__(self, data):
            self.data = data
            self.settimeout_calls = 0

        def settimeout(self, t):
            self.settimeout_calls += 1

        def recv(self, n):
            d, self.data = self.data[:n], self.data[n:]
            return d

    def test_parses_two_frames(self):
        import socket
        data = (core.h2_frame(0x0, 0x1, 5, b"abc") +
                core.h2_frame(0x6, 0x1, 0, b"12345678"))
        r = core.FrameReader(self.FakeSock(data))
        f1 = r.next_frame(1)
        self.assertEqual(f1[0], 0x0)
        self.assertEqual(f1[1], 0x1)
        self.assertEqual(f1[2], 5)
        self.assertEqual(f1[3], b"abc")
        f2 = r.next_frame(1)
        self.assertEqual(f2[0], 0x6)
        self.assertEqual(f2[3], b"12345678")
        with self.assertRaises(core.ConnectionClosed):
            r.next_frame(1)   # empty socket = remote closed

    def test_connection_closed(self):
        r = core.FrameReader(self.FakeSock(b""))
        with self.assertRaises(core.ConnectionClosed):
            r.next_frame(1)


class TestVersionRanges(unittest.TestCase):
    def test_123007_range(self):
        self.assertTrue(core.in_range((1, 9, 5), *core.VULN_RANGE_123007))
        self.assertTrue(core.in_range((1, 31, 8), *core.VULN_RANGE_123007))
        self.assertFalse(core.in_range((1, 9, 4), *core.VULN_RANGE_123007))
        self.assertFalse(core.in_range((1, 31, 9), *core.VULN_RANGE_123007))

    def test_version_vulnerable_is_branch_aware(self):
        v = core.version_vulnerable
        # vulnerable: mainline progression
        self.assertTrue(v((1, 9, 5), (1, 9, 5)))
        self.assertTrue(v((1, 25, 3), (1, 9, 5)))
        self.assertTrue(v((1, 31, 8), (1, 9, 5)))
        self.assertTrue(v((1, 30, 6), (1, 9, 5)))      # stable pre-fix
        # fixed: mainline 1.31.9+, stable 1.30.7+
        self.assertFalse(v((1, 31, 9), (1, 9, 5)))
        self.assertFalse(v((1, 31, 10), (1, 9, 5)))
        self.assertFalse(v((1, 30, 7), (1, 9, 5)))    # stable fixed release
        self.assertFalse(v((1, 30, 8), (1, 9, 5)))
        # predates HTTP/2 (123007) / predates the feature (123633)
        self.assertFalse(v((1, 9, 4), (1, 9, 5)))
        self.assertFalse(v((1, 19, 6), (1, 19, 7)))
        self.assertTrue(v((1, 19, 7), (1, 19, 7)))

    def test_version_assessment(self):
        a, b = core.version_assessment("1.31.8")
        self.assertIn("vulnerable", a)
        self.assertIn("vulnerable", b)
        a, b = core.version_assessment("1.31.9")
        self.assertEqual(a, "not in vulnerable range")
        self.assertEqual(b, "not in vulnerable range")
        a, b = core.version_assessment("1.30.7")
        self.assertEqual(a, "not in vulnerable range")   # fixed stable
        self.assertEqual(b, "not in vulnerable range")
        a, b = core.version_assessment("1.30.6")
        self.assertIn("vulnerable", a)
        self.assertIn("vulnerable", b)
        a, b = core.version_assessment("1.15.0")
        self.assertIn("vulnerable", a)   # 123007 introduced 1.9.5
        self.assertEqual(b, "not in vulnerable range")   # 123633 from 1.19.7


class TestResultDict(unittest.TestCase):
    def test_verdict_mapping(self):
        res = core.ProbeResult()
        res.behavior_123007 = "vulnerable"
        d = core.result_dict(res, 1)
        self.assertEqual(d["verdict"], "VULNERABLE")
        res = core.ProbeResult()
        d = core.result_dict(res, 0)
        self.assertEqual(d["verdict"], "assessment-only (active test not run)")

    def test_not_exposed_when_h2_absent(self):
        # HTTP/2 not negotiated must read as "not-exposed", distinct from a
        # patched verdict, so automation does not treat it as "test passed".
        res = core.ProbeResult()
        res.alpn_h2 = False
        d = core.result_dict(res, 0)
        self.assertIn("not-exposed", d["verdict"])

    def test_connection_error_beats_everything(self):
        res = core.ProbeResult()
        res.connection_error = True
        res.alpn_h2 = False
        d = core.result_dict(res, 3)
        self.assertEqual(d["verdict"], "error (connection failed)")


class TestStandaloneSync(unittest.TestCase):
    @unittest.skipUnless(
        os.path.exists(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "nginx-h2-probe.py")),
        "standalone not built")
    def test_standalone_is_fresh(self):
        import subprocess
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        standalone = os.path.join(root, "nginx-h2-probe.py")
        before = open(standalone, "rb").read()
        subprocess.run([sys.executable, "scripts/build_standalone.py"],
                       cwd=root, check=True, capture_output=True)
        after = open(standalone, "rb").read()
        self.assertEqual(before, after,
                         "nginx-h2-probe.py is out of date; re-run "
                         "scripts/build_standalone.py")


if __name__ == "__main__":
    unittest.main()