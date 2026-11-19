"""Unit tests for the on-host `local` checks: verdict computation and
exit codes, with subprocess helpers mocked (no nginx needed)."""

import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from nginx_h2_probe import local  # noqa: E402

CONF_H2 = """
user nginx;
http {
    server {
        listen 443 ssl http2;
        listen [::]:443 ssl http2;
    }
}
"""
CONF_NO_H2 = """
http {
    server {
        listen 443 ssl;
    }
}
"""
CONF_H2_PROXY = CONF_H2 + "    location / { proxy_pass http://up; }\n"


class LocalTestCase(unittest.TestCase):
    def _patch(self, version="1.31.8", module=True, conf=CONF_H2,
               nginx_found=True, conf_ok=True):
        def fake_run(cmd, use_sudo=False):
            if cmd == ["nginx", "-v"]:
                return ("nginx version: nginx/%s\n" % version,
                        nginx_found)
            if cmd == ["nginx", "-V"]:
                return ("--with-http_v2_module " if module else "", True)
            raise AssertionError(cmd)
        def fake_conf():
            return (conf, conf_ok)
        p1 = mock.patch.object(local, "_run", fake_run)
        p2 = mock.patch.object(local, "shutil").start()
        p2.which.return_value = "/usr/sbin/nginx" if nginx_found else None
        p1.start()
        p3 = mock.patch.object(local, "_get_config", fake_conf)
        p3.start()
        self.addCleanup(p1.stop)
        self.addCleanup(p2.stop)
        self.addCleanup(p3.stop)

    def test_exposed_exit_1(self):
        self._patch(version="1.31.8", conf=CONF_H2)
        code = local.run_local_checks()
        self.assertEqual(code, 1)

    def test_exposed_with_legacy_syntax_and_proxy(self):
        self._patch(version="1.18.0", conf=CONF_H2_PROXY)
        code = local.run_local_checks()
        self.assertEqual(code, 1)

    def test_fixed_version_exit_0(self):
        self._patch(version="1.31.9")
        self.assertEqual(local.run_local_checks(), 0)

    def test_fixed_stable_branch_exit_0(self):
        # 1.30.7 is numerically inside 1.9.5-1.31.8 but is the FIXED stable
        self._patch(version="1.30.7")
        self.assertEqual(local.run_local_checks(), 0)

    def test_vulnerable_code_but_h2_disabled_exit_0(self):
        self._patch(conf=CONF_NO_H2)
        self.assertEqual(local.run_local_checks(), 0)

    def test_module_absent_exit_0(self):
        self._patch(module=False)
        self.assertEqual(local.run_local_checks(), 0)

    def test_no_nginx_binary_exit_2(self):
        self._patch(nginx_found=False)
        self.assertEqual(local.run_local_checks(), 2)


if __name__ == "__main__":
    unittest.main()