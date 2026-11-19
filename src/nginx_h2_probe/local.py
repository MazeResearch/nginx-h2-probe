"""On-the-host checks: nginx binary version, HTTP/2 module and listeners,
reverse-proxy configuration. The configuration-aware answer for hosts you
can log into (covers Xint's five-condition exposure checklist for
CVE-2026-123007; the remote `check` covers the rest).

Verdict + exit codes:
  exit 1  -- code likely vulnerable per version AND HTTP/2 enabled
  exit 0   -- not exposed per version/config (or version already fixed)
  exit 2   -- could not determine (no nginx binary, unreadable config)

Caveat: distro backports keep old version strings; if the package is
backported this tool reports the version range only -- correlate with the
distro advisory, or confirm with the remote behavioural check.
"""

import re
import shutil
import subprocess
import sys

from nginx_h2_probe.core import version_vulnerable, VULN_RANGE_123007

# "listen" with http2 among its parameters: matches
#   listen 443 ssl http2;         (nginx 1.9.5 - 1.25.0 legacy syntax)
#   listen [::]:443 ssl http2;
#   listen 443 ssl;  http2 on;    (1.25.1+, matched by the second pattern)
HTTP2_LISTEN_RE = re.compile(r"^\s*listen\b[^;]*\bhttp2\b", re.M | re.I)
HTTP2_ON_RE = re.compile(r"^\s*http2\s+on\s*;", re.M | re.I)
HTTP3_RE = re.compile(r"(?:^\s*listen\b[^;]*\bquic\b|^\s*http3\s+on\s*;)",
                      re.M | re.I)
PROXY_RE = re.compile(r"\b(?:proxy_pass|fastcgi_pass|uwsgi_pass|grpc_pass|"
                      r"scgi_pass)\b")
# NGINX Plus reports an OSS base version (e.g. "nginx/1.27.4 (nginx-plus-r34)")
# that does NOT map to the OSS fix lines -- Plus ships its own fixed builds.
NGINX_PLUS_RE = re.compile(r"nginx-plus", re.I)


def _run(cmd, use_sudo=False):
    """Run a command, capture output. Never prompts: sudo is invoked with
    -n so it fails fast instead of hanging without a TTY. Returns
    (output, ok)."""
    argv = (["sudo", "-n"] if use_sudo else []) + cmd
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return p.stdout + p.stderr, p.returncode == 0
    except Exception as e:
        return "(failed: %s)" % e, False


def _get_config():
    """nginx -T without sudo first; fall back to sudo -n. Returns
    (config_text, ok)."""
    out, ok = _run(["nginx", "-T"])
    if ok and "nginx: configuration file" in out:
        return out, True
    out2, ok2 = _run(["nginx", "-T"], use_sudo=True)
    if ok2 and "nginx: configuration file" in out2:
        return out2, True
    return (out + out2), False


def run_local_checks():
    """Runs the local checks, prints a report, returns an exit code
    (0 not exposed / 1 exposed per version+config / 2 undetermined)."""
    out = {"nginx_found": bool(shutil.which("nginx"))}
    print("== nginx version ==")
    ver_out, ok = _run(["nginx", "-v"])
    print(ver_out.strip() or "(nginx binary not found / not in PATH)")
    out["version_output"] = ver_out.strip()
    m = re.search(r"nginx/([0-9]+\.[0-9]+\.[0-9]+)", ver_out)
    version = m.group(1) if m else None
    out["version"] = version
    is_plus = bool(NGINX_PLUS_RE.search(ver_out))
    out["nginx_plus"] = is_plus
    print()

    print("== HTTP/2 module present in binary? ==")
    vout, _ = _run(["nginx", "-V"])
    has_module = "--with-http_v2_module" in vout
    print("HTTP2_MODULE=%s" % ("present" if has_module
                               else "absent (not affected by these CVEs)"))
    out["http2_module"] = has_module
    print()

    print("== configuration (nginx -T%s) =="
          % ", then sudo -n" if not ok else "")
    conf, conf_ok = _get_config()
    if not conf_ok:
        print("(could not read the full configuration: run as a user with "
              "access to nginx -T, or with passwordless sudo)")
    conf_nc = "\n".join(line.split("#", 1)[0] for line in conf.splitlines())

    h2_listens = HTTP2_LISTEN_RE.findall(conf_nc)
    h2_on = HTTP2_ON_RE.findall(conf_nc)
    http2_enabled = bool(h2_listens or h2_on)
    print("== HTTP/2 enabled in configuration? ==")
    if h2_listens:
        for line in h2_listens[:10]:
            print("  %s" % line.strip())
    if h2_on:
        for line in h2_on[:10]:
            print("  %s" % line.strip())
    if not http2_enabled:
        print("no HTTP/2 listeners found")
    out["http2_enabled"] = http2_enabled
    print()

    print("== HTTP/3 (QUIC) listeners? (CVE-2026-121810) ==")
    h3 = HTTP3_RE.findall(conf_nc)
    for line in h3[:10]:
        print("  %s" % line.strip())
    if not h3:
        print("no HTTP/3 listeners found")
    out["http3_enabled"] = bool(h3)
    print()

    print("== reverse proxying in use? (needed for CVE-2026-123633) ==")
    proxy = PROXY_RE.findall(conf_nc)
    if proxy:
        print("upstream forwarding found (%d directive occurrences)"
              % len(proxy))
    else:
        print("no upstream forwarding found")
    out["reverse_proxy"] = bool(proxy)
    print()

    # ---- verdict -----------------------------------------------------------
    print("== verdict ==")
    if not out["nginx_found"]:
        print("UNDETERMINED: no nginx binary in PATH.")
        print("(exit 2)")
        return 2

    vt = tuple(int(x) for x in version.split(".")) if version else None
    vuln_code = version is not None and version_vulnerable(vt,
                                                           VULN_RANGE_123007[0])
    if version is None:
        print("UNDETERMINED: could not parse the nginx version.")
        print("(exit 2)")
        return 2
    if is_plus:
        # The OSS base version does not map to the Plus fix lines, so a
        # version verdict here would be wrong in both directions. Point the
        # user at the definitive sources instead of guessing.
        print("NGINX PLUS detected (%s). OSS version ranges do NOT apply: "
              "Plus ships its own fixed builds." % version)
        print("  Fixed Plus builds: CVE-2026-123007 in 37.0.8.1 / 37.3.0.1; "
              "CVE-2026-123633 in 37.0.7.1 / 37.2.0.1. Check your exact Plus "
              "build against F5 advisories K000163926 and K000163928.")
        if http2_enabled:
            print("  HTTP/2 IS enabled here, so if this build predates the "
                  "Plus fix it is exposed. The remote behavioural check "
                  "('nginx-h2-probe check HOST') decides from code behaviour, "
                  "not the version string.")
        print("(exit 2)")
        return 2
    if not vuln_code:
        print("Not exposed to CVE-2026-123007/123633 per version: %s is "
              "outside the vulnerable ranges (or already contains the "
              "fix)." % version)
        print("(exit 0)")
        return 0
    if not has_module:
        print("Not exposed per version, but note: this build lacks the "
              "HTTP/2 module, so the affected code is not compiled in.")
        print("(exit 0)")
        return 0
    if not http2_enabled:
        if not conf_ok:
            # No listeners found only because the config could not be read:
            # reporting "not exposed" here would be a dangerous false safe.
            print("UNDETERMINED: version %s has the vulnerable code, but the "
                  "configuration could not be read (no HTTP/2 listener can be "
                  "confirmed or ruled out). Re-run as a user with access to "
                  "'nginx -T' (or with passwordless sudo), or use the remote "
                  "behavioural check. Treat as potentially exposed until "
                  "confirmed." % version)
            print("(exit 2)")
            return 2
        print("Vulnerable code present (version %s) but HTTP/2 is not "
              "enabled on any listener -> not reachable." % version)
        print("(exit 0)")
        return 0

    print("EXPOSED to CVE-2026-123007: version %s is in the vulnerable "
          "range, the HTTP/2 module is compiled in, and HTTP/2 is "
          "enabled." % version)
    if proxy:
        print("Also EXPOSED to CVE-2026-123633: this server forwards to "
              "upstreams (proxy_pass family) over HTTP/2.")
    print("Caveat: distro backports keep old version strings -- if your "
          "package vendor shipped the fix, confirm against the distro "
          "advisory, or run the remote behavioural check "
          "('nginx-h2-probe check HOST') which reads code, not versions.")
    print("Action: upgrade to 1.30.7+ / 1.31.9+ or the vendor backport; "
          "until then disable HTTP/2 and reload, then verify old workers "
          "exited.")
    print("(exit 1)")
    return 1