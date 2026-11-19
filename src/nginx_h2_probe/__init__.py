"""nginx-h2-probe -- safe, reliable exposure check for the 2026 nginx
HTTP/2 RCEs (CVE-2026-123007, CVE-2026-123633).

Public API:

    from nginx_h2_probe import check

    result = check("origin.example.com", active=True)
    result["verdict"]             # "VULNERABLE" | "not-vulnerable/not-exposed" | "inconclusive"
    result["over_max_confirmed"]  # was the CVE-2026-123007 precondition reproduced?

CLI: ``nginx-h2-probe check HOST`` (also ``local`` and ``serve``).
"""

from nginx_h2_probe.core import (check, run, result_dict, version_assessment,
                                 VERSION)

__version__ = VERSION

__all__ = ["check", "run", "result_dict", "version_assessment", "__version__"]