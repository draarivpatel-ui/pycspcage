"""Audit a realistic but intentionally weak legacy CSP."""
from __future__ import annotations

from pycspcage import audit_csp


LEGACY_POLICY = (
    "default-src 'self'; "
    "script-src 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
    "object-src *; base-uri *; frame-ancestors *; "
    "report-uri http://localhost/"
)


def main() -> None:
    report = audit_csp(LEGACY_POLICY)
    print("safe:", report.safe, "score:", report.score, "grade:", report.grade)
    for finding in report.findings:
        print(finding.severity + " " + finding.code + " " + (finding.recommendation or ""))
    expected = {"UNSAFE_INLINE_ACTIVE", "UNSAFE_EVAL", "CDN_SCRIPT_GADGET_HOST", "OBJECT_SRC_NOT_NONE", "WEAK_BASE_URI", "WEAK_FRAME_ANCESTORS"}
    seen = {finding.code for finding in report.findings}
    missing = expected - seen
    if report.safe or missing:
        raise SystemExit("audit missed expected legacy bypasses: " + ",".join(sorted(missing)))


if __name__ == "__main__":
    main()
