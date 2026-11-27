"""Create and inspect a strict-dynamic Content-Security-Policy."""
from __future__ import annotations

from pycspcage import audit_csp, create_strict_csp, generate_nonce, parse_csp


def main() -> None:
    nonce = generate_nonce()
    header = create_strict_csp({"nonce": nonce})
    parsed = parse_csp(header)
    report = audit_csp(header)
    print("header:", header)
    print("policies:", parsed.policy_count, "directives:", parsed.directive_count)
    print("safe:", report.safe, "score:", report.score, "grade:", report.grade)
    if not report.safe or not report.strict_csp:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
