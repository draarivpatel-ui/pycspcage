"""Merge two policies and use a hash as a deployment gate."""
from __future__ import annotations

from pycspcage import audit_csp, compute_hash, merge_csp


INLINE_BOOT = "window.__BOOTED__ = true;"


def main() -> None:
    boot_hash = compute_hash(INLINE_BOOT, "sha256")
    application = "default-src 'self'; script-src 'self' 'sha256-" + boot_hash.split("-", 1)[1] + "'; object-src 'none'"
    navigation = "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    merged = merge_csp(application, navigation)
    report = audit_csp(merged)
    print("merged:", merged)
    print("hash:", boot_hash)
    print("safe:", report.safe, "score:", report.score)
    if not report.safe:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
