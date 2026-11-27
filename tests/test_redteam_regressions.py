"""Regression tests for the independent adversarial audit."""
from __future__ import annotations

import unittest

from helpers import PyCspCageTestCase, b64, strong_nonce, valid_hash
from pycspcage import CSPCAGE_ERROR_CODES, CspCageError, audit_csp, parse_csp


def script_policy(source):
    return "default-src 'self'; script-src " + source + "; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"


def endpoint_policy(endpoint):
    return "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri " + endpoint


def finding_codes(report):
    return {finding.code for finding in report.findings}


class RedTeamRegressionTests(PyCspCageTestCase):
    def test_max_findings_prioritizes_errors_over_warnings(self):
        report = audit_csp("object-src *", {"max_findings": 1})
        self.assertGreaterEqual(report.counts["errors"], 1)
        self.assertFalse(report.safe)

    def test_max_findings_never_turns_error_policy_safe(self):
        header = "default-src 'self'; object-src *; script-src 'unsafe-inline'"
        report = audit_csp(header, {"max_findings": 2})
        self.assertGreaterEqual(report.counts["errors"], 1)
        self.assertFalse(report.safe)

    def test_bare_jsdelivr_host_is_a_gadget_host(self):
        report = audit_csp(script_policy("https://jsdelivr.net"))
        self.assertFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_exact_path_angular_cdn_gadget_is_detected(self):
        url = "https://cdn.jsdelivr.net/npm/angular@1.8.2/angular.min.js"
        report = audit_csp(script_policy(url))
        self.assertFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_exact_path_cdnjsonp_gadget_is_detected(self):
        report = audit_csp("default-src 'self'; script-src https://cdnjs.cloudflare.com/ajax/libs/jsonp/1.0/callback.js; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.assertFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_ordinary_exact_path_cdn_is_not_automatically_gadget(self):
        report = audit_csp(script_policy("https://cdn.jsdelivr.net/npm/example@1/app.js"))
        self.assertNoFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_valid_hash_does_not_disable_live_cdn_host_source(self):
        report = audit_csp(script_policy("'" + valid_hash("sha256") + "' https://unpkg.com"))
        self.assertFinding(report, "CDN_SCRIPT_GADGET_HOST")
        self.assertFalse(report.safe)

    def test_strict_dynamic_still_suppresses_csp3_host_allowlist(self):
        nonce = strong_nonce(41)
        report = audit_csp(script_policy("'nonce-" + nonce + "' 'strict-dynamic' https://cdn.jsdelivr.net"))
        self.assertNoFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_trailing_dot_localhost_report_endpoint_is_private(self):
        for endpoint in ("https://localhost./csp", "https://x.localhost./csp", "https://127.0.0.1./csp"):
            report = audit_csp(endpoint_policy(endpoint))
            self.assertFinding(report, "REPORT_ENDPOINT_PRIVATE_NETWORK")

    def test_protocol_relative_report_endpoint_is_fully_inspected(self):
        report = audit_csp(endpoint_policy("//user:pass@localhost/csp"))
        self.assertFinding(report, "REPORT_ENDPOINT_PROTOCOL_RELATIVE")
        self.assertFinding(report, "REPORT_ENDPOINT_CREDENTIALS")
        self.assertFinding(report, "REPORT_ENDPOINT_PRIVATE_NETWORK")

    def test_ascii_oversize_rejected_before_character_scan(self):
        header = "default-src 'self' " + "A" * 9000
        with self.assertRaises(CspCageError) as caught:
            parse_csp(header)
        self.assertEqual(caught.exception.code, "CSPCAGE_INPUT_TOO_LARGE")

    def test_policy_cap_stops_processing_extra_headers(self):
        parsed = parse_csp(["default-src 'self'"] * 40, {"strict": False, "max_policies": 2, "max_findings": 512})
        self.assertLessEqual(parsed.policy_count, 2)
        self.assertIn("CSPCAGE_TOO_MANY_POLICIES", {error.code for error in parsed.errors})
        self.assertLessEqual(len(parsed.errors), 3)

    def test_error_cap_stops_consuming_trailing_header_sequence(self):
        consumed = []

        class CountingHeaders(list):
            def __iter__(self):
                for item in super().__iter__():
                    consumed.append(item)
                    yield item

        headers = CountingHeaders(["bad\x00header"] * 1000)
        parsed = parse_csp(headers, {"strict": False, "max_findings": 3})
        self.assertEqual(len(parsed.errors), 3)
        self.assertLessEqual(len(consumed), 4)

    def test_short_nonce_still_critical(self):
        report = audit_csp(script_policy("'nonce-" + b64(b"x" * 15) + "'"))
        self.assertFinding(report, "WEAK_NONCE_ENTROPY")
        self.assertFalse(report.safe)


if __name__ == "__main__":
    unittest.main()
