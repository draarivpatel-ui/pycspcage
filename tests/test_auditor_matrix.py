"""Auditor bypass detection and scoring matrix tests."""
from __future__ import annotations

import unittest
from types import MappingProxyType

from helpers import PyCspCageTestCase, b64, strict_header, strong_nonce, valid_hash
from pycspcage import audit_csp, is_safe_csp, parse_csp


def policy_with_script(source):
    return "default-src 'self'; script-src " + source + "; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"


def codes(report):
    return {finding.code for finding in report.findings}


class AuditorCoreTests(PyCspCageTestCase):
    def test_strict_header_is_clean_and_strict_shape(self):
        report = audit_csp(strict_header())
        self.assertTrue(report.valid)
        self.assertTrue(report.safe)
        self.assertTrue(report.strict_csp)
        self.assertEqual(report.score, 100)
        self.assertEqual(report.grade, "A+")
        self.assertEqual(report.counts["errors"], 0)
        self.assertEqual(report.counts["warnings"], 0)

    def test_hostile_text_never_throws(self):
        hostile_values = [
            "default-src 'self'\nscript-src *",
            "default-src 'self'\x00",
            "unknown-x 'self'",
            "default-src 'self'; default-src 'none'",
            "default-src 'sha256-short'",
            None,
            42,
        ]
        for value in hostile_values:
            report = audit_csp(value)
            self.assertFalse(report.valid)
            self.assertFalse(report.safe)
            self.assertGreaterEqual(report.counts["errors"], 1)

    def test_audit_accepts_parsed_input(self):
        parsed = parse_csp(strict_header())
        report = audit_csp(parsed)
        self.assertTrue(report.safe)
        self.assertEqual(report.policy_count, 1)

    def test_strict_option_treats_warnings_as_blocking(self):
        header = "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        normal = audit_csp(header)
        strict = audit_csp(header, {"strict": True})
        self.assertTrue(normal.safe)
        self.assertFalse(strict.safe)
        self.assertGreater(strict.counts["warnings"], 0)

    def test_is_safe_csp_matches_report(self):
        header = strict_header()
        self.assertEqual(is_safe_csp(header), audit_csp(header).safe)

    def test_report_objects_are_immutable(self):
        report = audit_csp(strict_header())
        with self.assertRaises(Exception):
            report.score = 1
        with self.assertRaises(TypeError):
            report.counts["errors"] = 99
        with self.assertRaises(AttributeError):
            report.findings += ()

    def test_parse_error_caps_score(self):
        report = audit_csp("default-src 'self'; default-src 'none'")
        self.assertFinding(report, "CSPCAGE_DUPLICATE_DIRECTIVE")
        self.assertLessEqual(report.score, 45)

    def test_multi_policy_score_uses_weakest_policy(self):
        chosen_nonce = strong_nonce(11)
        strong = "default-src 'self'; script-src 'nonce-" + chosen_nonce + "' 'strict-dynamic'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        weak = "script-src 'unsafe-inline'"
        report = audit_csp(strong + ", " + weak)
        self.assertEqual(report.policy_count, 2)
        self.assertFalse(report.strict_csp)
        self.assertLess(report.score, 100)

    def test_per_policy_results_present(self):
        report = audit_csp(strict_header())
        self.assertEqual(len(report.policies), 1)
        self.assertEqual(report.policies[0].score, 100)
        self.assertEqual(report.policies[0].grade, "A+")
        self.assertTrue(report.policies[0].strict_csp_shape)

    def test_invalid_options_fall_back_to_safe_defaults(self):
        report = audit_csp(strict_header(), {"max_bytes": 999999})
        self.assertTrue(report.safe)


THREAT_CASES = []

def add_threat(policy, code):
    THREAT_CASES.append((policy, code))


for directive in ("script-src", "script-src-elem", "script-src-attr", "default-src"):
    add_threat(directive + " 'unsafe-inline'", "UNSAFE_INLINE_ACTIVE")
    add_threat(directive + " 'unsafe-eval'", "UNSAFE_EVAL")
    add_threat(directive + " 'wasm-unsafe-eval'", "WASM_UNSAFE_EVAL")
    add_threat(directive + " 'unsafe-hashes'", "UNSAFE_HASHES")
    add_threat(directive + " *", "WILDCARD_SOURCE")
    add_threat(directive + " https:", "BROAD_HTTPS_SCHEME")
    add_threat(directive + " http:", "INSECURE_HTTP_SCHEME")
    add_threat(directive + " data:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " blob:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " filesystem:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " javascript:", "DANGEROUS_SCRIPT_SCHEME")
    add_threat(directive + " vbscript:", "DANGEROUS_SCRIPT_SCHEME")
    add_threat(directive + " *.example.com", "WILDCARD_HOST_SOURCE")
    add_threat(directive + " example.com:*", "WILDCARD_PORT_SOURCE")
    add_threat(directive + " http://example.com/app.js", "INSECURE_HTTP_HOST")

for directive in ("object-src", "connect-src", "form-action"):
    add_threat(directive + " *", "WILDCARD_SOURCE")
    add_threat(directive + " https:", "BROAD_HTTPS_SCHEME")
    add_threat(directive + " http:", "INSECURE_HTTP_SCHEME")
    add_threat(directive + " data:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " blob:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " filesystem:", "DANGEROUS_DATA_SCHEME")
    add_threat(directive + " javascript:", "DANGEROUS_SCRIPT_SCHEME")
    add_threat(directive + " *.example.com", "WILDCARD_HOST_SOURCE")
    add_threat(directive + " example.com:*", "WILDCARD_PORT_SOURCE")
    add_threat(directive + " http://example.com/submit", "INSECURE_HTTP_HOST")

for host in (
    "googleapis.com",
    "ajax.googleapis.com",
    "gstatic.com",
    "www.gstatic.com",
    "googleusercontent.com",
    "firebaseapp.com",
    "amazonaws.com",
    "s3.amazonaws.com",
    "cloudfront.net",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "raw.githubusercontent.com",
):
    add_threat("default-src 'self'; script-src https://" + host, "CDN_SCRIPT_GADGET_HOST")

for token, code in [
    ("'unsafe-inline'", "UNSAFE_INLINE_ACTIVE"),
    ("'unsafe-eval'", "UNSAFE_EVAL"),
    ("'wasm-unsafe-eval'", "WASM_UNSAFE_EVAL"),
]:
    add_threat(policy_with_script(token), code)

for byte_count in (1, 2, 4, 8, 15):
    nonce = b64(bytes([9]) * byte_count)
    add_threat(policy_with_script("'nonce-" + nonce + "'"), "WEAK_NONCE_ENTROPY")
for byte_count in (4, 8, 15):
    nonce = b64(bytes([9]) * byte_count)
    add_threat(policy_with_script("'nonce-" + nonce + "'"), "STATIC_NONCE_PLACEHOLDER")

for nonce in (
    b64(b"\x00" * 16),
    b64(bytes(range(16))),
    b64(bytes(range(15, -1, -1))),
    b64(b"ab" * 8),
):
    add_threat(policy_with_script("'nonce-" + nonce + "'"), "STATIC_NONCE_PLACEHOLDER")

for endpoint in (
    "http://reports.example.com/csp",
    "https://user@reports.example.com/csp",
    "https://user:pass@reports.example.com/csp",
    "https://localhost/csp",
    "https://127.0.0.1/csp",
    "https://10.0.0.8/csp",
    "https://169.254.1.1/csp",
    "https://172.16.0.8/csp",
    "https://192.168.0.8/csp",
    "https://100.64.0.8/csp",
    "https://198.18.0.8/csp",
    "https://[::1]/csp",
    "https://[fc00::1]/csp",
    "https://[fe80::1]/csp",
    "https://reports.example.com/",
    "//reports.example.com/csp",
):
    add_threat("default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri " + endpoint, "LEGACY_REPORT_URI")

for endpoint, code in [
    ("http://reports.example.com/csp", "REPORT_ENDPOINT_NOT_HTTPS"),
    ("https://user@reports.example.com/csp", "REPORT_ENDPOINT_CREDENTIALS"),
    ("https://localhost/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://127.0.0.1/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://10.0.0.8/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://169.254.1.1/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://172.16.0.8/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://192.168.0.8/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://[::1]/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK"),
    ("https://reports.example.com/", "REPORT_ENDPOINT_TOO_BROAD"),
    ("//reports.example.com/csp", "REPORT_ENDPOINT_PROTOCOL_RELATIVE"),
]:
    add_threat("default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri " + endpoint, code)

for value in ("*", "'self' https://example.com", "https:"):
    add_threat("default-src 'self'; script-src 'self'; object-src 'none'; base-uri " + value + "; form-action 'self'; frame-ancestors 'none'", "WEAK_BASE_URI")
for value in ("*", "https:"):
    add_threat("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors " + value, "WEAK_FRAME_ANCESTORS")

for value in ("*", "'self'", "https://example.com"):
    add_threat("default-src 'self'; script-src 'self'; object-src " + value + "; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "OBJECT_SRC_NOT_NONE")

add_threat("script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "MISSING_DEFAULT_SRC")
add_threat("object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "MISSING_SCRIPT_POLICY")
add_threat("default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "MISSING_SCRIPT_SRC")
add_threat("default-src 'self'; script-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'", "MISSING_OBJECT_SRC")
add_threat("default-src 'self'; script-src 'self'; object-src 'none'; form-action 'self'; frame-ancestors 'none'", "MISSING_BASE_URI")
add_threat("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'", "MISSING_FRAME_ANCESTORS")
add_threat("default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'", "MISSING_FORM_ACTION")
add_threat("default-src 'self'; default-src 'none'", "CSPCAGE_DUPLICATE_DIRECTIVE")
add_threat("made-up-directive 'self'", "CSPCAGE_UNKNOWN_DIRECTIVE")
add_threat("plugin-types application/pdf", "CSPCAGE_DEPRECATED_DIRECTIVE")
add_threat("default-src 'self'; script-src 'none' https://example.com/app.js", "NONE_WITH_OTHER_SOURCES")
add_threat("default-src 'self'; frame-ancestors 'none' https://example.com; object-src 'none'; base-uri 'none'; form-action 'self'", "NONE_WITH_OTHER_SOURCES")
add_threat("default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri https://2130706433/csp", "REPORT_ENDPOINT_PRIVATE_NETWORK")
add_threat("default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; report-uri https://2130706433/csp", "REPORT_ENDPOINT_NONCANONICAL_IP")
add_threat("default-src 'self'\n", "CSPCAGE_HEADER_INJECTION")
add_threat("default-src 'self'\x00", "CSPCAGE_CONTROL_CHARACTER")
add_threat("default-src 'self'\u202e", "CSPCAGE_INVALID_ASCII")


class ThreatMatrix(PyCspCageTestCase):
    pass


class NegativeAuditorTests(PyCspCageTestCase):
    def test_exact_path_cdn_is_not_gadget_finding(self):
        report = audit_csp(policy_with_script("https://cdn.jsdelivr.net/npm/example@1/app.js"))
        self.assertNoFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_strict_dynamic_suppresses_cdn_gadget_finding(self):
        nonce = strong_nonce(19)
        report = audit_csp(policy_with_script("'nonce-" + nonce + "' 'strict-dynamic' https://cdn.jsdelivr.net"))
        self.assertNoFinding(report, "CDN_SCRIPT_GADGET_HOST")

    def test_valid_hash_does_not_suppress_live_cdn_host(self):
        report = audit_csp(policy_with_script("'" + valid_hash("sha256") + "' https://unpkg.com"))
        self.assertFinding(report, "CDN_SCRIPT_GADGET_HOST")
        self.assertFalse(report.safe)

    def test_csp3_unsafe_inline_shadowing_is_warning(self):
        nonce = strong_nonce(23)
        report = audit_csp(policy_with_script("'unsafe-inline' 'nonce-" + nonce + "'"))
        self.assertFinding(report, "CSP3_UNSAFE_INLINE_IGNORED")
        self.assertNoFinding(report, "UNSAFE_INLINE_ACTIVE")

    def test_strong_nonce_alone_has_no_weakness_findings(self):
        nonce = b64(bytes((index * 37 + 11) % 256 for index in range(16)))
        report = audit_csp(policy_with_script("'nonce-" + nonce + "'"))
        self.assertNoFinding(report, "WEAK_NONCE_ENTROPY")
        self.assertNoFinding(report, "STATIC_NONCE_PLACEHOLDER")

    def test_repeated_nonce_detected_across_directives(self):
        nonce = strong_nonce(29)
        header = strict_header(nonce) + "; style-src 'nonce-" + nonce + "'"
        report = audit_csp(header)
        self.assertFinding(report, "REPEATED_NONCE")

    def test_https_report_endpoint_with_dedicated_path_is_clean_endpoint(self):
        header = strict_header() + "; report-uri https://reports.example.com/csp"
        report = audit_csp(header)
        self.assertFinding(report, "LEGACY_REPORT_URI")
        self.assertNoFinding(report, "REPORT_ENDPOINT_NOT_HTTPS")
        self.assertNoFinding(report, "REPORT_ENDPOINT_CREDENTIALS")
        self.assertNoFinding(report, "REPORT_ENDPOINT_PRIVATE_NETWORK")
        self.assertNoFinding(report, "REPORT_ENDPOINT_TOO_BROAD")

    def test_report_to_group_name_is_not_url_finding(self):
        header = strict_header() + "; report-to csp-endpoint"
        report = audit_csp(header)
        self.assertNoFinding(report, "REPORT_ENDPOINT_NOT_HTTPS")
        self.assertNoFinding(report, "REPORT_ENDPOINT_TOO_BROAD")

    def test_base_self_and_frame_self_are_not_weak(self):
        header = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'"
        report = audit_csp(header)
        self.assertNoFinding(report, "WEAK_BASE_URI")
        self.assertNoFinding(report, "WEAK_FRAME_ANCESTORS")

    def test_exact_object_none_is_not_weak(self):
        report = audit_csp(strict_header())
        self.assertNoFinding(report, "OBJECT_SRC_NOT_NONE")
        self.assertNoFinding(report, "MISSING_OBJECT_SRC")

    def test_scores_drop_monotonically_for_worse_policies(self):
        clean = audit_csp(strict_header()).score
        inline = audit_csp(policy_with_script("'unsafe-inline'")).score
        evil = audit_csp(policy_with_script("'unsafe-inline' 'unsafe-eval' javascript:")).score
        self.assertGreater(clean, inline)
        self.assertGreater(inline, evil)

    def test_findings_have_stable_fields(self):
        report = audit_csp(policy_with_script("'unsafe-inline'"))
        finding = next(item for item in report.findings if item.code == "UNSAFE_INLINE_ACTIVE")
        self.assertEqual(finding.severity, "error")
        self.assertEqual(finding.directive, "script-src")
        self.assertEqual(finding.policy_index, 0)
        self.assertIsNotNone(finding.recommendation)


for index, (policy, code) in enumerate(THREAT_CASES):
    def test_threat(self, policy=policy, code=code):
        report = audit_csp(policy)
        self.assertFinding(report, code)
    setattr(ThreatMatrix, "test_%03d_%s_detected" % (index, code.lower()), test_threat)


if __name__ == "__main__":
    unittest.main()
