"""Parser correctness and hostile-input matrix tests."""
from __future__ import annotations

import unittest

from helpers import PyCspCageTestCase, b64, strict_header, strong_nonce, valid_hash
from pycspcage import CSP_DIRECTIVES, CSPCAGE_ERROR_CODES, CspCageError, parse_csp, parse_source_expression


def source_test_header(token):
    return "default-src " + token


def assert_valid_source(case, test):
    parsed = parse_csp(source_test_header(case))
    source = parsed.policies[0].directive_map["default-src"].sources[0]
    test.assertEqual(source.token, case)


def assert_invalid_source(case, test):
    with test.assertRaises(CspCageError):
        parse_source_expression(case)


class ParserCoreTests(PyCspCageTestCase):
    def test_versioned_strict_header_parses(self):
        parsed = parse_csp(strict_header())
        self.assertEqual(parsed.policy_count, 1)
        self.assertEqual(parsed.directive_count, 14)
        self.assertEqual(len(parsed.errors), 0)
        self.assertIn("script-src", parsed.policies[0].directive_map)

    def test_multiple_headers_create_multiple_policies(self):
        parsed = parse_csp(["default-src 'self'", "default-src 'none'"])
        self.assertEqual(parsed.policy_count, 2)
        self.assertEqual(parsed.policies[0].index, 0)
        self.assertEqual(parsed.policies[1].index, 1)

    def test_comma_separated_policies_parse(self):
        parsed = parse_csp("default-src 'self', default-src 'none'")
        self.assertEqual(parsed.policy_count, 2)

    def test_directive_names_are_case_insensitive(self):
        parsed = parse_csp("DeFaUlT-SrC 'self'")
        self.assertIn("default-src", parsed.policies[0].directive_map)

    def test_non_strict_collects_errors(self):
        parsed = parse_csp("unknown-x 'self'; default-src 'self'", {"strict": False})
        self.assertGreaterEqual(len(parsed.errors), 1)
        self.assertEqual(parsed.errors[0].code, "CSPCAGE_UNKNOWN_DIRECTIVE")
        self.assertIn("default-src", parsed.policies[0].directive_map)

    def test_non_strict_marks_duplicate_ignored(self):
        parsed = parse_csp("default-src 'self'; default-src 'none'", {"strict": False})
        duplicates = [item for item in parsed.policies[0].directives if item.name == "default-src"]
        self.assertEqual(len(duplicates), 2)
        self.assertFalse(duplicates[0].ignored)
        self.assertTrue(duplicates[1].ignored)
        self.assertEqual(parsed.policies[0].directive_map["default-src"].tokens, ("'self'",))

    def test_error_context_is_bounded(self):
        with self.assertRaises(CspCageError) as caught:
            parse_csp("default-src 'self'\n")
        self.assertEqual(caught.exception.code, "CSPCAGE_HEADER_INJECTION")
        self.assertEqual(caught.exception.context["policy_index"], 0)

    def test_input_must_be_string_or_sequence(self):
        for bad in (None, 42, b"default-src 'self'", {}, []):
            with self.assertRaises(CspCageError):
                parse_csp(bad)

    def test_unknown_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", parse_csp, "default-src 'self'", {"made_up": 1})

    def test_zero_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", parse_csp, "default-src 'self'", {"max_bytes": 0})

    def test_bool_option_rejected_as_integer(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", parse_csp, "default-src 'self'", {"max_bytes": True})

    def test_hard_limit_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", parse_csp, "default-src 'self'", {"max_bytes": 65537})


VALID_DIRECTIVE_HEADERS = []
for _name in sorted(CSP_DIRECTIVES):
    if _name in ("sandbox", "upgrade-insecure-requests"):
        _value = ""
    elif _name in ("report-uri", "report-to"):
        _value = " https://reports.example.com/csp"
    elif _name == "require-sri-for":
        _value = " script style"
    elif _name == "require-trusted-types-for":
        _value = " 'script'"
    elif _name == "trusted-types":
        _value = " default dompurify"
    else:
        _value = " 'self'"
    VALID_DIRECTIVE_HEADERS.append((_name, _name + _value))

DEPRECATED = ["block-all-mixed-content", "plugin-types", "referrer"]
MALFORMED_HEADERS = [
    "",
    "   ",
    ",",
    "default-src 'self',",
    ",default-src 'self'",
    "default-src 'self', ,default-src 'none'",
    "default-src 'self';",
    "default-src 'self';;script-src 'self'",
    "default-src",
    "default-src ",
    "unknown-directive 'self'",
    "default-src 'self'; unknown-directive 'self'",
    "default src 'self'",
    "default-src\t\t",
    "default-src 'self'\r",
    "default-src 'self'\n",
    "default-src 'self'\x00",
    "default-src 'self'\x01",
    "default-src 'self'\x7f",
    "default-src 'self'\u202e",
    "default-src 'self'; default-src 'none'",
    "default-src 'self'; DEFAULT-SRC 'none'",
    "block-all-mixed-content",
    "plugin-types application/pdf",
    "referrer no-referrer",
    "upgrade-insecure-requests yes",
    "sandbox allow-not-real",
    "require-sri-for font",
    "require-trusted-types-for 'none'",
    "trusted-types bad policy!",
    "report-uri",
    "report-to one two",
    "report-uri bad\\endpoint",
    "report-uri http://example.com/%zz",
]

VALID_SOURCES = [
    "*",
    "'none'",
    "'self'",
    "'unsafe-inline'",
    "'unsafe-eval'",
    "'strict-dynamic'",
    "'unsafe-hashes'",
    "'report-sample'",
    "'wasm-unsafe-eval'",
    "'inline-speculation-rules'",
    "'SeLf'",
    "http:",
    "https:",
    "data:",
    "blob:",
    "filesystem:",
    "mediastream:",
    "ws:",
    "wss:",
    "javascript:",
    "example.com",
    "cdn.example.com",
    "example.com.",
    "a.example",
    "0.example.com",
    "example-site.com",
    "*.example.com",
    "*.cdn.example.co.uk",
    "example.com:443",
    "example.com:0",
    "example.com:65535",
    "example.com:*",
    "https://example.com",
    "http://example.com",
    "wss://example.com/socket",
    "https://example.com:443",
    "https://example.com:*",
    "https://example.com/",
    "https://example.com/app.js",
    "https://example.com/static/",
    "https://example.com/a%20b.js",
    "https://example.com/%2e%2e/app.js",
    "example.com/app.js",
    "example.com/static/",
    "127.0.0.1",
    "127.0.0.1:8080",
    "https://127.0.0.1/app.js",
    "192.168.1.20",
    "[::1]",
    "[2001:db8::1]",
    "[2001:db8::1]:443",
    "https://[2001:db8::1]",
    "https://[2001:db8::1]:443/app.js",
    "very-long-but-valid-label-" + "a" * 20 + ".example.com",
]
for _byte_count in (1, 4, 15, 16, 32, 64):
    VALID_SOURCES.append("'nonce-" + b64(bytes([7]) * _byte_count) + "'")
for _algorithm in ("sha256", "sha384", "sha512"):
    VALID_SOURCES.append("'" + valid_hash(_algorithm) + "'")

INVALID_SOURCES = [
    "",
    " ",
    "bad source",
    "bad\tsource",
    "'",
    "''",
    "'self",
    "self'",
    "'self'extra",
    "'unknown-keyword'",
    "'nonce-'",
    "'nonce-!!!'",
    "'nonce-A='",
    "'nonce-A'",
    "'sha256-'",
    "'sha1-" + b64(b"A" * 20) + "'",
    "'md5-" + b64(b"A" * 16) + "'",
    "'sha256-" + b64(b"A" * 31) + "'",
    "'sha256-" + b64(b"A" * 33) + "'",
    "'sha384-" + b64(b"A" * 32) + "'",
    "'sha512-" + b64(b"A" * 63) + "'",
    "'sha256-!!!!'",
    "'sha256-" + "A" * 43 + "==='",
    "'sha256-" + "A" * 41 + "=" + "'",
    "//example.com",
    "http://",
    "https://",
    "https://user@example.com",
    "https://user:pass@example.com",
    "https://example.com?x=1",
    "https://example.com#x",
    "https://example.com\\app.js",
    "https://example.com/%zz",
    "https://example.com/%a",
    "https://example.com/path*",
    "http://exa_mple.com",
    "http://-example.com",
    "http://example-.com",
    "http://example..com",
    "http://" + "a" * 64 + ".com",
    "http://" + "a" * 250 + ".com",
    "*example.com",
    "*. ",
    "*.",
    "*..example.com",
    "*.example-.com",
    "example.com:-1",
    "example.com:65536",
    "example.com:abc",
    "example.com:443:80",
    "example.com::443",
    "[::1",
    "::1]",
    "[::1x]",
    "[::1]x",
    "[::1]:65536",
    "https://[::1",
    "https://[]",
    "https://:443",
    "https://example.com:99999",
    "https://example.com;script-src",
    "https://example.com,img-src",
    "https://example.com\x00",
    "https://example.com\x1b",
    "https://example.com/\u202e",
    "https://exa%2emple.com",
    "https://127.1",
    "https://2130706433",
    "https://0x7f000001",
    "https://0177.0.0.1",
    "https://001.2.3.4",
    "https://[fe80::1%25eth0]",
]


BOUND_CASES = []
for _name, _option, _good, _bad in [
    ("bytes", "max_bytes", "default-src 'self'", "default-src 'self'    "),
    ("policies", "max_policies", "default-src 'self'", "default-src 'self', default-src 'none'"),
    ("directive_count", "max_directives_per_policy", "default-src 'self'", "default-src 'self'; object-src 'none'"),
    ("total_directives", "max_total_directives", "default-src 'self'", "default-src 'self'; object-src 'none'"),
    ("sources", "max_sources_per_directive", "default-src 'self'", "default-src 'self' https://example.com"),
    ("source_length", "max_source_length", "default-src 'self'", "default-src https://example.com"),
]:
    BOUND_CASES.append((_name, _option, _good, _bad))


class ValidDirectiveMatrix(PyCspCageTestCase):
    pass


class MalformedHeaderMatrix(PyCspCageTestCase):
    pass


class ValidSourceMatrix(PyCspCageTestCase):
    pass


class InvalidSourceMatrix(PyCspCageTestCase):
    pass


class BoundMatrix(PyCspCageTestCase):
    pass


def _add_test(cls, name, fn):
    setattr(cls, name, fn)


for index, (name, header) in enumerate(VALID_DIRECTIVE_HEADERS):
    def test_valid_directive(self, header=header, name=name):
        parsed = parse_csp(header)
        self.assertIn(name, parsed.policies[0].directive_map)
    _add_test(ValidDirectiveMatrix, "test_%02d_%s_valid" % (index, name.replace("-", "_")), test_valid_directive)

for index, header in enumerate(MALFORMED_HEADERS):
    def test_bad_header(self, header=header):
        with self.assertRaises(CspCageError):
            parse_csp(header)
    _add_test(MalformedHeaderMatrix, "test_%02d_malformed_header_rejected" % index, test_bad_header)

for index, source in enumerate(VALID_SOURCES):
    def test_valid_source(self, source=source):
        assert_valid_source(source, self)
    _add_test(ValidSourceMatrix, "test_%03d_valid_source" % index, test_valid_source)

for index, source in enumerate(INVALID_SOURCES):
    def test_invalid_source(self, source=source):
        assert_invalid_source(source, self)
    _add_test(InvalidSourceMatrix, "test_%03d_invalid_source" % index, test_invalid_source)

for index, (name, option, good, bad) in enumerate(BOUND_CASES):
    def test_bound_good(self, option=option, good=good):
        bound = len(good.encode("utf-8")) if option == "max_bytes" else 6 if option == "max_source_length" else 1
        parsed = parse_csp(good, {option: bound})
        self.assertGreaterEqual(parsed.policy_count, 1)
    def test_bound_bad(self, option=option, bad=bad):
        with self.assertRaises(CspCageError):
            parse_csp(bad, {option: 1})
    _add_test(BoundMatrix, "test_%02d_%s_within_bound" % (index, name), test_bound_good)
    _add_test(BoundMatrix, "test_%02d_%s_over_bound" % (index, name), test_bound_bad)


if __name__ == "__main__":
    unittest.main()
