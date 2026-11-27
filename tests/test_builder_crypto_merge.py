"""Builder, cryptographic helper, and merge security matrix tests."""
from __future__ import annotations

import base64
import hashlib
import re
import unittest

from helpers import PyCspCageTestCase, b64, strict_header, strong_nonce, valid_hash
from pycspcage import (
    CspCageError,
    audit_csp,
    build_csp,
    compute_hash,
    create_strict_csp,
    generate_nonce,
    merge_csp,
    normalize_directive_input,
    parse_csp,
)


MINIMAL_SAFE = {
    "default_src": ["'self'"],
    "object_src": ["'none'"],
    "base_uri": ["'none'"],
    "form_action": ["'self'"],
    "frame_ancestors": ["'none'"],
}


class BuilderCoreTests(PyCspCageTestCase):
    def test_minimal_safe_header_is_returned(self):
        header = build_csp(MINIMAL_SAFE)
        self.assertEqual(header, "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        self.assertTrue(audit_csp(header).safe)

    def test_create_strict_csp_is_clean(self):
        header = create_strict_csp()
        report = audit_csp(header)
        self.assertTrue(report.safe)
        self.assertTrue(report.strict_csp)
        self.assertEqual(report.score, 100)
        self.assertIn("'strict-dynamic'", header)
        self.assertIn("object-src 'none'", header)

    def test_create_strict_csp_accepts_supplied_nonce(self):
        nonce = strong_nonce(31)
        header = create_strict_csp({"nonce": nonce})
        self.assertIn("'nonce-" + nonce + "'", header)
        self.assertTrue(audit_csp(header).safe)

    def test_create_strict_csp_accepts_quoted_nonce(self):
        nonce = strong_nonce(33)
        header = create_strict_csp({"nonce": "'nonce-" + nonce + "'"})
        self.assertIn("'nonce-" + nonce + "'", header)

    def test_strict_header_has_csp3_inline_shadowing_when_requested(self):
        header = build_csp({
            "default_src": ["'self'"],
            "script_src": ["'unsafe-inline'", "'nonce-" + strong_nonce(35) + "'"],
            "object_src": ["'none'"],
            "base_uri": ["'none'"],
            "form_action": ["'self'"],
            "frame_ancestors": ["'none'"],
        })
        report = audit_csp(header)
        self.assertIn("CSP3_UNSAFE_INLINE_IGNORED", {finding.code for finding in report.findings})

    def test_header_order_is_deterministic(self):
        first = build_csp({"frameAncestors": ["'none'"], "defaultSrc": ["'self'"], "objectSrc": ["'none'"], "baseUri": ["'none'"], "formAction": ["'self'"]})
        second = build_csp({"object_src": ["'none'"], "form_action": ["'self'"], "default_src": ["'self'"], "base_uri": ["'none'"], "frame_ancestors": ["'none'"]})
        self.assertEqual(first, second)
        self.assertLess(first.index("default-src"), first.index("object-src"))
        self.assertLess(first.index("object-src"), first.index("base-uri"))

    def test_string_value_is_split_on_ascii_whitespace(self):
        header = build_csp(dict(MINIMAL_SAFE, script_src="'self' https://example.com/app.js"))
        self.assertIn("script-src 'self' https://example.com/app.js", header)

    def test_sandbox_true_is_valueless(self):
        header = build_csp(dict(MINIMAL_SAFE, sandbox=True))
        self.assertIn("; sandbox", header)
        parse_csp(header)

    def test_upgrade_insecure_requests_true_is_valueless(self):
        header = build_csp(dict(MINIMAL_SAFE, upgrade_insecure_requests=True))
        self.assertTrue(header.endswith("upgrade-insecure-requests"))
        parse_csp(header)

    def test_none_input_mapping_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_BUILD_INPUT", build_csp, None)

    def test_empty_mapping_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_BUILD_INPUT", build_csp, {})

    def test_none_values_are_omitted(self):
        header = build_csp(dict(MINIMAL_SAFE, script_src=None))
        self.assertNotIn("script-src", header)

    def test_unknown_build_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", build_csp, MINIMAL_SAFE, {"surprise": True})

    def test_require_clean_blocks_warnings(self):
        self.assertCodeRaises("CSPCAGE_UNSAFE_BUILD_OUTPUT", build_csp, MINIMAL_SAFE, {"require_clean_audit": True})

    def test_unsafe_error_carries_audit_report(self):
        with self.assertRaises(CspCageError) as caught:
            build_csp(dict(MINIMAL_SAFE, script_src=["*"]))
        self.assertEqual(caught.exception.code, "CSPCAGE_UNSAFE_BUILD_OUTPUT")
        self.assertTrue(hasattr(caught.exception, "audit"))
        self.assertIn("WILDCARD_SOURCE", {finding.code for finding in caught.exception.audit.findings})

    def test_strict_unknown_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", create_strict_csp, {"surprise": True})

    def test_strict_weak_nonce_rejected_by_audit(self):
        weak = b64(b"A" * 4)
        with self.assertRaises(CspCageError):
            create_strict_csp({"nonce": weak})

    def test_strict_report_uri_is_allowed_but_legacy(self):
        header = create_strict_csp({"report_uri": "https://reports.example.com/csp"})
        self.assertIn("report-uri https://reports.example.com/csp", header)
        self.assertIn("LEGACY_REPORT_URI", {finding.code for finding in audit_csp(header).findings})

    def test_normalize_returns_canonical_names(self):
        normalized = normalize_directive_input({"defaultSrc": "'self'", "object_src": "'none'"})
        self.assertIn("default-src", normalized)
        self.assertIn("object-src", normalized)


VALID_KEY_VARIANTS = []
for hyphen, variants in [
    ("default-src", ["default-src", "default_src", "defaultSrc", "DEFAULT-SRC"]),
    ("script-src-elem", ["script-src-elem", "script_src_elem", "scriptSrcElem"]),
    ("frame-ancestors", ["frame-ancestors", "frame_ancestors", "frameAncestors"]),
    ("upgrade-insecure-requests", ["upgrade-insecure-requests", "upgrade_insecure_requests", "upgradeInsecureRequests"]),
]:
    for variant in variants:
        VALID_KEY_VARIANTS.append((variant, hyphen))

INVALID_KEYS = [
    "",
    " ",
    "bad key",
    "unknown-directive",
    "plugin-types",
    "referrer",
    "block-all-mixed-content",
    "-bad",
    "bad-",
    "bad--key",
    "bad_key!",
    "__proto__",
    "__PROTO__",
    "constructor",
    "prototype",
    "key\x00",
    "key\n",
    "key\u202e",
    "x" * 81,
]

TOKEN_INJECTIONS = [
    "",
    "bad token",
    "bad\ttoken",
    "bad;token",
    "bad,token",
    "bad\\token",
    "bad\rtoken",
    "bad\ntoken",
    "bad\x00token",
    "bad\x1btoken",
    "bad\u202etoken",
    "x" * 513,
    None,
    42,
    b"'self'",
]

UNSAFE_BUILD_CASES = []
for directive in ("script_src", "object_src", "form_action"):
    for token in ("*", "javascript:", "data:", "blob:", "filesystem:", "http:"):
        UNSAFE_BUILD_CASES.append((directive, token))
for directive in ("script_src", "object_src"):
    for token in ("*.example.com", "example.com:*", "http://example.com/x"):
        UNSAFE_BUILD_CASES.append((directive, token))
UNSAFE_BUILD_CASES.append(("form_action", "http://example.com/x"))
UNSAFE_BUILD_CASES.extend([
    ("script_src", "'unsafe-inline'"),
    ("script_src", "'unsafe-eval'"),
    ("script_src", "'wasm-unsafe-eval'"),
    ("script_src", "https://cdn.jsdelivr.net"),
    ("script_src", "https://unpkg.com"),
    ("script_src", "https://cdnjs.cloudflare.com"),
    ("base_uri", "*"),
    ("base_uri", "https:"),
    ("frame_ancestors", "*"),
    ("frame_ancestors", "https:"),
    ("frame_ancestors", "http://example.com"),
])

VALID_CRYPTO_SIZES = list(range(16, 65))
INVALID_CRYPTO_SIZES = [-1, 0, 1, 8, 15, 65, 1024, True, 16.5, "16", None]

MERGE_CASES = [
    (
        ("default-src 'self'", "default-src https://example.com"),
        "default-src 'self' https://example.com",
    ),
    (
        ("object-src 'none'", "object-src 'self'"),
        "object-src 'none'",
    ),
    (
        ("script-src 'self'", "script-src 'self' https://example.com/app.js"),
        "script-src 'self' https://example.com/app.js",
    ),
    (
        ("base-uri 'none'", "frame-ancestors 'none'"),
        "base-uri 'none'; frame-ancestors 'none'",
    ),
]


class ValidKeyMatrix(PyCspCageTestCase):
    pass


class InvalidKeyMatrix(PyCspCageTestCase):
    pass


class TokenInjectionMatrix(PyCspCageTestCase):
    pass


class UnsafeBuildMatrix(PyCspCageTestCase):
    pass


class CryptoMatrix(PyCspCageTestCase):
    pass


class MergeMatrix(PyCspCageTestCase):
    pass


for index, (variant, canonical) in enumerate(VALID_KEY_VARIANTS):
    def test_key_variant(self, variant=variant, canonical=canonical):
        value = True if canonical == "upgrade-insecure-requests" else ["'none'"] if canonical in ("default-src", "script-src-elem", "frame-ancestors") else ["'none'"]
        normalized = normalize_directive_input({variant: value})
        self.assertIn(canonical, normalized)
    setattr(ValidKeyMatrix, "test_%02d_key_variant" % index, test_key_variant)

for index, key in enumerate(INVALID_KEYS):
    def test_invalid_key(self, key=key):
        with self.assertRaises(CspCageError):
            normalize_directive_input({key: ["'self'"]})
    setattr(InvalidKeyMatrix, "test_%02d_invalid_key" % index, test_invalid_key)

for index, token in enumerate(TOKEN_INJECTIONS):
    def test_token_injection(self, token=token):
        with self.assertRaises(CspCageError):
            build_csp(dict(MINIMAL_SAFE, script_src=["'self'", token]))
    setattr(TokenInjectionMatrix, "test_%02d_token_injection" % index, test_token_injection)

for index, (directive, token) in enumerate(UNSAFE_BUILD_CASES):
    def test_unsafe_build(self, directive=directive, token=token):
        with self.assertRaises(CspCageError) as caught:
            build_csp(dict(MINIMAL_SAFE, **{directive: [token]}))
        self.assertIn(caught.exception.code, ("CSPCAGE_UNSAFE_BUILD_OUTPUT", "CSPCAGE_INVALID_BUILD_INPUT"))
    setattr(UnsafeBuildMatrix, "test_%03d_unsafe_output_blocked" % index, test_unsafe_build)

for index, size in enumerate(VALID_CRYPTO_SIZES):
    def test_nonce_size(self, size=size):
        nonce = generate_nonce(size)
        raw = base64.b64decode(nonce.encode("ascii"), validate=True)
        self.assertEqual(len(raw), size)
        self.assertRegex(nonce, r"^[A-Za-z0-9+/]+={0,2}$")
    setattr(CryptoMatrix, "test_%02d_valid_nonce_size" % index, test_nonce_size)

for index, size in enumerate(INVALID_CRYPTO_SIZES):
    def test_bad_nonce_size(self, size=size):
        self.assertCodeRaises("CSPCAGE_INVALID_NONCE_INPUT", generate_nonce, size)
    setattr(CryptoMatrix, "test_%02d_invalid_nonce_size" % index, test_bad_nonce_size)

for index, (inputs, expected_fragment) in enumerate(MERGE_CASES):
    def test_merge_case(self, inputs=inputs, expected_fragment=expected_fragment):
        merged = merge_csp(*inputs)
        self.assertIn(expected_fragment, merged)
        parse_csp(merged)
    setattr(MergeMatrix, "test_%02d_merge_semantics" % index, test_merge_case)


class CryptoCoreTests(PyCspCageTestCase):
    def test_nonces_are_unique_in_practice(self):
        values = {generate_nonce() for _ in range(32)}
        self.assertEqual(len(values), 32)

    def test_hash_matches_hashlib_for_algorithms_and_content_types(self):
        contents = ["", "abc", "console.log(1);", b"\x00\x01binary", bytearray(b"bytearray"), memoryview(b"memory")]
        for algorithm in ("sha256", "sha384", "sha512"):
            for content in contents:
                data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
                expected = algorithm + "-" + base64.b64encode(hashlib.new(algorithm, data).digest()).decode("ascii")
                self.assertEqual(compute_hash(content, algorithm), expected)

    def test_sha256_empty_known_vector(self):
        self.assertEqual(compute_hash("", "sha256"), "sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=")

    def test_sha256_abc_known_vector(self):
        self.assertEqual(compute_hash("abc", "sha256"), "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")

    def test_invalid_hash_algorithm_rejected(self):
        for algorithm in ("", "sha1", "md5", "SHA256", "sha256 ", None, 256):
            self.assertCodeRaises("CSPCAGE_INVALID_HASH_INPUT", compute_hash, "abc", algorithm)

    def test_invalid_hash_content_rejected(self):
        for content in (None, 42, object(), ["x"], {"x": 1}):
            self.assertCodeRaises("CSPCAGE_INVALID_HASH_INPUT", compute_hash, content, "sha256")


class MergeCoreTests(PyCspCageTestCase):
    def test_list_input_expands(self):
        merged = merge_csp(["default-src 'self'", "object-src 'none'"])
        self.assertIn("default-src 'self'", merged)
        self.assertIn("object-src 'none'", merged)

    def test_mapping_input_accepted(self):
        merged = merge_csp({"default_src": ["'self'"]}, {"object_src": ["'none'"]})
        self.assertIn("default-src 'self'", merged)
        self.assertIn("object-src 'none'", merged)

    def test_parsed_input_accepted(self):
        parsed = parse_csp("default-src 'self'")
        merged = merge_csp(parsed, "object-src 'none'")
        self.assertIn("object-src 'none'", merged)

    def test_none_widening_requires_explicit_option(self):
        merged = merge_csp("img-src 'none'", "img-src 'self'")
        self.assertIn("img-src 'none'", merged)
        widened = merge_csp("img-src 'none'", "img-src 'self'", options={"allow_none_widening": True})
        self.assertIn("img-src 'self'", widened)
        self.assertNotIn("img-src 'none'", widened)

    def test_unsafe_inline_merge_rejected(self):
        self.assertCodeRaises("CSPCAGE_UNSAFE_INLINE_MERGE", merge_csp, "script-src 'unsafe-inline'", "script-src 'self'")

    def test_unsafe_inline_merge_explicitly_allowed(self):
        merged = merge_csp("script-src 'unsafe-inline'", "script-src 'self'", options={"allow_unsafe_inline": True, "allow_none_widening": True})
        self.assertIn("'unsafe-inline'", merged)

    def test_multi_policy_input_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_MERGE_INPUT", merge_csp, "default-src 'self', default-src 'none'", "object-src 'none'")

    def test_empty_merge_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_MERGE_INPUT", merge_csp)

    def test_unknown_merge_option_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", merge_csp, "default-src 'self'", options={"surprise": True})

    def test_non_mapping_options_rejected(self):
        self.assertCodeRaises("CSPCAGE_INVALID_OPTIONS", merge_csp, "default-src 'self'", options=True)

    def test_invalid_input_type_rejected(self):
        for bad in (None, 42, b"bytes", object()):
            self.assertCodeRaises("CSPCAGE_INVALID_MERGE_INPUT", merge_csp, bad)

    def test_output_is_reparsed_and_audited(self):
        merged = merge_csp("default-src 'self'", "object-src 'none'")
        self.assertEqual(parse_csp(merged).policy_count, 1)
        self.assertTrue(audit_csp(merged).valid)


if __name__ == "__main__":
    unittest.main()
