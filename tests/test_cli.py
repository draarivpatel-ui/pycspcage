"""Command line interface behavior and clean-failure tests."""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import unittest

from helpers import ROOT, PyCspCageTestCase, strict_header, strong_nonce
from pycspcage import audit_csp, parse_csp


def run_cli(args):
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(
        [sys.executable, "-m", "pycspcage"] + list(args),
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )


class CliCoreTests(PyCspCageTestCase):
    def test_version_exact(self):
        result = run_cli(["--version"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "pycspcage 1.0.0")
        self.assertEqual(result.stderr, "")

    def test_help_zero(self):
        result = run_cli(["--help"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("audit", result.stdout)
        self.assertIn("strict", result.stdout)

    def test_no_arguments_usage_error(self):
        result = run_cli([])
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_unknown_command_clean_error(self):
        result = run_cli(["not-a-command"])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)

    def test_parse_summary(self):
        result = run_cli(["parse", "default-src 'self'"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("policies=1", result.stdout)
        self.assertIn("directives=1", result.stdout)

    def test_parse_json_shape(self):
        result = run_cli(["parse", strict_header(), "--json"])
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertEqual(data["policy_count"], 1)
        self.assertEqual(data["directive_count"], 14)
        self.assertEqual(data["errors"], [])
        self.assertIn("script-src", data["policies"][0]["directive_map"])

    def test_parse_invalid_has_typed_error(self):
        result = run_cli(["parse", "unknown-x 'self'"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_UNKNOWN_DIRECTIVE", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_audit_clean_zero(self):
        result = run_cli(["audit", strict_header()])
        self.assertEqual(result.returncode, 0)
        self.assertIn("safe=true", result.stdout)
        self.assertIn("score=100", result.stdout)

    def test_audit_unsafe_one(self):
        result = run_cli(["audit", "script-src 'unsafe-inline'"])
        self.assertEqual(result.returncode, 1)
        self.assertIn("safe=false", result.stdout)

    def test_audit_unsafe_json_shape(self):
        result = run_cli(["audit", "script-src 'unsafe-inline' cdn.jsdelivr.net; object-src *", "--json"])
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        codes = {finding["code"] for finding in data["findings"]}
        self.assertIn("UNSAFE_INLINE_ACTIVE", codes)
        self.assertIn("CDN_SCRIPT_GADGET_HOST", codes)
        self.assertIn("OBJECT_SRC_NOT_NONE", codes)
        self.assertFalse(data["safe"])

    def test_audit_strict_warnings_one(self):
        header = "default-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
        normal = run_cli(["audit", header])
        strict = run_cli(["audit", header, "--strict"])
        self.assertEqual(normal.returncode, 0)
        self.assertEqual(strict.returncode, 1)

    def test_nonce_default(self):
        result = run_cli(["nonce"])
        self.assertEqual(result.returncode, 0)
        raw = base64.b64decode(result.stdout.strip().encode("ascii"), validate=True)
        self.assertEqual(len(raw), 16)

    def test_nonce_size(self):
        result = run_cli(["nonce", "32"])
        self.assertEqual(result.returncode, 0)
        raw = base64.b64decode(result.stdout.strip().encode("ascii"), validate=True)
        self.assertEqual(len(raw), 32)

    def test_nonce_bad_size(self):
        result = run_cli(["nonce", "8"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_INVALID_NONCE_INPUT", result.stderr)

    def test_hash_sha256_vector(self):
        result = run_cli(["hash", "abc"])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=")

    def test_hash_sha512_shape(self):
        result = run_cli(["hash", "abc", "--algorithm", "sha512"])
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stdout.startswith("sha512-"))

    def test_strict_outputs_parseable_clean_policy(self):
        result = run_cli(["strict"])
        self.assertEqual(result.returncode, 0)
        header = result.stdout.strip()
        self.assertTrue(audit_csp(header).safe)
        self.assertEqual(parse_csp(header).policy_count, 1)

    def test_strict_with_supplied_nonce(self):
        nonce = strong_nonce(41)
        result = run_cli(["strict", "--nonce", nonce])
        self.assertEqual(result.returncode, 0)
        self.assertIn("'nonce-" + nonce + "'", result.stdout)

    def test_build_valid_json(self):
        payload = json.dumps({"default_src": ["'self'"], "object_src": ["'none'"], "base_uri": ["'none'"], "form_action": ["'self'"], "frame_ancestors": ["'none'"]})
        result = run_cli(["build", payload])
        self.assertEqual(result.returncode, 0)
        self.assertIn("default-src 'self'", result.stdout)

    def test_build_invalid_json(self):
        result = run_cli(["build", "{"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_INVALID_INPUT", result.stderr)

    def test_build_non_object_json(self):
        result = run_cli(["build", "[]"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_INVALID_INPUT", result.stderr)

    def test_build_unsafe_json(self):
        payload = json.dumps({"script_src": ["*"]})
        result = run_cli(["build", payload])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_UNSAFE_BUILD_OUTPUT", result.stderr)

    def test_merge_two_headers(self):
        result = run_cli(["merge", "default-src 'self'", "object-src 'none'"])
        self.assertEqual(result.returncode, 0)
        self.assertIn("default-src 'self'", result.stdout)
        self.assertIn("object-src 'none'", result.stdout)

    def test_control_input_error_is_clean(self):
        result = run_cli(["parse", "default-src 'self'" + chr(27)])
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(chr(27), result.stderr)
        self.assertNotIn("Traceback", result.stderr)


BAD_INVOCATIONS = [
    ["parse"],
    ["audit"],
    ["build"],
    ["hash"],
    ["merge"],
    ["nonce", "x"],
    ["hash", "abc", "--algorithm", "sha1"],
    ["parse", "default-src 'self'", "--surprise"],
    ["audit", "default-src 'self'", "--surprise"],
    ["strict", "--surprise"],
]

BAD_PARSE_HEADERS = [
    "default-src 'self'\n",
    "default-src 'self'\x01",
    "default-src 'self'\u202e",
    "default-src 'self';",
    "default-src 'self'; default-src 'none'",
    "plugin-types application/pdf",
    "unknown-x 'self'",
    "default-src 'sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA='",
    "default-src 'nonce-!!!'",
    "default-src https://user@example.com",
]

UNSAFE_AUDIT_HEADERS = [
    "script-src 'unsafe-inline'",
    "script-src 'unsafe-eval'",
    "script-src *",
    "script-src javascript:",
    "script-src https://cdn.jsdelivr.net",
    "object-src *",
    "base-uri *",
    "frame-ancestors *",
    "object-src 'none'; base-uri *",
    "default-src *",
]


class BadInvocationMatrix(PyCspCageTestCase):
    pass


class BadParseCliMatrix(PyCspCageTestCase):
    pass


class UnsafeAuditCliMatrix(PyCspCageTestCase):
    pass


for index, args in enumerate(BAD_INVOCATIONS):
    def test_bad_invocation(self, args=args):
        result = run_cli(args)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)
    setattr(BadInvocationMatrix, "test_%02d_bad_invocation" % index, test_bad_invocation)

for index, header in enumerate(BAD_PARSE_HEADERS):
    def test_bad_parse_header(self, header=header):
        result = run_cli(["parse", header])
        self.assertEqual(result.returncode, 2)
        self.assertIn("CSPCAGE_", result.stderr)
        self.assertNotIn("Traceback", result.stderr)
    setattr(BadParseCliMatrix, "test_%02d_bad_parse_header" % index, test_bad_parse_header)

for index, header in enumerate(UNSAFE_AUDIT_HEADERS):
    def test_unsafe_audit_header(self, header=header):
        result = run_cli(["audit", header, "--json"])
        self.assertEqual(result.returncode, 1)
        data = json.loads(result.stdout)
        self.assertFalse(data["safe"])
        self.assertGreaterEqual(data["counts"]["errors"], 1)
    setattr(UnsafeAuditCliMatrix, "test_%02d_unsafe_audit_header" % index, test_unsafe_audit_header)


if __name__ == "__main__":
    unittest.main()
