"""Shared helpers for the pycspcage test suite."""
from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def strong_nonce(fill: int = 7) -> str:
    return b64(bytes((fill + index * 37 + index * index * 11) % 256 for index in range(16)))


def valid_hash(algorithm: str = "sha256") -> str:
    sizes = {"sha256": 32, "sha384": 48, "sha512": 64}
    return algorithm + "-" + b64(bytes(range(sizes[algorithm])))


def strict_header(nonce: str = None) -> str:
    nonce = strong_nonce() if nonce is None else nonce
    return (
        "default-src 'self'; "
        "script-src 'nonce-" + nonce + "' 'strict-dynamic'; "
        "style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; media-src 'self'; object-src 'none'; "
        "worker-src 'self'; manifest-src 'self'; base-uri 'none'; "
        "form-action 'self'; frame-ancestors 'none'; upgrade-insecure-requests"
    )


class PyCspCageTestCase(unittest.TestCase):
    def assertCodeRaises(self, code, func, *args, **kwargs):
        from pycspcage import CspCageError

        with self.assertRaises(CspCageError) as caught:
            func(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def assertFinding(self, report, code):
        self.assertIn(code, {finding.code for finding in report.findings})

    def assertNoFinding(self, report, code):
        self.assertNotIn(code, {finding.code for finding in report.findings})
