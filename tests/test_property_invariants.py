"""Deterministic property-style invariant tests (issue #2).

Generates bounded CSP headers from fixed seeds and checks parser/auditor
invariants: comma byte accounting, policy caps, finding truncation, and
duplicate-directive handling. Stdlib unittest only; runtime stays small.
"""
from __future__ import annotations

import random
import unittest

from helpers import PyCspCageTestCase
from pycspcage import audit_csp, parse_csp
from pycspcage.constants import CSPCAGE_ERROR_CODES

SEEDS = (1, 7, 42, 2026)
DIRECTIVES = ("default-src", "script-src", "style-src", "img-src", "connect-src", "object-src")
SOURCES = ("'self'", "'none'", "https://cdn.example.com", "data:", "'unsafe-inline'")


def generated_header(rng: random.Random) -> str:
    pieces = []
    for _ in range(rng.randint(1, 3)):
        directives = []
        for name in rng.sample(DIRECTIVES, rng.randint(1, 3)):
            directives.append(name + " " + " ".join(rng.sample(SOURCES, rng.randint(1, 2))))
        pieces.append("; ".join(directives))
    joiner = rng.choice((",", ", ", " ,  "))
    return joiner.join(pieces)


class CommaAccountingTests(PyCspCageTestCase):
    def test_max_bytes_counts_commas_and_whitespace_exactly_once(self):
        header = "default-src 'self', script-src 'self'"
        exact = len(header.encode("utf-8"))
        ok = parse_csp(header, {"strict": False, "max_bytes": exact})
        self.assertEqual(ok.policy_count, 2)
        self.assertNotIn(
            CSPCAGE_ERROR_CODES["INPUT_TOO_LARGE"], {e.code for e in ok.errors}
        )
        over = parse_csp(header, {"strict": False, "max_bytes": exact - 1})
        self.assertIn(
            CSPCAGE_ERROR_CODES["INPUT_TOO_LARGE"], {e.code for e in over.errors}
        )

    def test_generated_headers_never_exceed_policy_cap(self):
        for seed in SEEDS:
            rng = random.Random(seed)
            for _ in range(40):
                header = generated_header(rng)
                parsed = parse_csp(header, {"strict": False, "max_policies": 2})
                self.assertLessEqual(parsed.policy_count, 2)
                self.assertLessEqual(len(parsed.errors), 128)


class PolicyCapTests(PyCspCageTestCase):
    def test_max_policies_fails_closed_without_scanning_trailing_pieces(self):
        header = ", ".join("default-src 'self'" for _ in range(6))
        parsed = parse_csp(header, {"strict": False, "max_policies": 2})
        self.assertEqual(parsed.policy_count, 2)
        self.assertIn(
            CSPCAGE_ERROR_CODES["TOO_MANY_POLICIES"], {e.code for e in parsed.errors}
        )

    def test_empty_pieces_are_errors_not_policies(self):
        parsed = parse_csp("default-src 'self',, script-src 'self'", {"strict": False})
        self.assertEqual(parsed.policy_count, 2)
        self.assertIn(
            CSPCAGE_ERROR_CODES["EMPTY_POLICY"], {e.code for e in parsed.errors}
        )


class DuplicateDirectiveTests(PyCspCageTestCase):
    def test_duplicate_directive_never_overrides_first(self):
        header = "script-src 'self'; script-src 'unsafe-inline'"
        parsed = parse_csp(header, {"strict": False})
        policy = parsed.policies[0]
        effective = policy.directive_map["script-src"]
        self.assertEqual(effective.tokens, ("'self'",))
        duplicates = [d for d in policy.directives if d.name == "script-src"]
        self.assertTrue(duplicates[1].ignored)
        self.assertIn(
            CSPCAGE_ERROR_CODES["DUPLICATE_DIRECTIVE"], {e.code for e in parsed.errors}
        )


class FindingTruncationTests(PyCspCageTestCase):
    def test_later_error_is_not_dropped_behind_warnings(self):
        header = (
            "connect-src https:; form-action https:; "
            "script-src 'unsafe-inline'"
        )
        report = audit_csp(header, {"max_findings": 2})
        self.assertLessEqual(len(report.findings), 2)
        self.assertIn("error", {f.severity for f in report.findings})

    def test_parser_errors_stay_within_max_findings(self):
        header = "; ".join("bogus-directive 'self'" for _ in range(20))
        parsed = parse_csp(header, {"strict": False, "max_findings": 3})
        self.assertLessEqual(len(parsed.errors), 3)


if __name__ == "__main__":
    unittest.main()
