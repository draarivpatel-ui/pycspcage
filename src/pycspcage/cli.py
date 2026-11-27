"""Command line interface for pycspcage."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import fields, is_dataclass
from types import MappingProxyType
from typing import Any, Iterable, List, Mapping, Optional

from .auditor import audit_csp
from .builder import build_csp, create_strict_csp
from .constants import CSPCAGE_VERSION
from .crypto import compute_hash, generate_nonce
from .errors import CspCageError
from .merge import merge_csp
from .parser import parse_csp


def _plain(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return {field.name: _plain(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, MappingProxyType) or isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, BaseException):
        return {"type": type(value).__name__, "code": getattr(value, "code", None), "detail": getattr(value, "detail", str(value))}
    return value


def _json_output(value: Any) -> str:
    return json.dumps(_plain(value), sort_keys=True, separators=(",", ":"))


def _clean_error_text(text: str) -> str:
    return "".join(char if 0x20 <= ord(char) <= 0x7E or char in "\n\t" else "?" for char in text)


def _read_json_object(text: str, label: str) -> dict:
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise CspCageError("CSPCAGE_INVALID_INPUT", label + " must be a JSON object: " + error.msg)
    if not isinstance(value, dict):
        raise CspCageError("CSPCAGE_INVALID_INPUT", label + " must be a JSON object")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pycspcage", description="Strict CSP Level 3 parser, auditor, builder, nonce guard, and hash helper")
    parser.add_argument("--version", action="store_true", help="print the package version and exit")
    sub = parser.add_subparsers(dest="command")

    parse = sub.add_parser("parse", help="strictly parse a CSP header")
    parse.add_argument("header")
    parse.add_argument("--json", action="store_true")

    audit = sub.add_parser("audit", help="audit a CSP header")
    audit.add_argument("header")
    audit.add_argument("--json", action="store_true")
    audit.add_argument("--strict", action="store_true", help="treat warnings as enforcement failures")

    build = sub.add_parser("build", help="build a CSP from a JSON directive object")
    build.add_argument("directives_json")
    build.add_argument("--clean", action="store_true", help="require a warning-free audit")
    build.add_argument("--allow-unsafe-inline", action="store_true")

    strict = sub.add_parser("strict", help="create a strict-dynamic CSP")
    strict.add_argument("--nonce")
    strict.add_argument("--report-uri")

    nonce = sub.add_parser("nonce", help="generate a CSPRNG nonce")
    nonce.add_argument("bytes", nargs="?", type=int, default=16)

    hash_command = sub.add_parser("hash", help="compute a CSP hash for inline content")
    hash_command.add_argument("content")
    hash_command.add_argument("--algorithm", default="sha256", choices=("sha256", "sha384", "sha512"))

    merge = sub.add_parser("merge", help="merge two or more CSP headers")
    merge.add_argument("headers", nargs="+")
    merge.add_argument("--clean", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if args.version:
        print("pycspcage " + CSPCAGE_VERSION)
        return 0
    if args.command is None:
        parser.print_usage(sys.stderr)
        return 2
    try:
        if args.command == "parse":
            parsed = parse_csp(args.header)
            if args.json:
                print(_json_output(parsed))
            else:
                print("policies=" + str(parsed.policy_count) + " directives=" + str(parsed.directive_count))
            return 0
        if args.command == "audit":
            report = audit_csp(args.header, {"strict": True} if args.strict else None)
            print(_json_output(report) if args.json else "safe=" + str(report.safe).lower() + " score=" + str(report.score) + " grade=" + report.grade + " errors=" + str(report.counts["errors"]) + " warnings=" + str(report.counts["warnings"]))
            return 0 if report.safe else 1
        if args.command == "build":
            directives = _read_json_object(args.directives_json, "directives JSON")
            print(build_csp(directives, {"require_clean_audit": args.clean, "allow_unsafe_inline": args.allow_unsafe_inline}))
            return 0
        if args.command == "strict":
            options = {}
            if args.nonce is not None:
                options["nonce"] = args.nonce
            if args.report_uri is not None:
                options["report_uri"] = args.report_uri
            print(create_strict_csp(options))
            return 0
        if args.command == "nonce":
            print(generate_nonce(args.bytes))
            return 0
        if args.command == "hash":
            print(compute_hash(args.content, args.algorithm))
            return 0
        if args.command == "merge":
            print(merge_csp(*args.headers, options={"require_clean_audit": args.clean}))
            return 0
    except CspCageError as error:
        print(_clean_error_text(error.code + ": " + error.detail), file=sys.stderr)
        return 2
    except (TypeError, ValueError) as error:
        print(_clean_error_text("CSPCAGE_INVALID_INPUT: " + str(error)), file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
