"""Small bounded helpers shared by the parser, builder, and auditor."""
from __future__ import annotations

import base64
import binascii
from types import MappingProxyType
from typing import Any, Iterable, List, Mapping, Optional

from .constants import CSP_PARSE_BOUNDS, CSP_PARSE_HARD_LIMITS, CSPCAGE_ERROR_CODES, DANGEROUS_OBJECT_KEYS
from .errors import CspCageError


def byte_length(text: str) -> int:
    return len(text.encode("utf-8"))


def truncate_detail(text: object, max_length: int = 96) -> str:
    value = str(text)
    if len(value) <= max_length:
        return value
    return value[: max_length - 3] + "..."


def scan_header_characters(text: str, policy_index: int = 0) -> None:
    for index, char in enumerate(text):
        code = ord(char)
        if char in ("\r", "\n"):
            raise CspCageError(
                CSPCAGE_ERROR_CODES["HEADER_INJECTION"],
                "CR or LF header injection is forbidden",
                {"policy_index": policy_index, "character_index": index},
            )
        if code == 0:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["CONTROL_CHARACTER"],
                "NUL bytes are forbidden",
                {"policy_index": policy_index, "character_index": index},
            )
        if (code < 0x20 and char != "\t") or code == 0x7F:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["CONTROL_CHARACTER"],
                "control characters are forbidden",
                {"policy_index": policy_index, "character_index": index},
            )
        if code > 0x7E:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["INVALID_ASCII"],
                "non-ASCII, Unicode format, bidi, and surrogate code units are forbidden",
                {"policy_index": policy_index, "character_index": index},
            )


def split_whitespace(text: str) -> List[str]:
    return [part for part in text.strip().replace("\t", " ").split(" ") if part]


def is_plain_mapping(value: object) -> bool:
    return isinstance(value, dict)


def resolve_parse_options(options: Optional[Mapping[str, Any]] = None) -> Mapping[str, Any]:
    if options is None:
        options = {}
    if not is_plain_mapping(options):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "options must be a plain mapping")
    for key in options:
        if key not in CSP_PARSE_BOUNDS and key not in ("strict",):
            raise CspCageError(
                CSPCAGE_ERROR_CODES["INVALID_OPTIONS"],
                "unknown option " + truncate_detail(key, 40),
            )

    def bound(name: str) -> int:
        value = options.get(name, CSP_PARSE_BOUNDS[name])
        hard = CSP_PARSE_HARD_LIMITS[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > hard:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["INVALID_OPTIONS"],
                name + " must be an integer from 1 to " + str(hard),
            )
        return value

    return MappingProxyType({
        "max_bytes": bound("max_bytes"),
        "max_policies": bound("max_policies"),
        "max_directives_per_policy": bound("max_directives_per_policy"),
        "max_total_directives": bound("max_total_directives"),
        "max_sources_per_directive": bound("max_sources_per_directive"),
        "max_source_length": bound("max_source_length"),
        "max_findings": bound("max_findings"),
        "strict": options.get("strict", True) is not False,
    })


def decode_base64_value(value: object) -> Optional[bytes]:
    if not isinstance(value, str) or len(value) < 4 or len(value) > 1024:
        return None
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/_-="
    if any(char not in allowed for char in value):
        return None
    if "=" in value[:-2] or value.count("=") > 2:
        return None
    if "=" in value and len(value) % 4 != 0:
        return None
    if len(value) % 4 == 1:
        return None
    normalized = value.replace("-", "+").replace("_", "/")
    unpadded = normalized[:-2] if normalized.endswith("==") else normalized[:-1] if normalized.endswith("=") else normalized
    padded = unpadded + "=" * ((4 - len(unpadded) % 4) % 4)
    try:
        decoded = base64.b64decode(padded.encode("ascii"), validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        return None
    if not decoded:
        return None
    return decoded


def unique_tokens(tokens: Iterable[str]) -> List[str]:
    seen = set()
    output = []
    for token in tokens:
        if token not in seen:
            seen.add(token)
            output.append(token)
    return output


def assert_safe_object_key(key: object) -> None:
    lower = str(key).lower()
    if lower in DANGEROUS_OBJECT_KEYS:
        raise CspCageError(CSPCAGE_ERROR_CODES["PROTOTYPE_POLLUTION"], "dangerous object key is forbidden")
