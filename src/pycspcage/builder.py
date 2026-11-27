"""Safe deterministic CSP header builder."""
from __future__ import annotations

import re
from types import MappingProxyType
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .constants import CSP_DIRECTIVE_ORDER, CSP_DIRECTIVES, CSPCAGE_ERROR_CODES, DANGEROUS_OBJECT_KEYS, DEPRECATED_DIRECTIVES, SOURCE_LIST_DIRECTIVES
from .crypto import generate_nonce
from .errors import CspCageError
from .parser import parse_csp
from .utils import scan_header_characters, split_whitespace, truncate_detail, unique_tokens

_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


def normalize_directive_name(key: object) -> str:
    if not isinstance(key, str) or len(key) == 0 or len(key) > 80:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "directive keys must be bounded strings")
    scan_header_characters(key, 0)
    if any(char.isspace() for char in key):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "directive keys must not contain whitespace")
    if key.lower() in DANGEROUS_OBJECT_KEYS:
        raise CspCageError(CSPCAGE_ERROR_CODES["PROTOTYPE_POLLUTION"], "prototype-pollution directive keys are forbidden")
    name = _CAMEL_RE.sub(r"\1-\2", key).replace("_", "-").lower()
    if name in DANGEROUS_OBJECT_KEYS:
        raise CspCageError(CSPCAGE_ERROR_CODES["PROTOTYPE_POLLUTION"], "prototype-pollution directive keys are forbidden")
    if _NAME_RE.match(name) is None or name.startswith("-") or name.endswith("-") or "--" in name:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_DIRECTIVE_NAME"], "directive key is malformed: " + truncate_detail(key, 40))
    if name in DEPRECATED_DIRECTIVES:
        raise CspCageError(CSPCAGE_ERROR_CODES["DEPRECATED_DIRECTIVE"], "deprecated directive is forbidden: " + name)
    if name not in CSP_DIRECTIVES:
        raise CspCageError(CSPCAGE_ERROR_CODES["UNKNOWN_DIRECTIVE"], "unknown directive is forbidden: " + name)
    return name


def _assert_safe_token(token: object, directive_name: str) -> str:
    if not isinstance(token, str) or len(token) == 0 or len(token) > 512:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "tokens for " + directive_name + " must be non-empty bounded strings")
    scan_header_characters(token, 0)
    if any(char.isspace() for char in token) or ";" in token or "," in token or "\\" in token:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "token for " + directive_name + " contains whitespace, semicolon, comma, or backslash injection")
    return token


def _value_tokens(value: object, directive_name: str) -> Optional[List[str]]:
    if value is None:
        return None
    if isinstance(value, bool):
        if not value:
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "boolean false is ambiguous for " + directive_name + "; omit the directive instead")
        return []
    if isinstance(value, str):
        scan_header_characters(value, 0)
        if ";" in value or "," in value or "\\" in value:
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "directive value for " + directive_name + " contains semicolon, comma, or backslash injection")
        raw_tokens = split_whitespace(value)
    elif isinstance(value, (list, tuple)):
        raw_tokens = list(value)
    else:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "directive value for " + directive_name + " must be a string, sequence, or true")
    if len(raw_tokens) > 64:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "too many tokens for " + directive_name)
    return unique_tokens(_assert_safe_token(token, directive_name) for token in raw_tokens)


def normalize_directive_input(input_value: object) -> Dict[str, List[str]]:
    """Normalize a directive mapping to canonical hyphenated names."""

    if not isinstance(input_value, dict):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "directives must be supplied as a mapping")
    normalized: Dict[str, List[str]] = {}
    for key, value in input_value.items():
        name = normalize_directive_name(key)
        if name in normalized:
            raise CspCageError(CSPCAGE_ERROR_CODES["DUPLICATE_DIRECTIVE"], "duplicate directive after key normalization: " + name)
        tokens = _value_tokens(value, name)
        if tokens is None:
            continue
        if name == "upgrade-insecure-requests" and len(tokens) != 0:
            raise CspCageError(CSPCAGE_ERROR_CODES["UNEXPECTED_DIRECTIVE_VALUE"], "upgrade-insecure-requests does not accept tokens")
        if name in SOURCE_LIST_DIRECTIVES and len(tokens) == 0:
            raise CspCageError(CSPCAGE_ERROR_CODES["MISSING_DIRECTIVE_VALUE"], name + " requires at least one token")
        normalized[name] = tokens
    if len(normalized) == 0:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_BUILD_INPUT"], "at least one directive is required")
    return normalized


def _ordered_names(mapping: Mapping[str, Sequence[str]]) -> List[str]:
    known = [name for name in CSP_DIRECTIVE_ORDER if name in mapping]
    unknown = sorted(name for name in mapping if name not in CSP_DIRECTIVE_ORDER)
    return known + unknown


def serialize_directive_map(mapping: Mapping[str, Sequence[str]]) -> str:
    parts = []
    for name in _ordered_names(mapping):
        tokens = list(mapping[name])
        parts.append(name if len(tokens) == 0 else name + " " + " ".join(tokens))
    return "; ".join(parts)


def _normalize_build_options(options: Optional[Mapping[str, Any]]) -> Mapping[str, bool]:
    if options is None:
        return MappingProxyType({"require_clean_audit": False, "allow_unsafe_inline": False})
    if not isinstance(options, dict):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "build options must be a mapping")
    for key in options:
        if key not in ("require_clean_audit", "requireCleanAudit", "allow_unsafe_inline", "allowUnsafeInline"):
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "unknown build option " + truncate_detail(key, 40))
    require_clean = options.get("require_clean_audit", options.get("requireCleanAudit", False)) is True
    allow_inline = options.get("allow_unsafe_inline", options.get("allowUnsafeInline", False)) is True
    return MappingProxyType({"require_clean_audit": require_clean, "allow_unsafe_inline": allow_inline})


def build_csp(directives: Mapping[str, object], options: Optional[Mapping[str, Any]] = None) -> str:
    """Build a deterministic CSP header and re-parse plus re-audit it.

    Unsafe executable output is never returned. The audit is attached to the
    raised ``CspCageError`` as ``audit`` when serialization is blocked.
    """

    from .auditor import audit_csp

    build_options = _normalize_build_options(options)
    normalized = normalize_directive_input(directives)
    serialized = serialize_directive_map(normalized)
    parse_csp(serialized)
    audit = audit_csp(serialized)
    blocking_errors = 0
    for finding in audit.findings:
        if finding.severity != "error":
            continue
        if finding.code == "MISSING_SCRIPT_POLICY":
            continue
        if build_options["allow_unsafe_inline"] and finding.code == "UNSAFE_INLINE_ACTIVE":
            continue
        blocking_errors += 1
    if blocking_errors > 0 or (build_options["require_clean_audit"] and audit.counts["warnings"] > 0):
        error = CspCageError(CSPCAGE_ERROR_CODES["UNSAFE_BUILD_OUTPUT"], "serialized CSP did not pass the security audit")
        error.audit = audit
        raise error
    return serialized


def _normalize_nonce_token(nonce: object) -> str:
    if not isinstance(nonce, str) or len(nonce) == 0 or len(nonce) > 256:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_NONCE_INPUT"], "nonce must be a bounded base64 string")
    scan_header_characters(nonce, 0)
    value = nonce
    if value.startswith("'") and value.endswith("'"):
        value = value[1:-1]
    if value.lower().startswith("nonce-"):
        value = value[6:]
    if not re.match(r"^[A-Za-z0-9+/_-]+={0,2}$", value):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_NONCE_INPUT"], "nonce must use strict base64 characters")
    return value


def _strict_array(value: object, fallback: Sequence[str], name: str) -> List[str]:
    if value is None:
        return list(fallback)
    if not isinstance(value, (list, tuple)) or len(value) == 0 or len(value) > 32:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], name + " must be a non-empty bounded sequence")
    return list(value)


def _option(options: Mapping[str, Any], snake: str, camel: str, default: Any = None) -> Any:
    if snake in options:
        return options[snake]
    if camel in options:
        return options[camel]
    return default


def create_strict_csp(options: Optional[Mapping[str, Any]] = None) -> str:
    """Create a strict-dynamic CSP with a fresh or caller-supplied nonce."""

    if options is None:
        options = {}
    if not isinstance(options, dict):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "strict CSP options must be a mapping")
    allowed_pairs = (
        ("nonce", "nonce"),
        ("report_to", "reportTo"),
        ("report_uri", "reportUri"),
        ("connect_src", "connectSrc"),
        ("img_src", "imgSrc"),
        ("style_src", "styleSrc"),
        ("font_src", "fontSrc"),
        ("media_src", "mediaSrc"),
        ("worker_src", "workerSrc"),
        ("frame_ancestors", "frameAncestors"),
        ("form_action", "formAction"),
        ("upgrade_insecure_requests", "upgradeInsecureRequests"),
        ("require_trusted_types_for", "requireTrustedTypesFor"),
    )
    allowed = {item for pair in allowed_pairs for item in pair}
    for key in options:
        if key not in allowed:
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "unknown strict CSP option " + truncate_detail(key, 40))
    nonce = _normalize_nonce_token(_option(options, "nonce", "nonce", generate_nonce()))
    directives: Dict[str, object] = {
        "default_src": ["'self'"],
        "script_src": ["'nonce-" + nonce + "'", "'strict-dynamic'"],
        "style_src": _strict_array(_option(options, "style_src", "styleSrc"), ["'self'"], "style_src"),
        "img_src": _strict_array(_option(options, "img_src", "imgSrc"), ["'self'", "data:"], "img_src"),
        "font_src": _strict_array(_option(options, "font_src", "fontSrc"), ["'self'"], "font_src"),
        "connect_src": _strict_array(_option(options, "connect_src", "connectSrc"), ["'self'"], "connect_src"),
        "media_src": _strict_array(_option(options, "media_src", "mediaSrc"), ["'self'"], "media_src"),
        "worker_src": _strict_array(_option(options, "worker_src", "workerSrc"), ["'self'"], "worker_src"),
        "object_src": ["'none'"],
        "base_uri": ["'none'"],
        "frame_ancestors": _strict_array(_option(options, "frame_ancestors", "frameAncestors"), ["'none'"], "frame_ancestors"),
        "form_action": _strict_array(_option(options, "form_action", "formAction"), ["'self'"], "form_action"),
        "manifest_src": ["'self'"],
    }
    if _option(options, "upgrade_insecure_requests", "upgradeInsecureRequests", True) is not False:
        directives["upgrade_insecure_requests"] = True
    if _option(options, "require_trusted_types_for", "requireTrustedTypesFor", False) is True:
        directives["require_trusted_types_for"] = "'script'"
    report_to = _option(options, "report_to", "reportTo")
    report_uri = _option(options, "report_uri", "reportUri")
    if isinstance(report_to, str) and len(report_to) > 0:
        directives["report_to"] = report_to
    if isinstance(report_uri, str) and len(report_uri) > 0:
        directives["report_uri"] = report_uri
    return build_csp(directives, {"require_clean_audit": report_uri is None})
