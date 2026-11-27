"""Safe CSP merge helpers."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from .builder import build_csp, normalize_directive_input
from .constants import CSP_DIRECTIVE_ORDER, CSPCAGE_ERROR_CODES
from .errors import CspCageError
from .model import ParsedCsp
from .parser import parse_csp
from .utils import truncate_detail, unique_tokens

_OPTION_KEYS = {"allow_unsafe_inline", "allowUnsafeInline", "allow_none_widening", "allowNoneWidening", "require_clean_audit", "requireCleanAudit"}


def _map_from_parsed(parsed: ParsedCsp) -> Dict[str, List[str]]:
    if parsed.policy_count != 1:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_MERGE_INPUT"], "merge inputs must each contain exactly one policy")
    output: Dict[str, List[str]] = {}
    for item in parsed.policies[0].directives:
        if not item.ignored:
            output[item.name] = list(item.tokens)
    return output


def _map_from_input(input_value: object) -> Dict[str, List[str]]:
    if isinstance(input_value, str):
        return _map_from_parsed(parse_csp(input_value))
    if isinstance(input_value, ParsedCsp):
        return _map_from_parsed(input_value)
    if isinstance(input_value, dict):
        return normalize_directive_input(input_value)
    raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_MERGE_INPUT"], "merge input must be a CSP string, parsed CSP, or directive mapping")


def _normalize_merge_options(options: Optional[Mapping[str, Any]]) -> Mapping[str, bool]:
    if options is None:
        return {"allow_unsafe_inline": False, "allow_none_widening": False, "require_clean_audit": False}
    if not isinstance(options, dict):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "merge options must be a mapping")
    for key in options:
        if key not in _OPTION_KEYS:
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_OPTIONS"], "unknown merge option " + truncate_detail(key, 40))
    return {
        "allow_unsafe_inline": options.get("allow_unsafe_inline", options.get("allowUnsafeInline", False)) is True,
        "allow_none_widening": options.get("allow_none_widening", options.get("allowNoneWidening", False)) is True,
        "require_clean_audit": options.get("require_clean_audit", options.get("requireCleanAudit", False)) is True,
    }


def _ordered_names(names: Iterable[str]) -> List[str]:
    present = set(names)
    known = [name for name in CSP_DIRECTIVE_ORDER if name in present]
    unknown = sorted(name for name in present if name not in CSP_DIRECTIVE_ORDER)
    return known + unknown


def _none_token(token: str) -> bool:
    return token.lower() == "'none'"


def _unsafe_inline_token(token: str) -> bool:
    return token.lower() == "'unsafe-inline'"


def _assert_unsafe_inline_allowed(tokens: Sequence[str], options: Mapping[str, bool]) -> None:
    if not options["allow_unsafe_inline"] and any(_unsafe_inline_token(token) for token in tokens):
        raise CspCageError(CSPCAGE_ERROR_CODES["UNSAFE_INLINE_MERGE"], "merged output would contain 'unsafe-inline'; pass allow_unsafe_inline only after explicit review")


def _merge_token_sets(token_sets: Sequence[Sequence[str]], options: Mapping[str, bool]) -> List[str]:
    union: List[str] = []
    for tokens in token_sets:
        union.extend(tokens)
    unique = unique_tokens(union)
    has_none = any(_none_token(token) for token in unique)
    if has_none and not options["allow_none_widening"]:
        result = ["'none'"]
    elif has_none and len(unique) > 1:
        result = [token for token in unique if not _none_token(token)]
    else:
        result = unique
    _assert_unsafe_inline_allowed(result, options)
    return result


def merge_csp(*inputs: object, options: Optional[Mapping[str, Any]] = None) -> str:
    """Merge one-policy CSP strings, parsed values, or directive mappings.

    The union never silently widens ``'none'`` and never silently introduces
    ``'unsafe-inline'``. The merged output is rebuilt, reparsed, and audited.
    """

    merge_options = _normalize_merge_options(options)
    if len(inputs) == 1 and isinstance(inputs[0], (list, tuple)):
        inputs = tuple(inputs[0])
    if len(inputs) == 0:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_MERGE_INPUT"], "at least one policy is required")
    maps = [_map_from_input(input_value) for input_value in inputs]
    all_names: List[str] = []
    for mapping in maps:
        all_names.extend(mapping.keys())
    merged: Dict[str, List[str]] = {}
    for name in _ordered_names(all_names):
        token_sets = [mapping[name] for mapping in maps if name in mapping]
        merged[name] = _merge_token_sets(token_sets, merge_options)
    return build_csp(merged, {
        "require_clean_audit": merge_options["require_clean_audit"],
        "allow_unsafe_inline": merge_options["allow_unsafe_inline"],
    })
