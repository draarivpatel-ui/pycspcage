"""Strict bounded Content-Security-Policy Level 3 parser."""
from __future__ import annotations

import ipaddress
import re
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .constants import (
    CSP_DIRECTIVES,
    CSP_KEYWORDS,
    CSP_PARSE_HARD_LIMITS,
    CSPCAGE_ERROR_CODES,
    DEPRECATED_DIRECTIVES,
    HASH_DIGEST_BYTES,
    SANDBOX_TOKENS,
    SOURCE_LIST_DIRECTIVES,
)
from .errors import CspCageError
from .model import Directive, ParsedCsp, Policy, SourceExpression
from .utils import byte_length, decode_base64_value, resolve_parse_options, scan_header_characters, split_whitespace, truncate_detail

_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,63}$")
_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]{0,31}$")
_HOST_SOURCE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]{0,31})://(.*)$")
_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9-]+$")
_HEX_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


class _ParseState:
    def __init__(self, strict: bool, max_findings: int) -> None:
        self.strict = strict
        self.max_findings = max_findings
        self.errors: List[CspCageError] = []

    def add(self, error: CspCageError) -> None:
        if self.strict:
            raise error
        if len(self.errors) < self.max_findings:
            self.errors.append(error)

    def error(self, code: str, detail: str, context: Optional[Mapping[str, Any]] = None) -> None:
        self.add(CspCageError(code, detail, context))


def _normalize_input(input_value: Union[str, Sequence[str]]) -> List[str]:
    if isinstance(input_value, str):
        return [input_value]
    if isinstance(input_value, (list, tuple)) and len(input_value) > 0 and all(isinstance(item, str) for item in input_value):
        return list(input_value)
    raise CspCageError(
        CSPCAGE_ERROR_CODES["INVALID_INPUT"],
        "CSP input must be a string or a non-empty sequence of strings",
    )


def _valid_percent_encoding(token: str) -> bool:
    index = 0
    while index < len(token):
        if token[index] != "%":
            index += 1
            continue
        if index + 2 >= len(token) or not _HEX_RE.match(token[index + 1 : index + 3]):
            return False
        index += 3
    return True


def _validate_scheme(scheme: str) -> bool:
    return _SCHEME_RE.match(scheme) is not None


def _valid_port(text: str) -> Optional[Union[int, str]]:
    if text == "*":
        return "*"
    if not re.match(r"^[0-9]{1,5}$", text):
        return None
    port = int(text, 10)
    if port < 0 or port > 65535:
        return None
    return port


def _validate_dns_name(host: str) -> bool:
    canonical = host[:-1] if host.endswith(".") else host
    if len(canonical) == 0 or len(canonical) > 253:
        return False
    labels = canonical.split(".")
    for label in labels:
        if len(label) == 0 or len(label) > 63:
            return False
        if _DNS_LABEL_RE.match(label) is None:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False
    return True


def _validate_ipv4(host: str) -> bool:
    try:
        ipaddress.IPv4Address(host)
        return True
    except ValueError:
        return False


def _validate_ipv6(host: str) -> bool:
    try:
        ipaddress.IPv6Address(host)
        return True
    except ValueError:
        return False


def _host_error(detail: str) -> CspCageError:
    return CspCageError(CSPCAGE_ERROR_CODES["INVALID_HOST_SOURCE"], detail)


def _parse_host_and_port(host_port: str) -> Tuple[str, Optional[Union[int, str]], bool, bool]:
    if len(host_port) == 0:
        raise _host_error("host source is missing a host")
    if host_port.startswith("["):
        close = host_port.find("]")
        if close < 0:
            raise _host_error("IPv6 host is missing a closing bracket")
        host = host_port[1:close]
        if not _validate_ipv6(host):
            raise _host_error("IPv6 host is malformed")
        rest = host_port[close + 1 :]
        port = None
        if rest:
            if not rest.startswith(":"):
                raise _host_error("unexpected data after IPv6 host")
            port = _valid_port(rest[1:])
            if port is None:
                raise _host_error("port must be an integer from 0 to 65535 or a wildcard")
        return host.lower(), port, False, True

    host = host_port
    port = None
    if host_port.count(":") > 1:
        raise _host_error("IPv6 hosts must use brackets")
    if host_port.count(":") == 1:
        host, port_text = host_port.rsplit(":", 1)
        port = _valid_port(port_text)
        if port is None:
            raise _host_error("port must be an integer from 0 to 65535 or a wildcard")
    if len(host) == 0:
        raise _host_error("host source is missing a host")
    if host == "*":
        return "*", port, True, False
    wildcard = False
    dns_host = host
    if host.startswith("*."):
        wildcard = True
        dns_host = host[2:]
    canonical = dns_host[:-1] if dns_host.endswith(".") else dns_host
    if not (_validate_ipv4(canonical) or _validate_dns_name(dns_host)):
        raise _host_error("host name is malformed")
    return dns_host.lower(), port, wildcard, False


def _parse_host_source(token: str) -> SourceExpression:
    if not _valid_percent_encoding(token):
        raise _host_error("percent encoding is malformed")
    if "\\" in token or "?" in token or "#" in token:
        raise _host_error("host sources must not contain backslashes, queries, or fragments")
    if token.startswith("//"):
        raise _host_error("protocol-relative host sources are forbidden")

    scheme = None
    remainder = token
    match = _HOST_SOURCE_RE.match(token)
    if match is not None:
        scheme = match.group(1).lower()
        remainder = match.group(2)
        if not _validate_scheme(scheme):
            raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_SCHEME_SOURCE"], "scheme is malformed")
    if len(remainder) == 0:
        raise _host_error("host source is missing a host")

    slash = remainder.find("/")
    if slash >= 0:
        host_port = remainder[:slash]
        path = remainder[slash:]
    else:
        host_port = remainder
        path = ""
    if "@" in host_port:
        raise _host_error("userinfo in host sources is forbidden")
    if "%" in host_port:
        raise _host_error("percent encoding is forbidden in host names")
    host_part_for_ambiguity = host_port
    if host_part_for_ambiguity.startswith("["):
        close_probe = host_part_for_ambiguity.find("]")
        host_part_for_ambiguity = host_part_for_ambiguity[1:close_probe] if close_probe >= 0 else host_part_for_ambiguity
    else:
        host_part_for_ambiguity = host_part_for_ambiguity.split(":", 1)[0]
    probe_host = host_part_for_ambiguity[2:] if host_part_for_ambiguity.startswith("*.") else host_part_for_ambiguity
    probe_host = probe_host[:-1] if probe_host.endswith(".") else probe_host
    if probe_host and not _validate_ipv4(probe_host):
        numericish = re.match(r"^[0-9.]+$", probe_host) is not None
        leading_number_form = any(
            (label.lower().startswith("0x") and len(label) > 2) or (len(label) > 1 and label.startswith("0") and label.isdigit())
            for label in probe_host.split(".")
        )
        if numericish or leading_number_form:
            raise _host_error("non-canonical numeric host forms are forbidden")
    host, port, wildcard_host, ipv6 = _parse_host_and_port(host_port)
    if "*" in path:
        raise _host_error("path wildcards are not part of the CSP host-source grammar")
    has_exact_path = path not in ("", "/") and not path.endswith("/")
    kind = "wildcard" if host == "*" and not token.startswith("*.") else "host"
    return SourceExpression(
        kind=kind,
        token=token,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        host_is_wildcard=wildcard_host,
        ipv6=ipv6,
        has_exact_path=has_exact_path,
    )


def _decode_checked_base64(value: str, code: str, detail: str) -> bytes:
    decoded = decode_base64_value(value)
    if decoded is None:
        raise CspCageError(code, detail)
    return decoded


def _parse_quoted_source(token: str) -> SourceExpression:
    if len(token) < 2 or not token.endswith("'"):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_KEYWORD_SOURCE"], "quoted source has malformed quoting")
    inner = token[1:-1]
    if "'" in inner or len(inner) == 0:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_KEYWORD_SOURCE"], "quoted source is empty or contains nested quotes")
    lower = inner.lower()
    if lower in CSP_KEYWORDS:
        return SourceExpression(kind="keyword", token=token, keyword=lower)
    if lower.startswith("nonce-"):
        nonce = inner[6:]
        decoded = _decode_checked_base64(nonce, CSPCAGE_ERROR_CODES["INVALID_NONCE"], "nonce is not strict bounded base64")
        return SourceExpression(kind="nonce", token=token, nonce=nonce, decoded_bytes=len(decoded))
    algorithm, separator, digest = lower.partition("-")
    if separator and algorithm in ("sha256", "sha384", "sha512", "sha1", "md5"):
        if algorithm not in HASH_DIGEST_BYTES:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["UNSUPPORTED_HASH_ALGORITHM"],
                "only sha256, sha384, and sha512 CSP hashes are accepted",
            )
        decoded = _decode_checked_base64(digest, CSPCAGE_ERROR_CODES["INVALID_HASH"], "hash digest is not strict bounded base64")
        expected = HASH_DIGEST_BYTES[algorithm]
        if len(decoded) != expected:
            raise CspCageError(
                CSPCAGE_ERROR_CODES["INVALID_HASH"],
                algorithm + " hash digest must decode to exactly " + str(expected) + " bytes",
            )
        return SourceExpression(kind="hash", token=token, algorithm=algorithm, decoded_bytes=len(decoded))
    raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_KEYWORD_SOURCE"], "unknown quoted source keyword")


def parse_source_expression(token: str, max_source_length: int = 512) -> SourceExpression:
    """Parse one CSP source expression with strict bounds."""

    if len(token) == 0:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "source expression is empty")
    if len(token) > max_source_length:
        raise CspCageError(CSPCAGE_ERROR_CODES["SOURCE_TOO_LONG"], "source expression exceeds the configured bound")
    scan_header_characters(token, 0)
    if any(char.isspace() for char in token):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "source expression contains whitespace")
    if ";" in token or "," in token:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "source expression contains directive or policy separators")
    if token == "*":
        return SourceExpression(kind="wildcard", token=token, host="*", host_is_wildcard=True)
    if token.startswith("'") or token.endswith("'"):
        return _parse_quoted_source(token)
    if re.match(r"^[A-Za-z][A-Za-z0-9+.-]{0,31}:$", token):
        return SourceExpression(kind="scheme", token=token, scheme=token[:-1].lower())
    return _parse_host_source(token)


def _parse_endpoint_token(token: str, max_length: int) -> None:
    if len(token) == 0 or len(token) > max_length:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_ENDPOINT"], "reporting endpoint is empty or too long")
    scan_header_characters(token, 0)
    if any(char.isspace() for char in token) or "\\" in token or ";" in token or "," in token:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_ENDPOINT"], "reporting endpoint contains injection characters")
    if not _valid_percent_encoding(token):
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_ENDPOINT"], "reporting endpoint percent encoding is malformed")


def _validate_directive_value(name: str, tokens: List[str], state: _ParseState, max_source_length: int) -> Tuple[Tuple[str, ...], Tuple[SourceExpression, ...]]:
    token_tuple = tuple(tokens)
    if name in SOURCE_LIST_DIRECTIVES:
        if not tokens:
            state.error(CSPCAGE_ERROR_CODES["MISSING_DIRECTIVE_VALUE"], name + " requires at least one source expression")
            return (), ()
        sources: List[SourceExpression] = []
        for token in tokens:
            try:
                sources.append(parse_source_expression(token, max_source_length))
            except CspCageError as error:
                state.add(error)
        return token_tuple, tuple(sources)

    if name == "upgrade-insecure-requests":
        if tokens:
            state.error(CSPCAGE_ERROR_CODES["UNEXPECTED_DIRECTIVE_VALUE"], "upgrade-insecure-requests does not accept tokens")
        return token_tuple, ()
    if name == "sandbox":
        for token in tokens:
            if token not in SANDBOX_TOKENS:
                state.error(CSPCAGE_ERROR_CODES["INVALID_SANDBOX_TOKEN"], "unknown sandbox token " + truncate_detail(token, 50))
        return token_tuple, ()
    if name == "require-sri-for":
        for token in tokens:
            if token not in ("script", "style"):
                state.error(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "require-sri-for accepts only script and style")
        return token_tuple, ()
    if name == "require-trusted-types-for":
        if not tokens or any(token != "'script'" for token in tokens):
            state.error(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "require-trusted-types-for requires the 'script' token")
        return token_tuple, ()
    if name == "trusted-types":
        if not tokens:
            state.error(CSPCAGE_ERROR_CODES["MISSING_DIRECTIVE_VALUE"], "trusted-types requires at least one token")
        for token in tokens:
            lower = token.lower()
            valid = lower in ("'none'", "'allow-duplicates'", "*") or re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$", token) is not None
            if not valid:
                state.error(CSPCAGE_ERROR_CODES["INVALID_SOURCE_EXPRESSION"], "trusted-types policy name is malformed")
        return token_tuple, ()
    if name in ("report-uri", "report-to"):
        if not tokens:
            state.error(CSPCAGE_ERROR_CODES["MISSING_DIRECTIVE_VALUE"], name + " requires an endpoint token")
        if name == "report-to" and len(tokens) != 1:
            state.error(CSPCAGE_ERROR_CODES["UNEXPECTED_DIRECTIVE_VALUE"], "report-to accepts exactly one endpoint group token")
        for token in tokens:
            try:
                _parse_endpoint_token(token, max_source_length)
            except CspCageError as error:
                state.add(error)
        return token_tuple, ()
    state.error(CSPCAGE_ERROR_CODES["UNKNOWN_DIRECTIVE"], "unknown directive " + name)
    return (), ()


def _parse_csp_internal(input_value: Union[str, Sequence[str]], options: Optional[Mapping[str, Any]] = None) -> ParsedCsp:
    resolved = resolve_parse_options(options)
    state = _ParseState(bool(resolved["strict"]), int(resolved["max_findings"]))
    headers = _normalize_input(input_value)
    policies: List[Policy] = []
    total_directives = 0

    for header_index, header in enumerate(headers):
        try:
            scan_header_characters(header, header_index)
        except CspCageError as error:
            state.add(error)
            continue
        if byte_length(header) > int(resolved["max_bytes"]):
            state.error(CSPCAGE_ERROR_CODES["INPUT_TOO_LARGE"], "CSP header exceeds the configured byte bound", {"policy_index": header_index})
            continue
        pieces = header.split(",")
        for piece_index, piece in enumerate(pieces):
            if len(policies) >= int(resolved["max_policies"]):
                state.error(CSPCAGE_ERROR_CODES["TOO_MANY_POLICIES"], "too many comma-separated CSP policies")
                break
            if piece.strip() == "":
                state.error(CSPCAGE_ERROR_CODES["EMPTY_POLICY"], "empty policy in comma-separated header list", {"policy_index": len(policies)})
                continue
            policy_index = len(policies)
            segments = piece.split(";")
            directives: List[Directive] = []
            directive_map: Dict[str, Directive] = {}
            for directive_index, segment in enumerate(segments):
                if directive_index >= int(resolved["max_directives_per_policy"]):
                    state.error(CSPCAGE_ERROR_CODES["TOO_MANY_DIRECTIVES"], "too many directives in one policy", {"policy_index": policy_index})
                    break
                if total_directives >= int(resolved["max_total_directives"]):
                    state.error(CSPCAGE_ERROR_CODES["TOO_MANY_DIRECTIVES"], "too many total directives across all policies")
                    break
                if segment.strip() == "":
                    state.error(CSPCAGE_ERROR_CODES["EMPTY_DIRECTIVE"], "empty directive or trailing semicolon is forbidden", {"policy_index": policy_index})
                    continue
                parts = split_whitespace(segment)
                if not parts:
                    state.error(CSPCAGE_ERROR_CODES["EMPTY_DIRECTIVE"], "empty directive", {"policy_index": policy_index})
                    continue
                raw_name = parts[0]
                if _NAME_RE.match(raw_name) is None:
                    state.error(CSPCAGE_ERROR_CODES["INVALID_DIRECTIVE_NAME"], "directive name is malformed", {"policy_index": policy_index})
                    continue
                name = raw_name.lower()
                if name in DEPRECATED_DIRECTIVES:
                    state.error(CSPCAGE_ERROR_CODES["DEPRECATED_DIRECTIVE"], "deprecated directive is forbidden: " + name, {"policy_index": policy_index, "directive": name})
                    continue
                if name not in CSP_DIRECTIVES:
                    state.error(CSPCAGE_ERROR_CODES["UNKNOWN_DIRECTIVE"], "unknown directive " + truncate_detail(name, 60), {"policy_index": policy_index, "directive": name})
                    continue
                tokens = parts[1:]
                if len(tokens) > int(resolved["max_sources_per_directive"]):
                    state.error(CSPCAGE_ERROR_CODES["TOO_MANY_SOURCES"], "too many source expressions in " + name, {"policy_index": policy_index, "directive": name})
                    tokens = tokens[: int(resolved["max_sources_per_directive"])]
                ignored = False
                if name in directive_map:
                    ignored = True
                    state.error(CSPCAGE_ERROR_CODES["DUPLICATE_DIRECTIVE"], "duplicate directive is forbidden: " + name, {"policy_index": policy_index, "directive": name})
                normalized_tokens, sources = _validate_directive_value(name, tokens, state, int(resolved["max_source_length"]))
                item = Directive(
                    name=name,
                    tokens=normalized_tokens,
                    sources=sources,
                    index=directive_index,
                    ignored=ignored,
                )
                directives.append(item)
                total_directives += 1
                if not ignored:
                    directive_map[name] = item
            if directives:
                policies.append(Policy(index=policy_index, directives=tuple(directives), directive_map=MappingProxyType(dict(directive_map))))
            else:
                state.error(CSPCAGE_ERROR_CODES["EMPTY_POLICY"], "policy contains no valid directives", {"policy_index": policy_index})

    if len(policies) == 0 and not state.errors:
        state.error(CSPCAGE_ERROR_CODES["EMPTY_POLICY"], "CSP input contains no policy")
    directive_count = sum(len(policy.directives) for policy in policies)
    return ParsedCsp(
        policies=tuple(policies),
        policy_count=len(policies),
        directive_count=directive_count,
        header_count=len(headers),
        errors=tuple(state.errors),
    )


def parse_csp(input_value: Union[str, Sequence[str]], options: Optional[Mapping[str, Any]] = None) -> ParsedCsp:
    """Parse a CSP header string or sequence of header strings.

    Strict mode is the default and raises the first :class:`CspCageError`.
    Pass ``{"strict": False}`` in options to receive partial parse output with
    bounded errors in ``parsed.errors``; this mode exists for audit tooling.
    """

    return _parse_csp_internal(input_value, options)
