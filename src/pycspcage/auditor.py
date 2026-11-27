"""Real-world CSP bypass auditor."""
from __future__ import annotations

import ipaddress
import re
from types import MappingProxyType
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urlsplit

from .constants import CSP_PARSE_BOUNDS, CSPCAGE_ERROR_CODES, CSPCAGE_SEVERITY, PLACEHOLDER_NONCE_VALUES, SCRIPT_GADGET_HOSTS
from .errors import CspCageError
from .model import AuditFinding, AuditReport, Directive, ParsedCsp, Policy, PolicyAudit, SourceExpression
from .parser import _parse_csp_internal
from .utils import decode_base64_value, resolve_parse_options

ERROR = CSPCAGE_SEVERITY["ERROR"]
WARNING = CSPCAGE_SEVERITY["WARNING"]
NOTICE = CSPCAGE_SEVERITY["NOTICE"]

DEDUCTIONS = {
    "UNSAFE_INLINE_ACTIVE": 35,
    "UNSAFE_EVAL": 30,
    "WASM_UNSAFE_EVAL": 25,
    "WILDCARD_SOURCE": 25,
    "DANGEROUS_SCRIPT_SCHEME": 30,
    "DANGEROUS_DATA_SCHEME": 20,
    "INSECURE_HTTP_SCHEME": 20,
    "INSECURE_HTTP_HOST": 15,
    "CDN_SCRIPT_GADGET_HOST": 25,
    "WEAK_NONCE_ENTROPY": 15,
    "STATIC_NONCE_PLACEHOLDER": 20,
    "OBJECT_SRC_NOT_NONE": 15,
    "WEAK_BASE_URI": 15,
    "WEAK_FRAME_ANCESTORS": 20,
    "MISSING_SCRIPT_POLICY": 35,
    "REPORT_ENDPOINT_CREDENTIALS": 15,
    "NONE_WITH_OTHER_SOURCES": 15,
    "CSPCAGE_DUPLICATE_DIRECTIVE": 15,
    "CSPCAGE_UNKNOWN_DIRECTIVE": 15,
    "CSPCAGE_DEPRECATED_DIRECTIVE": 12,
    "CSPCAGE_INVALID_NONCE": 12,
    "CSPCAGE_INVALID_HASH": 12,
}


def _add(findings: List[AuditFinding], max_findings: int, severity: str, code: str, message: str, policy_index: Optional[int] = None, directive: Optional[str] = None, recommendation: Optional[str] = None, details: Optional[Mapping[str, Any]] = None) -> None:
    item = AuditFinding(
        severity=severity,
        code=code,
        message=message,
        policy_index=policy_index,
        directive=directive,
        recommendation=recommendation,
        details=MappingProxyType(dict(details or {})),
    )
    if len(findings) < max_findings:
        findings.append(item)
        return
    if severity != ERROR:
        return
    for index in range(len(findings) - 1, -1, -1):
        if findings[index].severity != ERROR:
            findings[index] = item
            return


def _directive(policy: Policy, name: str) -> Optional[Directive]:
    return policy.directive_map.get(name)


def _effective_fetch_directive(policy: Policy, name: str) -> Optional[Directive]:
    exact = _directive(policy, name)
    if exact is not None:
        return exact
    if name in ("script-src-elem", "script-src-attr"):
        script = _directive(policy, "script-src")
        if script is not None:
            return script
    return _directive(policy, "default-src")


def _token_is_none(token: str) -> bool:
    return token.lower() == "'none'"


def _exactly_none(item: Optional[Directive]) -> bool:
    return item is not None and len(item.tokens) == 1 and _token_is_none(item.tokens[0])


def _has_keyword(item: Optional[Directive], keyword: str) -> bool:
    return item is not None and any(source.kind == "keyword" and source.keyword == keyword for source in item.sources)


def _has_valid_hash(item: Optional[Directive]) -> bool:
    return item is not None and any(source.kind == "hash" for source in item.sources)


def _has_nonce(item: Optional[Directive]) -> bool:
    return item is not None and any(source.kind == "nonce" for source in item.sources)


def _has_strong_nonce_or_hash(item: Optional[Directive]) -> bool:
    if item is None:
        return False
    for source in item.sources:
        if source.kind == "hash":
            return True
        if source.kind == "nonce" and source.decoded_bytes >= 16:
            return True
    return False


def _script_relevant_directives(policy: Policy) -> List[Directive]:
    output: List[Directive] = []
    seen = set()
    for name in ("script-src", "script-src-elem", "script-src-attr"):
        item = _effective_fetch_directive(policy, name)
        if item is not None and id(item) not in seen:
            seen.add(id(item))
            output.append(item)
    return output


def _critical_source_directive(name: str) -> bool:
    return name in ("script-src", "script-src-elem", "script-src-attr", "object-src", "default-src", "connect-src", "form-action")


def _script_gadget_match(host: Optional[str]) -> Optional[str]:
    if host is None:
        return None
    candidate = host.lower()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if candidate.endswith("."):
        candidate = candidate[:-1]
    for gadget in SCRIPT_GADGET_HOSTS:
        if candidate == gadget or candidate.endswith("." + gadget):
            return gadget
    return None


def _analyze_unsafe_script_tokens(policy: Policy, item: Directive, findings: List[AuditFinding], max_findings: int) -> None:
    context = {"policy_index": policy.index, "directive": item.name}
    if _has_keyword(item, "unsafe-inline"):
        if _has_nonce(item) or _has_valid_hash(item):
            _add(findings, max_findings, WARNING, "CSP3_UNSAFE_INLINE_IGNORED", "'unsafe-inline' is ignored by CSP Level 3 browsers because a nonce or hash is present, but legacy CSP2 browsers may still execute inline scripts", recommendation="Remove unsafe-inline and keep strong nonces or hashes.", **context)
        else:
            _add(findings, max_findings, ERROR, "UNSAFE_INLINE_ACTIVE", "'unsafe-inline' permits inline script execution and is a primary XSS bypass", recommendation="Replace inline scripts with strong nonces or hashes.", **context)
    if _has_keyword(item, "unsafe-eval"):
        _add(findings, max_findings, ERROR, "UNSAFE_EVAL", "'unsafe-eval' permits eval and string-to-code execution", recommendation="Remove eval-like code paths and delete unsafe-eval.", **context)
    if _has_keyword(item, "wasm-unsafe-eval"):
        _add(findings, max_findings, ERROR, "WASM_UNSAFE_EVAL", "'wasm-unsafe-eval' permits WebAssembly compilation from attacker-controlled bytes", recommendation="Serve trusted Wasm artifacts from exact hosts instead.", **context)
    if _has_keyword(item, "unsafe-hashes"):
        _add(findings, max_findings, WARNING, "UNSAFE_HASHES", "'unsafe-hashes' extends hashes to inline event handlers and javascript URLs", recommendation="Remove inline handlers instead of enabling unsafe-hashes.", **context)
    if _has_keyword(item, "strict-dynamic") and not _has_strong_nonce_or_hash(item):
        _add(findings, max_findings, WARNING, "STRICT_DYNAMIC_WITHOUT_STRONG_PROOF", "'strict-dynamic' has little value without a strong nonce or a valid hash in the same directive", recommendation="Pair strict-dynamic with a 128-bit or stronger nonce or a valid hash.", **context)


def _analyze_none_union(policy: Policy, item: Directive, findings: List[AuditFinding], max_findings: int) -> None:
    has_none = any(source.kind == "keyword" and source.keyword == "none" for source in item.sources)
    if has_none and len(item.tokens) > 1:
        _add(findings, max_findings, ERROR, "NONE_WITH_OTHER_SOURCES", "'none' is combined with other source expressions; browsers do not treat the combined list as a deny-all rule", policy_index=policy.index, directive=item.name, recommendation="Use 'none' alone or remove it and keep only the intended allowlist.")


def _analyze_critical_sources(policy: Policy, item: Directive, findings: List[AuditFinding], max_findings: int) -> None:
    if not _critical_source_directive(item.name):
        return
    context = {"policy_index": policy.index, "directive": item.name}
    for source in item.sources:
        if source.kind == "wildcard":
            _add(findings, max_findings, ERROR, "WILDCARD_SOURCE", "a wildcard source permits scripts, objects, or connections from arbitrary origins", recommendation="Replace wildcards with exact HTTPS origins.", **context)
        if source.kind == "scheme":
            if source.scheme == "http":
                _add(findings, max_findings, ERROR, "INSECURE_HTTP_SCHEME", "the http scheme permits network attackers to replace protected resources", recommendation="Use exact HTTPS origins.", **context)
            elif source.scheme == "https":
                severity = WARNING if item.name in ("connect-src", "form-action") else ERROR
                _add(findings, max_findings, severity, "BROAD_HTTPS_SCHEME", "the bare https scheme is a wildcard over every HTTPS origin", recommendation="Use exact HTTPS origins.", **context)
            elif source.scheme in ("data", "blob", "filesystem"):
                severity = WARNING if item.name == "connect-src" else ERROR
                _add(findings, max_findings, severity, "DANGEROUS_DATA_SCHEME", str(source.scheme) + " is a dangerous broad scheme in " + item.name, recommendation="Remove data, blob, and filesystem schemes from executable or connection directives.", **context)
            elif source.scheme in ("javascript", "vbscript"):
                _add(findings, max_findings, ERROR, "DANGEROUS_SCRIPT_SCHEME", str(source.scheme) + " is an executable scheme", recommendation="Remove executable schemes immediately.", **context)
        if source.kind == "host":
            if source.scheme == "http":
                _add(findings, max_findings, ERROR, "INSECURE_HTTP_HOST", "an explicit HTTP host can be replaced by a network attacker", recommendation="Use HTTPS for every external origin.", **context)
            if source.host_is_wildcard:
                severity = WARNING if item.name in ("connect-src", "form-action") else ERROR
                _add(findings, max_findings, severity, "WILDCARD_HOST_SOURCE", "subdomain wildcard hosting is broader than an exact origin allowlist", recommendation="Use exact host names and paths where possible.", **context)
            if source.port == "*":
                severity = WARNING if item.name in ("connect-src", "form-action") else ERROR
                _add(findings, max_findings, severity, "WILDCARD_PORT_SOURCE", "a wildcard port broadens the origin beyond a single HTTPS service", recommendation="Pin the expected HTTPS port or omit the port for the scheme default.", **context)


def _cdn_path_is_known_gadget(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in ("angular", "angularjs", "jsonp", "callback"))


def _analyze_cdn_gadgets(policy: Policy, findings: List[AuditFinding], max_findings: int) -> None:
    for item in _script_relevant_directives(policy):
        if _has_keyword(item, "strict-dynamic"):
            continue
        for source in item.sources:
            if source.kind != "host":
                continue
            if source.has_exact_path and not _cdn_path_is_known_gadget(source.path):
                continue
            matched = _script_gadget_match(source.host)
            if matched is not None:
                detail = str(source.host) + " is a known JSONP, AngularJS, or CDN script-gadget bypass host"
                if source.has_exact_path:
                    detail = str(source.host) + str(source.path) + " pins a known executable CDN gadget path"
                _add(findings, max_findings, ERROR, "CDN_SCRIPT_GADGET_HOST", detail, policy_index=policy.index, directive=item.name, recommendation="Use strict-dynamic with a strong nonce or hash; do not rely on a live CDN host allowlist.", details={"gadget_host": matched})


def _analyze_framework_gaps(policy: Policy, findings: List[AuditFinding], max_findings: int) -> None:
    default_src = _directive(policy, "default-src")
    script_src = _directive(policy, "script-src")
    script_elem = _directive(policy, "script-src-elem")
    script_attr = _directive(policy, "script-src-attr")
    if default_src is None:
        _add(findings, max_findings, WARNING, "MISSING_DEFAULT_SRC", "default-src is missing, so unlisted fetch directives have no restrictive fallback", policy_index=policy.index, directive="default-src", recommendation="Add default-src 'none' or default-src 'self'.")
    if script_src is None and default_src is None and script_elem is None and script_attr is None:
        _add(findings, max_findings, ERROR, "MISSING_SCRIPT_POLICY", "neither script-src nor default-src constrains script execution", policy_index=policy.index, directive="script-src", recommendation="Add script-src with a strong nonce or hash and object-src 'none'.")
    elif script_src is None:
        _add(findings, max_findings, WARNING, "MISSING_SCRIPT_SRC", "script-src is missing and script execution relies on partial or fallback directives", policy_index=policy.index, directive="script-src", recommendation="Add an explicit script-src policy.")

    object_src = _directive(policy, "object-src")
    if object_src is None:
        _add(findings, max_findings, WARNING, "MISSING_OBJECT_SRC", "object-src 'none' is missing; plugin and object fallback posture is implicit", policy_index=policy.index, directive="object-src", recommendation="Add object-src 'none'.")
    elif not _exactly_none(object_src):
        _add(findings, max_findings, ERROR, "OBJECT_SRC_NOT_NONE", "object-src is not exactly 'none', leaving plugin or object injection surface", policy_index=policy.index, directive="object-src", recommendation="Set object-src 'none'.")

    base_uri = _directive(policy, "base-uri")
    if base_uri is None:
        _add(findings, max_findings, WARNING, "MISSING_BASE_URI", "base-uri is missing, so a base-tag injection can redirect relative URLs", policy_index=policy.index, directive="base-uri", recommendation="Set base-uri 'none' unless the application requires 'self'.")
    elif not (_exactly_none(base_uri) or (len(base_uri.tokens) == 1 and base_uri.tokens[0].lower() == "'self'")):
        _add(findings, max_findings, ERROR, "WEAK_BASE_URI", "base-uri is broader than 'none' or 'self'", policy_index=policy.index, directive="base-uri", recommendation="Set base-uri 'none' or base-uri 'self'.")

    frame_ancestors = _directive(policy, "frame-ancestors")
    if frame_ancestors is None:
        _add(findings, max_findings, WARNING, "MISSING_FRAME_ANCESTORS", "frame-ancestors is missing, leaving clickjacking protection to weaker legacy headers", policy_index=policy.index, directive="frame-ancestors", recommendation="Set frame-ancestors 'none' or frame-ancestors 'self'.")
    else:
        bad_wildcard = any(
            source.kind == "wildcard"
            or source.host_is_wildcard
            or source.port == "*"
            or (source.kind == "scheme" and source.scheme in ("http", "https", "data", "blob", "filesystem"))
            or (source.kind == "host" and source.scheme == "http")
            for source in frame_ancestors.sources
        )
        if bad_wildcard:
            _add(findings, max_findings, ERROR, "WEAK_FRAME_ANCESTORS", "frame-ancestors uses a wildcard or dangerous scheme and does not provide reliable clickjacking protection", policy_index=policy.index, directive="frame-ancestors", recommendation="Use frame-ancestors 'none', 'self', or exact HTTPS parent origins.")
        elif not (_exactly_none(frame_ancestors) or all((source.kind == "keyword" and source.keyword == "self") or source.kind == "host" for source in frame_ancestors.sources)):
            _add(findings, max_findings, WARNING, "BROAD_FRAME_ANCESTORS", "frame-ancestors should be none, self, or exact HTTPS parent origins", policy_index=policy.index, directive="frame-ancestors", recommendation="Reduce frame-ancestors to exact required parent origins.")

    form_action = _directive(policy, "form-action")
    if form_action is None:
        _add(findings, max_findings, WARNING, "MISSING_FORM_ACTION", "form-action is missing, so form navigation is not constrained by this policy", policy_index=policy.index, directive="form-action", recommendation="Set form-action 'self' or form-action 'none'.")


def _low_complexity_nonce(nonce: str) -> bool:
    decoded = decode_base64_value(nonce)
    if decoded is None or len(decoded) < 4:
        return False
    all_same = all(byte == decoded[0] for byte in decoded[1:])
    ascending = all(byte == (decoded[index - 1] + 1) % 256 for index, byte in enumerate(decoded[1:], 1))
    descending = all(byte == (decoded[index - 1] + 255) % 256 for index, byte in enumerate(decoded[1:], 1))
    if all_same or ascending or descending:
        return True
    if len(decoded) >= 8 and len(decoded) % 2 == 0:
        return all(decoded[index] == decoded[index % 2] for index in range(2, len(decoded)))
    return False


def _analyze_nonces(policy: Policy, findings: List[AuditFinding], max_findings: int, nonce_counts: Dict[str, int]) -> None:
    for item in policy.directives:
        for source in item.sources:
            if source.kind != "nonce" or source.nonce is None:
                continue
            lower = source.nonce.lower()
            if source.decoded_bytes < 16:
                _add(findings, max_findings, ERROR, "WEAK_NONCE_ENTROPY", "nonce decodes to fewer than 16 bytes and provides less than 128 bits of entropy", policy_index=policy.index, directive=item.name, recommendation="Use generate_nonce(16) or a stronger CSPRNG nonce.")
            if lower in PLACEHOLDER_NONCE_VALUES or lower.startswith("123456") or set(lower) == {"0"} or _low_complexity_nonce(source.nonce):
                _add(findings, max_findings, ERROR, "STATIC_NONCE_PLACEHOLDER", "nonce uses a predictable placeholder or static test value", policy_index=policy.index, directive=item.name, recommendation="Generate a fresh unpredictable nonce for every response.")
            nonce_counts[source.nonce] = nonce_counts.get(source.nonce, 0) + 1


def _parse_ipv4_number(part: str):
    if part == "":
        return None
    try:
        if part.lower().startswith("0x"):
            if len(part) == 2:
                return None
            return int(part, 16)
        if len(part) > 1 and part.startswith("0"):
            if any(char not in "01234567" for char in part):
                return None
            return int(part, 8)
        if not part.isdigit():
            return None
        return int(part, 10)
    except ValueError:
        return None


def _parse_whatwg_ipv4(host: str):
    try:
        return ipaddress.IPv4Address(host), False
    except ValueError:
        pass
    if re.match(r"^[0-9A-Fa-fxX.]+$", host) is None:
        return None, False
    parts = host.lower().split(".")
    if len(parts) > 4 or any(part == "" for part in parts):
        return None, False
    numbers = []
    for part in parts:
        number = _parse_ipv4_number(part)
        if number is None:
            return None, False
        numbers.append(number)
    for number in numbers[:-1]:
        if number > 255:
            return None, False
    remaining_bytes = 5 - len(numbers)
    if numbers[-1] >= 256 ** remaining_bytes:
        return None, False
    value = numbers[-1]
    for index, number in enumerate(numbers[:-1]):
        value += number * (256 ** (3 - index))
    try:
        return ipaddress.IPv4Address(value), str(ipaddress.IPv4Address(value)) != host
    except ValueError:
        return None, False


def _private_or_loopback_host(host: str) -> bool:
    lower = host.lower().strip("[]").rstrip(".")
    if lower == "localhost" or lower.endswith(".localhost") or lower.endswith(".local") or lower.endswith(".internal"):
        return True
    try:
        address = ipaddress.ip_address(lower)
    except ValueError:
        address, _alternate = _parse_whatwg_ipv4(lower)
        if address is None:
            return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    return bool(address.is_private or address.is_loopback or address.is_link_local or address.is_multicast or address.is_unspecified or address.is_reserved)


def _analyze_one_endpoint(token: str, policy: Policy, directive_name: str, findings: List[AuditFinding], max_findings: int) -> None:
    context = {"policy_index": policy.index, "directive": directive_name}
    if token.startswith("//"):
        _add(findings, max_findings, WARNING, "REPORT_ENDPOINT_PROTOCOL_RELATIVE", "protocol-relative reporting endpoints can leak reports over plaintext HTTP", recommendation="Use an explicit HTTPS endpoint.", **context)
    try:
        parsed = urlsplit(token)
    except ValueError:
        return
    if parsed.scheme == "" and parsed.netloc == "":
        return
    if parsed.username is not None or parsed.password is not None:
        _add(findings, max_findings, ERROR, "REPORT_ENDPOINT_CREDENTIALS", "reporting endpoint contains credentials in the URL", recommendation="Remove credentials and use a server-side secret or signed ingestion path.", **context)
    if parsed.scheme.lower() != "https":
        _add(findings, max_findings, WARNING, "REPORT_ENDPOINT_NOT_HTTPS", "reporting endpoint is not HTTPS and can expose violation reports", recommendation="Use HTTPS for every reporting endpoint.", **context)
    hostname = parsed.hostname or ""
    if hostname:
        alternate_ip, noncanonical_ip = _parse_whatwg_ipv4(hostname.lower().strip("[]"))
        if alternate_ip is not None and noncanonical_ip:
            _add(findings, max_findings, WARNING, "REPORT_ENDPOINT_NONCANONICAL_IP", "reporting endpoint uses a non-canonical numeric IP form that URL parsers may reinterpret", recommendation="Use the canonical dotted IPv4 or IPv6 form, or a DNS name.", **context)
    if hostname and _private_or_loopback_host(hostname):
        _add(findings, max_findings, WARNING, "REPORT_ENDPOINT_PRIVATE_NETWORK", "reporting endpoint targets loopback or private-network infrastructure and may become an SSRF primitive in server-side forwarding", recommendation="Use a tightly scoped external reporting ingestion service.", **context)
    if parsed.path in ("", "/") or "*" in hostname:
        _add(findings, max_findings, WARNING, "REPORT_ENDPOINT_TOO_BROAD", "reporting endpoint is broad or unprefixed and may mix sensitive violation reports with unrelated traffic", recommendation="Use a dedicated HTTPS reporting path.", **context)


def _analyze_reporting(policy: Policy, findings: List[AuditFinding], max_findings: int) -> None:
    report_uri = _directive(policy, "report-uri")
    if report_uri is not None:
        _add(findings, max_findings, WARNING, "LEGACY_REPORT_URI", "report-uri is legacy; report-to is the CSP Level 3 reporting mechanism", policy_index=policy.index, directive="report-uri", recommendation="Prefer report-to while retaining report-uri only for required legacy clients.")
        for token in report_uri.tokens:
            _analyze_one_endpoint(token, policy, "report-uri", findings, max_findings)
    report_to = _directive(policy, "report-to")
    if report_to is not None:
        token = report_to.tokens[0] if report_to.tokens else ""
        if ":" in token or "/" in token or "@" in token:
            _analyze_one_endpoint(token, policy, "report-to", findings, max_findings)


def _grade_from_score(score: int) -> str:
    if score >= 97:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def _score_findings(findings: Sequence[AuditFinding], policy_index: int) -> int:
    score = 100
    seen_codes = set()
    for finding in findings:
        if finding.policy_index is not None and finding.policy_index != policy_index:
            continue
        base = DEDUCTIONS.get(finding.code, 12 if finding.severity == ERROR else 5 if finding.severity == WARNING else 1)
        key = finding.code + ":" + str(finding.directive)
        deduction = min(4, (base + 3) // 4) if key in seen_codes else base
        seen_codes.add(key)
        score -= deduction
    return max(0, score)


def _strict_policy_shape(policy: Policy) -> bool:
    script = _effective_fetch_directive(policy, "script-src")
    object_src = _directive(policy, "object-src")
    base_uri = _directive(policy, "base-uri")
    frame_ancestors = _directive(policy, "frame-ancestors")
    script_strict = (
        script is not None
        and _has_keyword(script, "strict-dynamic")
        and _has_strong_nonce_or_hash(script)
        and not _has_keyword(script, "unsafe-inline")
        and not _has_keyword(script, "unsafe-eval")
    )
    base_strong = base_uri is not None and _exactly_none(base_uri)
    frame_strong = frame_ancestors is not None and (
        _exactly_none(frame_ancestors)
        or (len(frame_ancestors.tokens) == 1 and frame_ancestors.tokens[0].lower() == "'self'")
    )
    return bool(script_strict and _exactly_none(object_src) and base_strong and frame_strong)


def audit_csp(input_value: Union[str, Sequence[str], ParsedCsp], options: Optional[Mapping[str, Any]] = None) -> AuditReport:
    """Audit CSP input without throwing for hostile policy text.

    The audit parser is non-strict internally so malformed input becomes
    deterministic findings rather than exceptions.
    """

    try:
        resolved = resolve_parse_options(options)
    except CspCageError:
        resolved = resolve_parse_options(None)
    max_findings = int(resolved["max_findings"])
    findings: List[AuditFinding] = []
    parse_options = dict(resolved)
    parse_options["strict"] = False

    if isinstance(input_value, ParsedCsp):
        parsed = input_value
    else:
        try:
            parsed = _parse_csp_internal(input_value, parse_options)
        except CspCageError as error:
            parsed = ParsedCsp(policies=(), policy_count=0, directive_count=0, header_count=0, errors=(error,))
        except (TypeError, ValueError) as error:
            wrapped = CspCageError(CSPCAGE_ERROR_CODES["INVALID_INPUT"], "invalid CSP input")
            parsed = ParsedCsp(policies=(), policy_count=0, directive_count=0, header_count=0, errors=(wrapped,))

    parse_errors = list(parsed.errors)
    for error in parse_errors:
        context = getattr(error, "context", {})
        policy_index = context.get("policy_index") if isinstance(context, dict) else None
        directive = context.get("directive") if isinstance(context, dict) else None
        detail = getattr(error, "detail", "") or str(error)
        code = getattr(error, "code", CSPCAGE_ERROR_CODES["INVALID_INPUT"])
        _add(findings, max_findings, ERROR, code, detail, policy_index=policy_index, directive=directive, recommendation="Reject or rewrite the malformed CSP header before deployment.")

    nonce_counts: Dict[str, int] = {}
    for policy in parsed.policies:
        _analyze_framework_gaps(policy, findings, max_findings)
        for item in policy.directives:
            if not item.ignored:
                _analyze_none_union(policy, item, findings, max_findings)
                _analyze_critical_sources(policy, item, findings, max_findings)
        for item in _script_relevant_directives(policy):
            _analyze_unsafe_script_tokens(policy, item, findings, max_findings)
        _analyze_cdn_gadgets(policy, findings, max_findings)
        _analyze_nonces(policy, findings, max_findings, nonce_counts)
        _analyze_reporting(policy, findings, max_findings)

    if any(count > 1 for count in nonce_counts.values()):
        _add(findings, max_findings, WARNING, "REPEATED_NONCE", "the same nonce value appears repeatedly; repeated or static nonce deployment can make nonce protection worthless", recommendation="Generate a fresh nonce for every response and never reuse it.")

    errors = sum(1 for finding in findings if finding.severity == ERROR)
    warnings = sum(1 for finding in findings if finding.severity == WARNING)
    notices = sum(1 for finding in findings if finding.severity == NOTICE)
    policy_results: List[PolicyAudit] = []
    for policy in parsed.policies:
        score = _score_findings(findings, policy.index)
        if parse_errors:
            score = min(score, 45)
        policy_findings = [finding for finding in findings if finding.policy_index in (None, policy.index)]
        policy_results.append(PolicyAudit(
            policy_index=policy.index,
            directive_count=len(policy.directives),
            score=score,
            grade=_grade_from_score(score),
            error_count=sum(1 for finding in policy_findings if finding.severity == ERROR),
            warning_count=sum(1 for finding in policy_findings if finding.severity == WARNING),
            notice_count=sum(1 for finding in policy_findings if finding.severity == NOTICE),
            strict_csp_shape=_strict_policy_shape(policy),
        ))
    score = min((item.score for item in policy_results), default=0)
    strict = bool(isinstance(options, dict) and options.get("strict") is True)
    safe = errors == 0 and (not strict or warnings == 0)
    return AuditReport(
        findings=tuple(findings),
        counts={"errors": errors, "warnings": warnings, "notices": notices},
        score=score,
        grade=_grade_from_score(score),
        safe=safe,
        strict_csp=len(parse_errors) == 0 and len(policy_results) > 0 and all(item.strict_csp_shape for item in policy_results),
        policies=tuple(policy_results),
        valid=len(parse_errors) == 0,
        strict=strict,
        policy_count=parsed.policy_count,
    )


def is_safe_csp(input_value: Union[str, Sequence[str], ParsedCsp], options: Optional[Mapping[str, Any]] = None) -> bool:
    """Return the boolean enforcement decision from :func:`audit_csp`."""

    return audit_csp(input_value, options).safe
