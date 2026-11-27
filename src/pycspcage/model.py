"""Immutable public result models used by pycspcage."""
from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Tuple, Union


def freeze_value(value: Any) -> Any:
    """Recursively convert JSON-like containers to immutable values."""

    if isinstance(value, dict):
        frozen: Dict[Any, Any] = {}
        for key, item in value.items():
            frozen[key] = freeze_value(item)
        return MappingProxyType(frozen)
    if isinstance(value, (list, tuple)):
        return tuple(freeze_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(freeze_value(item) for item in sorted(value, key=repr))
    return value


@dataclass(frozen=True)
class SourceExpression:
    """A normalized CSP source expression."""

    kind: str
    token: str
    keyword: Optional[str] = None
    scheme: Optional[str] = None
    host: Optional[str] = None
    port: Optional[Union[int, str]] = None
    path: str = ""
    host_is_wildcard: bool = False
    ipv6: bool = False
    nonce: Optional[str] = None
    algorithm: Optional[str] = None
    decoded_bytes: int = 0
    has_exact_path: bool = False


@dataclass(frozen=True)
class Directive:
    """A parsed directive. Duplicate entries can be marked ``ignored``."""

    name: str
    tokens: Tuple[str, ...]
    sources: Tuple[SourceExpression, ...] = ()
    index: int = 0
    ignored: bool = False


@dataclass(frozen=True)
class Policy:
    """One CSP policy from a possibly multi-policy header list."""

    index: int
    directives: Tuple[Directive, ...]
    directive_map: Mapping[str, Directive] = field(compare=False)

    def directive(self, name: str) -> Optional[Directive]:
        return self.directive_map.get(name)


@dataclass(frozen=True)
class ParsedCsp:
    """Strict bounded parser output."""

    policies: Tuple[Policy, ...]
    policy_count: int
    directive_count: int
    header_count: int
    errors: Tuple[BaseException, ...] = ()


@dataclass(frozen=True)
class AuditFinding:
    """One deterministic security finding."""

    severity: str
    code: str
    message: str
    policy_index: Optional[int] = None
    directive: Optional[str] = None
    recommendation: Optional[str] = None
    details: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    def __post_init__(self) -> None:
        object.__setattr__(self, "details", freeze_value(dict(self.details)))
        if self.severity not in ("error", "warning", "notice"):
            raise ValueError("unknown finding severity")


@dataclass(frozen=True)
class PolicyAudit:
    """Per-policy summary inside an audit report."""

    policy_index: int
    directive_count: int
    score: int
    grade: str
    error_count: int
    warning_count: int
    notice_count: int
    strict_csp_shape: bool


@dataclass(frozen=True)
class AuditReport:
    """Complete CSP audit report. Audit functions never mutate input."""

    findings: Tuple[AuditFinding, ...]
    counts: Mapping[str, int]
    score: int
    grade: str
    safe: bool
    strict_csp: bool
    policies: Tuple[PolicyAudit, ...]
    valid: bool = True
    strict: bool = False
    policy_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "counts", MappingProxyType(dict(self.counts)))
