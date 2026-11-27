"""Zero-dependency CSP Level 3 firewall, XSS auditor, nonce guard, and builder."""
from __future__ import annotations

from .auditor import audit_csp, is_safe_csp
from .builder import build_csp, create_strict_csp, normalize_directive_input, serialize_directive_map
from .constants import (
    CSP_DIRECTIVE_ORDER,
    CSP_DIRECTIVES,
    CSP_KEYWORDS,
    CSP_PARSE_BOUNDS,
    CSP_PARSE_HARD_LIMITS,
    CSPCAGE_ERROR_CODES,
    CSPCAGE_SEVERITY,
    CSPCAGE_VERSION,
    DEPRECATED_DIRECTIVES,
    FETCH_DIRECTIVES,
    HASH_ALGORITHMS,
    HASH_DIGEST_BYTES,
    PLACEHOLDER_NONCE_VALUES,
    SCRIPT_GADGET_HOSTS,
    SOURCE_LIST_DIRECTIVES,
)
from .crypto import compute_hash, generate_nonce
from .errors import CspCageError, invalid_input, is_cspcage_error
from .merge import merge_csp
from .model import AuditFinding, AuditReport, Directive, ParsedCsp, Policy, PolicyAudit, SourceExpression
from .parser import parse_csp, parse_source_expression

__version__ = CSPCAGE_VERSION

__all__ = (
    "AuditFinding",
    "AuditReport",
    "CSP_DIRECTIVES",
    "CSP_DIRECTIVE_ORDER",
    "CSP_KEYWORDS",
    "CSP_PARSE_BOUNDS",
    "CSP_PARSE_HARD_LIMITS",
    "CSPCAGE_ERROR_CODES",
    "CSPCAGE_SEVERITY",
    "CSPCAGE_VERSION",
    "CspCageError",
    "DEPRECATED_DIRECTIVES",
    "Directive",
    "FETCH_DIRECTIVES",
    "HASH_ALGORITHMS",
    "HASH_DIGEST_BYTES",
    "PLACEHOLDER_NONCE_VALUES",
    "ParsedCsp",
    "Policy",
    "PolicyAudit",
    "SCRIPT_GADGET_HOSTS",
    "SOURCE_LIST_DIRECTIVES",
    "SourceExpression",
    "__version__",
    "audit_csp",
    "build_csp",
    "compute_hash",
    "create_strict_csp",
    "generate_nonce",
    "invalid_input",
    "is_cspcage_error",
    "is_safe_csp",
    "merge_csp",
    "normalize_directive_input",
    "parse_csp",
    "parse_source_expression",
    "serialize_directive_map",
)
