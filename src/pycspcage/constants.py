"""Constants for the pycspcage security firewall."""
from __future__ import annotations

from types import MappingProxyType

CSPCAGE_VERSION = "1.0.0"

CSPCAGE_ERROR_CODES = MappingProxyType({
    "INVALID_INPUT": "CSPCAGE_INVALID_INPUT",
    "INVALID_OPTIONS": "CSPCAGE_INVALID_OPTIONS",
    "INPUT_TOO_LARGE": "CSPCAGE_INPUT_TOO_LARGE",
    "TOO_MANY_POLICIES": "CSPCAGE_TOO_MANY_POLICIES",
    "TOO_MANY_DIRECTIVES": "CSPCAGE_TOO_MANY_DIRECTIVES",
    "TOO_MANY_SOURCES": "CSPCAGE_TOO_MANY_SOURCES",
    "SOURCE_TOO_LONG": "CSPCAGE_SOURCE_TOO_LONG",
    "HEADER_INJECTION": "CSPCAGE_HEADER_INJECTION",
    "CONTROL_CHARACTER": "CSPCAGE_CONTROL_CHARACTER",
    "INVALID_ASCII": "CSPCAGE_INVALID_ASCII",
    "EMPTY_POLICY": "CSPCAGE_EMPTY_POLICY",
    "EMPTY_DIRECTIVE": "CSPCAGE_EMPTY_DIRECTIVE",
    "MISSING_DIRECTIVE_VALUE": "CSPCAGE_MISSING_DIRECTIVE_VALUE",
    "UNEXPECTED_DIRECTIVE_VALUE": "CSPCAGE_UNEXPECTED_DIRECTIVE_VALUE",
    "INVALID_DIRECTIVE_NAME": "CSPCAGE_INVALID_DIRECTIVE_NAME",
    "UNKNOWN_DIRECTIVE": "CSPCAGE_UNKNOWN_DIRECTIVE",
    "DEPRECATED_DIRECTIVE": "CSPCAGE_DEPRECATED_DIRECTIVE",
    "DUPLICATE_DIRECTIVE": "CSPCAGE_DUPLICATE_DIRECTIVE",
    "INVALID_SOURCE_EXPRESSION": "CSPCAGE_INVALID_SOURCE_EXPRESSION",
    "INVALID_KEYWORD_SOURCE": "CSPCAGE_INVALID_KEYWORD_SOURCE",
    "INVALID_NONCE": "CSPCAGE_INVALID_NONCE",
    "INVALID_HASH": "CSPCAGE_INVALID_HASH",
    "UNSUPPORTED_HASH_ALGORITHM": "CSPCAGE_UNSUPPORTED_HASH_ALGORITHM",
    "INVALID_SCHEME_SOURCE": "CSPCAGE_INVALID_SCHEME_SOURCE",
    "INVALID_HOST_SOURCE": "CSPCAGE_INVALID_HOST_SOURCE",
    "INVALID_ENDPOINT": "CSPCAGE_INVALID_ENDPOINT",
    "INVALID_SANDBOX_TOKEN": "CSPCAGE_INVALID_SANDBOX_TOKEN",
    "INVALID_BUILD_INPUT": "CSPCAGE_INVALID_BUILD_INPUT",
    "INVALID_MERGE_INPUT": "CSPCAGE_INVALID_MERGE_INPUT",
    "INVALID_NONCE_INPUT": "CSPCAGE_INVALID_NONCE_INPUT",
    "INVALID_HASH_INPUT": "CSPCAGE_INVALID_HASH_INPUT",
    "UNSAFE_BUILD_OUTPUT": "CSPCAGE_UNSAFE_BUILD_OUTPUT",
    "UNSAFE_INLINE_MERGE": "CSPCAGE_UNSAFE_INLINE_MERGE",
    "PROTOTYPE_POLLUTION": "CSPCAGE_PROTOTYPE_POLLUTION",
})

CSPCAGE_SEVERITY = MappingProxyType({
    "ERROR": "error",
    "WARNING": "warning",
    "NOTICE": "notice",
})

CSP_PARSE_BOUNDS = MappingProxyType({
    "max_bytes": 8192,
    "max_policies": 4,
    "max_directives_per_policy": 32,
    "max_total_directives": 96,
    "max_sources_per_directive": 64,
    "max_source_length": 512,
    "max_findings": 128,
})

CSP_PARSE_HARD_LIMITS = MappingProxyType({
    "max_bytes": 65536,
    "max_policies": 16,
    "max_directives_per_policy": 64,
    "max_total_directives": 256,
    "max_sources_per_directive": 128,
    "max_source_length": 2048,
    "max_findings": 512,
})

FETCH_DIRECTIVES = (
    "child-src",
    "connect-src",
    "default-src",
    "font-src",
    "frame-src",
    "img-src",
    "manifest-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "script-src",
    "script-src-attr",
    "script-src-elem",
    "style-src",
    "style-src-attr",
    "style-src-elem",
    "worker-src",
)

SOURCE_LIST_DIRECTIVES = FETCH_DIRECTIVES + (
    "base-uri",
    "form-action",
    "frame-ancestors",
)

REPORTING_DIRECTIVES = ("report-uri", "report-to")
OTHER_DIRECTIVES = (
    "sandbox",
    "require-sri-for",
    "require-trusted-types-for",
    "trusted-types",
    "upgrade-insecure-requests",
)

CSP_DIRECTIVES = tuple(dict.fromkeys(
    SOURCE_LIST_DIRECTIVES + REPORTING_DIRECTIVES + OTHER_DIRECTIVES
))

CSP_DIRECTIVE_ORDER = (
    "default-src",
    "script-src",
    "script-src-elem",
    "script-src-attr",
    "style-src",
    "style-src-elem",
    "style-src-attr",
    "img-src",
    "font-src",
    "connect-src",
    "media-src",
    "object-src",
    "prefetch-src",
    "child-src",
    "frame-src",
    "worker-src",
    "manifest-src",
    "base-uri",
    "form-action",
    "frame-ancestors",
    "sandbox",
    "require-sri-for",
    "require-trusted-types-for",
    "trusted-types",
    "upgrade-insecure-requests",
    "report-uri",
    "report-to",
)

DEPRECATED_DIRECTIVES = (
    "block-all-mixed-content",
    "plugin-types",
    "referrer",
)

CSP_KEYWORDS = (
    "self",
    "unsafe-inline",
    "unsafe-eval",
    "strict-dynamic",
    "unsafe-hashes",
    "report-sample",
    "wasm-unsafe-eval",
    "inline-speculation-rules",
    "none",
)

SANDBOX_TOKENS = (
    "allow-downloads",
    "allow-forms",
    "allow-modals",
    "allow-orientation-lock",
    "allow-pointer-lock",
    "allow-popups",
    "allow-popups-to-escape-sandbox",
    "allow-presentation",
    "allow-same-origin",
    "allow-scripts",
    "allow-storage-access-by-user-activation",
    "allow-top-navigation",
    "allow-top-navigation-by-user-activation",
    "allow-top-navigation-to-custom-protocols",
)

HASH_ALGORITHMS = ("sha256", "sha384", "sha512")
HASH_DIGEST_BYTES = MappingProxyType({
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
})

DANGEROUS_OBJECT_KEYS = ("__proto__", "constructor", "prototype")

SCRIPT_GADGET_HOSTS = (
    "googleapis.com",
    "gstatic.com",
    "googleusercontent.com",
    "firebaseapp.com",
    "amazonaws.com",
    "cloudfront.net",
    "jsdelivr.net",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "raw.githubusercontent.com",
)

PLACEHOLDER_NONCE_VALUES = (
    "123456",
    "1234567890",
    "abcdef",
    "abc123",
    "test",
    "test-nonce",
    "nonce",
    "example",
    "sample",
    "placeholder",
    "change-me",
    "changeme",
    "static",
    "000000",
)
