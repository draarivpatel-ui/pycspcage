# Changelog

## 1.0.0

Initial production release.

### Added

- Strict bounded CSP Level 3 parser with multi-policy support and immutable parsed output.
- Real-world XSS-bypass auditor for unsafe inline script, eval, JSONP and CDN gadgets, weak nonces, missing object-src, base-uri, frame-ancestors, form-action, insecure schemes, wildcards, duplicate directives, and unsafe reporting endpoints.
- Safe deterministic header builder with parse-back and audit-before-return enforcement.
- Strict-dynamic CSP generator using fresh CSPRNG nonces.
- Conservative CSP merge API that does not silently widen none or introduce unsafe-inline.
- SHA-256, SHA-384, and SHA-512 CSP hash helper.
- Command line interface with parse, audit, build, strict, merge, nonce, and hash subcommands.
- Wheel typing marker, examples, distribution checks, documentation, CI matrix, and hardened release workflow.
