# pycspcage

Zero-dependency Content-Security-Policy Level 3 security firewall, XSS-bypass auditor, nonce and hash guard, and safe header builder for Python.

`pycspcage` parses bounded CSP headers, audits real-world bypass conditions, generates cryptographically strong nonces and hashes, builds safe headers, and merges policies without silently weakening them. It is designed for Django, Flask, FastAPI, Starlette, Pyramid, security middleware, CI policy checks, and plain WSGI or ASGI services.

The package uses only the Python standard library. It ships type information through `py.typed`, typed errors, immutable result objects, deterministic serialization, a command line interface, and distribution content checks.

## Install

```console
python3 -m pip install pycspcage
```

Python 3.9 or newer is required.

## Quick start

```python
from pycspcage import audit_csp, build_csp, create_strict_csp, generate_nonce, parse_csp

nonce = generate_nonce()
header = create_strict_csp({"nonce": nonce})

parsed = parse_csp(header)
print(parsed.policy_count, parsed.directive_count)

report = audit_csp(header)
print(report.safe, report.grade, report.score)

custom = build_csp({
    "default_src": ["'self'"],
    "script_src": ["'nonce-" + nonce + "'", "'strict-dynamic'"],
    "object_src": ["'none'"],
    "base_uri": ["'none'"],
    "form_action": ["'self'"],
    "frame_ancestors": ["'none'"],
})
```

## Strict bounded parser

```python
from pycspcage import CspCageError, parse_csp

try:
    parsed = parse_csp("default-src 'self'; script-src 'self' https://cdn.example.com/app.js")
    print(parsed.policies[0].directive_map["script-src"].sources)
except CspCageError as error:
    print(error.code, error.detail)
```

The parser understands comma-separated multi-policy header lists and sequences of header strings. It validates CSP Level 3 directive names, source expressions, nonces, hashes, host sources, scheme sources, sandbox tokens, reporting directives, Trusted Types directives, and valueless directives.

Unsafe input is bounded before interpretation.

| Bound | Default | Hard maximum |
| --- | ---: | ---: |
| Header bytes | 8192 | 65536 |
| Policies | 4 | 16 |
| Directives per policy | 32 | 64 |
| Total directives | 96 | 256 |
| Sources per directive | 64 | 128 |
| Source length | 512 | 2048 |
| Findings | 128 | 512 |

The parser rejects CR, LF, NUL, C0 and C1 controls, non-ASCII input, Unicode bidi or format smuggling, surrogate code units, empty policies, empty directives, malformed quoting, malformed nonce base64, wrong hash lengths, SHA-1 and MD5 hashes, invalid host names, bad ports, bad percent encoding, unknown directives, and deprecated directives.

Duplicate directives are rejected because CSP's first-directive-wins rule makes later entries a dangerous shadowing trap. Non-strict internal audit parsing can mark duplicate entries as ignored while still reporting the duplicate as a finding.

Deprecated directives rejected by the strict parser include `block-all-mixed-content`, `plugin-types`, and `referrer`. `report-uri` remains parseable for real-world compatibility, but the auditor marks it as legacy and recommends `report-to`.

## XSS-bypass auditor

```python
from pycspcage import audit_csp

report = audit_csp("script-src 'unsafe-inline' cdn.jsdelivr.net; object-src *")
for finding in report.findings:
    print(finding.severity, finding.code, finding.recommendation)
```

`audit_csp` never throws for hostile policy text. It returns an immutable report with errors, warnings, notices, a score from 0 to 100, a letter grade, per-policy results, and a strict-CSP shape indicator.

Detected classes include:

- Active `'unsafe-inline'` in script directives.
- CSP3 nonce or hash shadowing of `'unsafe-inline'`, with the legacy-browser bypass called out separately.
- `'unsafe-eval'`, `'wasm-unsafe-eval'`, and `'unsafe-hashes'`.
- Missing script fallback policy and missing `default-src` fallback.
- Missing `object-src 'none'` and permissive object sources.
- Missing or broad `base-uri` protection against base-tag hijacking.
- Missing or weak `frame-ancestors` clickjacking protection.
- Missing `form-action` navigation protection.
- Wildcards, broad `https:` scheme sources, insecure HTTP, `data:`, `blob:`, `filesystem:`, wildcard ports, and executable schemes in critical directives.
- JSONP, AngularJS, and CDN script-gadget hosts such as Google-hosted libraries, jsDelivr, unpkg, cdnjs, raw GitHub content, cloud storage, and CDN wildcard hosts when they are not neutralized by `'strict-dynamic'`.
- Nonces below 128 bits of decoded entropy, malformed nonce encodings, repeated nonces, predictable placeholders, constant byte sequences, ascending or descending byte sequences, and repeating byte pairs.
- SHA-1, MD5, malformed base64 digests, and wrong digest lengths for SHA-256, SHA-384, and SHA-512.
- Legacy `report-uri` use, non-HTTPS reporting endpoints, credential-bearing endpoints, loopback or private-network reporting targets, protocol-relative endpoints, and broad reporting paths.

Strict-CSP shape requires `'strict-dynamic'` paired with a strong nonce or valid hash, `object-src 'none'`, `base-uri 'none'`, and `frame-ancestors 'none'` or `'self'`, without unsafe script keywords.

## Safe builder

```python
from pycspcage import build_csp

header = build_csp({
    "default_src": ["'self'"],
    "script_src": ["'self'"],
    "object_src": ["'none'"],
    "base_uri": ["'none'"],
    "form_action": ["'self'"],
    "frame_ancestors": ["'self'"],
    "upgrade_insecure_requests": True,
})
```

The builder accepts canonical hyphenated keys, snake_case keys, or camelCase keys. It serializes directives in a deterministic CSP-oriented order. Directive keys and values are checked for semicolon injection, comma injection, whitespace smuggling, CR, LF, NUL, controls, backslashes, unknown directives, deprecated directives, duplicate normalized keys, and dangerous object keys.

Every serialized header is parsed again and audited before it is returned. A header that creates active unsafe script, wildcard object execution, executable schemes, weak base-uri or frame-ancestors posture, malformed syntax, or another error-level bypass raises `CSPCAGE_UNSAFE_BUILD_OUTPUT` instead of returning the header. Pass `{"require_clean_audit": True}` to also reject warnings.

`create_strict_csp()` creates a nonce-based strict-dynamic policy with restrictive defaults. It generates a fresh 128-bit nonce when one is not supplied.

## Nonces and hashes

```python
from pycspcage import compute_hash, generate_nonce

nonce = generate_nonce()       # 16 bytes from secrets.token_bytes
digest = compute_hash("console.log('hello')", "sha256")
```

`generate_nonce` uses `secrets.token_bytes` and accepts sizes from 16 to 64 bytes. Smaller nonces are rejected because they do not meet 128 bits of entropy. `compute_hash` supports only `sha256`, `sha384`, and `sha512` and returns the complete CSP token prefix, such as `sha256-...`.

## Safe merging

```python
from pycspcage import merge_csp

merged = merge_csp(
    "default-src 'self'; object-src 'none'",
    "script-src 'self' https://cdn.example.com/app.js; base-uri 'none'",
)
```

`merge_csp` accepts CSP strings, parsed CSP values, or directive mappings. Every input must contain exactly one policy. Union behavior is conservative: `'none'` is not silently widened and `'unsafe-inline'` is never introduced unless the caller explicitly passes `allow_unsafe_inline=True` in merge options. The merged output is rebuilt, parsed again, and audited.

## CLI

```console
python3 -m pycspcage parse "default-src 'self'"
python3 -m pycspcage audit "script-src 'unsafe-inline'" --json
python3 -m pycspcage strict
python3 -m pycspcage nonce 16
python3 -m pycspcage hash "console.log(1)" --algorithm sha256
python3 -m pycspcage build '{"default_src":["'"'self"'"],"object_src":["'"'none"'"]}'
```

Audit exit code is zero when the policy is safe and one when findings block it. Invalid input and malformed CLI use exit with code two. Error output is bounded and control characters are stripped.

## API reference

### Parsing

- `parse_csp(input, options=None)`: strict parser returning `ParsedCsp`.
- `parse_source_expression(token, max_source_length=512)`: parse one source expression.

Parse options are `max_bytes`, `max_policies`, `max_directives_per_policy`, `max_total_directives`, `max_sources_per_directive`, `max_source_length`, `max_findings`, and `strict`. Bounds outside the hard limits are rejected.

### Auditing

- `audit_csp(input, options=None)`: returns `AuditReport` and does not throw for hostile policy text.
- `is_safe_csp(input, options=None)`: boolean enforcement decision.

`AuditReport` exposes `valid`, `safe`, `strict`, `strict_csp`, `grade`, `score`, `policy_count`, `policies`, `counts`, and immutable `findings`.

### Building and merging

- `build_csp(directives, options=None)`: serialize a safe deterministic header.
- `create_strict_csp(options=None)`: create a strict-dynamic nonce policy.
- `merge_csp(*inputs, options=None)`: conservative union of one-policy inputs.
- `normalize_directive_input(mapping)`: canonicalize a directive mapping.
- `serialize_directive_map(mapping)`: deterministic serialization of an already normalized mapping.

### Cryptographic helpers

- `generate_nonce(byte_count=16)`: CSPRNG nonce.
- `compute_hash(content, algorithm="sha256")`: CSP hash token.

### Errors

All library input validation failures raise `CspCageError` with a stable `CSPCAGE_*` code in the `code` attribute. The auditor converts hostile policy text into findings instead of exceptions.

## Security model

The library is a local parser and policy firewall. It does not fetch URLs, resolve DNS, inspect certificates, run JavaScript, or trust caller-supplied remote key material. It does not replace correct output encoding, framework escaping, Trusted Types enforcement, or browser XSS filters. It gives deterministic server-side decisions for CSP generation and deployment gates.

## Examples

Run the examples from a source checkout:

```console
PYTHONPATH=src python3 examples/basic_strict_policy.py
PYTHONPATH=src python3 examples/audit_real_world_policy.py
PYTHONPATH=src python3 examples/merge_and_hash_gate.py
```

## Development

Run tests:

```console
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Build and inspect distributions:

```console
python3 -m pip install build
python3 -m build
python3 scripts/check_dist.py dist
```

## License

MIT. See [LICENSE](LICENSE).
