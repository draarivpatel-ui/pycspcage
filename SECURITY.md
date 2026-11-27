# Security policy

## Supported versions

The latest published 1.x release is supported. Security fixes are applied to the main branch before release.

## Reporting a vulnerability

Do not open a public issue with exploit details, proof-of-concept payloads, or unredacted application headers. Report suspected vulnerabilities privately through the repository owner's GitHub security advisory flow when available. If advisory flow is unavailable, open a minimal public issue asking for a private contact route and do not include the payload.

Include this information when it is safe to share:

- the affected version
- the API or CLI command used
- whether the issue is a parser bypass, resource exhaustion, incorrect block decision, or packaging integrity problem
- a minimal redacted input shape
- expected and actual behavior

## Scope

In scope:

- ReDoS or other resource exhaustion in CSP parsing or building
- incorrect acceptance of duplicate directives, malformed source expressions, weak hashes, unsafe nonces, or unsafe serialized output
- audit bypasses involving JSONP, CDN script gadgets, wildcards, insecure schemes, object injection, base-uri injection, or clickjacking posture
- malformed input that causes a traceback rather than a typed error or finding
- distribution files that differ from the source tree or contain unintended data

Out of scope:

- vulnerabilities in browsers, Python itself, or web frameworks
- exploitability of a deployment after a caller intentionally disables the firewall decision
- social engineering unrelated to parser or audit logic
- findings that require writing to a victim machine outside this library's API

## Security design notes

The library is stdlib-only at runtime. It does not open network connections, resolve DNS, execute shell commands, evaluate JavaScript, or write files. Audit functions return findings and leave enforcement to the caller.

The CLI exit code is part of the security boundary. An allowed result exits with zero. A blocked audit exits nonzero. Invalid input exits with a distinct nonzero code.
