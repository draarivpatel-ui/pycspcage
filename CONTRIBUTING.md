# Contributing

## Ground rules

- Keep the runtime library dependency-free and stdlib-only.
- Support Python 3.9 through 3.13 from one source tree.
- Use deterministic bounded parsers. Do not introduce eval, shell execution, network access, or catastrophic-backtracking regular expressions.
- Preserve stable `CSPCAGE_*` finding and error codes whenever possible.
- Treat every hostile input as a typed error or audit finding, not a traceback.
- Do not weaken strict output checks to make a test pass.

## Development setup

No runtime dependencies are required. Run tests directly from the source tree:

```console
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Run examples:

```console
PYTHONPATH=src python3 examples/basic_strict_policy.py
PYTHONPATH=src python3 examples/audit_real_world_policy.py
PYTHONPATH=src python3 examples/merge_and_hash_gate.py
```

Build and inspect distributions:

```console
python3 -m pip install build
python3 -m build
python3 scripts/check_dist.py dist
```

## Test expectations

Add tests for every parser branch and every new finding. Include hostile input cases, not only valid examples. Useful categories are:

- exact boundary lengths
- NUL and control characters
- bidi and zero-width characters
- lone surrogate code units
- comma and semicolon separator confusion
- duplicate directives and casing differences
- malformed base64 nonces and wrong digest lengths
- IPv4, IPv6, wildcard, port, and path edge cases
- JSONP and CDN gadget host matching
- reporting endpoint credentials and private-network targets
- CLI exit codes and JSON shape

Tests must use `unittest` and must not require network access.

## Coding style

Use compact, idiomatic Python. Keep type annotations compatible with Python 3.9. Runtime unions must use `typing.Union` or `typing.Optional`; do not use the Python 3.10 union operator. Keep public result objects frozen and convert mutable detail containers to immutable forms.

## Security reports

Follow [SECURITY.md](SECURITY.md). Do not attach live secrets, credential-bearing URLs, or unredacted application headers to issues or pull requests.
