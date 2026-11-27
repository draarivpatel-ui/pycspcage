"""CSPRNG nonce and CSP hash helpers."""
from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Union

from .constants import CSPCAGE_ERROR_CODES, HASH_ALGORITHMS
from .errors import CspCageError


def generate_nonce(byte_count: int = 16) -> str:
    """Return a fresh base64 nonce using ``secrets.token_bytes``.

    The default is 16 bytes, which is 128 bits of CSPRNG entropy. Sizes from
    16 through 64 bytes are accepted; smaller values are rejected instead of
    being silently weakened.
    """

    if not isinstance(byte_count, int) or isinstance(byte_count, bool) or byte_count < 16 or byte_count > 64:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_NONCE_INPUT"], "nonce size must be an integer from 16 to 64 bytes")
    return base64.b64encode(secrets.token_bytes(byte_count)).decode("ascii")


def compute_hash(content: Union[str, bytes, bytearray, memoryview], algorithm: str = "sha256") -> str:
    """Compute a CSP source hash for inline content.

    The return value is in CSP form, for example ``sha256-<base64>``.
    """

    if algorithm not in HASH_ALGORITHMS:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_HASH_INPUT"], "algorithm must be sha256, sha384, or sha512")
    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray, memoryview)):
        data = bytes(content)
    else:
        raise CspCageError(CSPCAGE_ERROR_CODES["INVALID_HASH_INPUT"], "content must be a string, bytes, bytearray, or memoryview")
    digest = hashlib.new(algorithm, data).digest()
    return algorithm + "-" + base64.b64encode(digest).decode("ascii")
