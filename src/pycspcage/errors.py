"""Typed errors raised by pycspcage."""
from __future__ import annotations

from typing import Any, Optional


class CspCageError(ValueError):
    """A bounded, typed input or policy error.

    The ``code`` attribute is stable machine-readable API surface. ``detail``
    is safe for display because control characters are rejected before values
    are interpreted.
    """

    def __init__(self, code: str, detail: str = "", context: Optional[Any] = None) -> None:
        self.code = code
        self.detail = detail
        if context is not None:
            self.context = context
        message = code if detail == "" else code + ": " + detail
        super().__init__(message)


def is_cspcage_error(value: object) -> bool:
    """Return whether *value* is a :class:`CspCageError`."""

    return isinstance(value, CspCageError)


def invalid_input(detail: str) -> CspCageError:
    from .constants import CSPCAGE_ERROR_CODES

    return CspCageError(CSPCAGE_ERROR_CODES["INVALID_INPUT"], detail)
