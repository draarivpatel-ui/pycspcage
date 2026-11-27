#!/usr/bin/env python3
"""Verify pycspcage wheel and source distribution contents."""
from __future__ import annotations

import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import List

PACKAGE = "pycspcage"
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
POSIX_HOME_PATTERN = re.compile(rb"/" + rb"Users" + rb"/[A-Za-z0-9._-]+")
WINDOWS_HOME_PATTERN = re.compile(rb"[A-Za-z]:\\\\" + rb"Users" + rb"\\\\[A-Za-z0-9._-]+")
EM_DASH = b"\xe2\x80\x94"
EN_DASH = b"\xe2\x80\x93"


def _fail(errors: List[str], message: str) -> None:
    errors.append(message)


def _scan_bytes(label: str, data: bytes, errors: List[str]) -> None:
    if EM_DASH in data or EN_DASH in data:
        _fail(errors, label + " contains a Unicode em dash or en dash")
    if POSIX_HOME_PATTERN.search(data) or WINDOWS_HOME_PATTERN.search(data):
        _fail(errors, label + " contains a local user path")
    for match in EMAIL_PATTERN.finditer(data):
        value = match.group(0).lower()
        allowed_example = value.endswith((b"example.invalid", b"example.com", b"example.org", b"example.net"))
        if not value.endswith(b"users.noreply.github.com") and not allowed_example:
            _fail(errors, label + " contains an email address")
            break


def _check_wheel(path: Path, errors: List[str]) -> None:
    with zipfile.ZipFile(str(path), "r") as archive:
        names = archive.namelist()
        if PACKAGE + "/py.typed" not in names:
            _fail(errors, "wheel is missing " + PACKAGE + "/py.typed")
        if not any(name.startswith(PACKAGE + "/") and name.endswith("__init__.py") for name in names):
            _fail(errors, "wheel is missing the " + PACKAGE + " package")
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.startswith("tests/") or "/tests/" in normalized:
                _fail(errors, "wheel contains test files: " + normalized)
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                _fail(errors, "wheel contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                _fail(errors, "wheel contains key-like content: " + normalized)
            if normalized.endswith((".py", ".txt", ".typed", "METADATA", "RECORD", "WHEEL")):
                _scan_bytes("wheel member " + normalized, archive.read(name), errors)
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            _fail(errors, "wheel must contain exactly one METADATA file")
        else:
            metadata = archive.read(metadata_names[0]).decode("utf-8", "replace")
            if "Name: pycspcage" not in metadata:
                _fail(errors, "wheel METADATA has the wrong package name")
            if "Version: 1.0.0" not in metadata:
                _fail(errors, "wheel METADATA has the wrong version")
            if "Requires-Python: >=3.9" not in metadata:
                _fail(errors, "wheel METADATA is missing Requires-Python >=3.9")
            if "Requires-Dist:" in metadata:
                _fail(errors, "wheel declares a runtime dependency")


def _check_sdist(path: Path, errors: List[str]) -> None:
    with tarfile.open(str(path), "r:gz") as archive:
        names = archive.getnames()
        required_suffixes = (
            "/pyproject.toml",
            "/README.md",
            "/LICENSE",
            "/SECURITY.md",
            "/CONTRIBUTING.md",
            "/CHANGELOG.md",
            "/src/pycspcage/__init__.py",
            "/src/pycspcage/py.typed",
            "/tests/test_parser_matrix.py",
            "/examples/basic_strict_policy.py",
            "/scripts/check_dist.py",
        )
        for suffix in required_suffixes:
            if not any(name.endswith(suffix) for name in names):
                _fail(errors, "sdist is missing " + suffix)
        for name in names:
            normalized = name.replace("\\", "/")
            if normalized.endswith((".pyc", ".pyo")) or "__pycache__" in normalized:
                _fail(errors, "sdist contains bytecode cache content: " + normalized)
            if normalized.endswith((".pem", ".key", ".p12", ".pfx")):
                _fail(errors, "sdist contains key-like content: " + normalized)
            if normalized.endswith((".py", ".md", ".toml", ".yml", ".typed", "PKG-INFO", "LICENSE")):
                member = archive.extractfile(name)
                if member is not None:
                    _scan_bytes("sdist member " + normalized, member.read(), errors)
        pkg_info_names = [name for name in names if len(name.split("/")) == 2 and name.endswith("/PKG-INFO")]
        if len(pkg_info_names) != 1:
            _fail(errors, "sdist must contain exactly one PKG-INFO file")
        else:
            extracted = archive.extractfile(pkg_info_names[0])
            if extracted is None:
                _fail(errors, "sdist PKG-INFO cannot be read")
            else:
                metadata = extracted.read().decode("utf-8", "replace")
                if "Name: pycspcage" not in metadata:
                    _fail(errors, "sdist PKG-INFO has the wrong package name")
                if "Version: 1.0.0" not in metadata:
                    _fail(errors, "sdist PKG-INFO has the wrong version")
                if "Requires-Python: >=3.9" not in metadata:
                    _fail(errors, "sdist PKG-INFO is missing Requires-Python >=3.9")
                if "Requires-Dist:" in metadata:
                    _fail(errors, "sdist declares a runtime dependency")


def check_dist(dist: Path) -> List[str]:
    errors: List[str] = []
    if not dist.is_dir():
        return ["distribution directory does not exist: " + str(dist)]
    wheels = sorted(dist.glob("*.whl"))
    sdists = sorted(dist.glob("*.tar.gz"))
    if len(wheels) != 1:
        _fail(errors, "expected exactly one wheel, found " + str(len(wheels)))
    if len(sdists) != 1:
        _fail(errors, "expected exactly one sdist, found " + str(len(sdists)))
    if wheels:
        _check_wheel(wheels[0], errors)
    if sdists:
        _check_sdist(sdists[0], errors)
    return errors


def main(argv: List[str]) -> int:
    dist = Path(argv[1]) if len(argv) > 1 else Path("dist")
    errors = check_dist(dist)
    if errors:
        for error in errors:
            print("check_dist: " + error, file=sys.stderr)
        return 1
    print("distribution contents verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
