"""Repository hygiene, packaging metadata, and release-policy tests."""
from __future__ import annotations

import ast
import re
import subprocess
import unittest
from pathlib import Path

from helpers import PyCspCageTestCase, ROOT
from pycspcage import CSPCAGE_VERSION, audit_csp, build_csp, compute_hash, create_strict_csp, generate_nonce, merge_csp, parse_csp

EM_DASH = b"\xe2\x80\x94"
EN_DASH = b"\xe2\x80\x93"
POSIX_HOME_PATTERN = re.compile(rb"/" + rb"Users" + rb"/[A-Za-z0-9._-]+")
WINDOWS_HOME_PATTERN = re.compile(rb"[A-Za-z]:\\\\" + rb"Users" + rb"\\\\[A-Za-z0-9._-]+")
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
VENDOR_KEY_PREFIXES = tuple("".join(parts).encode("ascii") for parts in (("ts", "key-"), ("s", "k-"), ("gh", "p_"), ("github", "_pat_"), ("AK", "IA"), ("xo", "x"), ("gs", "k_"), ("nv", "api-"), ("tv", "ly-"), ("AI", "za")))
MAILBOX_FRAGMENTS = tuple("".join(parts).encode("ascii") for parts in (("g", "mail.com"), ("out", "look.com"), ("hot", "mail.com"), ("ic", "loud.com"), ("pro", "ton.me"), ("ya", "hoo.com")))


def tracked_files():
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=str(ROOT), timeout=5)
    names = [name for name in output.split(b"\x00") if name]
    paths = []
    for name in names:
        relative = name.decode("utf-8").replace("\\", "/")
        if relative.startswith(".git/") or "__pycache__/" in relative or relative.endswith((".pyc", ".pyo")):
            continue
        paths.append(ROOT / relative)
    return paths


class RepositoryHygieneTests(PyCspCageTestCase):
    def test_file_inventory_exists_and_uses_git_index(self):
        files = tracked_files()
        self.assertGreater(len(files), 20)
        self.assertIn(ROOT / "src" / "pycspcage" / "__init__.py", files)
        self.assertIn(ROOT / "tests" / "test_hygiene.py", files)

    def test_no_unicode_dashes_in_repository_files(self):
        offenders = []
        for path in tracked_files():
            data = path.read_bytes()
            if EM_DASH in data or EN_DASH in data:
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_local_user_paths_in_repository_files(self):
        offenders = []
        for path in tracked_files():
            data = path.read_bytes()
            if POSIX_HOME_PATTERN.search(data) or WINDOWS_HOME_PATTERN.search(data):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_email_addresses_in_repository_files(self):
        offenders = []
        for path in tracked_files():
            data = path.read_bytes()
            for match in EMAIL_PATTERN.finditer(data):
                value = match.group(0).lower()
                allowed_example = value.endswith((b"example.invalid", b"example.com", b"example.org", b"example.net"))
                if not value.endswith(b"users.noreply.github.com") and not allowed_example:
                    offenders.append(str(path.relative_to(ROOT)))
                    break
        self.assertEqual(offenders, [])

    def test_no_personal_mailbox_provider_fragments(self):
        offenders = []
        for path in tracked_files():
            data = path.read_bytes().lower()
            if any(fragment in data for fragment in MAILBOX_FRAGMENTS):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_vendor_key_prefixes_in_repository_files(self):
        offenders = []
        for path in tracked_files():
            data = path.read_bytes()
            if any(prefix in data for prefix in VENDOR_KEY_PREFIXES):
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_coauthor_trailer_marker_in_repository_files(self):
        marker = "Co-" + "Authored-" + "By:"
        offenders = []
        for path in tracked_files():
            if marker.encode("ascii") in path.read_bytes():
                offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])

    def test_no_bytecode_or_build_output_in_inventory(self):
        offenders = []
        for path in tracked_files():
            normalized = str(path.relative_to(ROOT)).replace("\\", "/")
            if "__pycache__" in normalized or normalized.endswith((".pyc", ".pyo")) or normalized.startswith(("build/", "dist/")) or ".egg-info/" in normalized:
                offenders.append(normalized)
        self.assertEqual(offenders, [])

    def test_required_files_exist(self):
        required = [
            "pyproject.toml",
            "README.md",
            "LICENSE",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CHANGELOG.md",
            ".gitignore",
            ".gitattributes",
            "MANIFEST.in",
            "src/pycspcage/py.typed",
            "scripts/check_dist.py",
            "examples/basic_strict_policy.py",
            "examples/audit_real_world_policy.py",
            "examples/merge_and_hash_gate.py",
            ".github/workflows/ci.yml",
            ".github/workflows/publish.yml",
        ]
        missing = [name for name in required if not (ROOT / name).is_file()]
        self.assertEqual(missing, [])

    def test_python_files_parse_as_python(self):
        errors = []
        for path in tracked_files():
            if path.suffix != ".py":
                continue
            try:
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            except (SyntaxError, UnicodeDecodeError) as error:
                errors.append(str(path.relative_to(ROOT)) + ": " + str(error))
        self.assertEqual(errors, [])

    def test_git_history_hygiene_when_committed(self):
        probe = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if probe.returncode != 0:
            self.skipTest("initial commit is created after local verification")
        log = subprocess.check_output(["git", "log", "--format=%B%x00"], cwd=str(ROOT))
        self.assertNotIn(b"Co-Authored-By", log)
        self.assertNotIn(EM_DASH, log)
        self.assertNotIn(EN_DASH, log)

    def test_single_clean_commit_identity_when_committed(self):
        probe = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if probe.returncode != 0:
            self.skipTest("initial commit is created after local verification")
        count = subprocess.check_output(["git", "rev-list", "--count", "HEAD"], cwd=str(ROOT), text=True).strip()
        self.assertEqual(count, "1")
        header = subprocess.check_output(["git", "log", "-1", "--format=%an%x00%ae%x00%cn%x00%ce"], cwd=str(ROOT), text=True).strip().split("\x00")
        self.assertEqual(header[0], "draarivpatel-ui")
        self.assertEqual(header[1], "287273626+draarivpatel-ui@users.noreply.github.com")
        self.assertEqual(header[2], "draarivpatel-ui")
        self.assertEqual(header[3], "287273626+draarivpatel-ui@users.noreply.github.com")


class PackagingMetadataTests(PyCspCageTestCase):
    def test_pyproject_metadata(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('name = "pycspcage"', text)
        self.assertIn('version = "1.0.0"', text)
        self.assertIn('requires-python = ">=3.9"', text)
        self.assertIn('build-backend = "setuptools.build_meta"', text)
        self.assertIn('pycspcage = "pycspcage.cli:main"', text)
        self.assertIn('https://github.com/draarivpatel-ui/pycspcage', text)

    def test_pyproject_declares_zero_runtime_dependencies(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn("dependencies = []", text)
        self.assertNotIn("[project.optional-dependencies]", text)

    def test_package_version_constant(self):
        self.assertEqual(CSPCAGE_VERSION, "1.0.0")

    def test_py_typed_is_empty_marker(self):
        self.assertEqual((ROOT / "src" / "pycspcage" / "py.typed").read_bytes(), b"")

    def test_ci_matrix(self):
        text = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        for version in ("3.9", "3.10", "3.11", "3.12", "3.13"):
            self.assertIn('"' + version + '"', text)
        self.assertIn("ubuntu-24.04", text)
        self.assertIn("python3 -m unittest discover -s tests -v", text)
        self.assertIn("scripts/check_dist.py dist", text)

    def test_publish_workflow_hardening(self):
        text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
        self.assertIn("types: [published]", text)
        self.assertIn("id-token: write", text)
        self.assertIn("environment:", text)
        self.assertIn("name: pypi", text)
        self.assertIn("pypa/gh-action-pypi-publish@release/v1", text)
        self.assertNotIn("password:", text)
        self.assertNotIn("PYPI_TOKEN", text)
        self.assertNotIn("workflow_dispatch", text)

    def test_distribution_checker_mentions_expected_package(self):
        text = (ROOT / "scripts" / "check_dist.py").read_text(encoding="utf-8")
        self.assertIn('PACKAGE = "pycspcage"', text)
        self.assertIn("Requires-Dist:", text)
        self.assertIn("py.typed", text)


class PublicApiSmokeTests(PyCspCageTestCase):
    def test_public_functions_importable(self):
        self.assertTrue(callable(parse_csp))
        self.assertTrue(callable(audit_csp))
        self.assertTrue(callable(build_csp))
        self.assertTrue(callable(create_strict_csp))
        self.assertTrue(callable(merge_csp))
        self.assertTrue(callable(generate_nonce))
        self.assertTrue(callable(compute_hash))

    def test_generated_strict_policy_shape(self):
        header = create_strict_csp()
        self.assertTrue(audit_csp(header).strict_csp)
        self.assertEqual(parse_csp(header).errors, ())

    def test_library_has_no_network_modules(self):
        offenders = []
        for path in tracked_files():
            if path.suffix != ".py" or "tests" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [alias.name for alias in node.names]
                    root_name = getattr(node, "module", None)
                    if root_name:
                        names.append(root_name)
                    if any(name.split(".")[0] in ("socket", "requests", "urllib3", "http") for name in names):
                        offenders.append(str(path.relative_to(ROOT)))
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
