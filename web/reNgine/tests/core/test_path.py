"""
Unit tests for reNgine.core.path helpers: safe_unlink, safe_rmtree, resolve_results_dir_under_base.
Exercises edge cases: symlinks, paths outside base_dir, non-existent paths.
"""

import os
import shutil
import tempfile
import unittest

from reNgine.core.path import (
    normalize_relative_path,
    resolve_results_dir_under_base,
    safe_rmtree,
    safe_unlink,
)


class TestSafeUnlink(unittest.TestCase):
    """Tests for safe_unlink."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_removes_file_under_base(self):
        path = os.path.join(self.base, "file.txt")
        with open(path, "w") as f:
            f.write("x")
        result = safe_unlink(self.base, path)
        self.assertEqual(result, "removed")
        self.assertFalse(os.path.exists(path))

    def test_refuses_path_outside_base(self):
        path = os.path.join(self.outside, "file.txt")
        with open(path, "w") as f:
            f.write("x")
        result = safe_unlink(self.base, path)
        self.assertEqual(result, "refused")
        self.assertTrue(os.path.exists(path))

    def test_refuses_symlink_to_file_outside_base(self):
        real_file = os.path.join(self.outside, "real.txt")
        with open(real_file, "w") as f:
            f.write("x")
        link_under_base = os.path.join(self.base, "link.txt")
        os.symlink(real_file, link_under_base)
        result = safe_unlink(self.base, link_under_base)
        self.assertEqual(result, "refused")
        self.assertTrue(os.path.exists(real_file))

    def test_not_found_for_non_existent_path(self):
        path = os.path.join(self.base, "nonexistent.txt")
        result = safe_unlink(self.base, path)
        self.assertEqual(result, "not_found")

    def test_not_found_for_directory(self):
        dir_path = os.path.join(self.base, "subdir")
        os.makedirs(dir_path, exist_ok=True)
        result = safe_unlink(self.base, dir_path)
        self.assertEqual(result, "not_found")
        self.assertTrue(os.path.isdir(dir_path))


class TestSafeRmtree(unittest.TestCase):
    """Tests for safe_rmtree."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_removes_dir_under_base(self):
        path = os.path.join(self.base, "subdir")
        os.makedirs(path, exist_ok=True)
        with open(os.path.join(path, "f.txt"), "w") as f:
            f.write("x")
        result = safe_rmtree(self.base, path)
        self.assertEqual(result, "removed")
        self.assertFalse(os.path.exists(path))

    def test_refuses_path_outside_base(self):
        path = os.path.join(self.outside, "subdir")
        os.makedirs(path, exist_ok=True)
        result = safe_rmtree(self.base, path)
        self.assertEqual(result, "refused")
        self.assertTrue(os.path.exists(path))

    def test_refuses_symlink_to_dir_outside_base(self):
        real_dir = os.path.join(self.outside, "real_dir")
        os.makedirs(real_dir, exist_ok=True)
        link_under_base = os.path.join(self.base, "link_dir")
        os.symlink(real_dir, link_under_base)
        result = safe_rmtree(self.base, link_under_base)
        self.assertEqual(result, "refused")
        self.assertTrue(os.path.exists(real_dir))

    def test_not_found_for_non_existent_path(self):
        path = os.path.join(self.base, "nonexistent_dir")
        result = safe_rmtree(self.base, path)
        self.assertEqual(result, "not_found")

    def test_not_found_for_file_instead_of_dir(self):
        file_path = os.path.join(self.base, "file.txt")
        with open(file_path, "w") as f:
            f.write("x")
        result = safe_rmtree(self.base, file_path)
        self.assertEqual(result, "not_found")
        self.assertTrue(os.path.isfile(file_path))


class TestResolveResultsDirUnderBase(unittest.TestCase):
    """Tests for resolve_results_dir_under_base."""

    def setUp(self):
        self.base = tempfile.mkdtemp()
        self.outside = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)
        shutil.rmtree(self.outside, ignore_errors=True)

    def test_returns_path_for_valid_relative_dir_under_base(self):
        sub = os.path.join(self.base, "scan_1", "results")
        os.makedirs(sub, exist_ok=True)
        resolved = resolve_results_dir_under_base(self.base, "scan_1/results")
        self.assertIsNotNone(resolved)
        self.assertEqual(os.path.realpath(str(resolved)), os.path.realpath(sub))

    def test_returns_path_for_absolute_path_under_base(self):
        sub = os.path.join(self.base, "scan_1")
        os.makedirs(sub, exist_ok=True)
        resolved = resolve_results_dir_under_base(self.base, sub)
        self.assertIsNotNone(resolved)
        self.assertEqual(os.path.realpath(str(resolved)), os.path.realpath(sub))

    def test_returns_none_for_path_outside_base(self):
        resolved = resolve_results_dir_under_base(self.base, self.outside)
        self.assertIsNone(resolved)

    def test_returns_none_for_non_existent_path(self):
        resolved = resolve_results_dir_under_base(self.base, "nonexistent/foo")
        self.assertIsNone(resolved)

    def test_returns_none_for_empty_string(self):
        self.assertIsNone(resolve_results_dir_under_base(self.base, ""))
        self.assertIsNone(resolve_results_dir_under_base(self.base, "   "))

    def test_returns_none_for_file_instead_of_dir(self):
        file_path = os.path.join(self.base, "file.txt")
        with open(file_path, "w") as f:
            f.write("x")
        resolved = resolve_results_dir_under_base(self.base, "file.txt")
        self.assertIsNone(resolved)

    def test_returns_none_for_symlink_to_dir_outside_base(self):
        real_dir = os.path.join(self.outside, "real_dir")
        os.makedirs(real_dir, exist_ok=True)
        link_under_base = os.path.join(self.base, "link_dir")
        os.symlink(real_dir, link_under_base)
        resolved = resolve_results_dir_under_base(self.base, "link_dir")
        self.assertIsNone(resolved)

    def test_returns_none_for_relative_path_containing_dotdot(self):
        """Paths with '..' are rejected by _normalize_results_dir_components (no rewriting)."""
        self.assertIsNone(resolve_results_dir_under_base(self.base, "scan_1/../results"))
        self.assertIsNone(resolve_results_dir_under_base(self.base, "foo/../bar"))


class TestNormalizeRelativePath(unittest.TestCase):
    """Tests for normalize_relative_path: any path containing '..' segment is rejected; substring '..' in names is allowed."""

    def test_rejects_absolute_path(self):
        self.assertIsNone(normalize_relative_path("/foo/bar"))
        self.assertIsNone(normalize_relative_path("/"))

    def test_rejects_null_byte(self):
        self.assertIsNone(normalize_relative_path("foo\x00bar"))

    def test_rejects_empty_or_whitespace(self):
        self.assertIsNone(normalize_relative_path(""))
        self.assertIsNone(normalize_relative_path("   "))

    def test_rejects_single_dotdot_segment(self):
        self.assertIsNone(normalize_relative_path(".."))

    def test_rejects_any_path_containing_dotdot_segment(self):
        """Any path that contains a '..' segment is invalid and returns None (no rewriting)."""
        self.assertIsNone(normalize_relative_path("../foo"))
        self.assertIsNone(normalize_relative_path("foo/.."))
        self.assertIsNone(normalize_relative_path("a/../b"))
        self.assertIsNone(normalize_relative_path("reports/../public"))

    def test_allows_filename_containing_dotdot_substring(self):
        """Segment '..' is rejected; filename like 'file..name' is allowed (no segment equals '..')."""
        result = normalize_relative_path("file..name")
        self.assertIsNotNone(result)
        self.assertIn("file", result)
        self.assertIn("name", result)
