"""
Tests for core file operations.
"""

import os
import tempfile
import unittest

from reNgine.core.file import (
    _is_safe_path,
    _is_safe_pattern,
    _validate_path_security,
    ensure_directory_exists,
    is_nuclei_config_valid,
    read_file_lines,
    remove_file_or_pattern,
    write_file_lines,
)


class TestFileOperations(unittest.TestCase):
    """Test file operation functions."""

    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.test_dir, "test.txt")
        self.test_subdir = os.path.join(self.test_dir, "subdir")
        os.makedirs(self.test_subdir, exist_ok=True)

    def tearDown(self):
        """Clean up test environment."""
        import shutil

        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_remove_file_or_pattern_single_file(self):
        """Test removing a single file."""
        with open(self.test_file, "w") as f:
            f.write("test content")

        self.assertTrue(os.path.exists(self.test_file))
        result = remove_file_or_pattern(self.test_file)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_file))

    def test_remove_file_or_pattern_directory(self):
        """Test removing a directory."""
        self.assertTrue(os.path.exists(self.test_subdir))
        result = remove_file_or_pattern(self.test_subdir)
        self.assertTrue(result)
        self.assertFalse(os.path.exists(self.test_subdir))

    def test_remove_file_or_pattern_with_pattern(self):
        """Test removing files with pattern matching."""
        test_files = [
            os.path.join(self.test_subdir, "file1.txt"),
            os.path.join(self.test_subdir, "file2.txt"),
            os.path.join(self.test_subdir, "file3.log"),
        ]
        for file_path in test_files:
            with open(file_path, "w") as f:
                f.write("test content")

        result = remove_file_or_pattern(self.test_subdir, "*.txt")
        self.assertTrue(result)

        self.assertFalse(os.path.exists(test_files[0]))
        self.assertFalse(os.path.exists(test_files[1]))
        self.assertTrue(os.path.exists(test_files[2]))

    def test_remove_file_or_pattern_nonexistent_path(self):
        """Test removing non-existent path."""
        nonexistent_path = os.path.join(self.test_dir, "nonexistent.txt")
        result = remove_file_or_pattern(nonexistent_path)
        self.assertTrue(result)

    def test_remove_file_or_pattern_symlink_security(self):
        """Test that symlinks are rejected for security."""
        outside_file = os.path.join(tempfile.gettempdir(), "outside_target.txt")
        with open(outside_file, "w") as f:
            f.write("sensitive data")

        try:
            symlink_path = os.path.join(self.test_dir, "malicious_link")
            os.symlink(outside_file, symlink_path)

            result = remove_file_or_pattern(symlink_path)
            self.assertFalse(result)

            self.assertTrue(os.path.exists(outside_file))

        finally:
            if os.path.exists(outside_file):
                os.remove(outside_file)

    def test_remove_file_or_pattern_directory_traversal(self):
        """Test that directory traversal paths are rejected."""
        traversal_path = os.path.join(self.test_dir, "..", "sensitive_file.txt")
        result = remove_file_or_pattern(traversal_path)
        self.assertFalse(result)

    def test_remove_file_or_pattern_pattern_outside_directory(self):
        """Test that pattern matching doesn't escape directory boundaries."""
        parent_file = os.path.join(os.path.dirname(self.test_dir), "parent_file.txt")
        with open(parent_file, "w") as f:
            f.write("parent content")

        try:
            result = remove_file_or_pattern(self.test_dir, "../parent_file.txt")
            self.assertFalse(result)

            self.assertTrue(os.path.exists(parent_file))

        finally:
            if os.path.exists(parent_file):
                os.remove(parent_file)

    def test_is_safe_path(self):
        """Test _is_safe_path function."""
        base_path = "/safe/base"

        self.assertTrue(_is_safe_path(base_path, "/safe/base/file.txt"))
        self.assertTrue(_is_safe_path(base_path, "/safe/base/subdir/file.txt"))
        self.assertTrue(_is_safe_path(base_path, base_path))

        self.assertFalse(_is_safe_path(base_path, "/safe/base/../file.txt"))
        self.assertFalse(_is_safe_path(base_path, "/unsafe/file.txt"))
        self.assertFalse(_is_safe_path(base_path, "/safe/file.txt"))

    def test_is_safe_path_with_symlinks(self):
        """Test _is_safe_path function with symlinks."""
        symlink_target = os.path.join(tempfile.gettempdir(), "symlink_target")
        with open(symlink_target, "w") as f:
            f.write("target content")

        try:
            symlink_path = os.path.join(self.test_dir, "test_symlink")
            os.symlink(symlink_target, symlink_path)

            result = _is_safe_path(self.test_dir, symlink_path)
            self.assertIsInstance(result, bool)

        finally:
            if os.path.exists(symlink_target):
                os.remove(symlink_target)

    def test_validate_path_security(self):
        """Test _validate_path_security function."""
        is_safe, error = _validate_path_security("/nonexistent/path")
        self.assertTrue(is_safe)
        self.assertIsNone(error)

        with open(self.test_file, "w") as f:
            f.write("test")
        is_safe, error = _validate_path_security(self.test_file)
        self.assertTrue(is_safe)
        self.assertIsNone(error)

        symlink_path = os.path.join(self.test_dir, "test_link")
        os.symlink(self.test_file, symlink_path)
        is_safe, error = _validate_path_security(symlink_path)
        self.assertFalse(is_safe)
        self.assertIn("Symlink detected", error)

        traversal_path = os.path.join(self.test_dir, "..", "file.txt")
        is_safe, error = _validate_path_security(traversal_path)
        self.assertFalse(is_safe)
        self.assertIn("Directory traversal detected", error)

    def test_is_safe_pattern(self):
        """Test _is_safe_pattern function."""
        # Safe patterns
        self.assertTrue(_is_safe_pattern("*.txt"))
        self.assertTrue(_is_safe_pattern("*.csv"))
        self.assertTrue(_is_safe_pattern("file_*.log"))
        self.assertTrue(_is_safe_pattern("test?.txt"))
        self.assertTrue(_is_safe_pattern("data_*.json"))

        # Unsafe patterns - directory traversal
        self.assertFalse(_is_safe_pattern("../file.txt"))
        self.assertFalse(_is_safe_pattern(".."))
        self.assertFalse(_is_safe_pattern("file/../other.txt"))

        # Unsafe patterns - recursive matching
        self.assertFalse(_is_safe_pattern("**"))
        self.assertFalse(_is_safe_pattern("**/*.txt"))

        # Unsafe patterns - home directory
        self.assertFalse(_is_safe_pattern("~/file.txt"))
        self.assertFalse(_is_safe_pattern("~"))

        # Unsafe patterns - absolute paths (Linux/Debian specific)
        self.assertFalse(_is_safe_pattern("/file.txt"))

        # Unsafe patterns - hidden files
        self.assertFalse(_is_safe_pattern(".hidden"))
        self.assertFalse(_is_safe_pattern(".*"))

        # Unsafe patterns - too broad
        self.assertFalse(_is_safe_pattern("*"))
        self.assertFalse(_is_safe_pattern("?"))
        self.assertFalse(_is_safe_pattern(""))

        # Unsafe patterns - system files (Linux/Debian specific)
        self.assertFalse(_is_safe_pattern("*.so"))
        self.assertFalse(_is_safe_pattern("*.ini"))
        self.assertFalse(_is_safe_pattern("*.cfg"))
        self.assertFalse(_is_safe_pattern("*.conf"))
        self.assertFalse(_is_safe_pattern("*.log"))

        # Invalid inputs
        self.assertFalse(_is_safe_pattern(None))
        self.assertFalse(_is_safe_pattern(123))
        self.assertFalse(_is_safe_pattern([]))

    def test_remove_file_or_pattern_unsafe_pattern(self):
        """Test remove_file_or_pattern with unsafe patterns."""
        # Test with directory traversal pattern
        result = remove_file_or_pattern(self.test_subdir, "../*.txt")
        self.assertFalse(result)

        # Test with recursive pattern
        result = remove_file_or_pattern(self.test_subdir, "**/*.txt")
        self.assertFalse(result)

        # Test with hidden files pattern
        result = remove_file_or_pattern(self.test_subdir, ".*")
        self.assertFalse(result)

        # Test with system files pattern (Linux/Debian specific)
        result = remove_file_or_pattern(self.test_subdir, "*.so")
        self.assertFalse(result)

    def test_ensure_directory_exists(self):
        """Test ensure_directory_exists function."""
        new_dir = os.path.join(self.test_dir, "new_directory")

        self.assertFalse(os.path.exists(new_dir))

        result = ensure_directory_exists(new_dir)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(new_dir))
        self.assertTrue(os.path.isdir(new_dir))

    def test_ensure_directory_exists_already_exists(self):
        """Test ensure_directory_exists with existing directory."""
        self.assertTrue(os.path.exists(self.test_subdir))

        result = ensure_directory_exists(self.test_subdir)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(self.test_subdir))

    def test_ensure_directory_exists_security_validation(self):
        """Test ensure_directory_exists security validation."""
        # Test directory traversal attempt
        traversal_path = os.path.join(self.test_dir, "..", "sensitive_dir")
        result = ensure_directory_exists(traversal_path)
        self.assertFalse(result)

        # Test symlink attempt (if supported)
        try:
            symlink_path = os.path.join(self.test_dir, "malicious_link")
            os.symlink("/etc", symlink_path)
            result = ensure_directory_exists(symlink_path)
            self.assertFalse(result)
        except (OSError, AttributeError):
            # Symlinks not supported on this platform
            pass

        # Test path exists but is a file
        file_path = os.path.join(self.test_dir, "existing_file.txt")
        with open(file_path, "w") as f:
            f.write("test content")

        result = ensure_directory_exists(file_path)
        self.assertFalse(result)

    def test_ensure_directory_exists_nested_creation(self):
        """Test ensure_directory_exists creates nested directories safely."""
        # Test creating nested directories
        nested_path = os.path.join(self.test_dir, "level1", "level2", "level3")
        result = ensure_directory_exists(nested_path)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(nested_path))
        self.assertTrue(os.path.isdir(nested_path))

        # Verify all parent directories were created
        level1_dir = os.path.join(self.test_dir, "level1")
        level2_dir = os.path.join(level1_dir, "level2")

        self.assertTrue(os.path.exists(level1_dir))
        self.assertTrue(os.path.exists(level2_dir))

    def test_ensure_directory_exists_custom_permissions(self):
        """Test ensure_directory_exists with custom permissions."""
        custom_dir = os.path.join(self.test_dir, "custom_permissions")
        result = ensure_directory_exists(custom_dir, mode=0o700)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(custom_dir))

        # Verify permissions (may not work on all systems)
        try:
            stat_info = os.stat(custom_dir)
            # Check that permissions are at least as restrictive as requested
            actual_mode = stat_info.st_mode & 0o777
            self.assertLessEqual(actual_mode, 0o700)
        except (OSError, AttributeError):
            # Permission checking not supported on this platform
            pass

    def test_read_file_lines(self):
        """Test read_file_lines function."""
        test_content = [
            "line1",
            "",
            "# comment line",
            "line2",
            "  # indented comment",
            "line3",
        ]
        with open(self.test_file, "w") as f:
            for line in test_content:
                f.write(line + "\n")

        lines = read_file_lines(self.test_file, skip_empty=False, skip_comments=False)
        self.assertEqual(len(lines), 6)

        lines = read_file_lines(self.test_file, skip_empty=True, skip_comments=True)
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines, ["line1", "line2", "line3"])

    def test_read_file_lines_nonexistent_file(self):
        """Test read_file_lines with non-existent file."""
        nonexistent_file = os.path.join(self.test_dir, "nonexistent.txt")
        lines = read_file_lines(nonexistent_file)
        self.assertEqual(lines, [])

    def test_read_file_lines_security_validation(self):
        """Test read_file_lines security validation."""
        # Test directory traversal attempt
        traversal_path = os.path.join(self.test_dir, "..", "sensitive_file.txt")
        result = read_file_lines(traversal_path)
        self.assertEqual(result, [])

        # Test symlink attempt (if supported)
        try:
            symlink_path = os.path.join(self.test_dir, "malicious_link")
            os.symlink("/etc/passwd", symlink_path)
            result = read_file_lines(symlink_path)
            self.assertEqual(result, [])
        except (OSError, AttributeError):
            # Symlinks not supported on this platform
            pass

        # Test reading from directory (should fail)
        result = read_file_lines(self.test_dir)
        self.assertEqual(result, [])

    def test_read_file_lines_file_type_validation(self):
        """Test read_file_lines validates file type correctly."""
        # Create a test file
        test_file = os.path.join(self.test_dir, "test_file.txt")
        with open(test_file, "w") as f:
            f.write("test content\n")

        # Test reading from regular file (should work)
        result = read_file_lines(test_file)
        self.assertEqual(result, ["test content"])

        # Test reading from directory (should fail)
        result = read_file_lines(self.test_dir)
        self.assertEqual(result, [])

    def test_read_file_lines_encoding_handling(self):
        """Test read_file_lines handles encoding properly."""
        # Test with Unicode content
        unicode_file = os.path.join(self.test_dir, "unicode_file.txt")
        with open(unicode_file, "w", encoding="utf-8") as f:
            f.write("Hello 世界\nCafé\nnaïve\n")

        result = read_file_lines(unicode_file)
        expected = ["Hello 世界", "Café", "naïve"]
        self.assertEqual(result, expected)

    def test_write_file_lines(self):
        """Test write_file_lines function."""
        test_lines = ["line1", "line2", "line3"]

        result = write_file_lines(self.test_file, test_lines)
        self.assertTrue(result)

        with open(self.test_file, "r") as f:
            content = f.read()
        expected_content = "line1\nline2\nline3\n"
        self.assertEqual(content, expected_content)

    def test_write_file_lines_append_mode(self):
        """Test write_file_lines in append mode."""
        initial_lines = ["line1", "line2"]
        write_file_lines(self.test_file, initial_lines, mode="w")

        additional_lines = ["line3", "line4"]
        result = write_file_lines(self.test_file, additional_lines, mode="a")
        self.assertTrue(result)

        with open(self.test_file, "r") as f:
            content = f.read()
        expected_content = "line1\nline2\nline3\nline4\n"
        self.assertEqual(content, expected_content)

    def test_write_file_lines_security_validation(self):
        """Test write_file_lines security validation."""
        # Test directory traversal attempt
        traversal_path = os.path.join(self.test_dir, "..", "sensitive_file.txt")
        result = write_file_lines(traversal_path, ["malicious content"])
        self.assertFalse(result)

        # Test symlink attempt (if supported)
        try:
            symlink_path = os.path.join(self.test_dir, "malicious_link")
            os.symlink("/etc/passwd", symlink_path)
            result = write_file_lines(symlink_path, ["malicious content"])
            self.assertFalse(result)
        except (OSError, AttributeError):
            # Symlinks not supported on this platform
            pass

        # Test writing to subdirectory (should work and create directory)
        subdir_path = os.path.join(self.test_dir, "subdir", "nested_file.txt")
        result = write_file_lines(subdir_path, ["nested content"])
        self.assertTrue(result)
        self.assertTrue(os.path.exists(subdir_path))

        # Test empty lines list
        empty_file = os.path.join(self.test_dir, "empty_file.txt")
        result = write_file_lines(empty_file, [])
        self.assertTrue(result)
        self.assertTrue(os.path.exists(empty_file))

    def test_write_file_lines_parent_directory_creation(self):
        """Test write_file_lines creates parent directories safely."""
        # Test creating nested directories
        nested_path = os.path.join(self.test_dir, "level1", "level2", "level3", "deep_file.txt")
        result = write_file_lines(nested_path, ["deep content"])
        self.assertTrue(result)
        self.assertTrue(os.path.exists(nested_path))

        # Verify directory permissions are safe
        level1_dir = os.path.join(self.test_dir, "level1")
        level2_dir = os.path.join(level1_dir, "level2")
        level3_dir = os.path.join(level2_dir, "level3")

        self.assertTrue(os.path.exists(level1_dir))
        self.assertTrue(os.path.exists(level2_dir))
        self.assertTrue(os.path.exists(level3_dir))

    def test_write_file_lines_encoding_handling(self):
        """Test write_file_lines handles encoding properly."""
        # Test with Unicode content
        unicode_file = os.path.join(self.test_dir, "unicode_file.txt")
        unicode_lines = ["Hello 世界", "Café", "naïve", "résumé"]

        result = write_file_lines(unicode_file, unicode_lines)
        self.assertTrue(result)

        # Verify content was written correctly
        with open(unicode_file, "r", encoding="utf-8") as f:
            content = f.read()
        expected_content = "Hello 世界\nCafé\nnaïve\nrésumé\n"
        self.assertEqual(content, expected_content)

    def test_is_nuclei_config_valid(self):
        """Test is_nuclei_config_valid function."""
        result = is_nuclei_config_valid("/nonexistent/config.yaml")
        self.assertFalse(result)

        empty_config = os.path.join(self.test_dir, "empty.yaml")
        with open(empty_config, "w") as f:
            pass
        result = is_nuclei_config_valid(empty_config)
        self.assertFalse(result)

        comment_config = os.path.join(self.test_dir, "comment.yaml")
        with open(comment_config, "w") as f:
            f.write("# This is a comment\n# Another comment\n")
        result = is_nuclei_config_valid(comment_config)
        self.assertFalse(result)

        # Test with valid Nuclei config using key=value format
        valid_config = os.path.join(self.test_dir, "valid.yaml")
        with open(valid_config, "w") as f:
            f.write("# This is a comment\nseverity=critical\ntags=sql-injection\n")
        result = is_nuclei_config_valid(valid_config)
        self.assertTrue(result)

        # Test with valid Nuclei config using YAML format
        yaml_config = os.path.join(self.test_dir, "yaml.yaml")
        with open(yaml_config, "w") as f:
            f.write("# This is a comment\ninfo:\n  name: test-template\n  severity: high\n")
        result = is_nuclei_config_valid(yaml_config)
        self.assertTrue(result)

        # Test with invalid config containing only random text
        invalid_config = os.path.join(self.test_dir, "invalid.yaml")
        with open(invalid_config, "w") as f:
            f.write("# This is a comment\nThis is just random text\nNot a valid configuration\n")
        result = is_nuclei_config_valid(invalid_config)
        self.assertFalse(result)

        # Test with config containing only whitespace
        whitespace_config = os.path.join(self.test_dir, "whitespace.yaml")
        with open(whitespace_config, "w") as f:
            f.write("   \n\t\t\n  \t  \n")
        result = is_nuclei_config_valid(whitespace_config)
        self.assertFalse(result)

    def test_is_nuclei_config_valid_mixed_content(self):
        """Test is_nuclei_config_valid with mixed content."""
        mixed_config = os.path.join(self.test_dir, "mixed.yaml")
        with open(mixed_config, "w") as f:
            f.write("# Comment line\n\nseverity=critical\ninfo:\n  name: test-template\n# Another comment\n")
        result = is_nuclei_config_valid(mixed_config)
        self.assertTrue(result)

    def test_remove_file_or_pattern_invalid_pattern_directory(self):
        """Test remove_file_or_pattern with pattern on non-directory."""
        with open(self.test_file, "w") as f:
            f.write("test content")

        result = remove_file_or_pattern(self.test_file, "*.txt")
        self.assertFalse(result)

        self.assertTrue(os.path.exists(self.test_file))

    def test_remove_file_or_pattern_no_matching_files(self):
        """Test remove_file_or_pattern with pattern that matches no files."""
        result = remove_file_or_pattern(self.test_subdir, "*.nonexistent")
        self.assertTrue(result)

    def test_remove_file_or_pattern_partial_failure(self):
        """Test remove_file_or_pattern with partial failure."""
        file1 = os.path.join(self.test_subdir, "file1.txt")
        file2 = os.path.join(self.test_subdir, "file2.txt")

        with open(file1, "w") as f:
            f.write("content1")
        with open(file2, "w") as f:
            f.write("content2")

        os.chmod(file1, 0o444)

        try:
            remove_file_or_pattern(self.test_subdir, "*.txt")
            file2_exists = os.path.exists(file2)

            self.assertFalse(file2_exists, "file2 should have been removed")

        finally:
            try:
                if os.path.exists(file1):
                    os.chmod(file1, 0o644)
                    os.remove(file1)
            except OSError:
                pass
            try:
                if os.path.exists(file2):
                    os.remove(file2)
            except OSError:
                pass
