"""
Unit tests for command encoding handling.

Tests the robust encoding/decoding functionality for subprocess output.
"""

from reNgine.utilities.command import decode_bytes_robust
from utils.test_base import BaseTestCase


class TestCommandEncoding(BaseTestCase):
    """Test encoding handling in command execution."""

    def test_decode_valid_utf8(self):
        """Test decoding valid UTF-8 bytes."""
        data = "Hello World!".encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Hello World!")

    def test_decode_utf8_with_special_chars(self):
        """Test decoding UTF-8 with special characters."""
        data = "Héllo Wörld! 你好 🌍".encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Héllo Wörld! 你好 🌍")

    def test_decode_empty_bytes(self):
        """Test decoding empty bytes."""
        data = b""
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "")

    def test_decode_latin1_fallback(self):
        """Test fallback to latin-1 when UTF-8 fails."""
        # Latin-1 byte that is invalid UTF-8
        data = b"\xff\xfe"
        result = decode_bytes_robust(data, primary_encoding="utf-8", fallback_encoding="latin-1")
        # Should fall back to latin-1 without error
        self.assertIsInstance(result, str)
        self.assertEqual(len(result), 2)

    def test_decode_mixed_encoding_data(self):
        """Test decoding data with mixed encoding."""
        # Valid UTF-8 followed by invalid byte
        data = b"Valid text \xff invalid"
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        # Should use fallback or replace mode
        self.assertIsInstance(result, str)
        self.assertIn("Valid text", result)

    def test_decode_binary_data(self):
        """Test decoding binary data."""
        # Random binary data
        data = bytes(range(256))
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        # Should not raise exception
        self.assertIsInstance(result, str)

    def test_decode_with_null_bytes(self):
        """Test decoding data with null bytes."""
        data = b"Hello\x00World"
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Hello\x00World")

    def test_decode_newlines(self):
        """Test decoding data with different newline styles."""
        # Unix newlines
        data = b"Line 1\nLine 2\n"
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Line 1\nLine 2\n")

        # Windows newlines
        data = b"Line 1\r\nLine 2\r\n"
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Line 1\r\nLine 2\r\n")

    def test_decode_with_bom(self):
        """Test decoding UTF-8 data with BOM."""
        data = b"\xef\xbb\xbfHello World"
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        # UTF-8 BOM should be preserved or handled
        self.assertIsInstance(result, str)
        self.assertIn("Hello World", result)

    def test_decode_iso_8859_1_fallback(self):
        """Test decoding ISO-8859-1 (latin-1) data."""
        # String with characters valid in ISO-8859-1 but requiring special handling in UTF-8
        text = "Café résumé"
        data = text.encode("iso-8859-1")
        result = decode_bytes_robust(data, primary_encoding="utf-8", fallback_encoding="iso-8859-1")
        self.assertIsInstance(result, str)

    def test_decode_cp1252_data(self):
        """Test decoding Windows-1252 data."""
        # Windows-1252 specific characters
        data = b"\x80\x82\x83\x84"  # Euro sign and others in CP1252
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        # Should handle without exception
        self.assertIsInstance(result, str)

    def test_decode_japanese_utf8(self):
        """Test decoding Japanese UTF-8 text."""
        data = "こんにちは世界".encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "こんにちは世界")

    def test_decode_arabic_utf8(self):
        """Test decoding Arabic UTF-8 text."""
        data = "مرحبا بالعالم".encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "مرحبا بالعالم")

    def test_decode_emoji_utf8(self):
        """Test decoding emoji in UTF-8."""
        data = "Hello 👋 World 🌍 !".encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, "Hello 👋 World 🌍 !")

    def test_decode_long_text(self):
        """Test decoding long text."""
        text = "A" * 10000
        data = text.encode("utf-8")
        result = decode_bytes_robust(data, primary_encoding="utf-8")
        self.assertEqual(result, text)
        self.assertEqual(len(result), 10000)
