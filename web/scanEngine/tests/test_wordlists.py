"""
Unit tests for scanEngine.wordlists (wordlist upload and persistence helpers).
"""

from scanEngine.wordlists import (
    _candidate_short_name,
    _truncate_base_short,
    is_txt_filename,
    short_name_from_stem,
)
from utils.test_base import BaseTestCase


class TestShortNameFromStem(BaseTestCase):
    """Tests for short_name_from_stem."""

    def setUp(self):
        super().setUp()

    def test_sanitizes_to_alphanumeric_underscore_hyphen(self):
        self.assertEqual(short_name_from_stem("my-wordlist"), "my-wordlist")
        self.assertEqual(short_name_from_stem("my_wordlist"), "my_wordlist")
        self.assertEqual(short_name_from_stem("my.wordlist"), "my_wordlist")

    def test_strips_leading_trailing_underscores(self):
        self.assertEqual(short_name_from_stem("__wordlist__"), "wordlist")

    def test_empty_becomes_wordlist(self):
        self.assertEqual(short_name_from_stem("..."), "wordlist")


class TestIsTxtFilename(BaseTestCase):
    """Tests for is_txt_filename."""

    def test_accepts_txt(self):
        self.assertTrue(is_txt_filename("file.txt"))
        self.assertTrue(is_txt_filename("file.TXT"))

    def test_rejects_other_extensions(self):
        self.assertFalse(is_txt_filename("file.yaml"))
        self.assertFalse(is_txt_filename("file"))


class TestTruncateBaseShort(BaseTestCase):
    """Tests for _truncate_base_short (suffix-aware truncation)."""

    def test_no_suffix_returns_base_when_short_enough(self):
        self.assertEqual(_truncate_base_short("short", max_len=45), "short")

    def test_no_suffix_truncates_and_rstrips_underscore(self):
        long_base = "a" * 50
        self.assertEqual(len(_truncate_base_short(long_base, max_len=45)), 45)
        self.assertEqual(_truncate_base_short("x" * 50 + "_", max_len=45), "x" * 45)

    def test_no_suffix_empty_after_truncate_becomes_wordlist(self):
        self.assertEqual(_truncate_base_short("___", max_len=2), "wordlist")

    def test_with_suffix_truncates_base_so_suffix_fits(self):
        base = "a" * 50
        result = _truncate_base_short(base, max_len=50, suffix=123)
        self.assertEqual(len(result), 50)
        self.assertTrue(result.endswith("_123"))

    def test_with_suffix_different_suffixes_produce_different_results(self):
        base = "x" * 48
        r1 = _truncate_base_short(base, max_len=50, suffix=1)
        r2 = _truncate_base_short(base, max_len=50, suffix=2)
        self.assertNotEqual(r1, r2)
        self.assertEqual(r1, "x" * 48 + "_1")
        self.assertEqual(r2, "x" * 48 + "_2")


class TestCandidateShortName(BaseTestCase):
    """Tests for _candidate_short_name (suffix never truncated)."""

    def test_suffix_zero_returns_truncated_base_only(self):
        self.assertEqual(_candidate_short_name("base", 0, max_total=50), "base")
        long_base = "a" * 60
        self.assertEqual(len(_candidate_short_name(long_base, 0, max_total=50)), 50)

    def test_with_suffix_fits_within_max_total(self):
        base = "w" * 55
        result = _candidate_short_name(base, 999, max_total=50)
        self.assertEqual(len(result), 50)
        self.assertTrue(result.endswith("_999"))

    def test_with_suffix_collision_avoidance_distinct_candidates(self):
        base = "z" * 48
        candidates = [_candidate_short_name(base, i, max_total=50) for i in (1, 2, 10, 99)]
        self.assertEqual(len(candidates), len(set(candidates)))
