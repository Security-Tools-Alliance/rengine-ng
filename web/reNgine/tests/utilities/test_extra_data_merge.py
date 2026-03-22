"""
Tests for shared Secator extra_data merge helpers.
"""

from unittest.mock import patch

from typing import Any, Dict, List, Optional

from reNgine.utilities.extra_data_merge import (
    bounded_diagnostic_preview,
    coerce_extra_data_field_to_plain_dict,
    merge_extra_data_payload_into_model,
    merge_secator_item_extra_data_into_model,
)
from utils.test_base import BaseTestCase


class _ModelStub:
    """Minimal stand-in for a Django model with extra_data and save()."""

    def __init__(self, initial: Optional[Dict[str, Any]] = None) -> None:
        self.extra_data = initial if initial is not None else {}
        self.saved_update_fields: Optional[List[str]] = None

    def save(self, update_fields: Optional[List[str]] = None) -> None:
        self.saved_update_fields = list(update_fields) if update_fields is not None else []


class _NastyDict(dict):
    """Dict subclass whose iteration fails (simulates a broken mapping from bad JSON tooling)."""

    def __iter__(self):
        raise TypeError("nasty")


class ExtraDataMergeHelpersTestCase(BaseTestCase):
    def test_bounded_diagnostic_preview_truncates_and_supports_repr(self) -> None:
        long = "x" * 300
        out = bounded_diagnostic_preview(long, max_len=50)
        self.assertLessEqual(len(out), 50)
        self.assertTrue(out.endswith("...[truncated]"))
        self.assertEqual(bounded_diagnostic_preview(42), "42")
        self.assertEqual(bounded_diagnostic_preview([1], use_repr=True), "[1]")

    def test_coerce_extra_data_none_and_non_dict(self) -> None:
        self.assertEqual(coerce_extra_data_field_to_plain_dict(None), {})
        bad: Any = []
        self.assertEqual(coerce_extra_data_field_to_plain_dict(bad), {})

    def test_coerce_extra_data_broken_dict_subclass_returns_empty(self) -> None:
        self.assertEqual(coerce_extra_data_field_to_plain_dict(_NastyDict({"a": 1})), {})

    @patch("reNgine.utilities.extra_data_merge._logger")
    def test_coerce_logs_bounded_preview_when_copy_fails(self, mock_logger) -> None:
        coerce_extra_data_field_to_plain_dict(_NastyDict({"a": 1}))
        self.assertTrue(
            any(
                len(c.args) >= 3 and "preview=" in c.args[2] and "COERCE" == c.args[1]
                for c in mock_logger.log_line.call_args_list
            ),
        )

    def test_merge_payload_skips_non_dict_and_empty(self) -> None:
        obj = _ModelStub({})
        self.assertFalse(merge_extra_data_payload_into_model(obj, None))
        self.assertFalse(merge_extra_data_payload_into_model(obj, {}))
        bad_payload: Any = "bad"
        self.assertFalse(merge_extra_data_payload_into_model(obj, bad_payload))
        self.assertIsNone(obj.saved_update_fields)

    def test_merge_payload_no_op_when_unchanged(self) -> None:
        obj = _ModelStub({"a": 1})
        self.assertFalse(merge_extra_data_payload_into_model(obj, {"a": 1}))
        self.assertIsNone(obj.saved_update_fields)

    def test_merge_payload_persist_saves_when_changed(self) -> None:
        obj = _ModelStub({"a": 1})
        self.assertTrue(merge_extra_data_payload_into_model(obj, {"b": 2}))
        self.assertEqual(obj.extra_data, {"a": 1, "b": 2})
        self.assertEqual(obj.saved_update_fields, ["extra_data"])

    def test_merge_payload_persist_false_mutates_without_save(self) -> None:
        obj = _ModelStub({"x": 0})
        self.assertTrue(merge_extra_data_payload_into_model(obj, {"y": 1}, persist=False))
        self.assertEqual(obj.extra_data, {"x": 0, "y": 1})
        self.assertIsNone(obj.saved_update_fields)

    def test_merge_payload_replaces_unusable_dict_subclass_with_plain_dict(self) -> None:
        obj = _ModelStub()
        obj.extra_data = _NastyDict({"gone": 1})
        self.assertTrue(merge_extra_data_payload_into_model(obj, {"k": 2}))
        self.assertEqual(obj.extra_data, {"k": 2})

    def test_merge_secator_item_non_dict_extra_data(self) -> None:
        obj = _ModelStub({})
        not_a_dict: Any = []
        self.assertFalse(merge_secator_item_extra_data_into_model(obj, {"extra_data": not_a_dict}))
        self.assertIsNone(obj.saved_update_fields)

    def test_merge_secator_item_merges_dict(self) -> None:
        obj = _ModelStub({"k": 1})
        self.assertTrue(
            merge_secator_item_extra_data_into_model(obj, {"extra_data": {"k": 2, "z": 3}}),
        )
        self.assertEqual(obj.extra_data, {"k": 2, "z": 3})
        self.assertEqual(obj.saved_update_fields, ["extra_data"])
