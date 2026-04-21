"""Tests for build_scan_params_form_context."""

from targetApp.services.scan_params_context import build_scan_params_form_context
from utils.test_base import BaseTestCase


class BuildScanParamsFormContextTest(BaseTestCase):
    """Tests for build_scan_params_form_context."""

    def test_no_entity_returns_effective_defaults(self) -> None:
        """When no organization/scope/target, effective is not None and shows defaults."""
        ctx = build_scan_params_form_context()
        self.assertIsNotNone(ctx["scan_params_effective"])
        self.assertEqual(ctx["scan_params_effective"]["threads"]["source"], "default")
        self.assertEqual(ctx["scan_params_effective"]["threads"]["value"], 30)

    def test_no_entity_includes_section_vars(self) -> None:
        """When no entity, section title and help text are set."""
        ctx = build_scan_params_form_context()
        self.assertIn("scan_params_section_title", ctx)
        self.assertIn("scan_params_section_help_text", ctx)
        self.assertIn("scan_params_section_use_collapse", ctx)
        self.assertIn("scan_params_section_collapse_expanded", ctx)
        self.assertIn("scan_params_section_configure_button_label", ctx)
        self.assertTrue(ctx["scan_params_section_use_collapse"])
        self.assertEqual(ctx["scan_params_section_configure_button_label"], "Configure")

    def test_level_deduced_from_entity(self) -> None:
        """scan_params_level is deduced from the entity passed."""
        ctx_org = build_scan_params_form_context()
        self.assertEqual(ctx_org["scan_params_level"], "organization")

        scope = self.data_generator.create_scope()
        ctx_scope = build_scan_params_form_context(scope=scope)
        self.assertEqual(ctx_scope["scan_params_level"], "scope")

        target = self.data_generator.domain.scan_history.target
        ctx_target = build_scan_params_form_context(target=target)
        self.assertEqual(ctx_target["scan_params_level"], "target")

    def test_level_override_parameter(self) -> None:
        """Explicit level parameter overrides the deduced level."""
        ctx = build_scan_params_form_context(level="target")
        self.assertEqual(ctx["scan_params_level"], "target")

        ctx = build_scan_params_form_context(level="scope")
        self.assertEqual(ctx["scan_params_level"], "scope")

    def test_level_override_scan(self) -> None:
        """level='scan' is used for start-scan and subscan modal overrides."""
        ctx = build_scan_params_form_context(level="scan")
        self.assertEqual(ctx["scan_params_level"], "scan")
        self.assertIn("scan_params_effective", ctx)
        self.assertIn("scan_params_values", ctx)

    def test_header_initial_multiline_format(self) -> None:
        """When scan_params_values has header dict, header_initial is one line per header."""
        ctx = build_scan_params_form_context(
            scan_params_values={"header": {"X-Api-Key": "secret", "Cookie": "session=abc"}}
        )
        self.assertIn("header_initial", ctx)
        self.assertIn('"X-Api-Key": "secret"', ctx["header_initial"])
        self.assertIn('"Cookie": "session=abc"', ctx["header_initial"])
        self.assertEqual(ctx["header_initial"].count("\n"), 1)
