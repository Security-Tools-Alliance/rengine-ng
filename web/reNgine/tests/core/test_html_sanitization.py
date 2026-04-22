"""Regression tests for HTML sanitization helpers."""

from reNgine.core.html_sanitization import sanitize_html_for_display
from utils.test_base import BaseTestCase


class HtmlSanitizationTestCase(BaseTestCase):
    """Ensure sanitization stays robust for malformed parser nodes."""

    use_minimal_setup = True

    def test_sanitize_handles_template_object_without_crashing(self) -> None:
        html_content = (
            "<p>The html package before 2018-07-13 mishandles parser mode.</p>"
            "<template><object>embedded</object></template>"
        )

        sanitized = sanitize_html_for_display(html_content)

        self.assertIsInstance(sanitized, str)
        self.assertNotIn("<object", sanitized.lower())
