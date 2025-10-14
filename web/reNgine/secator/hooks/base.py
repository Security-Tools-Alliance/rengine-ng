"""
Base hooks for Secator runner lifecycle.
Implements static hooks that can be attached to Secator runners.
"""

from celery.utils.log import get_task_logger


logger = get_task_logger(__name__)


class SecatorHooks:
    """Base class for Secator lifecycle hooks."""

    def before_init(self):
        """Executed before runner init."""
        pass

    def on_init(self):
        """Executed when runner init completed."""
        pass

    def on_start(self):
        """Executed when runner starts."""
        pass

    def on_iter(self):
        """Executed on each iteration."""
        pass

    def on_end(self):
        """Executed when runner finishes."""
        pass

    def on_item_pre_convert(self, item):
        """
        Executed before item conversion.

        Args:
            item: Item to convert

        Returns:
            item: Modified or original item
        """
        return item

    def on_item(self, item):
        """
        Executed when item is emitted.

        Args:
            item: Emitted item

        Returns:
            item: Modified or original item
        """
        return item

    def on_duplicate(self, item):
        """
        Executed when duplicate detected.

        Args:
            item: Duplicate item

        Returns:
            item: Modified or original item
        """
        return item

    def on_error(self, item):
        """
        Executed on error.

        Args:
            item: Error item

        Returns:
            item: Modified or original item
        """
        return item
