"""Unit tests for the __init__ module (ColorFormatter and logger)."""

import logging

from traefiktounifi import ColorFormatter


class TestColorFormatter:
    """Test ColorFormatter class."""

    def test_format_debug(self):
        """Test that DEBUG messages are formatted with gray color."""
        formatter = ColorFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.DEBUG,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert "\033[90m" in formatted  # GRAY
        assert "\033[0m" in formatted  # RESET

    def test_format_info(self):
        """Test that INFO messages are formatted without color."""
        formatter = ColorFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert formatted == "test message\033[0m"  # Only RESET at the end

    def test_format_warning(self):
        """Test that WARNING messages are formatted with yellow color."""
        formatter = ColorFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert "\033[33m" in formatted  # YELLOW
        assert "\033[0m" in formatted  # RESET

    def test_format_error(self):
        """Test that ERROR messages are formatted with red color."""
        formatter = ColorFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert "\033[31m" in formatted  # RED
        assert "\033[0m" in formatted  # RESET

    def test_format_critical(self):
        """Test that CRITICAL messages are formatted with red color."""
        formatter = ColorFormatter("%(message)s")
        record = logging.LogRecord(
            name="test",
            level=logging.CRITICAL,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        formatted = formatter.format(record)
        assert "\033[31m" in formatted  # RED
        assert "\033[0m" in formatted  # RESET
