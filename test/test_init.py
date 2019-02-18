"""Tests for the __init__ script."""

from src import logger


def test_logger():
    """Test the logger initialized in __init__."""
    assert logger is not None


if __name__ == '__main__':
    test_logger()
