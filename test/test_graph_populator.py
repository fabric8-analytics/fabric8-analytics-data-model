"""Tests for the graph_populator module."""

from graph_populator import GraphPopulator
import pytest


def test_sanitize_text_for_query():
    """Test GraphPopulator._sanitize_text_for_query()."""
    f = GraphPopulator._sanitize_text_for_query
    assert 'pkg', f('pkg')
    assert 'desc', f(' desc\n')
    assert 'ASL\n"2.0"', f('ASL 2.0')
    assert 'ok', f('[ok]')
    assert 'ok', f("'ok'")
    with pytest.raises(ValueError):
        f(100)
