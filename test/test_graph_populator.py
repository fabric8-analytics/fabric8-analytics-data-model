"""Tests for the graph_populator module."""

from graph_populator import GraphPopulator
import pytest


def test_sanitize_text_for_query():
    """Test GraphPopulator._sanitize_text_for_query()."""
    f = GraphPopulator._sanitize_text_for_query
    assert 'pkg' == f('pkg')
    assert 'desc' == f('desc\n')
    assert 'desc' == f(' desc')
    assert 'desc' == f(' desc\n')
    assert 'ASL 2.0' == f('ASL\n"2.0"')
    assert '[ok]' == f('["ok\']')
    assert 'ok' == f("'ok'")
    assert '' == f(None)
    assert '' == f('')
    assert '' == f(' ')
    assert '' == f('\n')
    assert '' == f('\n ')
    assert '' == f(' \n ')
    assert '' == f('\n\n')
    assert '' == f('\t')
    with pytest.raises(ValueError):
        f(100)
    with pytest.raises(ValueError):
        f(None)
    with pytest.raises(ValueError):
        f(True)
    with pytest.raises(ValueError):
        f(False)


if __name__ == '__main__':
    test_sanitize_text_for_query()
