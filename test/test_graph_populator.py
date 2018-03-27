"""Tests for the graph_populator module."""

from graph_populator import GraphPopulator
import pytest


def test_sanitize_text_for_query():
    """Test GraphPopulator._sanitize_text_for_query()."""
    f = GraphPopulator._sanitize_text_for_query
    assert 'pkg' == f('pkg')
    assert 'desc' == f('desc\n')
    assert 'desc' == f(' desc')
    assert 'desc' == f(' desc ')
    assert 'foo bar' == f(' foo bar ')
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
        f(True)
    with pytest.raises(ValueError):
        f(False)


def test_sanitize_text_for_query_for_unicode_input():
    """Test GraphPopulator._sanitize_text_for_query() for Unicode input string."""
    f = GraphPopulator._sanitize_text_for_query
    assert 'pkg' == f(u'pkg')
    assert 'desc' == f(u'desc\n')
    assert 'desc' == f(u' desc')
    assert 'desc' == f(u' desc\n')
    assert 'desc' == f(u' desc ')
    assert 'foo bar' == f(u' foo bar ')
    assert 'ASL 2.0' == f(u'ASL\n"2.0"')
    assert '[ok]' == f(u'["ok\']')
    assert 'ok' == f(u"'ok'")
    assert '' == f(u'')
    assert '' == f(u' ')
    assert '' == f(u'\n')
    assert '' == f(u'\n ')
    assert '' == f(u' \n ')
    assert '' == f(u'\n\n')
    assert '' == f(u'\t')


if __name__ == '__main__':
    test_sanitize_text_for_query()
    test_sanitize_text_for_query_for_unicode_input
