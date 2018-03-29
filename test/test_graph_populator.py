"""Tests for the graph_populator module."""

from graph_populator import GraphPopulator
import pytest
import json
import logging
import config


logger = logging.getLogger(config.APP_NAME)


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


def test_correct_license_splitting():
    """Test the GraphPopulator.correct_license_splitting() class method."""
    g = GraphPopulator
    f = g.correct_license_splitting
    l1 = ["""
    Apache License, Version 2.0 and
    Common Development And Distribution License (CDDL) Version 1.0"""]

    logger.info(f(l1))
    assert f(l1) == ['Apache License, Version 2.0 and '
                     'Common Development And Distribution License (CDDL) Version 1.0']

    l2 = ['Apache License', 'Version2', 'GPL', 'Version 2.1']
    logger.info(f(l2))
    assert f(l2) == ['Apache License, Version2', 'GPL, Version 2.1']


def test_construct_version_query():
    """Test the GraphPopulator.construct_version_query() class method."""
    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {}
        }
    }
    q = GraphPopulator.construct_version_query(input_json)
    logger.info(q)

    assert q is ''

    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {"details": [
                {"description": "Some description here",
                 "declared_licenses": ["GPL v3", "APL v2.0"]}
            ]},
            "github_details": {},
            'libraries_io': {},
            'source_licenses': {},
            'security_issues': {
                "details": [
                    {"id": "CEV-007", "cvss": {"score": 9.7}}
                ]
            },
            'code_metrics': {"details": {"languages": [{
                "metrics": {
                    "functions": {
                        'average_cyclomatic_complexity': 3
                    }
                }
            }]}},
            'redhat_downstream': {
                "summary": {
                    "all_rhsm_product_names": ["access_points_rh"]
                }
            }

        }
    }
    q = GraphPopulator.construct_version_query(input_json)
    logger.info(q)

    assert "access_points" in q
    assert "0.4.59" in q
    assert "pypi" in q


def test_construct_package_query():
    """Test the GraphPopulator.construct_package_query() class method."""
    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {"details": [
                {"description": "Some description here"}
            ]},
            "github_details": {},
            'libraries_io': {}
        }
    }
    q = GraphPopulator.construct_version_query(input_json)
    logger.info(q)

    assert "access_points" in q
    assert "pypi" in q


def test_create_query_string():
    """Test the GraphPopulator.create_query_string() class method."""
    pass


if __name__ == '__main__':
    test_sanitize_text_for_query()
    test_sanitize_text_for_query_for_unicode_input
    test_construct_version_query()
    test_construct_package_query()
    test_create_query_string()
    test_correct_license_splitting()
