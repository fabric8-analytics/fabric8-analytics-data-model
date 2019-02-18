"""Tests for the graph_populator module."""

from src.graph_populator import GraphPopulator
import pytest
import logging
from src import config

logger = logging.getLogger(config.APP_NAME)


def test_sanitize_text_for_query():
    """Test GraphPopulator._sanitize_text_for_query()."""
    f = GraphPopulator.sanitize_text_for_query
    assert 'pkg' == f('pkg')
    assert 'desc' == f('desc\n')
    assert 'desc' == f(' desc')
    assert 'desc' == f(' desc ')
    assert 'foo bar' == f(' foo bar ')
    assert 'desc' == f(' desc\n')
    assert 'ASL 2.0' == f('ASL\n"2.0"')
    assert '[ok]' == f('["ok\']')
    assert 'ok' == f("'ok'")


def test_sanitize_text_for_query_whitespace_characters():
    """Test GraphPopulator._sanitize_text_for_query(), input is whitespace characters."""
    f = GraphPopulator.sanitize_text_for_query
    assert '' == f(None)
    assert '' == f('')
    assert '' == f(' ')
    assert '' == f('\n')
    assert '' == f('\n ')
    assert '' == f(' \n ')
    assert '' == f('\n\n')
    assert '' == f('\t')


def test_sanitize_text_for_query_exception_handling():
    """Test GraphPopulator._sanitize_text_for_query()."""
    f = GraphPopulator.sanitize_text_for_query
    with pytest.raises(ValueError):
        f(100)
    with pytest.raises(ValueError):
        f(True)
    with pytest.raises(ValueError):
        f(False)


def test_sanitize_text_for_query_for_unicode_input():
    """Test GraphPopulator._sanitize_text_for_query() for Unicode input string."""
    f = GraphPopulator.sanitize_text_for_query
    assert 'pkg' == f(u'pkg')
    assert 'desc' == f(u'desc\n')
    assert 'desc' == f(u' desc')
    assert 'desc' == f(u' desc\n')
    assert 'desc' == f(u' desc ')
    assert 'foo bar' == f(u' foo bar ')
    assert 'ASL 2.0' == f(u'ASL\n"2.0"')
    assert '[ok]' == f(u'["ok\']')
    assert 'ok' == f(u"'ok'")


def test_sanitize_text_for_query_whitespace_characters_in_unicode():
    """Test GraphPopulator._sanitize_text_for_query(), input is whitespace characters."""
    f = GraphPopulator.sanitize_text_for_query
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


def test_construct_version_query_1():
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

    assert "access_points" in q
    assert "0.4.59" in q
    assert "pypi" in q
    assert "addVertex" in q
    assert "drop()" not in q


def test_construct_version_query_2():
    """Test the GraphPopulator.construct_version_query() class method."""
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


def test_construct_version_query_3():
    """Test the GraphPopulator.construct_version_query() class method."""
    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {"details": [
                {"description": "Some description here",
                 "declared_license": "GPL \nv2.0"}
            ]}
        }
    }
    q = GraphPopulator.construct_version_query(input_json)
    logger.info(q)

    assert "access_points" in q
    assert "0.4.59" in q
    assert "pypi" in q


def test_construct_version_query_4():
    """Test the GraphPopulator.construct_version_query() class method."""
    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {"details": [
                {"description": "Some description here",
                 "declared_license": "GPL and\nv2.0"}
            ]}
        }
    }
    q = GraphPopulator.construct_version_query(input_json)
    logger.info(q)

    assert "access_points" in q
    assert "0.4.59" in q
    assert "pypi" in q

    input_json = {
        "version": "deb579d6e030503f430978ee229008b9bc912d40",
        "package": "github.com/gorilla/mux",
        "ecosystem": "go",
        "analyses": {
            "source_licenses": {
                "status": "success",
                "summary": {
                    "sure_licenses": [
                        "BSD-Modified"
                    ]
                }
            },
            "metadata": {
                "details": [
                    {
                        "code_repository": {
                            "type": "git",
                            "url": "https://github.com/gorilla/mux"
                        },
                        "dependencies": [],
                        "ecosystem": "gofedlib",
                        "name": "github.com/gorilla/mux",
                        "version": "deb579d6e030503f430978ee229008b9bc912d40"
                    }
                ]
            }
        }
    }
    q = GraphPopulator.construct_version_query(input_json)

    assert "'declared_licenses'" in q
    assert "'licenses'" in q
    assert "BSD-Modified" in q


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
            'libraries_io': {'schema': {'version': '2-0-0'},
                             'details': {'releases': {
                                 'count': 2,
                                 'recent': [{
                                     "published_at": "2016-09-09"}
                                 ],
                                 "published_at": "2016-09-09"
                             }}}
        }
    }
    str_package, prp_package = GraphPopulator.construct_package_query(input_json)
    logger.info(str_package, prp_package)

    assert 'access_points' in str_package
    assert "pypi" in str_package

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
    str_package, prp_package = GraphPopulator.construct_package_query(input_json)
    logger.info(str_package, prp_package)

    assert 'access_points' in str_package
    assert "pypi" in str_package

    input_json = {
        "version": "0.4.59",
        "package": "access_points",
        "ecosystem": "pypi",
        "analyses": {
            "metadata": {"details": [
                {"description": "Some description here"}
            ]},
            "github_details": {},
            'libraries_io': {'schema': {'version': '1-0-0'},
                             'details': {'releases': {
                                 'count': 2,
                                 'recent': [{"published_at": "2016-09-09"}],
                                 'latest': {
                                     'recent': {
                                         "0.4.59": "2016-09-09"
                                     }
                                 },
                                 "published_at": "2016-09-09"
                             }}}
        }
    }
    str_package, prp_package = GraphPopulator.construct_package_query(input_json)
    logger.info([str_package, prp_package])

    assert 'access_points' in str_package
    assert "pypi" in str_package


def test_create_query_string():
    """Test the GraphPopulator.create_query_string() class method."""
    pass


if __name__ == '__main__':
    test_sanitize_text_for_query()
    test_sanitize_text_for_query_for_unicode_input()
    test_sanitize_text_for_query_whitespace_characters()
    test_sanitize_text_for_query_whitespace_characters_in_unicode()
    test_sanitize_text_for_query_exception_handling()
    test_construct_version_query_1()
    test_construct_version_query_2()
    test_construct_version_query_3()
    test_construct_version_query_4()
    test_construct_package_query()
    test_create_query_string()
    test_correct_license_splitting()
