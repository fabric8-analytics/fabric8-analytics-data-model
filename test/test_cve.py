"""Tests for the cve module."""

import pytest
from mock import patch
from conftest import RequestsMockResponse

from src.cve import (
    CVEPut, CVEDelete, CVEGet,
    cve_node_replace_script_template,
    cve_node_delete_script_template
)


valid_put_input = {
    'cve_id': 'CVE-2018-0001',
    'cve_sources': 'snyk.io',
    'description': 'Some description.',
    'cvss_v2': 5.0,
    'ecosystem': 'pypi',
    'fixed_in': ['12.0'],
    'nvd_status': 'Analyzed',
    'affected': [
        {
            'name': 'numpy',
            'version': '11.0'
        },
        {
            'name': 'numpy',
            'version': '10.0'
        }
    ]
}

invalid_put_input = {
    'cve_id': 'CVE-2018-0001',
}

mocker_input = {
    "result": {
        "data": [
            {
                "cve": {
                    "ecosystem": ["maven"],
                    "cve_id": ["CVE-2018-0001"],
                    "cvss_v2": [10.0],
                    "nvd_status": ["Awaiting Analyses"],
                    "description": ["Some description here updated just now."],
                    "modified_date": ["20180911"],
                    "cve_sources": ["snyk.io"]
                },
                "epv": {
                    "pname": ["io.vertx:vertx-core"],
                    "version": ["3.4.1"],
                    "pecosystem": ["maven"],
                }
            }
        ]
    }
}


def test_cve_put_creation():
    """Test CVEPut input validation."""
    assert CVEPut(valid_put_input)

    with pytest.raises(ValueError):
        CVEPut(invalid_put_input)


def test_cve_put_get_qstring_for_cve_node():
    """Test CVEPut.get_qstring_for_cve_node()."""
    cve = CVEPut(valid_put_input)

    query_str, bindings_dict = cve.get_qstring_for_cve_node()
    assert query_str.startswith(cve_node_replace_script_template)

    json_payload = cve.prepare_payload(query_str, bindings_dict)
    assert 'bindings' in json_payload
    bindings = json_payload['bindings']

    assert 'cve_id' in bindings
    assert bindings['cve_id']
    assert 'description' in bindings
    assert bindings['description']
    assert 'cvss_v2' in bindings
    assert bindings['cvss_v2']
    assert 'modified_date' in bindings
    assert bindings['modified_date']


def test_cve_put_get_qstrings_for_edges():
    """Test CVEPut.get_qstrings_for_edges()."""
    cve = CVEPut(valid_put_input)

    results = cve.get_qstrings_for_edges()
    assert len(results) == 2  # 2 edges as the CVE affects 2 versions


@patch("src.cve.GraphPopulator.construct_graph_nodes")
@patch("src.cve.BayesianGraph.execute")
def test_create_pv_nodes(mock_bg, mock_gp):
    """Test CVEPut.create_pv_nodes()."""
    mock_gp.return_value = 'query'
    mock_bg.return_value = True, {}

    cve = CVEPut(valid_put_input)
    nodes, successfull_create = cve.create_pv_nodes()
    assert len(nodes) == 2
    assert successfull_create is True
    assert ('pypi', 'numpy', '10.0') in nodes
    assert ('pypi', 'numpy', '11.0') in nodes


@patch("src.cve.GraphPopulator.construct_graph_nodes")
@patch("src.cve.BayesianGraph.execute")
def test_create_pv_nodes_fail(mock_bg, mock_gp):
    """Test CVEPut.create_pv_nodes() fail."""
    mock_gp.return_value = 'query'
    mock_bg.return_value = (False, {'error': 'something happened'})

    cve = CVEPut(valid_put_input)
    nodes, successfull_create = cve.create_pv_nodes()
    assert len(nodes) == 0
    assert successfull_create is False


@patch("src.cve.CVEPut.create_pv_nodes")
def test_put_process_epv_fail(mock_pv):
    """Test the CVEPut.process() fail."""
    mock_pv.return_value = [], False

    cve = CVEPut(valid_put_input)
    cve.process()


@patch("src.cve.CVEPut.create_pv_nodes")
@patch("src.utils.requests.Session.post")
def test_put_process_cve_fail(mock_gremlin, mock_pv):
    """Test the CVEPut.process() success."""
    mock_pv.return_value = [], True
    mock_gremlin.side_effect = [RequestsMockResponse({}, 200),
                                RequestsMockResponse({}, 200),
                                RequestsMockResponse({}, 500),
                                RequestsMockResponse({}, 200)]

    cve = CVEPut(valid_put_input)
    cve.process()


valid_delete_input = {
    'cve_id': 'CVE-2018-0001'
}

invalid_delete_input = {
    'cve': 'CVE-2018-0001',
}


def test_cve_delete_creation():
    """Test CVEDelete input validation."""
    assert CVEDelete(valid_delete_input)

    with pytest.raises(ValueError):
        CVEDelete(invalid_delete_input)


def test_cve_delete_prepare_payload():
    """Test CVEDelete.prepare_payload()."""
    cve = CVEDelete(valid_delete_input)
    json_payload = cve.prepare_payload()

    assert 'gremlin' in json_payload
    assert json_payload['gremlin'].startswith(cve_node_delete_script_template)

    assert 'bindings' in json_payload
    bindings = json_payload['bindings']

    assert 'cve_id' in bindings
    assert bindings['cve_id']


@patch("src.cve.call_gremlin")
def test_cve_get_e(mocker):
    """Test getting CVEs for (ecosystem)."""
    mocker.return_value = {'result': {'data': ['CVE-2018-0001']}}

    cve = CVEGet('pypi', None, None)
    response = cve.get()

    assert response
    assert 'count' in response
    assert response['count'] == 1
    assert 'cve_ids' in response
    assert len(response['cve_ids']) == 1
    assert response['cve_ids'][0] == 'CVE-2018-0001'


@patch("src.cve.call_gremlin")
def test_cve_get_ep(mocker):
    """Test getting CVEs for (ecosystem,name)."""
    mocker.return_value = {'result': {'data': ['CVE-2018-0001', 'CVE-2018-0002']}}

    cve = CVEGet('pypi', 'numpy', None)
    response = cve.get()

    assert response
    assert 'count' in response
    assert response['count'] == 2
    assert 'cve_ids' in response
    assert len(response['cve_ids']) == 2
    assert response['cve_ids'][0] in ('CVE-2018-0001', 'CVE-2018-0002')
    assert response['cve_ids'][1] in ('CVE-2018-0001', 'CVE-2018-0002')


@patch("src.cve.call_gremlin")
def test_cve_get_epv(mocker):
    """Test getting CVEs for (ecosystem,name,version)."""
    mocker.return_value = {'result': {'data': []}}

    cve = CVEGet('pypi', 'numpy', '99.0')
    response = cve.get()

    assert response
    assert 'count' in response
    assert response['count'] == 0
    assert 'cve_ids' in response
    assert len(response['cve_ids']) == 0
