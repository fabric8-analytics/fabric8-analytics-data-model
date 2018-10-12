"""Tests for the cve module."""

import pytest
from mock import patch

from cve import (
    CVEPut, CVEDelete, CVEGet, CVEGetByDate,
    cve_node_replace_script_template,
    cve_node_delete_script_template
)


valid_put_input = {
    'cve_id': 'CVE-2018-0001',
    'description': 'Some description.',
    'cvss_v2': 10.0,
    'ecosystem': 'pypi',
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
                    "cvss": [10.0],
                    "nvd_status": ["Awaiting Analyses"],
                    "description": ["Some description here updated just now."],
                    "modified_date": ["20180911"]
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


def test_cve_put_prepare_payload():
    """Test CVEPut.prepare_payload()."""
    cve = CVEPut(valid_put_input)
    json_payload = cve.prepare_payload()

    assert 'gremlin' in json_payload
    assert json_payload['gremlin'].startswith(cve_node_replace_script_template)

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


@patch("cve.call_gremlin")
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


@patch("cve.call_gremlin")
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


@patch("cve.call_gremlin")
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


@patch("cve.call_gremlin")
def test_cve_get_by_date_valid(mocker):
    """Test getting CVEs for (ecosystem)."""
    mocker.return_value = mocker_input

    cve = CVEGetByDate('20160911')
    response = cve.get_bydate()

    assert response
    assert 'cve_list' in response
    assert response['cve_list'][0]['cve_id'] == 'CVE-2018-0001'
    assert 'ecosystem' in response['cve_list'][0]
    assert 'name' in response['cve_list'][0]
    assert 'version' in response['cve_list'][0]


def test_cve_get_by_date_empty_string():
    """Test getting CVEs for (ecosystem) with wrong input."""
    cve = CVEGetByDate('')
    response = cve.get_bydate()
    assert response
    assert 'count' in response
    assert response['count'] == 0
    assert 'cve_list' in response
    assert len(response['cve_list']) == 0


def test_cve_get_by_date_too_early():
    """Test getting CVEs for (ecosystem)."""
    with pytest.raises(ValueError):
        cve = CVEGetByDate('1000-01-01')
        response = cve.get_bydate()
        assert response is not None

    cve = CVEGetByDate('10000101')
    response = cve.get_bydate()
    assert response
    assert 'count' in response
    assert response['count'] == 0
    assert 'cve_list' in response
    assert len(response['cve_list']) == 0


def test_cve_get_by_date_too_late():
    """Test getting CVEs for (ecosystem)."""
    with pytest.raises(ValueError):
        cve = CVEGetByDate('9999-01-01')
        response = cve.get_bydate()
        assert response is not None

    cve = CVEGetByDate('99990101')
    response = cve.get_bydate()
    assert response
    assert 'count' in response
    assert response['count'] == 0
    assert 'cve_list' in response
    assert len(response['cve_list']) == 0


def test_cve_get_by_date_invalid():
    """Test getting CVEs for (ecosystem)."""
    with pytest.raises(ValueError):
        cve = CVEGetByDate('2016-09-11')
        response = cve.get_bydate()
        assert response is not None

    with pytest.raises(ValueError):
        cve = CVEGetByDate('11-09-2016')
        response = cve.get_bydate()
        assert response is not None


def test_cve_get_by_date_none(mocker):
    """Test getting CVEs for (ecosystem)."""
    mocker.return_value = {'result': {'data': []}}

    cve = CVEGetByDate(None)
    response = cve.get_bydate()

    assert response
    assert 'count' in response
    assert response['count'] == 0
    assert 'cve_list' in response
    assert len(response['cve_list']) == 0
