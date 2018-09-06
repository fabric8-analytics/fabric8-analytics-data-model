"""Tests for the rest_api module."""

import logging
import config
import json
from flask import url_for
from mock import patch
from test_cve import (
    valid_put_input, invalid_put_input, valid_delete_input, invalid_delete_input
)

logger = logging.getLogger(config.APP_NAME)


def test_readiness(client):
    """Add test for readiness API."""
    url = url_for('api_v1.readiness')
    response = client.get(url)
    logger.info(response)
    assert response.status_code == 200


def test_liveness(client):
    """Add test for liveness API."""
    url = url_for('api_v1.liveness')
    response = client.get(url)
    logger.info(response)
    assert response.status_code == 200


def test_pending(client):
    """Add test for pending graph sync API."""
    url = url_for('api_v1.pending')
    response = client.get(url)
    logger.info(response)
    assert response.status_code == 200
    data = json.loads(response.get_data())
    logger.info(data)
    assert 'pending_list' in data
    assert 'all_counts' in data


def test_sync_all(client):
    """Add test for graph sync API."""
    url = url_for('api_v1.sync_all')
    response = client.get(url)
    logger.info(response)
    assert response.status_code == 200
    data = json.loads(response.get_data())
    logger.info(data)
    assert 'count_imported_EPVs' in data
    assert 'epv' in data
    assert 'message' in data
    assert data['message'] == 'Nothing to be synced to Graph!'


def test_ingest_to_graph(client):
    """Add test for ingest to graph API."""
    input_data = []
    url = url_for('api_v1.ingest_to_graph')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    logger.info(response)
    assert response.status_code == 200
    data = response.get_data()
    logger.info("Returned data")
    logger.info(data)
    data = json.loads(response.get_data())
    logger.info(data)
    assert 'count_imported_EPVs' in data
    assert 'epv' in data
    assert 'message' in data
    assert data['message'] == 'Nothing to be synced to Graph!'


def test_ingest_to_graph_source(client):
    """Add test for ingest to graph API with source_repo in payload."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "commons-collections:commons-collections",
            "version": "3.2.1",
            "source_repo": "redhat_maven"
        }
    ]
    url = url_for('api_v1.ingest_to_graph')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 200
    data = json.loads(response.get_data())
    assert 'count_imported_EPVs' in data
    assert 'epv' in data
    assert 'message' in data
    assert data['message'] == 'Nothing to be synced to Graph!'


def test_ingest_to_graph_valid(client):
    """Add test for ingest to graph API when some key is missing."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "commons-collections:commons-collections",
            "source_repo": "redhat_maven"
        }
    ]
    url = url_for('api_v1.ingest_to_graph')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 400
    data = json.loads(response.get_data())
    epv_keys = input_data[0].keys()
    assert data['message'] == 'Invalid keys found in input: ' + ','.join(epv_keys)


@patch("rest_api.data_importer.import_epv_from_s3_http")
def test_ingest_to_graph_report(mocker, client):
    """Add test for ingest to graph API when report status is Failure."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "commons-collections:commons-collections",
            "version": "3.2.1",
            "source_repo": "redhat_maven"
        }
    ]
    mocker.return_value = {"status": "Failure"}
    url = url_for('api_v1.ingest_to_graph')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 500


def test_selective_ingest_empty(client):
    """Add test for selective ingest API with empty inputs."""
    input_data = {}
    url = url_for('api_v1.selective_ingest')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'No Packages provided. Nothing to be ingested' == data['message']

    input_data = {'package_list': []}
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'No Packages provided. Nothing to be ingested' == data['message']

    input_data = {'package_list': [], 'select_ingest': []}
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'No Packages provided. Nothing to be ingested' == data['message']


def test_selective_ingest_nonempty(client):
    """Add test for selective ingest API with wrong input."""
    url = url_for('api_v1.selective_ingest')
    input_data = {
        'package_list': [{}],
        'select_ingest': []}
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'Invalid keys found in input:' in data['message']


def test_selective_ingest_valid(client):
    """Add test for selective ingest API with wrong input."""
    url = url_for('api_v1.selective_ingest')
    input_data = {
        'package_list': [{"version": "0.4.59",
                          "name": "access_points",
                          "ecosystem": "pypi"
                          }],
        'select_ingest': []}

    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 200
    assert 'The import finished successfully!' in data['message']


def test_selective_ingest_valid_source(client):
    """Add test for selective ingest API with source_repo."""
    url = url_for('api_v1.selective_ingest')

    input_data = {
        'package_list': [{"version": "3.2.1",
                          "name": "commons-collections:commons-collections",
                          "ecosystem": "maven",
                          "source_repo": "redhat_maven"
                          }],
        'select_ingest': []}

    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 200
    assert 'Nothing to be synced to Graph!' in data['message']


def test_handle_properties_put(client, mocker):
    """Test PUT on /api/v1/<e>/<p>/<v>/properties."""
    gremlin_mock = mocker.patch('rest_api.BayesianGraph.execute')
    gremlin_mock.return_value = (True, {})
    url = url_for('api_v1.handle_properties', ecosystem='maven',
                  package='net.iharder:base64', version='2.3.9')
    payload = {'properties': [{'name': 'cve_ids', 'value': 'CVE-3005-1234:10'}]}
    response = client.put(url, content_type='application/json', data=json.dumps(payload))
    assert response.status_code == 200

    expected_statement = \
        "g.V()" \
        ".has('pecosystem','maven')" \
        ".has('pname','net.iharder:base64')" \
        ".has('version','2.3.9')" \
        ".properties('cve_ids')" \
        ".drop()" \
        ".iterate();" \
        "g.V()" \
        ".has('pecosystem','maven')" \
        ".has('pname','net.iharder:base64')" \
        ".has('version','2.3.9')" \
        ".property('cve_ids','CVE-3005-1234:10');"
    gremlin_mock.assert_called_once_with(expected_statement)


def test_handle_properties_delete(client, mocker):
    """Test DELETE on /api/v1/<e>/<p>/<v>/properties."""
    gremlin_mock = mocker.patch('rest_api.BayesianGraph.execute')
    gremlin_mock.return_value = (True, {})
    url = url_for('api_v1.handle_properties', ecosystem='maven',
                  package='net.iharder:base64', version='2.3.9')
    payload = {'properties': [{'name': 'cve_ids'}]}
    response = client.delete(url, content_type='application/json', data=json.dumps(payload))
    assert response.status_code == 200

    expected_statement = \
        "g.V()" \
        ".has('pecosystem','maven')" \
        ".has('pname','net.iharder:base64')" \
        ".has('version','2.3.9')" \
        ".properties('cve_ids')" \
        ".drop()" \
        ".iterate();"
    gremlin_mock.assert_called_once_with(expected_statement)


def test_create_blank_nodes_invalid(client):
    """Add test for create blank nodes API with wrong input."""
    url = url_for('api_v1.create_nodes')
    input_data = [{
        "ecosystem": "maven",
        "name": "pkg-1",
        "source_repo": "redhat-maven"
    }]
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'Invalid keys found in input:' in data['message']


def test_create_blank_nodes_empty(client):
    """Add test for create blank nodes API with an empty list input."""
    url = url_for('api_v1.create_nodes')
    input_data = []
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 400
    assert 'No EPVs provided. Please provide valid list of EPVs' in data['message']


def test_create_blank_nodes_valid(client):
    """Add test for create blank nodes API with wrong input."""
    url = url_for('api_v1.create_nodes')
    input_data = [
      {
        "ecosystem": "maven",
        "name": "pkg-1",
        "version": "1.0.0",
        "source_repo": "redhat-maven"
      }]
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    data = json.loads(response.get_data())
    logger.info(data)
    assert response.status_code == 200
    assert data['epv_nodes_created'] == 1


@patch("rest_api.data_importer.create_graph_nodes")
def test_create_blank_nodes_report_status(mocker, client):
    """Add test to create blank nodes API when report status is Failure."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "commons-collections:commons-collections",
            "version": "3.2.1",
            "source_repo": "redhat_maven"
        }
    ]
    mocker.return_value = {"status": "Failure"}
    url = url_for('api_v1.create_nodes')
    response = client.post(url,
                           data=json.dumps(input_data),
                           headers={'Content-Type': 'application/json'})
    assert response.status_code == 500


@patch("rest_api.CVEPut.process")
def test_cves_put(mocker, client):
    """Test PUT /api/v1/cves."""
    mocker.return_value = {}
    url = url_for('api_v1.cves_put_delete')
    response = client.put(
        url,
        data=json.dumps(valid_put_input),
        headers={'Content-Type': 'application/json'}
    )
    assert response.json == {}
    assert response.status_code == 200


@patch("rest_api.CVEPut.process")
def test_cves_put_invalid_input(mocker, client):
    """Test PUT /api/v1/cves with invalid input."""
    mocker.return_value = {}
    url = url_for('api_v1.cves_put_delete')
    response = client.put(
        url,
        data=json.dumps(invalid_put_input),
        headers={'Content-Type': 'application/json'}
    )
    assert 'error' in response.json
    assert response.status_code == 400


@patch("rest_api.CVEDelete.process")
def test_cves_delete(mocker, client):
    """Test DELETE /api/v1/cves."""
    mocker.return_value = {}
    url = url_for('api_v1.cves_put_delete')
    response = client.delete(
        url,
        data=json.dumps(valid_delete_input),
        headers={'Content-Type': 'application/json'}
    )
    assert response.json == {}
    assert response.status_code == 200


@patch("rest_api.CVEDelete.process")
def test_cves_delete_invalid_input(mocker, client):
    """Test DELETE /api/v1/cves with invalid input."""
    mocker.return_value = {}
    url = url_for('api_v1.cves_put_delete')
    response = client.delete(
        url,
        data=json.dumps(invalid_delete_input),
        headers={'Content-Type': 'application/json'}
    )
    assert 'error' in response.json
    assert response.status_code == 400


@patch("rest_api.CVEGet.get")
def test_cves_get_e(mocker, client):
    """Test GET /api/v1/cves/<ecosystem>."""
    mocker.return_value = {'count': 1, 'cve_ids': ['CVE-2018-0001']}
    url = url_for('api_v1.cves_get', ecosystem='pypi')
    response = client.get(
        url
    )
    assert response.status_code == 200


@patch("rest_api.CVEGet.get")
def test_cves_get_ep(mocker, client):
    """Test GET /api/v1/cves/<ecosystem>/<name>."""
    mocker.return_value = {'count': 1, 'cve_ids': ['CVE-2018-0001']}
    url = url_for('api_v1.cves_get', ecosystem='pypi', name='numpy')
    response = client.get(
        url
    )
    assert response.status_code == 200


@patch("cve.call_gremlin")
def test_cvedb_version_get(mocker, client):
    """Test GET /api/v1/cvedb-version."""
    mocker.return_value = {'result': {'data': ['9f4d54dd1a21584a40596c05d60ab00974953047']}}
    url = url_for('api_v1.cvedb_version_get')
    response = client.get(
        url
    )
    assert response.status_code == 200
    resp = response.json
    assert len(resp) == 1
    assert 'version' in resp
    assert resp['version'] == '9f4d54dd1a21584a40596c05d60ab00974953047'


@patch("cve.call_gremlin")
def test_cvedb_version_put(mocker, client):
    """Test PUT /api/v1/cvedb-version."""
    mocker.return_value = {'result': {'data': ['9f4d54dd1a21584a40596c05d60ab00974953047']}}
    url = url_for('api_v1.cvedb_version_put')
    response = client.put(
        url,
        data=json.dumps({'version': '9f4d54dd1a21584a40596c05d60ab00974953047'}),
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 200
    resp = response.json
    assert len(resp) == 1
    assert 'version' in resp
    assert resp['version'] == '9f4d54dd1a21584a40596c05d60ab00974953047'


def test_cvedb_version_put_invalid_input(client):
    """Test PUT /api/v1/cvedb-version."""
    url = url_for('api_v1.cvedb_version_put')
    response = client.put(
        url,
        data=json.dumps({'invalid': '9f4d54dd1a21584a40596c05d60ab00974953047'}),
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 400
    resp = response.json
    assert len(resp) == 1
    assert 'error' in resp
