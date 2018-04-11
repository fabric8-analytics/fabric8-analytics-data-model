"""Tests for the rest_api module."""

import logging
import config
import json
from flask import url_for
import rest_api


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
