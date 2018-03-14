"""Tests for the rest_api module."""

import rest_api
import unittest
import logging
import config
import json
from flask import url_for


logger = logging.getLogger(config.APP_NAME)


class RestApiTestCase(unittest.TestCase):
    """Test cases for Rest API."""

    def setUp(self):
        """Make the application instance ready for testing."""
        rest_api.app.testing = True
        self.app = rest_api.app.test_client()

    def tearDown(self):
        """Cleanup application instance after testing."""
        pass

    def test_readiness(self):
        """Add test for readiness API."""
        response = self.app.get('/api/v1/readiness')
        logger.info(response)
        assert response.status_code == 200

    def test_liveness(self):
        """Add test for liveness API."""
        response = self.app.get('/api/v1/liveness')
        logger.info(response)
        assert response.status_code == 200

    def test_pending(self):
        """Add test for pending graph sync API."""
        response = self.app.get('/api/v1/pending')
        logger.info(response)
        assert response.status_code == 200
        data = json.loads(response.get_data())
        logger.info(data)
        assert 'pending_list' in data
        assert 'all_counts' in data

    def test_sync_all(self):
        """Add test for graph sync API."""
        response = self.app.get('/api/v1/sync_all')
        logger.info(response)
        assert response.status_code == 200
        data = json.loads(response.get_data())
        logger.info(data)
        assert 'count_imported_EPVs' in data
        assert 'epv' in data
        assert 'message' in data
        assert data['message'] == 'Nothing to be synced to Graph!'

    def test_ingest_to_graph(self):
        """Add test for ingest to graph API."""
        input_data = []
        response = self.app.post('/api/v1/ingest_to_graph',
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

    def test_selective_ingest_empty(self):
        """Add test for selective ingest API with empty inputs."""
        input_data = {}
        response = self.app.post('/api/v1/selective_ingest',
                                 data=json.dumps(input_data),
                                 headers={'Content-Type': 'application/json'})
        data = json.loads(response.get_data())
        logger.info(data)
        assert response.status_code == 400
        assert 'No Packages provided. Nothing to be ingested' == data['message']

        input_data = {'package_list': []}
        response = self.app.post('/api/v1/selective_ingest',
                                 data=json.dumps(input_data),
                                 headers={'Content-Type': 'application/json'})
        data = json.loads(response.get_data())
        logger.info(data)
        assert response.status_code == 400
        assert 'No Packages provided. Nothing to be ingested' == data['message']

        input_data = {'package_list': [], 'select_ingest': []}
        response = self.app.post('/api/v1/selective_ingest',
                                 data=json.dumps(input_data),
                                 headers={'Content-Type': 'application/json'})
        data = json.loads(response.get_data())
        logger.info(data)
        assert response.status_code == 400
        assert 'No Packages provided. Nothing to be ingested' == data['message']

    def test_selective_ingest_nonempty(self):
        """Add test for selective ingest API with wrong input."""
        input_data = {
            'package_list': [{}],
            'select_ingest': []}
        response = self.app.post('/api/v1/selective_ingest',
                                 data=json.dumps(input_data),
                                 headers={'Content-Type': 'application/json'})
        data = json.loads(response.get_data())
        logger.info(data)
        assert response.status_code == 400
        assert 'Invalid keys found in input:' in data['message']

    def test_selective_ingest_valid(self):
        """Add test for selective ingest API with wrong input."""
        input_data = {
            'package_list': [{"version": "0.4.59",
                              "name": "access_points",
                              "ecosystem": "pypi"
                              }],
            'select_ingest': []}
        response = self.app.post('/api/v1/selective_ingest',
                                 data=json.dumps(input_data),
                                 headers={'Content-Type': 'application/json'})
        data = json.loads(response.get_data())
        logger.info(data)
        assert response.status_code == 200
        assert 'The import finished successfully!' in data['message']

    def test_handle_properties_put(self, client, mocker):
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

    def test_handle_properties_delete(self, client, mocker):
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


if __name__ == '__main__':
    unittest.main()
