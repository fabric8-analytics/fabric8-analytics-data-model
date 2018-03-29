"""Tests for the rest_api module (to be done)."""

import rest_api
import unittest
import logging
import config
import json

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
        """Add test for pelding graph sync API."""
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

    def test_selective_ingest(self):
        """Add test for selective ingest API."""

        input_data = {}
        self.app.post('/api/v1/selective_ingest',
                      data=json.dumps(input_data),
                      headers={'Content-Type': 'application/json'})

        input_data = {'package_list': []}
        self.app.post('/api/v1/selective_ingest',
                      data=json.dumps(input_data),
                      headers={'Content-Type': 'application/json'})

        input_data = {'package_list': [], 'select_ingest': []}
        self.app.post('/api/v1/selective_ingest',
                      data=json.dumps(input_data),
                      headers={'Content-Type': 'application/json'})


if __name__ == '__main__':
    unittest.main()
