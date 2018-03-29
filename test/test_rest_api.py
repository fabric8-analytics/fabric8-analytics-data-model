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


if __name__ == '__main__':
    unittest.main()

