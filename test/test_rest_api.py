"""Tests for the rest_api module (to be done)."""

import rest_api
import unittest
import logging
import config


logger = logging.getLogger(config.APP_NAME)


class RestApiTestCase(unittest.TestCase):

    def setUp(self):
        rest_api.app.testing = True
        self.app = rest_api.app.test_client()

    def tearDown(self):
        pass

    def test_readiness(self):
        response = self.app.get('/api/v1/readiness')
        logger.info(response)
        assert response.status_code == 200


if __name__ == '__main__':
    unittest.main()

