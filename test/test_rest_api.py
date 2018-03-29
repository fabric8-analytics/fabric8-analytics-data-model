"""Tests for the rest_api module (to be done)."""

from flask import current_app, url_for
import pytest
import rest_api
import unittest


class RestApiTestCase(unittest.TestCase):

    def setUp(self):
        rest_api.app.testing = True
        self.app = rest_api.app.test_client()

    def tearDown(self):
        pass


if __name__ == '__main__':
    unittest.main()

