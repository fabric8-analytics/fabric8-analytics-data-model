"""Definition of fixtures for static data, sessions etc. used by unit tests."""

import pytest

from rest_api import create_app


@pytest.fixture(scope='session')
def app():
    """Return Flask app object."""
    return create_app()


class RequestsMockResponse:
    """Mocked response from requests.post()."""

    def __init__(self, json_data, status_code):
        """Constructor."""
        self.json_data = json_data
        self.status_code = status_code
        self.content = 'This is expected ;)'

    def json(self):
        """Response body as json."""
        return self.json_data
