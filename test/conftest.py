"""Definition of fixtures for static data, sessions etc. used by unit tests."""

import pytest

from rest_api import create_app


@pytest.fixture
def app():
    return create_app()
