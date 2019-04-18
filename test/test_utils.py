"""Tests for the graph_populator module."""

import pytest
import datetime
from src.utils import get_current_version, execute_gremlin_dsl, get_timestamp, call_gremlin
import logging
from src import config
from mock import patch
from conftest import RequestsMockResponse

logger = logging.getLogger(config.APP_NAME)


def test_get_current_version():
    """Test the function get_version_information."""
    out1, out2 = get_current_version('maven', 'io.vertx:vertx-web')
    assert out1 == -1
    assert out2 == -1


@patch("src.utils.get_session_retry")
def test_execute_gremlin_dsl(mocker):
    """Test the function get_version_information."""
    mocker.return_value = ""
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': 'maven',
            'pkg': 'io.vertx:vertx-web'
        }
    }
    out = execute_gremlin_dsl(payload)
    assert out is None


class MockedSession:
    """Mocked session object used by the following test."""

    def __init__(self):
        """Construct instance of this class."""
        self.id = None

    def post(self, url="http://", data=None):
        """Get post value."""
        return MockedResponse()


class MockedResponse:
    """Mocked response object used by the following test."""

    def __init__(self):
        """Construct instance of this class."""
        self.id = None

    def status_code(self):
        """Get status code value."""
        return '404'


@patch("src.utils.get_session_retry")
def test_execute_gremlin_dsl2(mocker):
    """Test the function get_version_information."""
    mocker.return_value = MockedSession()
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': 'maven',
            'pkg': 'io.vertx:vertx-web'
        }
    }
    out = execute_gremlin_dsl(payload)
    print(out)
    assert out is None


def test_get_timestamp():
    """Test utils.get_timestamp()."""
    timestamp = get_timestamp()
    result = (datetime.datetime.utcnow()).strftime('%Y%m%d')
    assert result == timestamp


@patch("src.utils.requests.Session.post")
def test_gremlin_call(mocker):
    """Test utils.call_gremlin()."""
    mocker.return_value = RequestsMockResponse({}, 200)
    assert call_gremlin({'dummy': 'payload'}) == {}


@patch("src.utils.requests.Session.post")
def test_bad_gremlin_call(mocker):
    """Test utils.call_gremlin()."""
    mocker.return_value = RequestsMockResponse({}, 500)
    with pytest.raises(ValueError):
        call_gremlin({'dummy': 'payload'})


if __name__ == '__main__':
    test_get_current_version()
    test_execute_gremlin_dsl()
    test_execute_gremlin_dsl2()
