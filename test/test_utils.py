"""Tests for the graph_populator module."""

from utils import get_current_version, execute_gremlin_dsl
import logging
import config
from mock import patch

logger = logging.getLogger(config.APP_NAME)


def test_get_current_version():
    """Test the function get_version_information."""
    out1, out2 = get_current_version('maven', 'io.vertx:vertx-web')
    assert out1 == -1
    assert out2 == -1


@patch("utils.get_session_retry")
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
        print(url)
        print(data)
        return MockedResponse()


class MockedResponse:
    """Mocked response object used by the following test."""

    def __init__(self):
        """Construct instance of this class."""
        self.id = None

    def status_code(self):
        """Get status code value."""
        return '404'


@patch("utils.get_session_retry")
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


if __name__ == '__main__':
    test_get_current_version()
    test_execute_gremlin_dsl()
    test_execute_gremlin_dsl2()
