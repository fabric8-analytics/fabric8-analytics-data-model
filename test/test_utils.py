"""Tests for the graph_populator module."""

import pytest
import datetime
from src.utils import get_current_version, execute_gremlin_dsl, get_timestamp, \
    call_gremlin, rectify_latest_version, get_latest_version_non_cve, \
    update_non_cve_version, get_all_versions, fetch_pkg_details_via_cve, \
    sync_all_non_cve_version, sync_all_latest_version, sync_all_cve_source,\
    rectify_cve_source
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
        assert url is not None
        # just not to have dead code
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


@patch("src.utils.rectify_latest_version")
def test_sync_all_latest_version(mock1):
    """Test sync_all_latest_version function."""
    mock1.return_value = ""
    resp = sync_all_latest_version("test/data/all_packages_test.json")
    assert resp['status'] == "Success"


@patch("src.utils.get_latest_versions_for_ep")
@patch("src.utils.execute_gremlin_dsl")
def test_rectify_latest_version(mock1, mock2):
    """Test rectify_latest_version function."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "io.vertx:vertx-web"
        }
    ]

    mock2.return_value = "1.2.3"
    mock1.return_value = {
        "name": "io.vertx:vertx-web",
        "latest_version": "1.2.4"
    }

    resp = rectify_latest_version(input_data)
    assert resp['status'] == "Success"

    input_data[0]['actual_latest_version'] = "1.1.1"
    input_data[0]['latest_version'] = "1.1.0"
    resp = rectify_latest_version(input_data)
    assert resp['status'] == "Success"

    input_data.append({
        "ecosystem": "maven",
        "name": "io.vertx:vertx-client"
    })
    mock1.return_value = None
    resp = rectify_latest_version(input_data)
    assert resp['status'] == "Success"


@patch("src.utils.GREMLIN_QUERY_SIZE", 1)
@patch("src.utils.get_latest_versions_for_ep")
@patch("src.utils.execute_gremlin_dsl")
def test_rectify_latest_version2(mock1, mock2):
    """Test rectify_latest_version function."""
    input_data = [
        {
            "ecosystem": "maven",
            "name": "io.vertx:vertx-web"
        }
    ]

    mock2.return_value = "1.2.3"
    mock1.return_value = None

    input_data.append({
        "ecosystem": "maven",
        "name": "io.vertx:vertx-client"
    })
    resp = rectify_latest_version(input_data)
    assert resp['status'] == "Success"

    mock1.return_value = {
        "name": "io.vertx:vertx-web",
        "latest_version": "1.2.4"
    }

    resp = rectify_latest_version(input_data)
    assert resp['status'] == "Success"


@patch("src.utils.get_all_versions")
@patch("src.utils.execute_gremlin_dsl")
def test_get_latest_version_non_cve(mock1, mock2):
    """Test get_latest_version_non_cve function."""
    mock1.return_value = {
        "result": {
                "data": ["1.2.3"]
            }
    }
    ver = get_latest_version_non_cve("maven", "io.vertx:vertx-web", "1.1.1")
    assert ver == "1.1.1"

    mock2.return_value = ["1.1.1", "1.1.2"]
    ver = get_latest_version_non_cve("maven", "io.vertx:vertx-web", "-1")
    assert ver == "1.1.2"


@patch("src.utils.execute_gremlin_dsl")
def test_update_non_cve_version(mock1):
    """Test update_non_cve_version function."""
    input = {
        "lodash": {
            "latest_version": "1.1.1",
            "ecosystem": "pypi",
            "latest_non_cve_version": "1.1.1"
        },
        "request": {
            "latest_version": "1.1.2",
            "ecosystem": "pypi"
        }
    }
    mock1.return_value = {
        "result": {
            "data": ["blahblah"]
        }
    }
    res = update_non_cve_version(input)
    assert res == "Success"

    mock1.return_value = {
        "result": {
            "data": []
        }
    }
    res = update_non_cve_version(input)
    assert res is None


@patch("src.utils.execute_gremlin_dsl")
def test_get_all_versions(mock1):
    """Test get_all_versions function."""
    mock1.return_value = {
        "result": {
            "data": ["1.1", "1.2", "1.3", "1.x", "> 2.4", "~1.2", "1.6|8"]
        }
    }

    vers = get_all_versions('npm', 'lodash', True)
    assert "1.1" in vers
    assert "1.x" not in vers

    vers = get_all_versions('npm', 'lodash', False)
    assert "1.1" in vers
    assert "1.x" not in vers


@patch("src.utils.execute_gremlin_dsl")
def test_fetch_pkg_details_via_cve(mock1):
    """Test fetch_pkg_details_via_cve function."""
    mock1.return_value = {
        "result": {
            "data": [{
                "ecosystem": ["npm"],
                "name": ["lodash"],
                "latest_version": ["1.1.1"]
            }]
        }
    }
    res = fetch_pkg_details_via_cve("1")
    assert res[0]["latest_version"] == "1.1.1"

    mock1.return_value = None
    res = fetch_pkg_details_via_cve("1")
    assert len(res) == 0


@patch("src.utils.update_non_cve_on_pkg")
@patch("src.utils.get_latest_version_non_cve")
@patch("src.utils.fetch_pkg_details_via_cve")
@patch("src.utils.execute_gremlin_dsl")
def test_sync_all_non_cve_version(mock1, mock2, mock3, mock4):
    """Test sync_all_non_cve_version function."""
    mock1.return_value = {
        "result": {
            "data": ["1"]
        }
    }

    mock2.return_value = [
        {
            "ecosystem": "npm",
            "name": "lodash",
            "latest_version": "1.1.1"
        }
    ]

    mock3.return_value = "1.1.2"
    mock4.return_value = None
    res = sync_all_non_cve_version(["npm"])
    assert res["message"] == "Latest non cve version rectified for the EPVs"


@patch("src.utils.rectify_cve_source")
@patch("src.utils.execute_gremlin_dsl")
def test_sync_all_cve_source(mock1, mock2):
    """Test sync_all_non_cve_version function."""
    input = {
        "cve_sources": "CRA",
        "ecosystems": ["npm"]
    }
    mock1.return_value = {
        "message": "cve sources updated for the CVEs",
        "status": "Success"
    }
    mock2.return_value = None

    res = sync_all_cve_source(input)
    assert res["message"] == "Latest cve source rectified for the CVEs"
    assert res["status"] == "Success"


@patch("src.utils.execute_gremlin_dsl")
def test_rectify_cve_source(mock1):
    """Test sync_all_non_cve_version function."""
    input = ['CVE-2018-3717']
    mock1.return_value = None

    res = rectify_cve_source(input, 'CRA')
    assert res["message"] == "cve sources updated for the CVEs"
    assert res["status"] == "Success"


if __name__ == '__main__':
    test_get_current_version()
    test_execute_gremlin_dsl()
    test_execute_gremlin_dsl2()
    test_rectify_latest_version()
    test_rectify_latest_version2()
    test_get_latest_version_non_cve()
    test_update_non_cve_version()
    test_get_all_versions()
    test_fetch_pkg_details_via_cve()
    test_sync_all_non_cve_version()
    test_sync_all_cve_source()
    test_rectify_cve_source()
