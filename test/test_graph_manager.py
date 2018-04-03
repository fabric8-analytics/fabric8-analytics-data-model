"""Tests for the graph_manager module (to be done)."""

from graph_manager import BayesianGraph as g
import logging
import config


logger = logging.getLogger(config.APP_NAME)


def test_execute_invalid_query():
    """Test execution of invalid query."""
    invalid_query = "g.count"

    status, data = g.execute(invalid_query)
    logger.info([status, data])
    assert status is False
    assert "No such property: count for class:" in data["message"]


def test_return_json_response_data():
    """Test valid response is returned from graph db."""
    query = "g.V().count()"
    status, data = g.execute(query)
    logger.info([status, data])
    assert status is True
    r = g.return_json_response_data(data)
    logger.info(r)
    assert r >= 0


def test_is_index_created():
    """Test validity created index."""
    status = g.is_index_created()
    logger.info(status)
    assert status is False


def test_is_schema_defined():
    """Test if schema was initialized correctly."""
    status = g.is_schema_defined()
    logger.info(status)
    assert status is True


if __name__ == '__main__':
    test_execute_invalid_query()
    test_return_json_response_data()
    test_is_index_created()
