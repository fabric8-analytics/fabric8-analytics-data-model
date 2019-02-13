"""The tests for Minio put/get operations.

Test that the ecosystem/package/version information could be stored and retrieved from
the Minio storage.
"""

import logging
from src.data_importer import PostgresHandler

logging.basicConfig()
logger = logging.getLogger(__name__)


def test_fetch_pending_list():
    """Test pending list is empty."""
    h = PostgresHandler()
    data = h.fetch_pending_epvs()
    pending_list = data["pending_list"]
    assert pending_list == []


if __name__ == '__main__':
    test_fetch_pending_list()
