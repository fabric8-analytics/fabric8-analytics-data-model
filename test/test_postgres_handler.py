"""The tests for Minio put/get operations.

Test that the ecosystem/package/version information could be stored and retrieved from
the Minio storage.
"""

import logging
from data_importer import PostgresHandler

logging.basicConfig()
logger = logging.getLogger(__name__)


def test_fetch_pending_list():
    h = PostgresHandler()
    pending_list = h.fetch_pending_epvs()
    assert pending_list == []


if __name__ == '__main__':
    test_fetch_pending_list()
