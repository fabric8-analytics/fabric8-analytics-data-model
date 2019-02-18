"""Sanity check of the graph DB REST API."""

from src.graph_manager import BayesianGraph
import time
import sys
import logging
from src import config

logging.basicConfig()
logger = logging.getLogger(config.APP_NAME)
logger.setLevel(logging.DEBUG)


MAX_DELAY = 20 * 60  # 20 minutes


def test_http_connection():
    """Test the connection to a graph DB and the result send from the DB."""
    result = BayesianGraph.execute("g.V().count()")
    code, data = result
    logger.info(result)
    # logger.info code
    # logger.info data
    # logger.info data['result']['data']
    assert (code is True)
    assert (data['result']['data'][0] >= 0)

    logger.info("Connection to HTTP endpoint: SUCCESS")


def time_remaining(start_time, current_time, max_delay=MAX_DELAY):
    """Compute the remaining time."""
    return max_delay - (current_time - start_time)


def main():
    """Start the sanity check of the graph DB REST API."""
    waittime = 5

    start_time = time.time()

    logger.info("Connecting to HTTP...")
    while time_remaining(start_time, time.time()) > 0:
        try:
            test_http_connection()
            break
        except Exception as e:
            logger.info("Connection to HTTP endpoint: FAILED... %s" % e)
            logger.info("Retrying after %s seconds" % waittime)
            time.sleep(waittime)

    if time_remaining(start_time, time.time() > 0):
        return sys.exit(0)
    else:
        return sys.exit(-1)


if __name__ == "__main__":
    logger.info("Starting sanitycheck")
    main()
    logger.info("Ending sanitycheck")
