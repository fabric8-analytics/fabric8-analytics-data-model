from graph_manager import BayesianGraph
import traceback
import time
import sys
import logging

logger = logging.getLogger(__name__)


MAX_DELAY = 20 * 60  # 5 minutes


def test_http_connection():
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
    return max_delay - (current_time - start_time)

def main():
    waittime = 5

    start_time = time.time()

    logger.info ("Connecting to HTTP...")
    while time_remaining(start_time, time.time()) > 0:
        try:
            test_http_connection()
            break
        except Exception as e:
            # tb = traceback.format_exc()
            logger.info("Connection to HTTP endpoint: FAILED... %s" % e)
            logger.info("Retrying after %s seconds" % waittime)
            time.sleep(waittime)

    if time_remaining(start_time, time.time() > 0):
        return sys.exit(0)
    else:
        return sys.exit(-1)


if __name__ == "__main__":
    main()
