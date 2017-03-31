import set_logging as log
from graph_manager import BayesianGraph
import traceback
import time
import sys

MAX_DELAY = 20 * 60  # 5 minutes


def test_websocket_connection():
    g = BayesianGraph.instance()
    result = g.V().count().toList()
    assert (result is not None)
    vcount = result[0]
    assert (vcount >= 0)
    log.logger.info("Connection to WebSocket endpoint: SUCCESS")


def test_http_connection():
    result = BayesianGraph.execute("g.V().count()")
    code, data = result
    log.logger.info(result)
    # log.logger.info code
    # log.logger.info data
    # log.logger.info data['result']['data']
    assert (code is True)
    assert (data['result']['data'][0] >= 0)

    log.logger.info("Connection to HTTP endpoint: SUCCESS")


def time_remaining(start_time, current_time, max_delay=MAX_DELAY):
    return max_delay - (current_time - start_time)

def main():
    waittime = 5

    start_time = time.time()

    log.logger.info ("Connecting to HTTP...")
    while time_remaining(start_time, time.time()) > 0:
        try:
            test_http_connection()
            break
        except Exception as e:
            # tb = traceback.format_exc()
            log.logger.info("Connection to HTTP endpoint: FAILED... %s" % e)
            log.logger.info("Retrying after %s seconds" % waittime)
            time.sleep(waittime)

    log.logger.info ("Connecting to WebSocket...")
    while time_remaining(start_time, time.time()) > 0:
        try:
            test_websocket_connection()
            break
        except Exception as e:
            # tb = traceback.format_exc()
            log.logger.info("Connection to WebSocket endpoint: FAILED... %s" % e)
            log.logger.info("Retrying after %s seconds" % waittime)
            time.sleep(waittime)

    if time_remaining(start_time, time.time() > 0):
        return sys.exit(0)
    else:
        return sys.exit(-1)


if __name__ == "__main__":
    main()
