"""Utils functions for generic usage."""

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import json
import logging
from src import config
from datetime import datetime
import os
from f8a_utils.versions import get_latest_versions_for_ep


logger = logging.getLogger(__name__)
GREMLIN_QUERY_SIZE = int(os.getenv('GREMLIN_QUERY_SIZE', 25))


def get_session_retry(retries=3, backoff_factor=0.2, status_forcelist=(404, 500, 502, 504),
                      session=None):
    """Set HTTP Adapter with retries to session."""
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries,
                  backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    return session


def get_response_data(json_response, data_default):
    """Retrieve data from the JSON response.

    Data default parameters takes what should data to be returned.
    """
    return json_response.get("result", {}).get("data", data_default)


def execute_gremlin_dsl(payloads):
    """Execute the gremlin query and return the response."""
    try:
        resp = get_session_retry().post(config.GREMLIN_SERVER_URL_REST, data=json.dumps(payloads))
        if resp.status_code == 200:
            json_response = resp.json()

            return json_response
        else:
            logger.error("HTTP error {}. Error retrieving Gremlin data.".format(
                resp.status_code))
            return None

    except Exception as e:
        logger.error(e)
        return None


def get_current_version(eco, pkg):
    """To fetch the latest version and libio latest version."""
    query_str = "g.V().has('ecosystem', eco).has('name',pkg).valueMap()"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': eco,
            'pkg': pkg
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])

    if not result_data:
        return -1, -1
    latest_ver = result_data[0].get('latest_version', [''])[0]
    libio_ver = result_data[0].get('libio_latest_version', [''])[0]

    return latest_ver, libio_ver


def get_timestamp():
    """Get YYYYMMDD format timestamp from `utcnow()`."""
    return (datetime.utcnow()).strftime('%Y%m%d')


def call_gremlin(json_payload):
    """Call Gremlin with given payload.

    And return exactly what Gremlin has to say.
    Raise ValueError on non-200 status code.
    """
    url = config.GREMLIN_SERVER_URL_REST
    payload_str = json.dumps(json_payload)
    logger.debug('Calling Gremlin at {url} with payload {p}'.format(url=url, p=payload_str))
    response = get_session_retry().post(url, data=payload_str)
    if response.status_code != 200:
        logger.error('Gremlin call failed ({st}): {resp}'.format(
            st=response.status_code, resp=str(response.content)
        ))
        raise ValueError('Graph error: {e}'.format(e=str(response.content)))
    return response.json()


def rectify_latest_version(input):
    """Rectify the latest version of the EPVs."""
    query_str = "g.V().has('ecosystem', '{arg0}')." \
                "has('name', '{arg1}')" \
                ".property('latest_version', '{arg2}');"
    args = []
    resp = {
        "message": "Latest version rectified for the EPVs",
        "status": "Success"
    }
    for epv in input:
        if 'ecosystem' in epv and 'name' in epv:
            eco = epv['ecosystem']
            pkg = epv['name']
            tmp = {
                "0": eco,
                "1": pkg
            }
            if 'actual_latest_version' in epv:
                latest = epv['actual_latest_version']
            else:
                latest = get_latest_versions_for_ep(eco, pkg)
            tmp['2'] = latest
            known_latest = ''
            if 'latest_version' in epv:
                known_latest = epv['latest_version']
            if known_latest != latest:
                args.append(tmp)
    result_data = batch_query_executor(query_str, args)
    logger.info("Latest version updated for the EPVs ->", result_data)
    return resp


def batch_query_executor(query_string, args):
    """Execute the gremlin query in batches of 20."""
    tmp_query = ""
    counter = 0
    query = ""
    for arg in args:
        if len(arg) == 3:
            tmp_query = query_string.format(arg0=arg['0'], arg1=arg['1'], arg2=arg['2'])
            counter += 1
        if counter == 1:
            query = ""
        query += tmp_query

        if counter >= GREMLIN_QUERY_SIZE:
            counter = 0
            payload = {'gremlin': query}
            gremlin_response = execute_gremlin_dsl(payload)
            if gremlin_response is None:
                logger.error("Error while trying to fetch data from graph. "
                             "Expected response, got None...Query->", query)

    if counter < GREMLIN_QUERY_SIZE:
        payload = {'gremlin': query}
        gremlin_response = execute_gremlin_dsl(payload)
        if gremlin_response is None:
            logger.error("Error while trying to fetch data from graph. "
                         "Expected response, got None...Query->", query)

    return args
