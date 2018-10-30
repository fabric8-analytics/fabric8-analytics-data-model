"""Utils functions for generic usage."""

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import json
import logging
import config
from datetime import datetime

logger = logging.getLogger(__name__)


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
    response = requests.post(url, data=payload_str)
    if response.status_code != 200:
        logger.error('Gremlin call failed ({st}): {resp}'.format(
            st=response.status_code, resp=str(response.content)
        ))
        raise ValueError('Graph error: {e}'.format(e=str(response.content)))
    return response.json()


def prepare_response(gremlin_json):
    """Prepare response to be sent to user based on Gremlin data."""
    cve_list = []
    resp = gremlin_json.get('result', {}).get('data', [])
    for cve in resp:
        if 'cve' in cve and 'epv' in cve:
            cve_dict = {
                "cve_id": cve.get('cve').get('cve_id', [None])[0],
                "cvss": cve.get('cve').get('cvss_v2', [None])[0],
                "description": cve.get('cve').get('description', [None])[0],
                "ecosystem": cve.get('cve').get('ecosystem', [None])[0],
                "name": cve.get('epv').get('pname', [None])[0],
                "version": cve.get('epv').get('version', [None])[0],
                "status": cve.get('cve').get('status', [None])[0],
                "fixed_in": cve.get('cve').get('fixed_in', [None])[0]
            }
            cve_list.append(cve_dict)

    return {"count": len(cve_list), "cve_list": cve_list}
