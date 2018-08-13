# -*- coding: utf-8 -*-

# Copyright © 2018 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Yusuf Zainee <yzainee@redhat.com>
#

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import json
import logging
import config

logger = logging.getLogger(config.APP_NAME)

#GREMLIN_SERVER_URL_REST = "http://{host}:{port}".format(
#    host=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_HOST", "localhost"),
#    port=os.environ.get("BAYESIAN_GREMLIN_HTTP_SERVICE_PORT", "8182"))

GREMLIN_SERVER_URL_REST = "http://bayesian-gremlin-http-miteshpatel-greenfield-test.dev.rdu2c.fabric8.io/"


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
        resp = get_session_retry().post(GREMLIN_SERVER_URL_REST, data=json.dumps(payloads))
        if resp.status_code == 200:
            json_response = resp.json()

            return json_response
        else:
            logger.error("HTTP error {}. Error retrieving Gremlin data.".format(
                response.status_code))
            return None

    except Exception:
        logger.error(traceback.format_exc())
        return None


def get_current_version(eco, pkg):
    query_str = "g.V()has('ecosystem', eco).has('name',pkg)"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': eco,
            'pkg': pkg
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [{0: 0}])
    return result_data[0]['properties']['latest_version'][0]['value'],\
        result_data[0]['properties']['libio_latest_version'][0]['value']
