"""Utils functions for generic usage."""

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import requests
import json
import logging
from src import config
from datetime import datetime
import os
from f8a_utils.versions import get_latest_versions_for_ep, select_latest_version
import re


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


def get_latest_version_non_cve(eco, pkg, ver=""):
    """To check if the latest version (input) has cve."""
    result_data = []
    logger.info("Fetching latest non cve version {e} {p}".format(e=eco, p=pkg))
    if ver and ver != "-1":
        # Check if the passed latest version has cve or not
        query_str = "g.V().has('pecosystem', eco).has('pname', pkg).has('version', ver)" \
                    ".not(outE('has_cve')).valueMap()"
        payload = {
            'gremlin': query_str,
            'bindings': {
                'eco': eco,
                'pkg': pkg,
                'ver': ver
            }
        }
        gremlin_response = execute_gremlin_dsl(payload)
        result_data = get_response_data(gremlin_response, [])
    if len(result_data) == 0:
        # result_data will be 0 if cve is found. Fetch all versions
        logger.info("Latest version node not found in graph")
        all_ver = get_all_versions(eco, pkg, True)
        # Use util function to select the latest of all the versions fetched
        return select_latest_version(all_ver)
    else:
        logger.info("Latest version node found in graph")
        return ver


def update_non_cve_version(affected_pkgs):
    """To update the latest non cve version on the pkg node."""
    x = 0
    for key in affected_pkgs:
        eco = key.split("@DELIM@")[0]
        pkg = key.split("@DELIM@")[1]
        # Get the latest non cve version
        latest_ver = get_latest_version_non_cve(eco, pkg,
                                                affected_pkgs[key])
        logger.info("latest non cve version ->", latest_ver)
        # Update the package node to include the property for non cve version
        res = update_non_cve_on_pkg(eco, pkg, latest_ver)
        if res == "Success":
            x += 1
    if len(affected_pkgs) == x:
        return "Success"


def update_non_cve_on_pkg(eco, pkg, latest_ver):
    """To populate the field with non cve latest version data."""
    query_str = "g.V().has('ecosystem', eco).has('name', pkg)" \
                ".property('latest_non_cve_version', latest_ver)"
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': eco,
            'pkg': pkg,
            'latest_ver': latest_ver
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [])

    if not result_data:
        logger.error("Could not update the latest non cve version {eco} {pkg} {ver}".
                     format(eco=eco, pkg=pkg, ver=latest_ver))
        return "Failed"
    else:
        logger.info("Updated the latest non cve version {eco} {pkg} {ver}".
                    format(eco=eco, pkg=pkg, ver=latest_ver))
        return "Success"


def get_all_versions(eco, pkg, cve_check):
    """To get all versions for a package."""
    if cve_check:
        query_str = "g.V().has('ecosystem', eco).has('name',pkg).out('has_version')" \
                    ".not(outE('has_cve')).values('version')"
    else:
        query_str = "g.V().has('ecosystem', eco).has('name',pkg)" \
                    ".out('has_version').values('version')"
    valid_versions = []
    payload = {
        'gremlin': query_str,
        'bindings': {
            'eco': eco,
            'pkg': pkg
        }
    }
    gremlin_response = execute_gremlin_dsl(payload)
    result_data = get_response_data(gremlin_response, [])

    if not result_data:
        return valid_versions

    for version in result_data:
        if len(re.findall("[\\^*<>+=~|\\s\xa0]|.x", version)) == 0:
            valid_versions.append(version)

    return valid_versions


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


def fetch_pkg_details_via_cve(cves):
    """Query the graph to get the pkg details from cve ids."""
    pkg_details = []
    x = 1
    for cve_id in cves:
        logger.info("{id}. Fetching details for the CVE-> {cve}".format(id=x, cve=cve_id))
        x += 1
        query_str = "g.V().has('cve_id', '{}').in('has_cve').in('has_version')" \
                    ".dedup().valueMap()".format(cve_id)
        payload = {
            'gremlin': query_str
        }
        gremlin_response = execute_gremlin_dsl(payload)
        if gremlin_response:
            result_data = get_response_data(gremlin_response, [{0: 0}])
            for res in result_data:
                latest_version = ""
                if "latest_version" in res:
                    latest_version = res['latest_version'][0]
                tmp = {
                    "ecosystem": res['ecosystem'][0],
                    "name": res['name'][0],
                    "latest_version": latest_version
                }
                pkg_details.append(tmp)
        else:
            logger.info("----------Corrupted Data--------")

    return pkg_details


def sync_all_non_cve_version(input):
    """Update all the pkg nodes with CVE with the latest non cve version."""
    logger.info("Sync called for CVEs to update the latest non cve versions.")
    resp = {
        "message": "Latest non cve version rectified for the EPVs",
        "status": "Success"
    }
    for eco in input:
        # Fetch all the cve ids for the ecosystem
        query_str = "g.V().has('cecosystem', '{}').values('cve_id')".format(eco)
        payload = {
            'gremlin': query_str
        }
        gremlin_response = execute_gremlin_dsl(payload)
        result_data = get_response_data(gremlin_response, [{0: 0}])

        # For each CVE id, find the list of pkgs
        pkgs = fetch_pkg_details_via_cve(result_data)
        for pkg in pkgs:
            eco = pkg['ecosystem']
            name = pkg['name']
            latest = pkg['latest_version']
            logger.info("Updating non cve version for {eco} {name}".format(eco=eco, name=name))
            # Get the non cve version for the pkg
            non_cve_ver = get_latest_version_non_cve(eco, name, latest)
            # Update the pkg node with the non cve version
            update_non_cve_on_pkg(eco, name, non_cve_ver)
    return resp


def rectify_latest_version(input):
    """Rectify the latest version of the EPVs."""
    query_str = "g.V().has('ecosystem', '{arg0}')" \
                ".has('name', '{arg1}')" \
                ".property('latest_version', '{arg2}')" \
                ".property('latest_version_last_updated', '{arg3}');"
    args = []
    resp = {
        "message": "Latest version rectified for the EPVs",
        "status": "Success"
    }
    cur_date = (datetime.utcnow()).strftime('%Y%m%d')
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
            tmp['3'] = cur_date
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
        if len(arg) == 4:
            tmp_query = query_string.format(arg0=arg['0'], arg1=arg['1'],
                                            arg2=arg['2'], arg3=arg['3'])
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
