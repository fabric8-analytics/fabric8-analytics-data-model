import json
import os
import re


def get_version(input_json):
    return input_json.get('version') or ''


def get_refstack_name(input_json):
    return input_json.get('name') or ''


def get_ecosystem(input_json):
    return input_json.get('ecosystem') or ''


def get_package(input_json):
    return input_json.get('package') or ''


def get_refstack_license(input_json):
    return input_json.get('license') or ''


def get_refstack_description(input_json):
    return input_json.get('description') or ''


def get_description(input_json):
    result = ''
    if 'metadata' in input_json['analyses'] and 'details' in input_json['analyses']['metadata'] and len(input_json["analyses"]["metadata"]["details"]) != 0:
        result = input_json['analyses']['metadata'][
            'details'][0].get('description') or ''
    return re.sub('[^A-Za-z0-9_ ]', '', result).lower()


def get_hashes(input_json):
    return ''


def get_latest_version(input_json):
    return input_json.get('latest_version') or ''


def get_version_dependents_count(input_json):
    return input_json.get('dependents_count') or -1


def get_last_incr_update_ts(input_json):
    return input_json.get('last_incremental_update_timestamp')


def get_last_imported_epv(input_json):
    return input_json.get('last_imported_epv')


def get_package_info(input_json):
    result = ''
    result2 = -1
    if 'package_info' in input_json:
        result = input_json['package_info'].get('relative_usage') or ''
        result2 = input_json['package_info'].get('dependents_count') or -1
    return result, result2


def is_shipped_as_downstream(input_json, ecosystem):
    if 'redhat_downstream' in input_json['analyses']:
        rdh_json = input_json['analyses']['redhat_downstream']
        if ecosystem == 'npm' and 'summary' in rdh_json and 'registered_srpms' in rdh_json['summary']:
            if len(rdh_json['summary']['registered_srpms']) != 0:
                return True
        elif ecosystem == 'maven' and 'summary' in rdh_json and 'all_rhsm_product_names' in rdh_json['summary']:
            if len(rdh_json['summary']['all_rhsm_product_names']) != 0:
                return True
    return False


def packed_in_downstream(input_json, ecosystem):
    pck_names = []
    if 'redhat_downstream' in input_json['analyses']:
        rdh_json = input_json['analyses']['redhat_downstream']
        if ecosystem == 'npm' and 'summary' in rdh_json and 'package_names' in rdh_json['summary']:
            pck_names = rdh_json['summary']['package_names']
        elif ecosystem == 'maven' and 'summary' in rdh_json and 'rh_mvn_matched_versions' in rdh_json['summary']:
            pck_names = rdh_json['summary']['rh_mvn_matched_versions']
    return set(pck_names)


def published_in_downstream(input_json, ecosystem):
    pck_channels = []
    if 'redhat_downstream' in input_json['analyses']:
        rdh_json = input_json['analyses']['redhat_downstream']
        if ecosystem == 'npm' and 'summary' in rdh_json and 'all_rhn_channels' in rdh_json['summary']:
            pck_channels = rdh_json['summary']['all_rhn_channels']
        elif ecosystem == 'maven' and 'summary' in rdh_json and 'all_rhsm_product_names' in rdh_json['summary']:
            pck_channels = rdh_json['summary']['all_rhsm_product_names']
    return set(pck_channels)


def read_from_file(fname):
    data = None
    with open(os.path.abspath(fname)) as f:
        data = json.load(f)
    return data
