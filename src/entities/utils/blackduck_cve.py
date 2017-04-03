from entities.entity_base import EntityBase
from entities.support_vectors import SecurityDetails
from entities.utils import get_values as gv


def load_from_json(input_json):
    issue_list = []
    if 'blackduck' in input_json and 'items' in input_json['blackduck']:
        items = input_json['blackduck']['items']
        if len(items) > 0:
            for item in items:
                if 'vulnerabilityWithRemediation' in item and item['vulnerabilityWithRemediation'] is not None:
                    cve_id = item['vulnerabilityWithRemediation'].get('vulnerabilityName') or None
                    if  cve_id is not None or cve_id != '':
                        issue = item['vulnerabilityWithRemediation']
                        issue_list.append(issue)
    return issue_list


def add_blackduck_issue(issue):
    blcve_criteria = {'cve_id':issue['vulnerabilityName']}
    obj_returned = SecurityDetails.find_by_criteria('CVE', blcve_criteria)
    if obj_returned is None:
        obj_returned = SecurityDetails(issue['vulnerabilityName'])
        obj_returned.save()
    obj_returned.add_blackduck_data(issue)
    return obj_returned
