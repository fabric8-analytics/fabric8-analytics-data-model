from entities.package import Package
from entities.version import Version
from entities.support_vectors import SecurityDetails
from entities.utils import get_values as gv
from entities.utils import blackduck_cve as bl
import logging
import config

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

serve_static_json = gv.read_from_file('test/data/npm--serve-static-1.7.1.json')
input_json = gv.read_from_file('test/data/api-response-examples.json')


def test_security_object():
    bl_list = bl.load_from_json(input_json['analyses'])
    assert len(bl_list) == 1

    objBlackduck = bl.add_blackduck_issue(bl_list[0])
    assert objBlackduck.bl_base_score == 4.3
    assert objBlackduck.bl_description == 'Open redirect vulnerability in the serve-static plugin before 1.7.2 for Node.js, when mounted at the root, allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a // (slash slash) followed by a domain in the PATH_INFO to the default URI.'
    assert objBlackduck.bl_exploitability_subscore == 8.6
    assert objBlackduck.bl_impact_subscore == 2.9
    assert objBlackduck.bl_remediation_status.lower() == 'new'
    assert objBlackduck.bl_remediation_updated_at == '2016-08-05T13:42:07.705Z'
    assert objBlackduck.bl_remediation_created_at == '2016-08-05T13:42:07.705Z'
    assert objBlackduck.bl_severity.lower() == 'medium'
    assert objBlackduck.bl_source.lower() == 'nvd'
    assert objBlackduck.bl_vulnerability_name == 'CVE-2015-1164'
    assert objBlackduck.bl_vulnerability_published_date == '2015-01-22T19:08:21.013Z'
    assert objBlackduck.bl_vulnerability_updated_date == '2015-01-23T21:11:11.353Z'
    assert objBlackduck.last_updated is not None
    
    SecurityDetails.delete_by_id(objBlackduck.id)


def test_blackduck_graph():
    bl_list = []
    p = Package.load_from_json(serve_static_json)
    assert p.save() is not None
    
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    bl_list = bl.load_from_json(input_json['analyses'])
    assert len(bl_list) == 1

    objBlackduck = bl.add_blackduck_issue(bl_list[0])
    v.add_blackduck_cve_edge(objBlackduck.id)

    bl_criteria = {'vulnerability_name' :  'CVE-2015-1164'}
    obj_fetch = SecurityDetails.find_by_criteria('CVE', bl_criteria)
    assert obj_fetch.last_updated == objBlackduck.last_updated

    SecurityDetails.delete_by_id(obj_fetch.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


