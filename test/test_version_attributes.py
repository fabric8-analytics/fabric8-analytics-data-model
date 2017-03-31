import config
import logging
from entities.package import Package
from entities.utils import get_values as gv
from entities.version import Version
from entities.github_details import load_github_result_from_json
from entities.code_metrics import CodeMetricsResult as CMR
from entities.support_vectors import SecurityDetails as SD

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

npm_crumb_data = gv.read_from_file('test/data/npm-crumb-4.0.0.json')
serve_static_json = gv.read_from_file('test/data/npm--serve-static-1.7.1.json')
npm_abbr_data = gv.read_from_file('test/data/npm--abbrev-1.0.4.json')


def test_additional_data_as_attr():

    add_details = {}
    pck_obj = Package.load_from_json(serve_static_json)
    assert pck_obj.last_updated is None
    assert pck_obj.save() is not None
    
    ver_obj = Version.load_from_json(serve_static_json, package=pck_obj)
    assert ver_obj.last_updated is None
    ver_obj.save()
    v_ts1 = ver_obj.last_updated
    assert pck_obj.last_updated is not None
    assert v_ts1 is not None

    pck_obj.create_version_edge(ver_obj)
    code_metrics = CMR.load_from_json(
        npm_crumb_data["analyses"]["code_metrics"])

    security_data = serve_static_json["analyses"]["security_issues"]
    security_list, cvss_score = SD.load_from_json(security_data)

    if len(security_data.get("details", {})) > 0:
        obj = security_data.get("details")[0]
        cve_id = obj.get("id", "")
        cvss = obj.get("cvss", "")
        temp_set = set()
        temp_set.add(str(cve_id) + ":" + str(cvss))
        add_details["cve_ids"] = temp_set

    add_details["cm_loc"] = code_metrics.details.languages[0].code_lines
    add_details["cm_num_files"] = code_metrics.details.languages[0].files_count
    add_details["cm_avg_cyclomatic_complexity"] = code_metrics.details.\
        languages[0].average_cyclomatic_complexity

    ver_obj.add_additional_data_as_attr(add_details)
    assert ver_obj.last_updated >= v_ts1

    version_criteria = {'pecosystem': pck_obj.ecosystem,
                        'pname': pck_obj.name, 'version': ver_obj.version}

    present_version = Version.find_by_criteria(
        ver_obj.label, pck_obj, version_criteria)
    logger.info(present_version.__dict__)
    assert present_version.cm_loc == 3
    assert present_version.cm_num_files == 1
    assert present_version.cm_avg_cyclomatic_complexity == -1
    assert present_version.cve_ids == set()
    assert present_version.last_updated == ver_obj.last_updated

    Version.delete_by_id(ver_obj.id)
    Package.delete_by_id(pck_obj.id)




