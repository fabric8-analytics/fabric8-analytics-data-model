import config
import logging
from entities.package import Package
from entities.utils import get_values as gv
from entities.version import Version
from entities.github_details import load_github_result_from_json

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

serve_static_json = gv.read_from_file('test/data/npm--serve-static-1.7.1.json')


def test_github_attr():
    pck_obj = Package.load_from_json(serve_static_json)
    assert pck_obj.last_updated is None

    assert pck_obj.save() is not None
    p_ts1 = pck_obj.last_updated
    assert p_ts1 is not None
    assert Package.count() == 1

    github_result = load_github_result_from_json(serve_static_json)
    assert github_result.last_updated is None

    pck_obj.add_github_details_as_attr(github_result)
    assert pck_obj.last_updated >= p_ts1

    package_criteria = {
        'ecosystem': pck_obj.ecosystem, 'name': pck_obj.name}

    present_package = Package.find_by_criteria('Package', package_criteria)
    assert present_package.last_updated== pck_obj.last_updated
    assert present_package.gh_forks == 84
    assert present_package.gh_stargazers == 538
    assert present_package.gh_issues_last_year_opened == 15
    assert present_package.gh_issues_last_year_closed == 16
    assert present_package.gh_issues_last_month_opened == 0
    assert present_package.gh_issues_last_month_closed == 0
    assert present_package.gh_prs_last_year_opened == 11
    assert present_package.gh_prs_last_year_closed == 11
    assert present_package.gh_prs_last_month_opened == 1
    assert present_package.gh_prs_last_month_closed == 1


    Package.delete_by_id(pck_obj.id)
    assert Package.count() == 0  

