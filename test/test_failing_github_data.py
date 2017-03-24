from entities.package import Package
from entities.version import Version
from entities.github_details import GithubResult
from entities.utils import get_values as gv

import config
import logging

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


npm_sequence_3 = gv.read_from_file('test/data/npm-sequence-3.0.0.json')

def test_empty_github_results():
    p = Package.load_from_json(npm_sequence_3)
    p.save()
    v = Version.load_from_json(npm_sequence_3, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    # input_json = gv.read_from_file('test/data/npm-sequence-3.0.0.json')
    github_data = npm_sequence_3["analyses"]["github_details"]
    github_result = GithubResult.load_from_json(github_data)
    assert (github_result.details is not None)
    assert github_result.last_updated is None

    # gid = github_result.save()
    v.add_edge_github_details(github_result)
    ls_before = github_result.last_updated
    assert ls_before is not None
    assert (github_result.id is not None)

    v.add_edge_github_details(github_result)
    ls_after = github_result.last_updated
    assert ls_after >= ls_before
    assert GithubResult.count() == 1

    GithubResult.delete_by_id(github_result.id)

    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)    
