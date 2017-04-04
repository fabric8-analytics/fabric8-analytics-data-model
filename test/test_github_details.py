from entities.github_details import load_github_result_from_json
from entities.utils import get_values as gv


def test_github_details_empty():
    npm_abbrev = gv.read_from_file('test/data/npm--abbrev-1.0.4.json')
    github_result = load_github_result_from_json(npm_abbrev)
    assert (github_result.status == "unknown")
    assert (github_result.summary == [])


def test_github_details_non_empty():
    npm_serve_static = gv.read_from_file(
        'test/data/npm--serve-static-1.7.1.json')
    github_result = load_github_result_from_json(npm_serve_static)
    assert (github_result.status == "success")
    assert (github_result.summary == [])
    assert (github_result.details is not None)
    details = github_result.details
    assert (details.open_issues_count == 2)
    assert (details.forks_count == 84)
    assert (details.subscribers_count == 23)
    assert (details.stargazers_count == 538)
    assert (details.last_year_commits.sum == 30)
    assert (len(details.last_year_commits.weekly) == 52)

    assert (details.updated_issues.year.opened == 15)
    assert (details.updated_issues.year.closed == 16)
    assert (details.updated_issues.month.opened == 0)
    assert (details.updated_issues.month.closed == 0)

    assert (details.updated_pull_requests.year.opened == 11)
    assert (details.updated_pull_requests.year.closed == 11)
    assert (details.updated_pull_requests.month.opened == 1)
    assert (details.updated_pull_requests.month.closed == 1)

