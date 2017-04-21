from entities.entity_base import EntityBase
from entities.utils import get_values as gv
import time
import logging

logger = logging.getLogger(__name__)


class GithubLastYearCommits():
    def __init__(self, sum=-1, weekly=[]):
        self.sum = sum  # jsl.IntField(required=True)
        self.weekly = weekly  # jsl.ArrayField(jsl.IntField(), required=True)
        self.last_updated = None


class GithubItemsByTime():
    def __init__(self, opened=-1, closed=-1):
        self.opened = opened  # jsl.IntField(required=True)
        self.closed = closed  # jsl.IntField(required=True)
        self.last_updated = None


__default_time__ = GithubItemsByTime()


class GithubUpdatedIssues():
    def __init__(self, year=__default_time__, month=__default_time__):
        self.year = year  # jsl.DocumentField(GithubItemsByTime, as_ref=True)
        self.month = month  # jsl.DocumentField(GithubItemsByTime, as_ref=True)
        self.last_updated = None


class GithubUpdatedPullRequests(GithubUpdatedIssues):
    def __init__(self, year=__default_time__, month=__default_time__):
        # super(GithubUpdatedPullRequests, self).__init__()
        self.year = year  # jsl.DocumentField(GithubItemsByTime, as_ref=True)
        self.month = month  # jsl.DocumentField(GithubItemsByTime, as_ref=True)
        self.last_updated = None

class GithubDetail:
    def __init__(self,
                 forks_count=-1,
                 last_year_commits=GithubLastYearCommits(),
                 open_issues_count=-1,
                 stargazers_count=-1, subscribers_count=-1,
                 updated_issues=GithubUpdatedIssues(),
                 updated_pull_requests=GithubUpdatedPullRequests()):
        self.forks_count = forks_count  # jsl.IntField()
        self.open_issues_count = open_issues_count  # jsl.IntField()
        self.stargazers_count = stargazers_count  # jsl.IntField()
        self.subscribers_count = subscribers_count  # jsl.IntField()
        # jsl.DocumentField(GithubLastYearCommits, as_ref=True)
        self.last_year_commits = last_year_commits
        # jsl.DocumentField(GithubUpdatedIssues, as_ref=True)
        self.updated_issues = updated_issues
        # jsl.DocumentField(GithubUpdatedPullRequests, as_ref=True)
        self.updated_pull_requests = updated_pull_requests
        self.last_updated = None

class GithubResult(EntityBase):
    label = "GithubDetail"

    def __init__(self, package_version, status=None, details=None, summary=None):
        super(GithubResult, self).__init__()
        self.package_version = package_version
        # jsl.StringField(enum=["success", "error", "unknown"], required=True)
        self.status = status
        # jsl.DocumentField(GithubDetail, required=True, as_ref=True)
        self.details = details
        # jsl.ArrayField(jsl.StringField(), required=True)
        self.summary = summary
        self.last_updated = None

    @classmethod
    def load_from_json(cls, github_data):
        summary = github_data["summary"]
        status = github_data["status"]
        github_result = GithubResult(
                None, details=None, summary=summary, status=status)

        if status == "success":
            details_data = github_data["details"]
            last_year_commits = GithubLastYearCommits(weekly=details_data["last_year_commits"]["weekly"],
                                                      sum=details_data[
                                                          "last_year_commits"]["sum"]
                                                      )

            month_opened_issues, month_closed_issues = -1, -1
            if "month" in details_data["updated_issues"]:
                month_opened_issues = details_data["updated_issues"]["month"]["opened"]
                month_closed_issues = details_data["updated_issues"]["month"]["closed"]

            updated_issues_by_month = GithubItemsByTime(opened=month_opened_issues, closed=month_closed_issues)

            year_opened_issues, year_closed_issues = -1, -1
            if "year" in details_data["updated_issues"]:
                year_opened_issues = details_data["updated_issues"]["year"]["opened"]
                year_closed_issues = details_data["updated_issues"]["year"]["closed"]

            updated_issues_by_year = GithubItemsByTime(opened=year_opened_issues, closed=year_closed_issues)

            updated_issues = GithubUpdatedIssues(month=updated_issues_by_month, year=updated_issues_by_year)

            month_opened_prs, month_closed_prs = -1, -1
            if "month" in details_data["updated_pull_requests"]:
                month_opened_prs = details_data["updated_pull_requests"]["month"]["opened"]
                month_closed_prs = details_data["updated_pull_requests"]["month"]["closed"]

            updated_prs_by_month = GithubItemsByTime(opened=month_opened_prs, closed=month_closed_prs)

            year_opened_prs, year_closed_prs = -1, -1
            if "month" in details_data["updated_pull_requests"]:
                year_opened_prs = details_data["updated_pull_requests"]["year"]["opened"]
                year_closed_prs = details_data["updated_pull_requests"]["year"]["closed"]

            updated_prs_by_year = GithubItemsByTime(opened=year_opened_prs, closed=year_closed_prs)
            updated_pull_requests = GithubUpdatedPullRequests(month=updated_prs_by_month, year=updated_prs_by_year)
            details = GithubDetail(forks_count=details_data["forks_count"],
                                   subscribers_count=details_data[
                                       "subscribers_count"],
                                   open_issues_count=details_data[
                                       "open_issues_count"],
                                   stargazers_count=details_data[
                                       "stargazers_count"],
                                   last_year_commits=last_year_commits,
                                   updated_issues=updated_issues,
                                   updated_pull_requests=updated_pull_requests
                                   )
            github_result.details = details
        else:
            github_result.details = GithubDetail()

        return github_result

    def create(self):
        try:
            ts = time.time()
            results = self.g().addV(self.label). \
                property('vertex_label', self.label). \
                property('forks_count', self.details.forks_count). \
                property('open_issues_count', self.details.open_issues_count). \
                property('stargazers_count', self.details.stargazers_count). \
                property('subscribers_count', self.details.subscribers_count). \
                property('last_updated', ts).\
                toList()

            logger.debug("create() GithubResult - results: %s" % results)

            self.last_updated = ts
            self.id = results[0].id
            logger.debug("Vertex ID : %s, GithubResult: %s" % (self.id, self))
            return self.id

        except Exception as e:
            logger.error("create() failed: %s" % e)
            return None

    def update(self):
        try:
            ts = time.time()
            results = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('forks_count', self.details.forks_count). \
                property('open_issues_count', self.details.open_issues_count). \
                property('stargazers_count', self.details.stargazers_count). \
                property('subscribers_count', self.details.subscribers_count). \
                property('last_updated', ts).\
                toList()

            self.last_updated = ts
            logger.debug("update() GithubResult - results: %s" % results)
            logger.debug("Vertex ID : %s, GithubResult: %s" % (self.id, self))
            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None


# parent object is GithubResult

def load_github_result_from_json(input_json):
    github_data = input_json["analyses"]["github_details"]
    github_result = GithubResult.load_from_json(github_data)
    return github_result
    