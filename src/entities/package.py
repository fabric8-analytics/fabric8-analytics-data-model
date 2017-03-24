from entities.entity_base import EntityBase
from entities.utils import get_values as gv
import config
import traceback
import time
import logging

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Package(EntityBase):

    def __init__(self, ecosystem='', name='', package_relative_used='', package_dependents_count=0, latest_version='', **github_dict):
        super(Package, self).__init__()
        self.ecosystem = ecosystem
        self.name = name
        self.package_relative_used = package_relative_used
        self.package_dependents_count = package_dependents_count
        self.latest_version = latest_version
        if len(github_dict) is not 0:
            self.gh_stargazers = github_dict.get("gh_stargazers",0)
            self.gh_forks = github_dict.get("gh_forks",0)
            self.gh_issues_last_year_opened = github_dict.get("gh_issues_last_year_opened",0)
            self.gh_issues_last_year_closed = github_dict.get("gh_issues_last_year_closed",0)
            self.gh_issues_last_month_opened = github_dict.get("gh_issues_last_month_opened",0)
            self.gh_issues_last_month_closed = github_dict.get("gh_issues_last_month_closed",0)
            self.gh_prs_last_year_opened = github_dict.get("gh_prs_last_year_opened",0)
            self.gh_prs_last_year_closed = github_dict.get("gh_prs_last_year_closed",0)
            self.gh_prs_last_month_opened = github_dict.get("gh_prs_last_month_opened",0)
            self.gh_prs_last_month_closed = github_dict.get("gh_prs_last_month_closed",0)
        self.last_updated = None

    @classmethod
    def load_from_file(cls, file_name):
        input_json = gv.read_from_file(file_name)
        return cls.load_from_json(input_json)

    @classmethod
    def load_from_json(cls, input_json):
        pck_info = gv.get_package_info(input_json)
        objpackage = Package(gv.get_ecosystem(input_json),
                             gv.get_package(input_json),
                             pck_info[0],
                             pck_info[1],
                             gv.get_latest_version(input_json))
        return objpackage

    @classmethod
    def find_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).toList()

        except Exception as e:
            logger.error("find_all() failed: %s" % e)
            return None

    @classmethod
    def count(cls):
        try:
            return len(cls.find_all())

        except Exception as e:
            logger.error("count() failed: %s" % e)
            return None

    @classmethod
    def edge_count(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()). \
                outE().count().toList()[0]

        except Exception as e:
            logger.error("edge_count() failed: %s" % e)

    @classmethod
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None

    @classmethod
    def return_entity_obj(cls, ecosystem, name, package_relative_used, package_dependents_count, latest_version, id, last_updated, **github_dict):
        objpackage = Package(ecosystem, name, package_relative_used,
                             package_dependents_count, latest_version, **github_dict)
        objpackage.last_updated = last_updated
        objpackage.id = id
        return objpackage

    def save(self):
        package_criteria = {'ecosystem': self.ecosystem, 'name': self.name}
        present_package = Package.find_by_criteria(
                self.label, package_criteria)
        if present_package is None:
            return self.create()
        else:
            self.id = present_package.id
            return self.update()

    @classmethod
    def find_by_criteria(cls, label, criteria_dict):
        github_dict ={}
        try:
            query = cls.g().V().has('vertex_label', label)
            for k, v in criteria_dict.items():
                query = query.has(k, v)
            check_pck = query.toList()
            logger.debug("query sent:------ %s" % query)
            logger.debug("query_result:----- %s" % check_pck)

            if len(check_pck) == 0:
                return None
            else:
                values = cls.g().V(check_pck[0].id).valueMap().toList()[0]
                gh_list = ["gh_issues_last_year_opened","gh_issues_last_year_closed","gh_issues_last_month_opened", "gh_issues_last_month_closed",
                           "gh_prs_last_month_opened","gh_prs_last_month_closed","gh_prs_last_year_opened","gh_prs_last_year_closed",
                            "gh_forks","gh_stargazers"]
                for each in gh_list:
                    if each in values.keys():
                        github_dict[each]=values.get(each)[0]

                return cls.return_entity_obj(values.get('ecosystem')[0], values.get('name')[0], values.get('package_relative_used')[0], values.get('package_dependents_count')[0],
                                             values.get('latest_version')[0], check_pck[0].id, values.get('last_updated')[0], **github_dict)

        except Exception as e:
            logger.error("find_by_criteria() failed: %s" % e)
            return None

    def create(self):
        try:
            package_criteria = {'ecosystem': self.ecosystem, 'name': self.name}
            present_package = Package.find_by_criteria(
                self.label, package_criteria)
            logger.debug("Package contents: %s" % self.to_json())
            if present_package is None:
                ts = time.time()
                results = self.g().addV(self.label). \
                    property('vertex_label', self.label). \
                    property('ecosystem', self.ecosystem). \
                    property('name', self.name). \
                    property('package_relative_used', self.package_relative_used). \
                    property('package_dependents_count', self.package_dependents_count). \
                    property('latest_version', self.latest_version). \
                    property('last_updated', ts). \
                    toList()

                logger.debug("create() %s - results: %s" %
                             (self.label, results))

                self.last_updated = ts
                self.id = results[0].id
                logger.info("Vertex ID : %s, %s: %s" %
                            (self.id, self.label, self))
                return self.id

            else:
                logger.debug("Package exists: %s " %
                             present_package.id)
                self.last_updated = present_package.last_updated
                self.id = present_package.id
                return self.id

        except Exception as e:
            logger.error("create() failed: %s" % traceback.print_exc())
            return None

    def update(self):
        try:
            ts = time.time()
            results = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('ecosystem', self.ecosystem).\
                property('name', self.name).\
                property('package_relative_used', self.package_relative_used).\
                property('package_dependents_count', self.package_dependents_count).\
                property('latest_version', self.latest_version).\
                property('last_updated', ts).\
                toList()

            self.last_updated = ts
            logger.debug("update() %s - results: %s" % (self.label, results))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))

            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None

    def create_version_edge(self, v):
        try:
            result = Package.edge_exists(self.id, v.id, 'has_version')

            if result == True:
                logger.info("Package-version edge present, nothing to do")
                return

            elif result == False:
                g = self.g()
                return g.V(self.id).addE("has_version").property('last_updated',time.time()).to(g.V(v.id)).toList()

        except Exception as e:
            logger.error("package_version_edge() failed: %s" % e)
            return None

    def get_versions(self):
        try:
            g = self.g()
            results = g.V(self.id).out("has_version").toList()
            logger.debug("results: %s" % results)
            return results

        except Exception as e:
            logger.error("get_versions_of_package() failed: %s" % e)
            return None

    @classmethod
    def edge_exists(cls, id1, id2, edge_label):
        try:
            g = cls.g()
            version_returned = g.V(id1).outE(
                edge_label).inV().hasId(id2).toList()
            if len(version_returned) == 0:
                return False
            return True

        except Exception as e:
            msg = "edge_exists() failed: %s" % e
            logger.error(msg)
            tb = traceback.format_exc()
            logger.error("EDGE_EXISTS failure  %s" % tb)
            raise RuntimeError(msg)

    def add_github_details_as_attr(self, github_result):

        logger.debug("reached add_github_details_as_attributes")
        self.github_details = github_result
        if github_result.details is not None:
            ts = time.time()
            details = github_result.details
            self.gh_stargazers = details.stargazers_count
            self.gh_forks = details.forks_count
            self.gh_issues_last_year_opened = details.updated_issues.year.opened
            self.gh_issues_last_year_closed = details.updated_issues.year.closed
            self.gh_issues_last_month_opened = details.updated_issues.month.opened
            self.gh_issues_last_month_closed = details.updated_issues.month.closed
            self.gh_prs_last_year_opened = details.updated_pull_requests.year.opened
            self.gh_prs_last_year_closed = details.updated_pull_requests.year.closed
            self.gh_prs_last_month_opened = details.updated_pull_requests.month.opened
            self.gh_prs_last_month_closed = details.updated_pull_requests.month.closed
            try:
                results = self.g().V(self.id). \
                    property('gh_stargazers', details.stargazers_count). \
                    property('gh_forks', details.forks_count). \
                    property('gh_issues_last_year_opened', details.updated_issues.year.opened). \
                    property('gh_issues_last_year_closed', details.updated_issues.year.closed ). \
                    property('gh_issues_last_month_opened', details.updated_issues.month.opened). \
                    property('gh_issues_last_month_closed', details.updated_issues.month.closed). \
                    property('gh_prs_last_year_opened', details.updated_pull_requests.year.opened). \
                    property('gh_prs_last_year_closed', details.updated_pull_requests.year.closed). \
                    property('gh_prs_last_month_opened', details.updated_pull_requests.month.opened). \
                    property('gh_prs_last_month_closed', details.updated_pull_requests.month.closed). \
                    property('last_updated', ts).\
                    toList()
                self.last_updated = ts
                logger.debug("add_github_details_as_attr() %s - results: %s" % (self.label, results))
                logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))

            except Exception as e:
                logger.error("add_github_details_as_attr() failed: %s" % e)

        return self.github_details



