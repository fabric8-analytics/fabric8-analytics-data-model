from entities.entity_base import EntityBase
from entities.package import Package
from entities.code_metrics import CodeMetricsResult, CodeMetricsLanguage
from entities.utils import get_values as gv
import config
import re
import logging
import time

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


class Version(EntityBase):

    def __init__(self, package,version='', hash_values='', description='', dependents_count=0,
                 shipped_as_downstream=False,
                 github_details=0, **add_data):
        super(Version, self).__init__()
        self.ecosystem_package = package
        self.version = version
        self.hash_values = hash_values
        self.authored_by = []
        self.contributed_by = []
        self.description = description
        self.dependents_count = dependents_count
        self.shipped_as_downstream = shipped_as_downstream
        self.depends_on = []
        self.similar_to = []
        self.covered_under = []
        self.licenses = set()
        self.has_nvd_issues = []
        self.github_details = github_details
        self.is_packaged_in = set()
        self.is_published_in = set()
        if len(add_data)>0:
            self.cve_ids = add_data.get("cve_ids", set())
            self.cvss_scores = add_data.get("cvss_scores",set())
            self.cm_loc = add_data.get("cm_loc", 0)
            self.cm_num_files = add_data.get("cm_num_files", 0)
            self.cm_avg_cyclomatic_complexity = add_data.get("cm_avg_cyclomatic_complexity", 0.0)
            self.relative_used = add_data.get("relative_used", "")
        self.last_updated = None

    def version_depends_on(self, version, dependency_type=''):
        self.depends_on.append(
            {"version": version, "dependency_type": dependency_type})

    def version_similar_to(self, version, similarity_score=''):
        self.similar_to.append(
            {"version": version, "similarity_score": similarity_score})

    def version_covered_under(self, license, license_count=''):
        self.covered_under.append(
            {"license": license, "license_count": license_count})

    def version_authored_by(self, person):
        self.authored_by.append(person)

    def version_contributed_by(self, person):
        self.contributed_by.append(person)

    def version_has_nvd_issues(self, security):
        self.has_nvd_issues.append(security)

    @classmethod
    def load_from_file(cls, file_name):
        input_json = gv.read_from_file(file_name)
        return cls.load_from_json(input_json)

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
    def count_dependency(cls, version_id):
        try:
            return cls.g().V(version_id).outE().hasLabel("depends_on").count().toList()[0]

        except Exception as e:
            logger.error("count_dependency() for version failed: %s" % e)
            return None

    @classmethod
    def load_from_json(cls, input_json, package=None):
        eco = package.ecosystem
        objversion = Version(package,
                             version=gv.get_version(input_json),
                             hash_values=gv.get_hashes(input_json),
                             description=gv.get_description(input_json),
                             dependents_count=gv.get_version_dependents_count(
                                 input_json),
                             shipped_as_downstream=gv.is_shipped_as_downstream(input_json, eco))
        downstream_pck_names = gv.packed_in_downstream(
            input_json, eco)
        downstream_channels = gv.published_in_downstream(input_json, eco)
        objversion.is_packaged_in = downstream_pck_names
        objversion.is_published_in = downstream_channels
        return objversion

    def delete(self):
        try:
            if self.id is not None:
                return self.g().V(self.id).drop().toList()

        except Exception as e:
            logger.error("delete() failed: %s" % e)
            return None

    @classmethod
    def delete_all(cls):
        try:
            return cls.g().V().has('vertex_label', cls._get_label()).drop().toList()

        except Exception as e:
            logger.error("delete all() failed: %s" % e)
            return None

    def save(self):
        package_criteria = {
            'ecosystem': self.ecosystem_package.ecosystem, 'name': self.ecosystem_package.name}
        pck_obj = Package.find_by_criteria('Package', package_criteria)
        if pck_obj is None:
            logger.error(
                "create() failed because package node does not exists")
            return None
        version_criteria = {'pecosystem': self.ecosystem_package.ecosystem,
                            'pname': self.ecosystem_package.name, 'version': self.version}
        present_version = Version.find_by_criteria(
                self.label, pck_obj, version_criteria)
        if present_version is None:
            return self.create()
        else:
            self.id = present_version.id
            return self.update()

    @classmethod
    def return_entity_obj(cls, package, version, description, dependents_count, shipped_as_downstream, licenses, packaged_in, published_in, id, last_updated, **add_data_dict):
        objversion = Version(package, version,
                            description, dependents_count, shipped_as_downstream, **add_data_dict)
        objversion.id = id
        objversion.licenses = licenses
        objversion.is_packaged_in = packaged_in
        objversion.is_published_in = published_in
        objversion.last_updated = last_updated
        return objversion

    @classmethod
    def find_by_criteria(cls, label, pck_obj, criteria_dict):
        add_data_dict = {}
        try:
            query = cls.g().V().has('vertex_label', label)
            for k, v in criteria_dict.items():
                query = query.has(k, v)
            check_ver = query.toList()
            logger.debug("query sent:------ %s" % query)
            logger.debug("query_result:----- %s" % check_ver)
            if len(check_ver) == 0:
                return None
            else:
                values = cls.g().V(check_ver[0].id).valueMap().toList()[0]
                add_data_list = ["cm_loc","cm_num_files","cm_avg_cyclomatic_complexity","relative_used", "cve_ids"]
                for each in add_data_list:
                    if each in values.keys():
                        if each is "cve_ids":
                            add_data_dict[each]=values.get(each)
                        else:
                            add_data_dict[each]=values.get(each)[0]

                return cls.return_entity_obj(pck_obj, values.get('version')[0],
                                             values.get('description')[0],
                                             values.get('dependents_count')[0],
                                             values.get('shipped_as_downstream')[0],
                                             values.get('licenses', '[]'),
                                             values.get('is_packaged_in'),
                                             values.get('is_published_in'),
                                             check_ver[0].id,  values.get('last_updated')[0], **add_data_dict)

        except Exception as e:
            logger.error("find_by_criteria() failed: %s" % e)
            return None

    def create(self):
        logger.debug("create() %s - data:\n%s\n" %
                     (self.label, self.to_json()))

        if self.ecosystem_package is None:
            logger.error("create() failed because ecosystem_package is None")
            return None
        package_criteria = {
            'ecosystem': self.ecosystem_package.ecosystem, 'name': self.ecosystem_package.name}
        pck_obj = Package.find_by_criteria('Package', package_criteria)
        if pck_obj is None:
            logger.error(
                "create() failed because package node does not exists")
            return None

        try:
            version_criteria = {'pecosystem': self.ecosystem_package.ecosystem,
                                'pname': self.ecosystem_package.name, 'version': self.version}
            present_version = Version.find_by_criteria(
                self.label, pck_obj, version_criteria)
            if present_version is None:
                ts = time.time()
                query = self.g().addV(self.label). \
                    property('vertex_label', self.label). \
                    property('pname', self.ecosystem_package.name). \
                    property('pecosystem', self.ecosystem_package.ecosystem). \
                    property('version', self.version). \
                    property('description', self.description). \
                    property('dependents_count', self.dependents_count). \
                    property('shipped_as_downstream', self.shipped_as_downstream). \
                    property('last_updated', ts)

                for pck in self.is_packaged_in:
                    query.property('is_packaged_in', pck)

                for pub in self.is_published_in:
                    query.property('is_published_in', pub)

                results = query.toList()

                logger.debug("create() %s - results: %s" %
                             (self.label, results))

                self.last_updated = ts
                self.id = results[0].id
                logger.debug("results: %s" % (results))
                logger.info("Vertex ID : %s, %s: %s" %
                            (self.id, self.label, self))
                return self.id

            else:
                logger.debug("Version exists: %s " %
                             present_version.id)
                self.last_updated = present_version.last_updated
                self.id = present_version.id
                return self.id

        except Exception as e:
            logger.error("create() failed: %s" % e)
            return None

    def update(self):
        try:
            ts = time.time()
            query = self.g().V(self.id). \
                property('vertex_label', self.label). \
                property('pname', self.ecosystem_package.name). \
                property('pecosystem', self.ecosystem_package.ecosystem). \
                property('version', self.version). \
                property('description', self.description). \
                property('dependents_count', self.dependents_count). \
                property('shipped_as_downstream', self.shipped_as_downstream). \
                property('last_updated', ts)

            for pck in self.is_packaged_in:
                query.property('is_packaged_in', pck)

            for pub in self.is_published_in:
                query.property('is_published_in', pub)

            results = query.toList()    
            self.last_updated = ts
            logger.debug("update() %s - results: %s" % (self.label, results))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))
            return self.id

        except Exception as e:
            logger.error("update() failed: %s" % e)
            return None

    def add_license_edge(self, license_detail, license_count):
        try:
            result = Version.edge_exists(
                self.id, license_detail.id, 'licensed_under')
            if result == True:
                logger.info("version-license edge present, nothing to do")
                return
            elif result == False:
                g = self.g()
                results = g.V(self.id).\
                    addE('licensed_under').\
                    property('license_count', license_count).\
                    property('last_updated', time.time()).\
                    to(g.V(license_detail.id)).\
                    toList()

                logger.debug("add_license_edge(): %s - results: %s" %
                             (self.label, results))
                return results

        except Exception as e:
            logger.error("add_edge_version_license_data failed: %s" % e)
            return None

    def add_security_edge(self, security_detail, cvss):
        try:
            result = Version.edge_exists(
                self.id, security_detail.id, 'contains_cve')
            if result == True:
                logger.info("version-security edge present, nothing to do")
                return
            elif result == False:
                g = self.g()
                results = g.V(self.id).\
                    addE('contains_cve').\
                    property('cvss', cvss).\
                    property('last_updated', time.time()).\
                    to(g.V(security_detail.id)).\
                    toList()

                logger.debug("add_security_edge(): %s - results: %s" %
                             (self.label, results))
                return results

        except Exception as e:
            logger.error("add_edge_version_security_data failed: %s" % e)
            return None

    def add_edge_github_details(self, github_result):
        try:
            g = self.g()
            query = g.V(self.id).outE('has_github_details').inV()
            results = query.toList()
            if len(results) == 0:
                github_result.create()
                results = g.V(self.id). \
                    addE('has_github_details'). \
                    property('last_updated', time.time()).\
                    to(g.V(github_result.id)). \
                    toList()

                logger.debug("add_edge_github_details(): %s - results: %s" %
                             (self.label, results))
                return github_result
            else:
                github_result.id = results[0].id
                github_result.update()
                return github_result

        except Exception as e:
            logger.error("add_edge_version_github_details failed: %s" % e)
            return None


    def add_edge_author(self, author):
        try:
            result = Version.edge_exists(
                self.id, author.id, 'authored_by')
            if result == True:
                logger.info("version-author edge present, nothing to do")
                return
            elif result == False:
                g = self.g()
                results = g.V(self.id). \
                    addE('authored_by'). \
                    property('last_updated', time.time()).\
                    to(g.V(author.id)). \
                    toList()

                logger.debug("add_edge_author(): %s - results: %s" %
                             (self.label, results))
                return results

        except Exception as e:
            logger.error("add_edge_version_authored_by  failed: %s" % e)
            return None

    def add_edge_contributor(self, contributor):
        try:
            result = Version.edge_exists(
                self.id, contributor.id, 'contributed_by')
            if result == True:
                logger.info("version-contributor edge present, nothing to do")
                return
            elif result == False:
                g = self.g()
                results = g.V(self.id). \
                    addE('contributed_by'). \
                    property('last_updated', time.time()).\
                    to(g.V(contributor.id)). \
                    toList()

                logger.debug("add_edge_contributor(): %s - results: %s" %
                             (self.label, results))
                return results

        except Exception as e:
            logger.error("add_edge_version_contributed_by failed: %s" % e)
            return None

    def add_edge_dependency(self, dependency, dependency_type):
        try:
            result = Version.edge_exists(
                self.id, dependency.id, 'depends_on', {'dependency_type': dependency_type})
            if result == True:
                logger.info(
                    "version-version-dependency-dependency_type edge present, nothing to do")
                return
            elif result == False:
                g = self.g()
                results = g.V(self.id).\
                    addE('depends_on').\
                    property('dependecy_type', dependency_type).\
                    property('last_updated', time.time()).\
                    to(g.V(dependency.id)).\
                    toList()

                logger.debug("d_dependency_edge(): %s - results: %s" %
                             (self.label, results))
                return results

        except Exception as e:
            logger.error(
                "add_edge_version_depends_on_version all failed: %s" % e)
            return None

    def add_code_metrics_edge(self, code_metrics):
        try:
            g = self.g()
            query = g.V(self.id).outE('has_code_metrics').inV()
            results = query.toList()
            if len(results) == 0:
                code_metrics.create()
                results = g.V(self.id).\
                    addE('has_code_metrics').\
                    property('last_updated', time.time()).\
                    to(g.V(code_metrics.id)).\
                    toList()

                logger.debug("add_code_metrics_edge(): %s - results: %s" %
                             (self.label, results))
                return code_metrics
            else:
                    code_metrics.id =results[0].id
                    code_metrics.update()
                    return code_metrics

        except Exception as e:
            logger.error("add_code_metrics_edge() failed: %s" % e)
            return None

    @classmethod
    def edge_exists(cls, id1, id2, edge_label, criteria_dict={}):
        try:
            g = cls.g()
            query = g.V(id1).outE(
                edge_label).inV().hasId(id2)
            if len(criteria_dict) > 0:
                for k, v in criteria_dict.items():
                    query.has(k, v)

            value_returned = query.toList()
            if len(value_returned) == 0:
                return False
            return True

        except Exception as e:
            msg = "edge_exists() failed: %s" % e
            logger.error(msg)
            raise RuntimeError(msg)


    def add_additional_data_as_attr(self, code_metrics):

        logger.debug("reached add_details_as_attributes")
        cm_details = {}
        cm_details["cm_loc"] = code_metrics.summary.total_lines
        cm_details["cm_num_files"] = code_metrics.summary.total_files

        code_complexity = 0.0
        for each in code_metrics.details.languages:
            code_complexity += each.average_cyclomatic_complexity
        cm_details["cm_avg_cyclomatic_complexity"] = code_complexity/len(code_metrics.details.languages)
        #cm_details["relative_used"] = code_metrics.relative_used # what should go here

        self.add_details = cm_details

        # self.licences = self.add_details.get("licences", [])
        #self.cve_ids = self.add_details.get("cve_ids", [])
        self.cm_loc = self.add_details.get("cm_loc", 0)
        self.cm_num_files = self.add_details.get("cm_num_files", 0)
        self.cm_avg_cyclomatic_complexity = self.add_details.\
            get("cm_avg_cyclomatic_complexity", 0.0)
        self.relative_used = self.add_details.get("relative_used", "")
        try:
            ts = time.time()
            query = self.g().V(self.id). \
                property('cm_loc', self.cm_loc). \
                property('cm_num_files', self.cm_num_files). \
                property('cm_avg_cyclomatic_complexity', self.cm_avg_cyclomatic_complexity). \
                property('relative_used', self.relative_used). \
                property('last_updated', ts)

            results = query.toList()        

            self.last_updated = ts
            logger.debug("add_additional_details_as_attr() %s - results: %s" % (self.label, results))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))

        except Exception as e:
            logger.error("add_additional_details_as_attr() failed: %s" % e)

        return self.add_details



    def add_license_attribute(self, licenses):
        try:
            self.licenses = licenses
            logger.debug("Saving license under version")
            ts = time.time()
            query = self.g().V(self.id).\
                            property('last_updated', ts)
                            
            for l in self.licenses:
                query.property('licenses', l)

            results = query.toList()                    
            
            self.last_updated = ts
            logger.debug("add_license_as_attr() %s - results: %s" %
                         (self.label, results))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))
            return self.licenses
        except Exception as e:
            logger.error("add_license_attributes() failed: %s" % e)
            return None


    def add_cve_ids(self, cvss, cve_id):
        cve_to_add = []
        cve = ""
        try:
            if cvss and cve_id is not None:
                cve = str(cve_id) + ":" + str(cvss)
                self.g().V(self.id). \
                property('cve_ids', cve). \
                toList()
                self.cve_ids.add(cve)
            logger.debug("add_cve_ids() %s" % (self.label))
            logger.info("Vertex ID : %s, %s: %s" % (self.id, self.label, self))
        except Exception as e:
            logger.error("add_additional_details_as_attr() failed: %s" % e)


        return cve


    def add_blackduck_cve_edge(self, security_detail):
        try:
            g = self.g()
            results = g.V(self.id).\
                addE('has_bl_cve').\
                property('last_updated', time.time()).\
                to(g.V(security_detail.id)).\
                toList()

            logger.debug("add_blackduck_cve_edge(): %s - results: %s" %
                         (self.label, results))
            return results

        except Exception as e:
            logger.error("add_blackduck_cve_edge() failed: %s" % e)
            return None

    def get_version_out_edge(self, edge_label):
            try:
                g = self.g()
                results = g.V(self.id).out(edge_label).toList()
                logger.debug("results: %s" % results)
                return results

            except Exception as e:
                logger.error("get_versions_of_package() failed: %s" % e)
                return None
