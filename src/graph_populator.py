# from graph_manager import BayesianGraph
from entities.package import Package
from entities.version import Version
from entities.graph_metadata import GraphMetaData
from entities.people import Author, Contributor
from entities.github_details import GithubResult
from entities.code_metrics import CodeMetricsResult
from entities.support_vectors import LicenseDetails, SecurityDetails
from entities.utils import version_dependencies as vdv
from entities.utils import blackduck_cve as bl
import logging
import re
import time

logger = logging.getLogger(__name__)


class GraphPopulator(object):

    @classmethod
    def update_metadata(cls, input_json):
        logger.info("Instantiating graph metadata ...")

        # Note: we look for meta-data vertex with only one criteria about label
        # There is no additional criteria on properties because we want to maintain only one such vertex.
        graph_meta = GraphMetaData.find_by_criteria(GraphMetaData.__name__, {})
        if graph_meta is None:
            graph_meta = GraphMetaData.load_from_json(input_json)
        else:
            graph_meta.update_from_json(input_json)
        meta_id = graph_meta.save()
        logger.info("Graph MetaData node ID: %s" % meta_id)

    @classmethod
    def get_metadata(cls):
        return GraphMetaData.find_by_criteria(GraphMetaData.__name__, {})

    @classmethod
    def construct_version_query(cls, input_json):
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        version = input_json.get('version')
        ver_deps_count = str(input_json.get('dependents_count', -1))
        description = input_json.get('analyses', {}).get('metadata', {}).get('details', [])[0]['description']

        # Get Code Metrics Details
        count = 0
        tot_complexity = 0.0
        for lang in input_json.get('analyses', {}).get('code_metrics', {}).get('details', {}).get('languages', []):
            if lang.get('metrics', {}).get('average_cyclomatic_complexity'):
                count += 1
                tot_complexity += lang['metrics']['average_cyclomatic_complexity']
        cm_avg_cyclomatic_complexity = str(tot_complexity / count) if count > 0 else '-1'
        cm_loc = str(input_json.get('analyses', {}).get('code_metrics', {}).get('summary', {}).get('total_lines', -1))
        cm_num_files = str(input_json.get('analyses', {})
                           .get('code_metrics', {}).get('summary', {}).get('total_files', -1))

        # Get downstream details
        shipped_as_downstream = 'false'
        if len(input_json.get('analyses', {}).get('redhat_downstream', {})
                       .get('summary', {}).get('all_rhsm_product_names', [])) > 0:
            shipped_as_downstream = 'true'

        str_version = "ver = g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')" \
                      ".has('version','" + version + "').tryNext().orElseGet{graph.addVertex('pecosystem','" \
                       + ecosystem + "', 'pname','" + pkg_name + "', 'version','" + version + "', " \
                      "'vertex_label', 'Version')};" \
                      "ver.property('last_updated'," + str(time.time()) + ");" \
                      "ver.property('shipped_as_downstream'," + shipped_as_downstream + ");" \
                      "ver.property('description','" + re.sub('[^A-Za-z0-9_ ]', '', description).lower() + "');" \
                      "ver.property('dependents_count'," + ver_deps_count + ");" \
                      "ver.property('cm_num_files'," + cm_num_files + ");" \
                      "ver.property('cm_avg_cyclomatic_complexity'," + cm_avg_cyclomatic_complexity + ");" \
                      "ver.property('cm_loc'," + str(cm_loc) + ");"

        # Add license details
        licenses = input_json.get('analyses', {}).get('source_licenses', {}).get('summary', {}).get('sure_licenses', [])
        str_lic = " ".join(map(lambda x: "ver.property('licenses', '" + x + "');", licenses))
        str_version += str_lic

        # Add CVE property if it exists
        cves = []
        for cve in input_json.get('analyses', {}).get('security_issues', {}).get('details', []):
            cves.append(cve.get('id') + ":" + str(cve.get('cvss', {}).get('score')))
        str_cve = " ".join(map(lambda x: "ver.property('cve_ids', '" + x + "');", cves))

        str_version += str_cve

        return str_version

    @classmethod
    def construct_package_query(cls, input_json):
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')

        # Get Metadata Details
        latest_version = input_json.get('latest_version') or ''
        pkg_deps_count = str(input_json.get('package_info', {}).get('dependents_count', -1))
        pkg_usage = input_json.get('package_info', {}).get('relative_usage', 'NA')

        # Get Github Details
        gh_prs_last_year_opened = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                      .get('updated_pull_requests', {}).get('year', {}).get('opened', -1))
        gh_prs_last_month_opened = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                       .get('updated_pull_requests', {}).get('month', {}).get('opened', -1))
        gh_prs_last_year_closed = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                      .get('updated_pull_requests', {}).get('year', {}).get('closed', -1))
        gh_prs_last_month_closed = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                       .get('updated_pull_requests', {}).get('month', {}).get('closed', -1))
        gh_issues_last_year_opened = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                         .get('updated_issues', {}).get('year', {}).get('opened', -1))
        gh_issues_last_month_opened = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                          .get('updated_issues', {}).get('month', {}).get('opened', -1))
        gh_issues_last_year_closed = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                         .get('updated_issues', {}).get('year', {}).get('closed', -1))
        gh_issues_last_month_closed = str(input_json.get('analyses', {}).get('github_details', {}).get('details', {})
                                          .get('updated_issues', {}).get('month', {}).get('closed', -1))
        gh_forks = str(input_json.get('analyses', {})
                       .get('github_details', {}).get('details', {}).get('forks_count', -1))
        gh_stargazers = str(input_json.get('analyses', {})
                            .get('github_details', {}).get('details', {}).get('stargazers_count', -1))

        # Create the query string
        str_package = "pkg = g.V().has('ecosystem','" + ecosystem + "').has('name','" + pkg_name + "').tryNext()" \
                      ".orElseGet{graph.addVertex('ecosystem', '" + ecosystem + "', 'name', '" + pkg_name + "', " \
                      "'vertex_label', 'Package')};" \
                      "pkg.property('gh_prs_last_year_opened', " + gh_prs_last_year_opened + ");" \
                      "pkg.property('gh_prs_last_month_opened', " + gh_prs_last_month_opened + ");" \
                      "pkg.property('gh_prs_last_year_closed', " + gh_prs_last_year_closed + ");" \
                      "pkg.property('gh_prs_last_month_closed', " + gh_prs_last_month_closed + ");" \
                      "pkg.property('gh_issues_last_year_opened', " + gh_issues_last_year_opened + ");" \
                      "pkg.property('gh_issues_last_month_opened', " + gh_issues_last_month_opened + ");" \
                      "pkg.property('gh_issues_last_year_closed', " + gh_issues_last_year_closed + ");" \
                      "pkg.property('gh_issues_last_month_closed', " + gh_issues_last_month_closed + ");" \
                      "pkg.property('gh_forks', " + gh_forks + ");" \
                      "pkg.property('gh_stargazers', " + gh_stargazers + ");" \
                      "pkg.property('latest_version', '" + latest_version + "');" \
                      "pkg.property('package_relative_used', '" + pkg_usage + "');" \
                      "pkg.property('package_dependents_count', " + pkg_deps_count + ");" \
                      "pkg.property('last_updated', " + str(time.time()) + ");"

        return str_package

    @classmethod
    def create_query_string(cls, input_json):

        # NPM packages with dependencies, versions i.e. Package version
        # creation of query string
        str_gremlin = cls.construct_package_query(input_json) + \
                      cls.construct_version_query(input_json)

        # Add edge from Package to Version
        str_gremlin += "edge_c = pkg.addEdge('has_version', ver);"
        print(str_gremlin)
        return str_gremlin

    @classmethod
    def populate_from_json(cls, input_json):

        # NPM packages with dependencies, versions i.e. Package version
        # insertion
        logger.info("Instantiating package ...")
        package = Package.load_from_json(input_json)
        logger.info("Saving package ...")
        pkg_id = package.save()
        logger.info(" Package node ID: %s" % pkg_id)
        if pkg_id is None:
            return
        version = Version.load_from_json(input_json, package=package)
        ver_id = version.save()
        logger.info(" Version node ID: %s" % ver_id)
        package.create_version_edge(version)

        analyses = input_json["analyses"]
        if "dependency_snapshot" in analyses:
            dependency_snapshot = analyses["dependency_snapshot"]
            dependency_pck_list, dependency_ver_list, dependency_type = vdv.load_dependencies(
                version.ecosystem_package.ecosystem, dependency_snapshot)
            for d_pck, d_ver, d_type in zip(dependency_pck_list, dependency_ver_list, dependency_type):
                d_pck.save()
                if d_pck is None:
                    continue
                d_ver.save()
                d_pck.create_version_edge(d_ver)
                version.add_edge_dependency(d_ver, d_type)
        
        if "metadata" in analyses:
            meta_data = analyses["metadata"]
            print("  Adding authors_list")
            authors_list = Author.load_from_json(meta_data)
            for author in authors_list:
                a_id = author.save()
                print("    author ID: %s" % a_id)
                version.add_edge_author(author)

            print("  Adding contributor_list")
            contributor_list = Contributor.load_from_json(meta_data)
            for contributor in contributor_list:
                c_id = contributor.save()
                print("    contributor ID: %s" % c_id)
                version.add_edge_author(contributor)

        # License Information
        if "source_licenses" in analyses:
            print("  Adding source_licenses")
            licenses = set()
            license_data = analyses["source_licenses"]
            license_details_list, license_counts_list, licenses = LicenseDetails.load_from_json(
                license_data)
            for used_license, license_count in zip(license_details_list, license_counts_list):
                lic_id = used_license.save()
                print("    license_data ID: %s" % lic_id)
                version.add_license_edge(used_license, license_count)

            version.add_license_attribute(licenses)

        # NVD Security Information
        if "security_issues" in analyses:
            print("  Adding security_issues")
            security_data = analyses["security_issues"]
            security_list, cvss_score = SecurityDetails.load_from_json(
                security_data)
            for s, cvss in zip(security_list, cvss_score):
                ss_id = s.save()
                print("    security_data ID: %s" % ss_id)
                version.add_security_edge(s, cvss)

        # GitHub Details
        if "github_details" in analyses:
            print("  Adding github_details")
            github_data = analyses["github_details"]
            github_result = GithubResult.load_from_json(github_data)
            package.add_github_details_as_attr(github_result)
            version.add_edge_github_details(github_result)

        # Code Metrics
        if "code_metrics" in analyses:
            print("  Adding code_metrics")
            code_metrics_data = analyses["code_metrics"]
            code_metrics = CodeMetricsResult.load_from_json(code_metrics_data)
            version.add_code_metrics_edge(code_metrics)
            cm_details = {}
            cm_details["cm_loc"] = code_metrics.summary.total_lines
            cm_details["cm_num_files"] = code_metrics.summary.total_files
            code_complexity = 0
            for each in code_metrics.details.languages:
               code_complexity += each.average_cyclomatic_complexity
            cm_details["cm_avg_cyclomatic_complexity"] = code_complexity/len(code_metrics.details.languages)
            version.add_additional_data_as_attr(cm_details)

        if "blackduck" in analyses:
            print("Adding extra security info via blackduck")
            blackduck_cve = analyses["blackduck"]
            issue_list = bl.load_from_json(blackduck_cve)
            for issue in issue_list:
                bl_obj = bl.add_blackduck_issue(issue)
                version.add_blackduck_cve_edge(bl_obj.id)

