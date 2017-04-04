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
    def populate_from_json(cls, input_json):

        # NPM packages with dependencies, versions i.e. Package version
        # insertion
        logger.info("Instantiating package ...")
        package = Package.load_from_json(input_json)
        logger.info("Saving package ...")
        pkg_id = package.save()
        logger.info(" Package node ID: %s" % pkg_id)

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

