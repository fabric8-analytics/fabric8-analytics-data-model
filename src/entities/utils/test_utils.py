from entities.package import Package
from entities.version import Version
from entities.support_vectors import LicenseDetails, SecurityDetails
from entities.github_details import GithubResult
from entities.people import Author, Contributor
from entities.utils import get_values as gv
from entities.utils import version_dependencies as vdv


def load_package_version_values(filename):

    input_json = gv.read_from_file(filename)

    objpackage = Package.load_from_json(input_json)

    objversion = Version.load_from_json(input_json, objpackage)

    github_data = input_json["analyses"]["github_details"]
    github_result = GithubResult.load_from_json(github_data)
    objversion.github_details = github_result

    authors_data = input_json["analyses"]["metadata"]
    authors_list = Author.load_from_json(authors_data)
    for objauthor in authors_list:
        objversion.version_authored_by(objauthor)

    contributors_data = input_json["analyses"]["metadata"]
    contributor_list = Contributor.load_from_json(contributors_data)
    for objcontributor in contributor_list:
        objversion.version_contributed_by(objcontributor)

    license_data = input_json["analyses"]["source_licenses"]
    license_details_list, license_counts_list, license_names = LicenseDetails.load_from_json(
        license_data)
    for objlicense, license_count in zip(license_details_list, license_counts_list):
        objversion.version_covered_under(objlicense, license_count)

    objversion.licenses = license_names

    dependency_data = input_json["analyses"]["metadata"]
    _, dependency_ver_list, dependency_type = \
        vdv.load_dependencies(
            objversion.ecosystem_package.ecosystem, dependency_data)
    for d_ver, d_type in zip(dependency_ver_list, dependency_type):
        objversion.version_depends_on(d_ver, d_type)

    security_data = input_json["analyses"]["security_issues"]
    security_list, __ = SecurityDetails.load_from_json(security_data)
    for objsecurity in security_list:
        objversion.version_has_nvd_issues(objsecurity)

    return objversion
