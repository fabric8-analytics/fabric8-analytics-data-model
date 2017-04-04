from entities.utils import test_utils
from entities.version import Version
import logging

logger = logging.getLogger(__name__)


def test_package_version_basic_properties():
    test_npm_abbrev_1_0_4 = test_utils.load_package_version_values(
        "test/data/npm--abbrev-1.0.4.json")
    assert (test_npm_abbrev_1_0_4.ecosystem_package.name == "abbrev" and
            test_npm_abbrev_1_0_4.ecosystem_package.ecosystem == "npm")
    assert (test_npm_abbrev_1_0_4.ecosystem_package.package_relative_used == "not used")
    assert (test_npm_abbrev_1_0_4.ecosystem_package.package_dependents_count == 204)
    assert (test_npm_abbrev_1_0_4.authored_by[0].name == "Isaac Z. Schlueter")
    assert (test_npm_abbrev_1_0_4.contributed_by == [])
    assert (test_npm_abbrev_1_0_4.dependents_count == -1)
    assert (test_npm_abbrev_1_0_4.ecosystem_package.latest_version == "1.0.9")
    assert (test_npm_abbrev_1_0_4.description ==
            "like rubys abbrev module but in js")

    test_npm_serve_static_1_7_1 = test_utils.load_package_version_values(
        "test/data/npm--serve-static-1.7.1.json")
    assert (test_npm_serve_static_1_7_1.ecosystem_package.name == "serve-static"
            and test_npm_serve_static_1_7_1.ecosystem_package.ecosystem == "npm")
    assert (test_npm_serve_static_1_7_1.ecosystem_package.package_relative_used == "often")
    assert (test_npm_serve_static_1_7_1.ecosystem_package.package_dependents_count == 2037)
    assert (test_npm_serve_static_1_7_1.authored_by[
            0].name == "Douglas Christopher Wilson")
    assert (test_npm_serve_static_1_7_1.contributed_by == [])
    assert (test_npm_serve_static_1_7_1.dependents_count == 18)
    assert (test_npm_serve_static_1_7_1.ecosystem_package.latest_version == "1.11.1")
    assert (test_npm_serve_static_1_7_1.description == "serve static files")


def test_version_dependency():
    test_npm_abbrev_1_0_4 = test_utils.load_package_version_values(
        "test/data/npm--abbrev-1.0.4.json")
    assert (len(test_npm_abbrev_1_0_4.depends_on) == 0)

    test_npm_serve_static_1_7_1 = test_utils.load_package_version_values(
        "test/data/npm--serve-static-1.7.1.json")
    dep_list = ["escape-html",
                "utils-merge",
                "parseurl",
                "send"]
    checker = [
        v["version"].ecosystem_package.name in dep_list for v in test_npm_serve_static_1_7_1.depends_on]
    logger.debug("Serve-static dep values %s" % checker)
    assert all(checker)
    assert (len(test_npm_serve_static_1_7_1.depends_on) == 4)


def test_version_security():
    test_npm_abbrev_1_0_4 = test_utils.load_package_version_values(
        "test/data/npm--abbrev-1.0.4.json")
    assert(len(test_npm_abbrev_1_0_4.has_nvd_issues) == 0)

    test_npm_serve_static_1_7_1 = test_utils.load_package_version_values(
        "test/data/npm--serve-static-1.7.1.json")
    assert (len(test_npm_serve_static_1_7_1.has_nvd_issues) == 1)
    assert (test_npm_serve_static_1_7_1.has_nvd_issues[
        0].cve_id == "CVE-2015-1164")
    assert (test_npm_serve_static_1_7_1.has_nvd_issues[
        0].access.get('vector').lower() == 'network')
    assert (test_npm_serve_static_1_7_1.has_nvd_issues[
        0].impact.get('availability').lower() == 'none')


def test_version_license():
    test_npm_abbrev_1_0_4 = test_utils.load_package_version_values(
        "test/data/npm--abbrev-1.0.4.json")
    assert (len(test_npm_abbrev_1_0_4.covered_under) == 1)
    assert (test_npm_abbrev_1_0_4.covered_under[0]["license"].name == "MITNFA"
            and test_npm_abbrev_1_0_4.covered_under[0]["license_count"] == 1)

    test_npm_serve_static_1_7_1 = test_utils.load_package_version_values(
        "test/data/npm--serve-static-1.7.1.json")
    assert (len(test_npm_serve_static_1_7_1.covered_under) == 1)
    assert (test_npm_serve_static_1_7_1.covered_under[0]["license"].name == "MITNFA"
            and test_npm_serve_static_1_7_1.covered_under[0]["license_count"] == 1)


def test_downstream_summary():
    test_npm_abbrev_1_0_4 = test_utils.load_package_version_values(
        "test/data/npm--abbrev-1.0.4.json")
    assert (test_npm_abbrev_1_0_4.shipped_as_downstream == True)
    assert (len(test_npm_abbrev_1_0_4.is_packaged_in) == 3)
    pck_list = ["rh-nodejs4-nodejs-abbrev",
                "nodejs010-nodejs-abbrev",
                "nodejs-abbrev"]
    checker = [
        name in pck_list for name in test_npm_abbrev_1_0_4.is_packaged_in]
    logger.debug("Abbrev packaged_in values %s" % checker)
    assert (all(checker))
    assert (len(test_npm_abbrev_1_0_4.is_published_in) == 0)

    test_npm_serve_static_1_7_1 = test_utils.load_package_version_values(
        "test/data/npm--serve-static-1.7.1.json")
    assert (test_npm_serve_static_1_7_1.shipped_as_downstream == False)
    assert (len(test_npm_serve_static_1_7_1.is_packaged_in) == 1)
    pck_list = ["nodejs-serve-static"]
    checker = [
        name in pck_list for name in test_npm_serve_static_1_7_1.is_packaged_in]
    logger.debug("Serve-static packaged_in values %s" % checker)
    assert (all(checker))
    assert (len(test_npm_serve_static_1_7_1.is_published_in) == 0)
