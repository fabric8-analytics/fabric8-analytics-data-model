from entities.package import Package
from entities.version import Version
from entities.support_vectors import LicenseDetails, SecurityDetails
from entities.github_details import GithubResult
from entities.people import Person, Author, Contributor
from entities.utils import get_values as gv
from entities.utils import version_dependencies as vdv

import logging
import config
from graph_manager import BayesianGraph

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)

serve_static_json = gv.read_from_file('test/data/npm--serve-static-1.7.1.json')


def test_create_package_entity():
    p = Package()
    assert (p.id is None)
    assert (p.label == "Package")
    assert p.last_updated is None

    packages = Package.find_all()
    assert (len(packages) == 0)

    p = Package.load_from_file('test/data/npm--serve-static-1.7.1.json')

    r = p.save()
    assert (r is not None)
    ls_before = p.last_updated
    assert ls_before is not None
    assert (Package.count() == 1)

    criteria_dict = {'ecosystem' : 'npm', 'name' : 'serve-static'}
    p2 = Package.find_by_criteria('Package', criteria_dict)
    assert p2.last_updated == p.last_updated

    p.save()  # must be an update
    assert (Package.count() == 1)
    ls_after = p.last_updated
    assert ls_after >= ls_before
    
    p.create()  # duplicate should not create new node
    assert (Package.count() == 1)
    Package.delete_by_id(p.id)

    assert (Package.count() == 0)


def test_version_entity():
    p = Package.load_from_json(serve_static_json)
    p.save()

    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    assert (Version.count() == 1)
    ls_before = v.last_updated
    assert ls_before is not None

    criteria_dict = {'pecosystem' : 'npm', 'pname' : 'serve-static', 'version' : '1.7.1'}
    v2 = Version.find_by_criteria('Version', p, criteria_dict)
    assert v2.last_updated == v.last_updated

    v.save()
    ls_after = v.last_updated
    assert (Version.count() == 1)
    assert ls_after >= ls_before
    assert v.last_updated >= v2.last_updated

    test_packaged_in = ['nodejs-serve-static']
    test_published_in = []
    assert(all(pck in test_packaged_in for pck in v.is_packaged_in))
    assert(all(pub in test_published_in for pck in v.is_published_in))

    # now create an edge
    edge_count_before = Package.edge_count()
    p.create_version_edge(v)
    edge_count_after = Package.edge_count()
    assert (edge_count_after == edge_count_before + 1)

    # now try to create an edge again
    edge_count_before = Package.edge_count()
    p.create_version_edge(v)
    edge_count_after = Package.edge_count()
    assert (edge_count_after == edge_count_before)

    # this should return all versions associated with this package
    p_versions = p.get_versions()
    assert (len(p_versions) == 1)

    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_support_vector_license():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    license_data = serve_static_json["analyses"]["source_licenses"]
    license_details_list, license_counts_list, _ = LicenseDetails.load_from_json(
        license_data)
    ts_list = []
    for license_detail, license_count in zip(license_details_list, license_counts_list):
        license_detail.save()
        assert license_detail.last_updated is not None
        ts_list.append(license_detail.last_updated)
        v.add_license_edge(license_detail, license_count)


    assert (LicenseDetails.count() == 1)

    new_license_detail = LicenseDetails(name='MITNFA')
    new_license_detail.save()
    assert new_license_detail.last_updated >= ts_list[0]

    # Duplicate license should not be inserted
    assert (LicenseDetails.count() == 1)

    for l_id in license_details_list:
        LicenseDetails.delete_by_id(l_id.id)
        LicenseDetails.delete_by_id(new_license_detail.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_support_vector_security():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    security_data = serve_static_json["analyses"]["security_issues"]
    security_list, cvss_score = SecurityDetails.load_from_json(security_data)
    ts_list = []
    for s, cvss in zip(security_list, cvss_score):
        s.save()
        assert s.last_updated is not None
        ts_list.append(s.last_updated)
        v.add_security_edge(s, cvss)

    security_before = SecurityDetails.count()
    assert(security_before == 1)

    present_security = SecurityDetails.find_by_criteria('CVE', {'cve_id':'CVE-2015-1164'})
    assert(len(present_security.references) == 5)
    ref_list = ["https://github.com/expressjs/serve-static/issues/26", 
                "https://bugzilla.redhat.com/show_bug.cgi?id=1181917",
                "http://xforce.iss.net/xforce/xfdb/99936",
                "http://www.securityfocus.com/bid/72064",
                "http://nodesecurity.io/advisories/serve-static-open-redirect"    
                ]
    assert(all(r in ref_list for r in present_security.references))            

    repeat_security_detail = SecurityDetails(
        cve_id='CVE-2015-1164', cvss=4.3, summary='')
    repeat_security_detail.issue_has_access('authentication','')
    repeat_security_detail.issue_has_access('vector','NETWORK')
    repeat_security_detail.issue_has_access('complexity','MEDIUM')
    repeat_security_detail.issue_has_impact('integrity','partial')
    repeat_security_detail.issue_has_impact('confidentiality','')
    repeat_security_detail.issue_has_impact('availability','')
    
    repeat_security_detail.save()
    assert repeat_security_detail.id == s.id
    assert repeat_security_detail.last_updated >= ts_list[0]
    assert(SecurityDetails.count() == 1)

    for s in security_list:
        SecurityDetails.delete_by_id(s.id)

    SecurityDetails.delete_by_id(repeat_security_detail.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_support_vector_github_detail():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    github_data = serve_static_json["analyses"]["github_details"]
    github_result = GithubResult.load_from_json(github_data)
    assert github_result.last_updated is None

    v.add_edge_github_details(github_result)
    ls_before = github_result.last_updated
    assert (GithubResult.count() == 1)

    count_before = len(v.get_version_out_edge('has_github_details'))
    assert count_before == 1


    #try adding the edge again
    v.add_edge_github_details(github_result)
    count_after = len(v.get_version_out_edge('has_github_details'))
    ls_after = github_result.last_updated
    assert count_before == count_after
    assert ls_after >= ls_before

    GithubResult.delete_by_id(github_result.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_person_author():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    authors_data = serve_static_json["analyses"]["metadata"]
    authors_list = Author.load_from_json(authors_data)
    ts_list = []
    for a in authors_list:
        a.save()
        assert a.last_updated is not None
        ts_list.append(a.last_updated)
        v.add_edge_author(a)

    author_before = Author.count()
    assert (author_before == 1)

    author_detail = Author(name='Douglas Christopher Wilson',
                           email='doug@somethingdoug.com')
    author_detail.save()
    assert author_detail.last_updated >= a.last_updated
    assert (Author.count() == 1)

    for a in authors_list:
        Author.delete_by_id(a.id)
        
    Author.delete_by_id(author_detail.id)
    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_person_contributor():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    assert p.last_updated is not None
    assert v.last_updated is not None

    contributors_data = serve_static_json["analyses"]["metadata"]
    contributors_list = Contributor.load_from_json(contributors_data)
    for c in contributors_list:
        c.save()
        assert c.last_updated is not None
        v.add_edge_contributor(c)

    assert (Contributor.count() == 0)

    for c in contributors_list:
        Contributor.delete_by_id(c.id)

    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)


def test_version_dependencies():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)
    dependency_data = serve_static_json["analyses"]["metadata"]
    dependency_pck_list, dependency_ver_list, dependency_type = \
        vdv.load_dependencies(v.ecosystem_package.ecosystem, dependency_data)
    for d_pck, d_ver, d_type in zip(dependency_pck_list, dependency_ver_list, dependency_type):
        d_pck.save()
        d_ver.save()
        d_pck.create_version_edge(d_ver)
        v.add_edge_dependency(d_ver, d_type)

    assert(Version.count_dependency(v.id) == 8)
    assert (Version.count() + Package.count() == 18)

    for pd, vd in zip(dependency_pck_list, dependency_ver_list):
        Version.delete_by_id(vd.id)
        Package.delete_by_id(pd.id)

    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)

