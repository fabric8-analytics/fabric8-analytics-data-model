from entities.package import Package
from entities.utils import get_values as gv
from entities.version import Version
from entities.support_vectors import LicenseDetails
import re


serve_static_json = gv.read_from_file('test/data/npm--serve-static-1.7.1.json')


def test_add_license_attr():
    p = Package.load_from_json(serve_static_json)
    p.save()
    v = Version.load_from_json(serve_static_json, package=p)
    v.save()
    p.create_version_edge(v)

    ts1 = v.last_updated
    assert p.last_updated is not None
    assert ts1 is not None

    license_data = serve_static_json["analyses"]["source_licenses"]
    _, _, licenses = LicenseDetails.load_from_json(
        license_data)
    v.add_license_attribute(licenses)
    assert v.last_updated >= ts1

    version_criteria = {
        'pecosystem': v.ecosystem_package.ecosystem, 'pname': v.ecosystem_package.name, 'version': v.version}
    present_version = Version.find_by_criteria('Version', p, version_criteria)
    assert present_version.last_updated == v.last_updated
    assert (len(present_version.licenses) == 1)
    test_set = ['MITNFA']

    assert present_version.licenses == test_set

    Version.delete_by_id(v.id)
    Package.delete_by_id(p.id)

