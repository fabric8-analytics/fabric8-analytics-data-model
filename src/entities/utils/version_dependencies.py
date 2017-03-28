from entities.package import Package
from entities.version import Version


def get_dependencies(dependency_data):
    dep_list = {}
    if 'details' in dependency_data and len(dependency_data["details"]) != 0:
        value = dependency_data["details"][0]
    else:
        value = dependency_data

    if "dependencies" in value and value["dependencies"] is not None:
        dep_list["direct_dependency"] = value["dependencies"]
    if "devel_dependencies" in value and value["devel_dependencies"] is not None:
        dep_list["devel_dependency"] = value["devel_dependencies"]

    return dep_list

# TODO: Semver resolution for npm package.json


def load_dependencies(ecosystem, dependency_data):
    dependency_pck_list = []
    dependency_ver_list = []
    dependency_type = []
    dependencies = get_dependencies(dependency_data)

    for dep_type, dep_list in dependencies.items():
        for d in dep_list:
            splits = d.split(" ")

            (n, v) = ("", "")
            if len(splits) >= 1:
                n = splits[0]
            if len(splits) >= 2:
                v = splits[1]

            pck_criteria_dict = {'ecosystem': ecosystem, 'name': n}
            pck_dep = Package.find_by_criteria('Package', pck_criteria_dict) or Package(ecosystem, n)

            ver_criteria_dict = {'pecosystem': ecosystem, 'pname': n, 'version': v}
            ver_dep = Version.find_by_criteria('Version', pck_dep, ver_criteria_dict) or Version(pck_dep, v)

            dependency_pck_list.append(pck_dep)
            dependency_ver_list.append(ver_dep)
            dependency_type.append(dep_type)

    return dependency_pck_list, dependency_ver_list, dependency_type
