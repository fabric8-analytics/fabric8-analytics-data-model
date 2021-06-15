"""Class containing classmethods used to construct queries to the graph database."""

import logging
import re
import time
from six import string_types
from src import config
from src.utils import get_current_version, get_latest_version_non_cve
from datetime import datetime
from f8a_utils.versions import get_latest_versions_for_ep

logger = logging.getLogger(config.APP_NAME)


class GraphPopulator(object):
    """Class containing classmethods used to construct queries to the graph database."""

    @classmethod
    def construct_graph_nodes(cls, epv):
        """Create query string to create empty EPV nodes."""
        ecosystem = epv.get('ecosystem')
        pkg_name = epv.get('name')
        version = epv.get('version')
        source_repo = epv.get('source_repo', '')
        license = epv.get('license', [])
        gh_link = epv.get('gh_link', '')
        latest_version = epv.get('latest_version', '')
        if not latest_version:
            latest_version = get_latest_versions_for_ep(ecosystem, pkg_name)
        bindings = {
            "ecosystem": ecosystem,
            "name": pkg_name,
            "version": version,
            "repo": source_repo,
            "gh_link": gh_link,
            "latest": latest_version,
            "ep_count": ecosystem + "_pkg_count",
            "epv_count": ecosystem + "_ver_count",
            "last_updated": str(time.time()),
            "vertex_p": "Package",
            "vertex_c": "Count",
            "vertex_v": "Version"
        }
        if ecosystem and pkg_name and version:
            # Query to Create Package Node
            # TODO: refactor into the separate module
            pkg_str = "pkg = g.V().has('ecosystem',ecosystem).has('name', name)." \
                      "tryNext().orElseGet{g.V()." \
                      "has('vertex_label',vertex_c).choose(has(ep_count)," \
                      "sack(assign).by(ep_count).sack(sum).by(constant(" \
                      "1)).property(ep_count,sack())," \
                      "property(ep_count,1)).iterate();" \
                      "graph.addVertex('ecosystem', ecosystem, " \
                      "'name', name, 'vertex_label', vertex_p);};" \
                      "pkg.property('latest_version', latest);" \
                      "pkg.property('last_updated', last_updated);"

            # Query to Create Version Node
            # TODO: refactor into the separate module
            ver_str = "ver = g.V().has('pecosystem', ecosystem).has('pname', " \
                      "name).has('version', version).tryNext().orElseGet{" \
                      "g.V().has('vertex_label', vertex_c).choose(has(epv_count)," \
                      "sack(assign).by(epv_count).sack(sum).by(constant(" \
                      "1)).property(epv_count,sack())," \
                      "property(epv_count,1)).iterate();" \
                      "graph.addVertex('pecosystem',ecosystem, 'pname',name, " \
                      "'version', version, 'vertex_label', vertex_v);};" \
                      "ver.property('last_updated',last_updated);"
            # Add version node properties
            if source_repo:
                ver_str += "ver.property('source_repo', repo);"

            if license and len(license) > 0:
                counter = 1
                for lic in license:
                    ver_str += "ver.property('declared_licenses', lic" + str(counter) + ");"
                    bindings["lic" + str(counter)] = lic
                    counter += 1

            # Add package node properties
            if gh_link:
                pkg_str += "pkg.property('gh_link', gh_link);"

            # Query to create an edge between Package Node to Version Node
            # TODO: refactor into the separate module
            edge_str = "edge_c = g.V().has('pecosystem', ecosystem).has('pname'," \
                       "name).has('version', version).in(" \
                       "'has_version').tryNext()" \
                       ".orElseGet{pkg.addEdge('has_version', ver)};"

            return pkg_str + ver_str + edge_str, bindings
        else:
            return None, None

    @classmethod
    def sanitize_text_for_query(cls, text):
        """
        Sanitize text so it can used in queries.

        :param text: string, text to sanitize
        :return: sanitized text
        """
        if text is None:
            return ''

        if isinstance(text, list) and not text:
            return ''
        if not isinstance(text, string_types):
            raise ValueError(
                'Invalid query text: expected string, got {t}'.format(t=type(text))
            )
        # remove newlines, quotes and backslash character
        text = " ".join([line.strip() for line in text.split("\n")])
        text = re.sub("""['"]""", "", text)
        text = text.replace('\\', "")
        return text.strip()

    @classmethod
    def correct_license_splitting(cls, license_list):
        """Correct the incorrect splitting of licenses."""
        final_declared_licenses = list()
        for dl in license_list:
            dl = cls.sanitize_text_for_query(dl)
            if dl.startswith(("version", "Version", " version", " Version")):
                final_declared_licenses[-1] = final_declared_licenses[-1] + ", " + dl.strip()
            else:
                final_declared_licenses.append(dl)
        return final_declared_licenses

    @classmethod
    def construct_version_query(cls, input_json):
        """Construct the query to retrieve detailed information of given version of a package."""
        # TODO: reduce cyclomatic complexity
        # see https://fabric8-analytics.github.io/dashboard/fabric8-analytics-data-model.cc.D.html
        # issue: https://github.com/fabric8-analytics/fabric8-analytics-data-model/issues/232
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        version = cls.sanitize_text_for_query(input_json.get('version'))
        description = ''
        source_repo = input_json.get('source_repo', None)

        details_data = input_json.get('analyses', {}).get('metadata', {}).get('details', [])
        if len(details_data) > 0:
            description = details_data[0].get('description', '')
            description = cls.sanitize_text_for_query(description)

        licenses = []
        drop_props = []
        str_version = prp_version = drop_prop = ""

        # TODO: refactor into the separate module
        str_version += "ver = g.V().has('pecosystem', '{ecosystem}').has('pname', '{pkg_name}')." \
                       "has('version', '{version}').tryNext().orElseGet{{" \
                       "g.V().has('vertex_label','Count').choose(" \
                       "has('{ecosystem}_ver_count'),sack(assign).by('{ecosystem}_ver_count')." \
                       "sack(sum).by(constant(1)).property('{ecosystem}_ver_count',sack())," \
                       "property('{ecosystem}_ver_count',1)).iterate();" \
                       "graph.addVertex('pecosystem','{ecosystem}', 'pname','{pkg_name}', " \
                       "'version', '{version}', 'vertex_label', 'Version');}};" \
                       "ver.property('last_updated',{last_updated});".format(
                        ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                        last_updated=str(time.time()))

        # Add Description if not blank
        if description:
            prp_version += "ver.property('description','{description}');".format(
                description=re.sub(r'[^A-Za-z0-9_\\/\'":. ]', '', description)
            )
        # Add Source Repo if not blank
        if source_repo:
            prp_version += "ver.property('source_repo','{source_repo}');".format(
                source_repo=source_repo
            )

        # Get Metadata Details
        if 'metadata' in input_json.get('analyses', {}):
            details = input_json.get('analyses').get('metadata', {}).get('details', [])
            if details and details[0]:
                declared_licenses = []
                if details[0].get('declared_licenses'):
                    # list of license names
                    declared_licenses = details[0]['declared_licenses']
                elif details[0].get('declared_license'):
                    # string with comma separated license names
                    # see: github.com/fabric8-analytics/fabric8-analytics-data-model/issues/71
                    # TODO: Factor out this license normalization elsewhere into a module ?
                    """
                    Split multiline license string by newlines and trim whitespaces around each
                    -----
                    Apache License, Version 2.0 and
                    Common Development And Distribution License (CDDL) Version 1.0
                    -----
                    above string becomes
                    ['Apache License, Version 2.0',
                    'Common Development And Distribution License (CDDL) Version 1.0']
                    """
                    declared_str = details[0]['declared_license']

                    if "and\n" in declared_str:  # case described above
                        declared_licenses = [x.strip() for x in declared_str.split("and\n")]
                    elif "\n" in declared_str:  # avoid newlines, they break gremlin queries
                        # trim each line and then join by a space
                        no_newlines = " ".join([x.strip() for x in declared_str.split("\n")])
                        # split by comma
                        declared_licenses = [x.strip() for x in no_newlines.split(",")]
                    else:  # default behavior
                        # split by comma
                        declared_licenses = [x.strip()
                                             for x in declared_str.split(",")]
                elif ecosystem == "go" and licenses:
                    declared_licenses = licenses
                declared_licenses = cls.correct_license_splitting(
                    declared_licenses)

                # Clear declared licenses field before refreshing
                drop_props.append('declared_licenses')

                prp_version += " ".join(["ver.property('declared_licenses', '{}');".format
                                         (dl) for dl in declared_licenses])

        if len(drop_props) > 0:
            drop_prop += "g.V().has('pecosystem','{ecosystem}').has('pname','{pkg_name}')." \
                         "has('version','{version}').properties('{p}').drop().iterate();".format(
                            ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                            p="','".join(drop_props))

        str_version = drop_prop + str_version + (prp_version if prp_version else '')

        return str_version

    @classmethod
    def construct_package_query(cls, input_json):
        """Construct the query to retrieve detailed information of given package."""
        # TODO: reduce cyclomatic complexity
        # see https://fabric8-analytics.github.io/dashboard/fabric8-analytics-data-model.cc.D.html
        # issue: https://github.com/fabric8-analytics/fabric8-analytics-data-model/issues/232
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        pkg_name_tokens = re.split(r'\W+', pkg_name)
        prp_package = ""
        drop_prop = ""
        drop_props = []
        # TODO: refactor into the separate module
        str_package = "pkg = g.V().has('ecosystem','{ecosystem}').has('name', '{pkg_name}')." \
                      "tryNext().orElseGet{{g.V()." \
                      "has('vertex_label','Count').choose(has('{ecosystem}_pkg_count')," \
                      "sack(assign).by('{ecosystem}_pkg_count').sack(sum).by(constant(" \
                      "1)).property('{ecosystem}_pkg_count',sack())," \
                      "property('{ecosystem}_pkg_count',1)).iterate();" \
                      "graph.addVertex('ecosystem', '{ecosystem}', 'name', " \
                      "'{pkg_name}', 'vertex_label', 'Package'); }};" \
                      "pkg.property('last_updated', {last_updated});".format(
                        ecosystem=ecosystem, pkg_name=pkg_name, last_updated=str(time.time()))
        cur_latest_ver, cur_libio_latest_ver = get_current_version(ecosystem, pkg_name)
        cur_date = (datetime.utcnow()).strftime('%Y%m%d')
        latest_version = cls.sanitize_text_for_query(input_json.get('latest_version'))

        if latest_version:
            # If latest version dont have cve, then it becomes the latest non cve version as well
            non_cve_ver = get_latest_version_non_cve(ecosystem, pkg_name, latest_version)
            prp_package += "pkg.property('latest_non_cve_version', '{}');".format(non_cve_ver)
            prp_package += "pkg.property('latest_version', '{}');".format(latest_version)
            if latest_version != cur_latest_ver:
                prp_package += "pkg.property('latest_version_last_updated', '{}');".format(cur_date)

        # Get Github Details
        if 'github_details' in input_json.get('analyses', {}):
            gh_details = input_json.get('analyses', {})\
                .get('github_details', {}).get('details', {})

            prp_package += create_query("prs",
                                        gh_details.get("updated_pull_requests", {}), "month")
            prp_package += create_query("prs",
                                        gh_details.get("updated_pull_requests", {}), "year")

            prp_package += create_query("issues", gh_details.get("updated_issues", {}), "month")
            prp_package += create_query("issues", gh_details.get("updated_issues", {}), "year")

            prp_package += set_property(gh_details, 'forks_count', 'gh_forks')
            prp_package += set_property(gh_details, 'stargazers_count', 'gh_stargazers')
            prp_package += set_property(gh_details, 'open_issues_count', 'gh_open_issues_count')
            prp_package += set_property(gh_details, 'subscribers_count', 'gh_subscribers_count')
            prp_package += set_property(gh_details, 'subscribers_count', 'gh_subscribers_count')
            prp_package += set_property(gh_details, 'contributors_count', 'gh_contributors_count')

            gh_refreshed_on = gh_details.get('updated_on')
            if gh_refreshed_on:
                prp_package += "pkg.property('gh_refreshed_on', '{}');".format(gh_refreshed_on)

            # Add github topics
            topics = gh_details.get('topics', [])
            if topics:
                drop_props.append('topics')
                str_package += " ".join(["pkg.property('topics', '{}');".format(t)
                                         for t in topics if t])

        # Add tokens for a package
        if pkg_name_tokens:
            drop_props.append('tokens')
            str_package += " ".join(["pkg.property('tokens', '{}');".format(t)
                                     for t in pkg_name_tokens if t])

        # Refresh the properties whereever applicable
        if len(drop_props) > 0:
            drop_prop += "g.V().has('ecosystem','{ecosystem}').has('name'," \
                         "'{pkg_name}').properties('{p}').drop().iterate();".format(
                            ecosystem=ecosystem, pkg_name=pkg_name, p="','".join(drop_props))

        return drop_prop + str_package, prp_package

    @classmethod
    def create_query_string(cls, input_json):
        """Create query to get information about the package or package+version ."""
        # TODO add check of JSON against the schema

        # NPM packages with dependencies, versions i.e. Package version
        # TODO add check for existence of this attribute
        pkg_name = input_json.get('package')
        # TODO add check for existence of this attribute
        ecosystem = input_json.get('ecosystem')
        version = cls.sanitize_text_for_query(input_json.get('version'))
        # creation of query string
        str_gremlin = ""
        str_package, prp_package = cls.construct_package_query(input_json)
        if prp_package:
            str_gremlin = str_package + prp_package

        if version is not None and version != '':
            str_gremlin_version = cls.construct_version_query(input_json)
            # Add edge from Package to Version
            if str_gremlin_version:
                str_gremlin += str_gremlin_version
                if not prp_package:
                    # TODO: refactor into the separate module
                    str_gremlin += "pkg = g.V().has('ecosystem','{ecosystem}')." \
                                   "has('name', '{pkg_name}').tryNext().orElseGet{{" \
                                   "g.V().has('vertex_label','Count').choose(has('" \
                                   "{ecosystem}_pkg_count'),sack(assign).by('" \
                                   "{ecosystem}_pkg_count').sack(sum).by(constant(1))." \
                                   "property('{ecosystem}_pkg_count',sack()),property(" \
                                   "'{ecosystem}_pkg_count',1)).iterate();graph.addVertex(" \
                                   "'ecosystem', '{ecosystem}', 'name', '{pkg_name}', " \
                                   "'vertex_label', 'Package');}};" \
                                   "pkg.property('last_updated', {last_updated});".format(
                                        ecosystem=ecosystem, pkg_name=pkg_name,
                                        last_updated=str(time.time()))
                # TODO: refactor into the separate module
                str_gremlin += "edge_c = g.V().has('pecosystem','{ecosystem}').has('pname'," \
                               "'{pkg_name}').has('version','{version}').in(" \
                               "'has_version').tryNext()" \
                               ".orElseGet{{pkg.addEdge('has_version', ver)}};".format(
                                ecosystem=ecosystem, pkg_name=pkg_name, version=version)

        logger.info("Gremlin Query: %s" % str_gremlin)
        return str_gremlin


def set_property(data, type, property_name):
    """Set properties in query."""
    query = ''
    value = data.get(type, -1)
    if value != -1 and value:
        query += "pkg.property('{}', {});".format(property_name, value)
    return query


def create_query(property_name, data, duration):
    """Create gremlin query."""
    query = ''
    query += set_property(data.get(duration, {}), "opened", "gh_" +
                          property_name + "_last_" + duration + "_opened")
    query += set_property(data.get(duration, {}), "closed", "gh_" +
                          property_name + "_last_" + duration + "_closed")
    return query
