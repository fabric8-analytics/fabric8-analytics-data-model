"""Class containing classmethods used to construct queries to the graph database."""

import logging
import re
import time
from dateutil.parser import parse as parse_datetime
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
        if ecosystem and pkg_name and version:
            # Query to Create Package Node
            # TODO: refactor into the separate module
            pkg_str = "pkg = g.V().has('ecosystem','{ecosystem}').has('name', '{pkg_name}')." \
                      "tryNext().orElseGet{{g.V()." \
                      "has('vertex_label','Count').choose(has('{ecosystem}_pkg_count')," \
                      "sack(assign).by('{ecosystem}_pkg_count').sack(sum).by(constant(" \
                      "1)).property('{ecosystem}_pkg_count',sack())," \
                      "property('{ecosystem}_pkg_count',1)).iterate();" \
                      "graph.addVertex('ecosystem', '{ecosystem}', " \
                      "'name', '{pkg_name}', 'vertex_label', 'Package');}};" \
                      "pkg.property('latest_version', '{latest_version}');" \
                      "pkg.property('last_updated', {last_updated});".format(
                        ecosystem=ecosystem, latest_version=latest_version, pkg_name=pkg_name,
                        last_updated=str(time.time())
                       )

            # Query to Create Version Node
            # TODO: refactor into the separate module
            ver_str = "ver = g.V().has('pecosystem', '{ecosystem}').has('pname', " \
                      "'{pkg_name}').has('version', '{version}').tryNext().orElseGet{{" \
                      "g.V().has('vertex_label','Count').choose(has('{ecosystem}_ver_count')," \
                      "sack(assign).by('{ecosystem}_ver_count').sack(sum).by(constant(" \
                      "1)).property('{ecosystem}_ver_count',sack())," \
                      "property('{ecosystem}_ver_count',1)).iterate();" \
                      "graph.addVertex('pecosystem','{ecosystem}', 'pname','{pkg_name}', " \
                      "'version', '{version}', 'vertex_label', 'Version');}};" \
                      "ver.property('last_updated',{last_updated});".format(
                        ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                        last_updated=str(time.time()))
            # Add version node properties
            if source_repo:
                ver_str += "ver.property('source_repo','{source_repo}');".format(
                    source_repo=source_repo
                )

            if license and len(license) > 0:
                for lic in license:
                    ver_str += "ver.property('declared_licenses','{license}');".format(
                        license=lic
                    )

            # Add package node properties
            if gh_link:
                pkg_str += "pkg.property('gh_link','{gh_link}');".format(
                    gh_link=gh_link
                )

            # Query to create an edge between Package Node to Version Node
            # TODO: refactor into the separate module
            edge_str = "edge_c = g.V().has('pecosystem','{ecosystem}').has('pname'," \
                       "'{pkg_name}').has('version','{version}').in(" \
                       "'has_version').tryNext()" \
                       ".orElseGet{{pkg.addEdge('has_version', ver)}};".format(
                        ecosystem=ecosystem, pkg_name=pkg_name, version=version)

            return pkg_str + ver_str + edge_str
        else:
            return None

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
        # Check if license and cve analyses succeeded. Then we refresh the property
        if 'success' == input_json.get('analyses', {}).get('source_licenses', {}).get('status'):
            drop_props.append('licenses')
        if 'success' == input_json.get('analyses', {}).get('security_issues', {}).get('status'):
            drop_props.append('cve_ids')

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
        # Get Code Metrics Details
        if 'code_metrics' in input_json.get('analyses', {}):
            count = 0
            tot_complexity = 0.0
            languages = input_json.get('analyses').get('code_metrics').get('details', {}) \
                .get('languages', [])
            for lang in languages:
                if lang.get('metrics', {}).get('functions', {}).get(
                        'average_cyclomatic_complexity'):
                    count += 1
                    tot_complexity += lang['metrics']['functions']['average_cyclomatic_complexity']
            cm_avg_cyclomatic_complexity = str(tot_complexity / count) if count > 0 else '-1'
            cm_loc = str(input_json.get('analyses').get('code_metrics').get('summary', {})
                         .get('total_lines', -1))

            cm_num_files = str(input_json.get('analyses').get('code_metrics').get('summary', {})
                               .get('total_files', -1))
            prp_version += "ver.property('cm_num_files',{cm_num_files});" \
                           "ver.property('cm_avg_cyclomatic_complexity', " \
                           "{cm_avg_cyclomatic_complexity});" \
                           "ver.property('cm_loc',{cm_loc});".format(
                            cm_num_files=cm_num_files, cm_loc=cm_loc,
                            cm_avg_cyclomatic_complexity=cm_avg_cyclomatic_complexity)

        # Get downstream details

        if len(input_json.get('analyses', {}).get('redhat_downstream', {})
                .get('summary', {}).get('all_rhsm_product_names', [])) > 0:
            shipped_as_downstream = 'true'
            prp_version += "ver.property('shipped_as_downstream',{shipped_as_downstream});".format(
                shipped_as_downstream=shipped_as_downstream
            )

        # Add license details
        if 'source_licenses' in input_json.get('analyses', {}):
            licenses = input_json.get('analyses').get('source_licenses').get('summary', {}) \
                .get('sure_licenses', [])
            licenses = [cls.sanitize_text_for_query(lic) for lic in licenses]
            prp_version += " ".join(["ver.property('licenses', '{}');"
                                    .format(lic) for lic in licenses])

        # Add CVE property if it exists
        if 'security_issues' in input_json.get('analyses', {}):
            cves = []
            for cve in input_json.get('analyses', {}).get('security_issues', {}).get('details', []):
                cves.append(cve.get('id') + ":" + str(cve.get('cvss', {}).get('score')))
            prp_version += " ".join(["ver.property('cve_ids', '{}');".format(c) for c in cves])

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
                # Create License Node and edge from EPV
                for lic in declared_licenses:
                    prp_version += "lic = g.V().has('lname', '{lic}').tryNext().orElseGet{{" \
                                   "graph.addVertex('vertex_label', 'License', 'lname', '{lic}', " \
                                   "'last_updated',{last_updated})}}; g.V(ver).out(" \
                                   "'has_declared_license').has('lname', '{lic}').tryNext()." \
                                   "orElseGet{{ver.addEdge('has_declared_license', lic)}};".format(
                                    lic=lic, last_updated=str(time.time()))

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
        last_updated_flag = 'false'
        latest_version = cls.sanitize_text_for_query(input_json.get('latest_version'))

        if latest_version:
            # If latest version dont have cve, then it becomes the latest non cve version as well
            non_cve_ver = get_latest_version_non_cve(ecosystem, pkg_name, latest_version)
            prp_package += "pkg.property('latest_non_cve_version', '{}');".format(non_cve_ver)
            prp_package += "pkg.property('latest_version', '{}');".format(latest_version)
            if latest_version != cur_latest_ver:
                prp_package += "pkg.property('latest_version_last_updated', '{}');".format(cur_date)
                last_updated_flag = 'true'

        # Get Github Details
        if 'github_details' in input_json.get('analyses', {}):
            gh_details = input_json.get('analyses').get('github_details').get('details', {})
            gh_prs_last_year_opened = str(gh_details.get('updated_pull_requests', {})
                                          .get('year', {}).get('opened', -1))
            gh_prs_last_month_opened = str(gh_details.get('updated_pull_requests', {})
                                           .get('month', {}).get('opened', -1))
            gh_prs_last_year_closed = str(gh_details.get('updated_pull_requests', {})
                                          .get('year', {}).get('closed', -1))
            gh_prs_last_month_closed = str(gh_details.get('updated_pull_requests', {})
                                           .get('month', {}).get('closed', -1))
            gh_issues_last_year_opened = str(gh_details.get('updated_issues', {})
                                             .get('year', {}).get('opened', -1))
            gh_issues_last_month_opened = str(gh_details.get('updated_issues', {})
                                              .get('month', {}).get('opened', -1))
            gh_issues_last_year_closed = str(gh_details.get('updated_issues', {})
                                             .get('year', {}).get('closed', -1))
            gh_issues_last_month_closed = str(gh_details.get('updated_issues', {})
                                              .get('month', {}).get('closed', -1))
            gh_forks = str(gh_details.get('forks_count', -1))
            gh_refreshed_on = gh_details.get('updated_on')
            gh_stargazers = str(gh_details.get('stargazers_count', -1))
            gh_open_issues_count = str(gh_details.get('open_issues_count', -1))
            gh_subscribers_count = str(gh_details.get('subscribers_count', -1))
            gh_contributors_count = str(gh_details.get('contributors_count', -1))
            topics = gh_details.get('topics', [])

            # TODO: refactor into the separate module
            prp_package += "pkg.property('gh_prs_last_year_opened', {gh_prs_last_year_opened});" \
                           "pkg.property('gh_prs_last_month_opened', {gh_prs_last_month_opened});" \
                           "pkg.property('gh_prs_last_year_closed', {gh_prs_last_year_closed});" \
                           "pkg.property('gh_prs_last_month_closed', {gh_prs_last_month_closed});" \
                           "pkg.property('gh_issues_last_year_opened', " \
                           "{gh_issues_last_year_opened});" \
                           "pkg.property('gh_issues_last_month_opened', " \
                           "{gh_issues_last_month_opened});" \
                           "pkg.property('gh_issues_last_year_closed', " \
                           "{gh_issues_last_year_closed});" \
                           "pkg.property('gh_issues_last_month_closed', " \
                           "{gh_issues_last_month_closed});" \
                           "pkg.property('gh_forks', {gh_forks});" \
                           "pkg.property('gh_refreshed_on', '{gh_refreshed_on}');" \
                           "pkg.property('gh_stargazers', {gh_stargazers});" \
                           "pkg.property('gh_open_issues_count', {gh_open_issues_count});" \
                           "pkg.property('gh_subscribers_count', {gh_subscribers_count});" \
                           "pkg.property('gh_contributors_count', {gh_contributors_count});".format(
                            gh_prs_last_year_opened=gh_prs_last_year_opened,
                            gh_prs_last_month_opened=gh_prs_last_month_opened,
                            gh_prs_last_year_closed=gh_prs_last_year_closed,
                            gh_prs_last_month_closed=gh_prs_last_month_closed,
                            gh_issues_last_year_opened=gh_issues_last_year_opened,
                            gh_issues_last_month_opened=gh_issues_last_month_opened,
                            gh_issues_last_year_closed=gh_issues_last_year_closed,
                            gh_issues_last_month_closed=gh_issues_last_month_closed,
                            gh_forks=gh_forks, gh_stargazers=gh_stargazers,
                            gh_refreshed_on=gh_refreshed_on,
                            gh_open_issues_count=gh_open_issues_count,
                            gh_subscribers_count=gh_subscribers_count,
                            gh_contributors_count=gh_contributors_count)

            # Add github topics
            if topics:
                drop_props.append('topics')
                str_package += " ".join(["pkg.property('topics', '{}');".format(t)
                                         for t in topics if t])

        # Add tokens for a package
        if pkg_name_tokens:
            drop_props.append('tokens')
            str_package += " ".join(["pkg.property('tokens', '{}');".format(t)
                                     for t in pkg_name_tokens if t])

        # Get Libraries.io data
        if 'libraries_io' in input_json.get('analyses', {}):
            v2 = input_json['analyses']['libraries_io'].get('schema', {}).get('version', '0-0-0') \
                 >= '2-0-0'
            details = input_json['analyses']['libraries_io'].get('details', {})
            libio_dependents_projects = details.get('dependents', {}).get('count', -1)
            libio_dependents_repos = details.get('dependent_repositories', {}).get('count', -1)
            releases = details.get('releases', {})
            libio_total_releases = int(releases.get('count', -1))
            libio_latest_version = libio_latest_published_at = ''
            if libio_total_releases > 0:
                if v2:
                    libio_latest = releases.get('recent', [{}])[-1]  # last is latest
                    libio_latest_published_at = libio_latest.get('published_at', '')
                    libio_latest_version = libio_latest.get('number', '')
                else:
                    libio_latest_published_at = releases.get('latest', {}).get('published_at', '')
                    libio_latest_version = releases.get('latest', {}).get('version', '')

                if libio_latest_version != cur_libio_latest_ver and last_updated_flag != 'true':
                    prp_package += "pkg.property('latest_version_last_updated', '{}');" \
                        .format(cur_date)

            if libio_latest_published_at:
                t = libio_latest_published_at
                p = parse_datetime(t).timetuple() if t else ''
                published_at = str(time.mktime(p)) if p else ''
                prp_package += "pkg.property('libio_latest_release', '{}');".format(published_at)

            if details.get('dependent_repositories', {}).get('top'):
                drop_props.append('libio_usedby')
                for key, val in details.get('dependent_repositories', {}).get('top', {}).items():
                    prp_package += "pkg.property('libio_usedby', '{key}:{val}');".format(
                        key=key, val=val)

            prp_package += "pkg.property('libio_dependents_projects', " \
                           "'{libio_dependents_projects}');" \
                           "pkg.property('libio_dependents_repos', '{libio_dependents_repos}');" \
                           "pkg.property('libio_total_releases', '{libio_total_releases}');" \
                           "pkg.property('libio_latest_version', '{libio_latest_version}');".format(
                            libio_dependents_projects=libio_dependents_projects,
                            libio_dependents_repos=libio_dependents_repos,
                            libio_total_releases=libio_total_releases,
                            libio_latest_version=libio_latest_version)

            # Update EPV Github Release Date based on libraries_io data
            if v2:
                # 'recent' is list of {'number':n, 'published_at':p} including the latest
                for release in releases.get('recent', []):
                    rel_published = release.get('published_at', '')
                    parsed_dt = parse_datetime(rel_published).timetuple() if rel_published else ''
                    timestamp = time.mktime(parsed_dt) if parsed_dt else ''

                    prp_package += "g.V().has('pecosystem','{ecosystem}').has('pname'," \
                                   "'{pkg_name}').has('version','{version}')." \
                                   "property('gh_release_date',{gh_rel});".format(
                                    ecosystem=ecosystem, pkg_name=pkg_name,
                                    version=release.get('number', ''),
                                    gh_rel=str(timestamp))
            else:
                if libio_latest_published_at:
                    gh_release = time.mktime(parse_datetime(libio_latest_published_at).timetuple())
                    prp_package += "g.V().has('pecosystem','{ecosystem}').has('pname'," \
                                   "'{pkg_name}')." \
                                   "has('version','{libio_latest_version}')." \
                                   "property('gh_release_date', {gh_rel});".format(
                                    pkg_name=pkg_name, ecosystem=ecosystem,
                                    libio_latest_version=libio_latest_version,
                                    gh_rel=str(gh_release))
                for version, release in releases.get('latest', {}).get('recent', {}).items():
                    prp_package += "g.V().has('pecosystem','{ecosystem}').has('pname'," \
                                   "'{pkg_name}').has('version','{version}')." \
                                   "property('gh_release_date',{gh_rel});".format(
                                    ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                                    gh_rel=str(time.mktime(parse_datetime(release).timetuple())))

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
