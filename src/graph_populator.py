"""Class containing classmethods used to construct queries to the graph database."""

import logging
import re
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class GraphPopulator(object):
    """Class containing classmethods used to construct queries to the graph database."""

    @classmethod
    def correct_license_splitting(cls, license_list):
        final_declared_licenses = list()
        for dl in license_list:
            if dl.startswith(("version", "Version")):
                final_declared_licenses[-1] = final_declared_licenses[-1] + ", " \
                                              + dl
            else:
                final_declared_licenses.append(dl)
        return final_declared_licenses

    @classmethod
    def construct_version_query(cls, input_json):
        """Construct the query to retrieve detailed information of given version of a package."""
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        version = input_json.get('version')
        description = ''
        try:
            if len(input_json.get('analyses', {}).get('metadata', {}).get('details')) > 0:
                description = input_json.get('analyses').get('metadata').get('details')[0].get(
                    'description', '')
                description = description.replace("'", "\\'")
        except Exception:
            # we pass and move forward without description
            pass

        drop_props = []
        str_version = prp_version = drop_prop = ""
        # Check if license and cve analyses succeeded. Then we refresh the property
        if 'success' == input_json.get('analyses', {}).get('source_licenses', {}).get('status'):
            drop_props.append('licenses')
        if 'success' == input_json.get('analyses', {}).get('security_issues', {}).get('status'):
            drop_props.append('cve_ids')

        str_version += "ver = g.V().has('pecosystem', '{ecosystem}').has('pname', '{pkg_name}')." \
                       "has('version', '{version}').tryNext().orElseGet{{" \
                       "graph.addVertex('pecosystem','{ecosystem}', 'pname','{pkg_name}', " \
                       "'version', '{version}', 'vertex_label', 'Version')}};" \
                       "ver.property('last_updated',{last_updated});".format(
                            ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                            last_updated=str(time.time())
                       )

        # Add Description if not blank
        if description:
            prp_version += "ver.property('description','{description}');".format(
                description=re.sub('[^A-Za-z0-9_\\\/\'":. ]', '', description)
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
                               cm_avg_cyclomatic_complexity=cm_avg_cyclomatic_complexity
                           )

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
            prp_version += " ".join(["ver.property('licenses', '{}');".format(l) for l in licenses])

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
                elif details[0].get('declared_licenses'):
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
                        declared_licenses = [x.strip() for x in declared_str.split(",")]
                    declared_licenses = cls.correct_license_splitting(declared_licenses)

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
                                       lic=lic, last_updated=str(time.time())
                                   )

        if len(drop_props) > 0:
            drop_prop += "g.V().has('pecosystem','{ecosystem}').has('pname','{pkg_name}')." \
                         "has('version','{version}').properties('{p}').drop().iterate();".format(
                            ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                            p="','".join(drop_props)
                         )

        str_version = drop_prop + str_version + prp_version if prp_version else ''

        return str_version

    @classmethod
    def construct_package_query(cls, input_json):
        """Construct the query to retrieve detailed information of given package."""
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        pkg_name_tokens = re.split('\W+', pkg_name)
        prp_package = ""
        drop_prop = ""
        drop_props = []
        str_package = "pkg = g.V().has('ecosystem','{ecosystem}').has('name', '{pkg_name}')." \
                      "tryNext().orElseGet{{graph.addVertex('ecosystem', '{ecosystem}', 'name', " \
                      "'{pkg_name}', 'vertex_label', 'Package')}};" \
                      "pkg.property('last_updated', {last_updated});".format(
                        ecosystem=ecosystem, pkg_name=pkg_name, last_updated=str(time.time())
                      )

        latest_version = input_json.get('latest_version') or ''
        if latest_version:
            prp_package += "pkg.property('latest_version', '{}');".format(latest_version)

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
            gh_stargazers = str(gh_details.get('stargazers_count', -1))
            gh_open_issues_count = str(gh_details.get('open_issues_count', -1))
            gh_subscribers_count = str(gh_details.get('subscribers_count', -1))
            gh_contributors_count = str(gh_details.get('contributors_count', -1))

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
                                gh_open_issues_count=gh_open_issues_count,
                                gh_subscribers_count=gh_subscribers_count,
                                gh_contributors_count=gh_contributors_count
                           )

        # Add tokens for a package
        if pkg_name_tokens:
            drop_props.append('tokens')
            str_package += " ".join(["pkg.property('tokens', '{}');".format(t)
                                     for t in pkg_name_tokens if t])

        # Get Libraries.io data
        if 'libraries_io' in input_json.get('analyses', {}):
            libio_dependents_projects = input_json.get('analyses').get('libraries_io') \
                                                  .get('details', {}) \
                                                  .get('dependents', {}).get('count', -1)
            libio_dependents_repos = input_json.get('analyses').get('libraries_io') \
                                               .get('details', {}) \
                                               .get('dependent_repositories', {}).get('count', -1)
            libio_total_releases = input_json.get('analyses').get('libraries_io') \
                                             .get('details', {}) \
                                             .get('releases', {}).get('count', -1)
            libio_latest_release = input_json.get('analyses').get('libraries_io') \
                                             .get('details', {}).get('releases', {}) \
                                             .get('latest', {}).get('published_at')
            libio_latest_version = input_json.get('analyses').get('libraries_io') \
                                             .get('details', {}).get('releases', {}) \
                                             .get('latest', {}).get('version', '')

            if libio_latest_release is not None:
                try:
                    prp_package += "pkg.property('libio_latest_release', '{}');".format(
                        str(time.mktime(datetime.strptime(libio_latest_release,
                                                          '%b %d, %Y').timetuple()))
                    )
                except Exception:
                    # We pass if we do not get timestamp information in required format
                    pass

            if input_json.get('analyses').get('libraries_io').get('details', {})\
                    .get('dependent_repositories', {}).get('top', {}):
                drop_props.append('libio_usedby')

            for key, val in input_json.get('analyses').get('libraries_io').get('details', {}) \
                                      .get('dependent_repositories', {}).get('top', {}).items():
                prp_package += "pkg.property('libio_usedby', '{key}:{val}');".format(
                    key=key, val=val
                )

            prp_package += "pkg.property('libio_dependents_projects', " \
                           "'{libio_dependents_projects}');" \
                           "pkg.property('libio_dependents_repos', '{libio_dependents_repos}');" \
                           "pkg.property('libio_total_releases', '{libio_total_releases}');" \
                           "pkg.property('libio_latest_version', '{libio_latest_version}');".format(
                                libio_dependents_projects=libio_dependents_projects,
                                libio_dependents_repos=libio_dependents_repos,
                                libio_total_releases=libio_total_releases,
                                libio_latest_version=libio_latest_version
                           )

            # Update EPV Github Release Date based on libraries_io data
            try:
                if libio_latest_release:
                    prp_package += "g.V().has('pecosystem','{ecosystem}').has('pname'," \
                                   "'{pkg_name}')." \
                                   "has('version','{libio_latest_version}')." \
                                   "property('gh_release_date', {gh_rel});".format(
                                        pkg_name=pkg_name, ecosystem=ecosystem,
                                        libio_latest_version=libio_latest_version,
                                        gh_rel=str(time.mktime(datetime.strptime(
                                            libio_latest_release, '%b %d, %Y').timetuple()))
                                   )
                for version, release in input_json.get('analyses').get('libraries_io') \
                                                  .get('details', {}).get('releases', {}) \
                                                  .get('latest', {}).get('recent', {}).items():
                    prp_package += "g.V().has('pecosystem','{ecosystem}').has('pname'," \
                                   "'{pkg_name}').has('version','{version}')." \
                                   "property('gh_release_date',{gh_rel});".format(
                                        ecosystem=ecosystem, pkg_name=pkg_name, version=version,
                                        gh_rel=str(time.mktime(datetime.strptime(release,
                                                   '%b %d, %Y').timetuple()))
                                   )
            except Exception:
                # We pass if we do not get timestamp information in required format
                pass

        # Refresh the properties whereever applicable
        if len(drop_props) > 0:
            drop_prop += "g.V().has('ecosystem','{ecosystem}').has('name'," \
                         "'{pkg_name}').properties('{p}').drop().iterate();".format(
                            ecosystem=ecosystem, pkg_name=pkg_name, p="','".join(drop_props)
                         )

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
        version = input_json.get('version')
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
                    str_gremlin += "pkg = g.V().has('ecosystem','{ecosystem}')." \
                                   "has('name', '{pkg_name}').tryNext().orElseGet{{" \
                                   "graph.addVertex('ecosystem', '{ecosystem}', 'name', " \
                                   "'{pkg_name}', 'vertex_label', 'Package')}};" \
                                   "pkg.property('last_updated', {last_updated});".format(
                                        ecosystem=ecosystem, pkg_name=pkg_name,
                                        last_updated=str(time.time())
                                   )
                str_gremlin += "edge_c = g.V().has('pecosystem','{ecosystem}').has('pname'," \
                               "'{pkg_name}').has('version','{version}').in(" \
                               "'has_version').tryNext()" \
                               ".orElseGet{{pkg.addEdge('has_version', ver)}};".format(
                                    ecosystem=ecosystem, pkg_name=pkg_name, version=version
                               )

        print(str_gremlin)
        return str_gremlin
