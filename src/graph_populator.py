import logging
import re
import time
from datetime import datetime

logger = logging.getLogger(__name__)


class GraphPopulator(object):
    @classmethod
    def construct_version_query(cls, input_json):
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        version = input_json.get('version')
        description = ''
        try:
            if len(input_json.get('analyses', {}).get('metadata', {}).get('details')) > 0:
                description = input_json.get('analyses').get('metadata').get('details')[0].get('description', '')
                description = description.replace("'", "\\'")
        except:
            # we pass and move forward without description
            pass

        drop_props = []
        str_version = ""
        # Check if license and cve analyses succeeded. Then we refresh the property
        if 'success' == input_json.get('analyses', {}).get('source_licenses', {}).get('status'):
            drop_props.append('licenses')
        if 'success' == input_json.get('analyses', {}).get('security_issues', {}).get('status'):
            drop_props.append('cve_ids')
        if len(drop_props) > 0:
            str_version = "g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')" \
                          ".has('version','" + version + "').properties('" + "','".join(drop_props) + "')." \
                          "drop().iterate();" \

        str_version += "ver = g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')" \
                       ".has('version','" + version + "').tryNext().orElseGet{graph.addVertex('pecosystem','" \
                       + ecosystem + "', 'pname','" + pkg_name + "', 'version','" + version + "', " \
                       "'vertex_label', 'Version')};" \
                       "ver.property('last_updated'," + str(time.time()) + ");"
        # Add Description if not blank
        if description:
            str_version += "ver.property('description','" + re.sub('[^A-Za-z0-9_\\\/\'":. ]', '', description) + "');"
        # Get Code Metrics Details
        if 'code_metrics' in input_json.get('analyses', {}):
            count = 0
            tot_complexity = 0.0
            for lang in input_json.get('analyses').get('code_metrics').get('details', {}).get('languages', []):
                if lang.get('metrics', {}).get('functions', {}).get('average_cyclomatic_complexity'):
                    count += 1
                    tot_complexity += lang['metrics']['functions']['average_cyclomatic_complexity']
            cm_avg_cyclomatic_complexity = str(tot_complexity / count) if count > 0 else '-1'
            cm_loc = str(input_json.get('analyses').get('code_metrics').get('summary', {}).get('total_lines', -1))
            cm_num_files = str(input_json.get('analyses').get('code_metrics').get('summary', {})
                               .get('total_files', -1))
            str_version += "ver.property('cm_num_files'," + cm_num_files + ");" \
                           "ver.property('cm_avg_cyclomatic_complexity'," + cm_avg_cyclomatic_complexity + ");" \
                           "ver.property('cm_loc'," + str(cm_loc) + ");"

        # Get downstream details
        shipped_as_downstream = 'false'
        if len(input_json.get('analyses', {}).get('redhat_downstream', {})
               .get('summary', {}).get('all_rhsm_product_names', [])) > 0:
            shipped_as_downstream = 'true'
        str_version += "ver.property('shipped_as_downstream'," + shipped_as_downstream + ");"

        # Add license details
        if 'source_licenses' in input_json.get('analyses', {}):
            licenses = input_json.get('analyses').get('source_licenses').get('summary', {}).get('sure_licenses', [])
            str_version += " ".join(map(lambda x: "ver.property('licenses', '" + x + "');", licenses))

        # Add CVE property if it exists
        if 'security_issues' in input_json.get('analyses', {}):
            cves = []
            for cve in input_json.get('analyses', {}).get('security_issues', {}).get('details', []):
                cves.append(cve.get('id') + ":" + str(cve.get('cvss', {}).get('score')))
            str_version += " ".join(map(lambda x: "ver.property('cve_ids', '" + x + "');", cves))

        # Get Metadata Details
        if 'metadata' in input_json.get('analyses', {}):
            details = input_json.get('analyses').get('metadata', {}).get('details', [])
            if details and details[0]:
                declared_license = details[0].get('declared_license')
                declared_licenses = []
                if isinstance(declared_license, list):
                    declared_licenses = declared_license
                else:
                    declared_licenses.append(declared_license)

                str_version += " ".join(map(lambda x: "ver.property('declared_licenses', '" + x + "');", declared_licenses))
                # Create License Node and edge from EPV
                for lic in declared_licenses:
                    str_version += "lic = g.V().has('lname','" + lic + "').tryNext()." \
                                   "orElseGet{graph.addVertex('vertex_label', 'License', 'lname', '" + lic + "', " \
                                   "'last_updated'," + str(time.time()) + ")};" \
                                   "g.V(ver).out('has_declared_license').has('lname', '" + lic + "').tryNext()." \
                                   "orElseGet{ver.addEdge('has_declared_license', lic)};"

        return str_version

    @classmethod
    def construct_package_query(cls, input_json):
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        pkg_name_tokens = re.split('\W+', pkg_name)

        str_package = "pkg = g.V().has('ecosystem','" + ecosystem + "').has('name','" + pkg_name + "').tryNext()" \
                      ".orElseGet{graph.addVertex('ecosystem', '" + ecosystem + "', 'name', '" + pkg_name + "', " \
                      "'vertex_label', 'Package')};"

        latest_version = input_json.get('latest_version') or ''
        str_package += "pkg.property('latest_version', '" + latest_version + "');" \
                       "pkg.property('last_updated', " + str(time.time()) + ");"

        # Get Github Details
        if 'github_details' in input_json.get('analyses', {}):
            gh_details = input_json.get('analyses').get('github_details').get('details', {})
            gh_prs_last_year_opened = str(gh_details.get('updated_pull_requests', {}).get('year', {}).get('opened', -1))
            gh_prs_last_month_opened = str(gh_details.get('updated_pull_requests', {}).get('month', {}).get('opened', -1))
            gh_prs_last_year_closed = str(gh_details.get('updated_pull_requests', {}).get('year', {}).get('closed', -1))
            gh_prs_last_month_closed = str(gh_details.get('updated_pull_requests', {}).get('month', {}).get('closed', -1))
            gh_issues_last_year_opened = str(gh_details.get('updated_issues', {}).get('year', {}).get('opened', -1))
            gh_issues_last_month_opened = str(gh_details.get('updated_issues', {}).get('month', {}).get('opened', -1))
            gh_issues_last_year_closed = str(gh_details.get('updated_issues', {}).get('year', {}).get('closed', -1))
            gh_issues_last_month_closed = str(gh_details.get('updated_issues', {}).get('month', {}).get('closed', -1))
            gh_forks = str(gh_details.get('forks_count', -1))
            gh_stargazers = str(gh_details.get('stargazers_count', -1))
            gh_open_issues_count = str(gh_details.get('open_issues_count', -1))
            gh_subscribers_count = str(gh_details.get('subscribers_count', -1))

            str_package += "pkg.property('gh_prs_last_year_opened', " + gh_prs_last_year_opened + ");" \
                           "pkg.property('gh_prs_last_month_opened', " + gh_prs_last_month_opened + ");" \
                           "pkg.property('gh_prs_last_year_closed', " + gh_prs_last_year_closed + ");" \
                           "pkg.property('gh_prs_last_month_closed', " + gh_prs_last_month_closed + ");" \
                           "pkg.property('gh_issues_last_year_opened', " + gh_issues_last_year_opened + ");" \
                           "pkg.property('gh_issues_last_month_opened', " + gh_issues_last_month_opened + ");" \
                           "pkg.property('gh_issues_last_year_closed', " + gh_issues_last_year_closed + ");" \
                           "pkg.property('gh_issues_last_month_closed', " + gh_issues_last_month_closed + ");" \
                           "pkg.property('gh_forks', " + gh_forks + ");" \
                           "pkg.property('gh_stargazers', " + gh_stargazers + ");" \
                           "pkg.property('gh_open_issues_count', " + gh_open_issues_count + ");" \
                           "pkg.property('gh_subscribers_count', " + gh_subscribers_count + ");"

        # Add tokens for a package
        for tkn in pkg_name_tokens:
            if tkn:
                str_package += "pkg.property('tokens', '" + tkn + "');"

        # Get Libraries.io data
        if 'libraries_io' in input_json.get('analyses', {}):
            libio_dependents_projects = input_json.get('analyses').get('libraries_io').get('details', {}) \
                                                  .get('dependents', {}).get('count', -1)
            libio_dependents_repos = input_json.get('analyses').get('libraries_io').get('details', {}) \
                                               .get('dependent_repositories', {}).get('count', -1)
            libio_total_releases = input_json.get('analyses').get('libraries_io').get('details', {}) \
                                             .get('releases', {}).get('count', -1)
            libio_latest_release = input_json.get('analyses').get('libraries_io').get('details', {}) \
                                             .get('releases', {}).get('latest', {}).get('published_at')
            libio_latest_version = input_json.get('analyses').get('libraries_io').get('details', {}) \
                                             .get('releases', {}).get('latest', {}).get('version', '')

            if libio_latest_release is not None:
                try:
                    str_package += "pkg.property('libio_latest_release', '" + \
                                   str(time.mktime(datetime.strptime(libio_latest_release,
                                                                     '%b %d, %Y').timetuple()))+"');"
                except:
                    # We pass if we do not get timestamp information in required format
                    pass

            for key, val in input_json.get('analyses').get('libraries_io').get('details', {}) \
                                      .get('dependent_repositories', {}).get('top', {}).items():
                str_package += "pkg.property('libio_usedby', '" + key + ":" + val + "');"

            str_package += "pkg.property('libio_dependents_projects', '" + libio_dependents_projects + "');" \
                           "pkg.property('libio_dependents_repos', '" + libio_dependents_repos + "');" \
                           "pkg.property('libio_total_releases', '" + libio_total_releases + "');" \
                           "pkg.property('libio_latest_version', '" + libio_latest_version + "');"

            # Update EPV Github Release Date based on libraries_io data
            try:
                if libio_latest_release:
                    str_package += "g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')." \
                                   "has('version','" + libio_latest_version + "')." \
                                   "property('gh_release_date'," + str(time.mktime(datetime.strptime(libio_latest_release,
                                                                       '%b %d, %Y').timetuple())) + ");"
                for version, release in input_json.get('analyses').get('libraries_io').get('details', {}) \
                                                  .get('releases', {}).get('latest', {}).get('recent', {}).items():
                    str_package += "g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')." \
                                   "has('version','" + version + "')." \
                                   "property('gh_release_date'," + str(time.mktime(datetime.strptime(release,
                                                                       '%b %d, %Y').timetuple())) + ");"
            except:
                # We pass if we do not get timestamp information in required format
                pass

        return str_package

    @classmethod
    def create_query_string(cls, input_json):

        # NPM packages with dependencies, versions i.e. Package version
        pkg_name = input_json.get('package')
        ecosystem = input_json.get('ecosystem')
        version = input_json.get('version')
        # creation of query string
        str_gremlin = cls.construct_package_query(input_json)
        if version is not None and version != '':
            str_gremlin += cls.construct_version_query(input_json)
            # Add edge from Package to Version
            str_gremlin += "edge_c = g.V().has('pecosystem','" + ecosystem + "').has('pname','" + pkg_name + "')" \
                           ".has('version','" + version + "').in('has_version').tryNext()" \
                           ".orElseGet{pkg.addEdge('has_version', ver)};"
        print(str_gremlin)
        return str_gremlin
