        mgmt = graph.openManagement();

        // for package
        ecosystem = mgmt.getPropertyKey('ecosystem');
        if(ecosystem == null) {
            ecosystem = mgmt.makePropertyKey('ecosystem').dataType(String.class).make();
        }

        name = mgmt.getPropertyKey('name');
        if(name == null) {
            name = mgmt.makePropertyKey('name').dataType(String.class).make();
        }

        package_relative_used = mgmt.getPropertyKey('package_relative_used');
        if(package_relative_used == null) {
            package_relative_used = mgmt.makePropertyKey('package_relative_used').dataType(String.class).make();
        }

        package_dependents_count = mgmt.getPropertyKey('package_dependents_count');
        if(package_dependents_count == null) {
            package_dependents_count = mgmt.makePropertyKey('package_dependents_count').dataType(Integer.class).make();
        }

        latest_version = mgmt.getPropertyKey('latest_version');
        if(latest_version == null) {
            latest_version = mgmt.makePropertyKey('latest_version').dataType(String.class).make();
        }

        latest_version_last_updated = mgmt.getPropertyKey('latest_version_last_updated');
        if(latest_version_last_updated == null) {
            latest_version_last_updated = mgmt.makePropertyKey('latest_version_last_updated').dataType(String.class).make();
        }

        latest_non_cve_version = mgmt.getPropertyKey('latest_non_cve_version');
        if(latest_non_cve_version == null) {
            latest_non_cve_version = mgmt.makePropertyKey('latest_non_cve_version').dataType(String.class).make();
        }

        // package github details

        gh_link = mgmt.getPropertyKey('gh_link');
        if(gh_link == null) {
            gh_link = mgmt.makePropertyKey('gh_link').dataType(String.class).make();
        }

        gh_stargazers = mgmt.getPropertyKey('gh_stargazers');
        if(gh_stargazers == null) {
            gh_stargazers = mgmt.makePropertyKey('gh_stargazers').dataType(Integer.class).make();
        }

        gh_open_issues_count = mgmt.getPropertyKey('gh_open_issues_count');
        if(gh_open_issues_count == null) {
            gh_open_issues_count = mgmt.makePropertyKey('gh_open_issues_count').dataType(Integer.class).make();
        }

        gh_subscribers_count = mgmt.getPropertyKey('gh_subscribers_count');
        if(gh_subscribers_count == null) {
            gh_subscribers_count = mgmt.makePropertyKey('gh_subscribers_count').dataType(Integer.class).make();
        }

        gh_contributors_count = mgmt.getPropertyKey('gh_contributors_count');
        if(gh_contributors_count == null) {
            gh_contributors_count = mgmt.makePropertyKey('gh_contributors_count').dataType(Integer.class).make();
        }

        gh_forks = mgmt.getPropertyKey('gh_forks');
        if(gh_forks == null) {
            gh_forks = mgmt.makePropertyKey('gh_forks').dataType(Integer.class).make();
        }

        gh_refreshed_on = mgmt.getPropertyKey('gh_refreshed_on');
        if(gh_refreshed_on == null) {
            gh_refreshed_on = mgmt.makePropertyKey('gh_refreshed_on').dataType(String.class).make();
        }

        gh_issues_last_year = mgmt.getPropertyKey('gh_issues_last_year');
        if(gh_issues_last_year == null) {
            gh_issues_last_year = mgmt.makePropertyKey('gh_issues_last_year').dataType(Integer.class).make();
        }

        gh_issues_last_month = mgmt.getPropertyKey('gh_issues_last_month');
        if(gh_issues_last_month == null) {
            gh_issues_last_month = mgmt.makePropertyKey('gh_issues_last_month').dataType(Integer.class).make();
        }

        gh_prs_last_year = mgmt.getPropertyKey('gh_prs_last_year');
        if(gh_prs_last_year == null) {
            gh_prs_last_year = mgmt.makePropertyKey('gh_prs_last_year').dataType(Integer.class).make();
        }

        gh_prs_last_month= mgmt.getPropertyKey('gh_prs_last_month');
        if(gh_prs_last_month == null) {
            gh_prs_last_month = mgmt.makePropertyKey('gh_prs_last_month').dataType(Integer.class).make();
        }

        // # for version
        pname = mgmt.getPropertyKey('pname');
        if(pname == null) {
            pname = mgmt.makePropertyKey('pname').dataType(String.class).make();
        }

        pecosystem = mgmt.getPropertyKey('pecosystem');
        if(pecosystem == null) {
            pecosystem = mgmt.makePropertyKey('pecosystem').dataType(String.class).make();
        }

        version = mgmt.getPropertyKey('version');
        if(version == null) {
            version = mgmt.makePropertyKey('version').dataType(String.class).make();
        }

        description = mgmt.getPropertyKey('description');
        if(description== null) {
            description = mgmt.makePropertyKey('description').dataType(String.class).make();
        }

        shipped_as_downstream = mgmt.getPropertyKey('shipped_as_downstream');
        if(shipped_as_downstream == null) {
            shipped_as_downstream = mgmt.makePropertyKey('shipped_as_downstream').dataType(Boolean.class).make();
        }

        // for licenses

        licenses = mgmt.getPropertyKey('licenses');
        if(licenses == null) {
            licenses = mgmt.makePropertyKey('licenses').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        declared_licenses = mgmt.getPropertyKey('declared_licenses');
        if(declared_licenses == null) {
            declared_licenses = mgmt.makePropertyKey('declared_licenses').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        libio_licenses = mgmt.getPropertyKey('libio_licenses');
        if(libio_licenses == null) {
            libio_licenses = mgmt.makePropertyKey('libio_licenses').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // for CVEs

        cecosystem = mgmt.getPropertyKey('cecosystem');
        if(cecosystem == null) {
            cecosystem = mgmt.makePropertyKey('cecosystem').dataType(String.class).make();
        }

        cve_ids = mgmt.getPropertyKey('cve_ids');
        if(cve_ids == null) {
            cve_ids = mgmt.makePropertyKey('cve_ids').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        cvss_scores = mgmt.getPropertyKey('cvss_scores');
        if(cvss_scores == null) {
            cvss_scores =  mgmt.makePropertyKey('cvss_scores').dataType(Float.class).cardinality(Cardinality.SET).make();
        }

        // for snyk CVEs

        snyk_cve_ids = mgmt.getPropertyKey('snyk_cve_ids');
        if(snyk_cve_ids == null) {
            snyk_cve_ids = mgmt.makePropertyKey('snyk_cve_ids').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        snyk_ecosystem = mgmt.getPropertyKey('snyk_ecosystem');
        if(snyk_ecosystem == null) {
            snyk_ecosystem = mgmt.makePropertyKey('snyk_ecosystem').dataType(String.class).make();
        }

        snyk_vuln_id = mgmt.getPropertyKey('snyk_vuln_id');
        if(snyk_vuln_id == null) {
            snyk_vuln_id = mgmt.makePropertyKey('snyk_vuln_id').dataType(String.class).make();
        }

        snyk_cwes = mgmt.getPropertyKey('snyk_cwes');
        if(snyk_cwes == null) {
            snyk_cwes = mgmt.makePropertyKey('snyk_cwes').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        vulnerable_commit_hashes = mgmt.getPropertyKey('vulnerable_commit_hashes');
        if(vulnerable_commit_hashes == null) {
            vulnerable_commit_hashes = mgmt.makePropertyKey('vulnerable_commit_hashes').dataType(String.class).make();
        }

        package_name = mgmt.getPropertyKey('package_name');
        if(package_name == null) {
            package_name = mgmt.makePropertyKey('package_name').dataType(String.class).make();
        }

        vulnerable_versions = mgmt.getPropertyKey('vulnerable_versions');
        if(vulnerable_versions== null) {
            vulnerable_versions = mgmt.makePropertyKey('vulnerable_versions').dataType(String.class).make();
        }

        module_name = mgmt.getPropertyKey('module_name');
        if(module_name == null) {
            module_name = mgmt.makePropertyKey('module_name').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        vuln_commit_date_rules = mgmt.getPropertyKey('vuln_commit_date_rules');
        if(vuln_commit_date_rules == null) {
            vuln_commit_date_rules = mgmt.makePropertyKey('vuln_commit_date_rules').dataType(String.class).make();
        }

        // for code metrics

        cm_loc = mgmt.getPropertyKey('cm_loc');
        if(cm_loc == null) {
            cm_loc = mgmt.makePropertyKey('cm_loc').dataType(Integer.class).make();
        }

        cm_num_files = mgmt.getPropertyKey('cm_num_files');
        if(cm_num_files == null) {
            cm_num_files = mgmt.makePropertyKey('cm_num_files').dataType(Integer.class).make();
        }

        cm_avg_cyclomatic_complexity = mgmt.getPropertyKey('cm_avg_cyclomatic_complexity');
        if(cm_avg_cyclomatic_complexity == null) {
            cm_avg_cyclomatic_complexity = mgmt.makePropertyKey('cm_avg_cyclomatic_complexity').dataType(Float.class).make();
        }

        // downstream usage

        relative_used = mgmt.getPropertyKey('relative_used');
        if(relative_used == null) {
            relative_used = mgmt.makePropertyKey('relative_used').dataType(String.class).make();
        }

        dependents_count =mgmt.getPropertyKey('dependents_count');
        if(dependents_count == null) {
            dependents_count = mgmt.makePropertyKey('dependents_count').dataType(Integer.class).make();
        }

        is_packaged_in= mgmt.getPropertyKey('is_packaged_in');
        if(is_packaged_in == null) {
            is_packaged_in = mgmt.makePropertyKey('is_packaged_in').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        is_published_in = mgmt.getPropertyKey('is_published_in');
        if(is_published_in == null) {
            is_published_in = mgmt.makePropertyKey('is_published_in').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // # for license
        lname= mgmt.getPropertyKey('lname');
        if(lname == null) {
            lname = mgmt.makePropertyKey('lname').dataType(String.class).make();
        }

        license_count = mgmt.getPropertyKey('license_count');
        if(license_count == null ) {
            license_count = mgmt.makePropertyKey('license_count').dataType(Integer.class).make();
        }

        // # for person
        email = mgmt.getPropertyKey('email');
        if(email == null) {
            email=mgmt.makePropertyKey('email').dataType(String.class).make();
        }

        // # for security
        cve_id = mgmt.getPropertyKey('cve_id');
        if(cve_id == null ) {
             cve_id = mgmt.makePropertyKey('cve_id').dataType(String.class).make();
        }

        cvedb_version = mgmt.getPropertyKey('cvedb_version');
        if(cvedb_version == null ) {
             cvedb_version = mgmt.makePropertyKey('cvedb_version').dataType(String.class).make();
        }

        cvss = mgmt.getPropertyKey('cvss');
        if(cvss == null) {
            cvss = mgmt.makePropertyKey('cvss').dataType(Float.class).make();
        }

        cvss_v2 = mgmt.getPropertyKey('cvss_v2');
        if(cvss_v2 == null) {
            cvss_v2 = mgmt.makePropertyKey('cvss_v2').dataType(Float.class).make();
        }

        cvss_v3 = mgmt.getPropertyKey('cvss_v3');
        if(cvss_v3 == null) {
            cvss_v3 = mgmt.makePropertyKey('cvss_v3').dataType(Float.class).make();
        }

        nvd_status = mgmt.getPropertyKey('nvd_status');
        if(nvd_status == null){
            nvd_status = mgmt.makePropertyKey('nvd_status').dataType(String.class).make();
        }

        fixed_in = mgmt.getPropertyKey('fixed_in');
        if(fixed_in == null){
            fixed_in = mgmt.makePropertyKey('fixed_in').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        summary = mgmt.getPropertyKey('summary');
        if(summary == null) {
            summary = mgmt.makePropertyKey('summary').dataType(String.class).make();
        }

        access_authentication = mgmt.getPropertyKey('access_authentication');
        if(access_authentication == null) {
            access_authentication = mgmt.makePropertyKey('access_authentication').dataType(String.class).make();
        }

        access_complexity = mgmt.getPropertyKey('access_complexity');
        if(access_complexity == null) {
            access_complexity = mgmt.makePropertyKey('access_complexity').dataType(String.class).make();
        }

        access_vector = mgmt.getPropertyKey('access_vector');
        if(access_vector == null) {
            access_vector = mgmt.makePropertyKey('access_vector').dataType(String.class).make();
        }

        impact_availability = mgmt.getPropertyKey('impact_availability');
        if(impact_availability == null) {
            impact_availability = mgmt.makePropertyKey('impact_availability').dataType(String.class).make();
        }

        impact_confidentiality = mgmt.getPropertyKey('impact_confidentiality');
        if(impact_confidentiality == null) {
            impact_confidentiality  = mgmt.makePropertyKey('impact_confidentiality').dataType(String.class).make();
        }

        impact_integrity = mgmt.getPropertyKey('impact_integrity');
        if(impact_integrity == null) {
            impact_integrity  = mgmt.makePropertyKey('impact_integrity').dataType(String.class).make();
        }

        references = mgmt.getPropertyKey('references');
        if(references == null) {
            references = mgmt.makePropertyKey('references').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // # for edges
        has_version = mgmt.getEdgeLabel('has_version');
        if(has_version == null) {
            has_version = mgmt.makeEdgeLabel('has_version').make();
        }

        depends_on = mgmt.getEdgeLabel('depends_on');
        if(depends_on == null) {
            depends_on = mgmt.makeEdgeLabel('depends_on').make();
        }

        contains_cve = mgmt.getEdgeLabel('contains_cve');
        if(contains_cve == null) {
            contains_cve = mgmt.makeEdgeLabel('contains_cve').make();
        }

        licensed_under = mgmt.getEdgeLabel('licensed_under');
        if(licensed_under == null) {
            licensed_under = mgmt.makeEdgeLabel('licensed_under').make();
        }

        has_declared_license = mgmt.getEdgeLabel('has_declared_license');
        if(has_declared_license == null) {
            has_declared_license = mgmt.makeEdgeLabel('has_declared_license').make();
        }

        authored_by = mgmt.getEdgeLabel('authored_by');
        if(authored_by == null) {
            authored_by = mgmt.makeEdgeLabel('authored_by').make();
        }

        contributed_by = mgmt.getEdgeLabel('contributed_by');
        if(contributed_by == null) {
            contributed_by = mgmt.makeEdgeLabel('contributed_by').make();
        }

        has_github_details = mgmt.getEdgeLabel('has_github_details');
        if(has_github_details == null) {
            has_github_details = mgmt.makeEdgeLabel('has_github_details').make();
        }

        has_code_metrics = mgmt.getEdgeLabel('has_code_metrics');
        if(has_code_metrics == null) {
            has_code_metrics = mgmt.makeEdgeLabel('has_code_metrics').make();
        }

        has_tagged = mgmt.getEdgeLabel('has_tagged');
        if(has_tagged == null) {
            has_tagged = mgmt.makeEdgeLabel('has_tagged').make();
        }

        // # for github

        gh_issues_opened_last_year = mgmt.getPropertyKey('gh_issues_opened_last_year');
        if(gh_issues_opened_last_year == null) {
            gh_issues_opened_last_year = mgmt.makePropertyKey('gh_issues_opened_last_year').dataType(Integer.class).make();
        }

        gh_issues_opened_last_month = mgmt.getPropertyKey('gh_issues_opened_last_month');
        if(gh_issues_opened_last_month == null) {
            gh_issues_opened_last_month = mgmt.makePropertyKey('gh_issues_opened_last_month').dataType(Integer.class).make();
        }

        gh_prs_opened_last_year = mgmt.getPropertyKey('gh_prs_opened_last_year');
        if(gh_prs_opened_last_year == null) {
            gh_prs_opened_last_year = mgmt.makePropertyKey('gh_prs_opened_last_year').dataType(Integer.class).make();
        }

        gh_prs_opened_last_month = mgmt.getPropertyKey('gh_prs_opened_last_month');
        if(gh_prs_opened_last_month == null) {
            gh_prs_opened_last_month = mgmt.makePropertyKey('gh_prs_opened_last_month').dataType(Integer.class).make();
        }

        gh_issues_closed_last_year = mgmt.getPropertyKey('gh_issues_closed_last_year');
        if(gh_issues_closed_last_year == null) {
            gh_issues_closed_last_year = mgmt.makePropertyKey('gh_issues_closed_last_year').dataType(Integer.class).make();
        }

        gh_issues_closed_last_month = mgmt.getPropertyKey('gh_issues_closed_last_month');
        if(gh_issues_closed_last_month == null) {
            gh_issues_closed_last_month = mgmt.makePropertyKey('gh_issues_closed_last_month').dataType(Integer.class).make();
        }

        gh_prs_closed_last_year = mgmt.getPropertyKey('gh_prs_closed_last_year');
        if(gh_prs_closed_last_year == null) {
            gh_prs_closed_last_year = mgmt.makePropertyKey('gh_prs_closed_last_year').dataType(Integer.class).make();
        }

        gh_prs_closed_last_month = mgmt.getPropertyKey('gh_prs_closed_last_month');
        if(gh_prs_closed_last_month == null) {
            gh_prs_closed_last_month = mgmt.makePropertyKey('gh_prs_closed_last_month').dataType(Integer.class).make();
        }

        //extra_properties
        vertex_label = mgmt.getPropertyKey('vertex_label');
        if(vertex_label == null) {
            vertex_label = mgmt.makePropertyKey('vertex_label').dataType(String.class).make();
        }

        last_updated = mgmt.getPropertyKey('last_updated');
        if(last_updated == null){
            last_updated = mgmt.makePropertyKey('last_updated').dataType(Double.class).make();
        }

        modified_date = mgmt.getPropertyKey('modified_date');
        if(modified_date == null){
            modified_date = mgmt.makePropertyKey('modified_date').dataType(String.class).make();
        }

        // for Black Duck Security
        base_score = mgmt.getPropertyKey('base_score');
        if(base_score == null){
            base_score = mgmt.makePropertyKey('base_score').dataType(Float.class).make();
        }

        exploitability_subscore = mgmt.getPropertyKey('exploitability_subscore');
        if(exploitability_subscore == null){
            exploitability_subscore = mgmt.makePropertyKey('exploitability_subscore').dataType(Float.class).make();
        }

        impact_subscore = mgmt.getPropertyKey('impact_subscore');
        if(impact_subscore == null){
            impact_subscore = mgmt.makePropertyKey('impact_subscore').dataType(Float.class).make();
        }

        remediation_status = mgmt.getPropertyKey('remediation_status');
        if(remediation_status == null){
            remediation_status = mgmt.makePropertyKey('remediation_status').dataType(String.class).make();
        }

        remediation_updated_at = mgmt.getPropertyKey('remediation_updated_at');
        if(remediation_updated_at == null){
            remediation_updated_at = mgmt.makePropertyKey('remediation_updated_at').dataType(String.class).make();
        }

        remediation_created_at = mgmt.getPropertyKey('remediation_created_at');
        if(remediation_created_at == null){
            remediation_created_at = mgmt.makePropertyKey('remediation_created_at').dataType(String.class).make();
        }

        severity = mgmt.getPropertyKey('severity');
        if(severity == null){
            severity = mgmt.makePropertyKey('severity').dataType(String.class).make();
        }

        source = mgmt.getPropertyKey('source');
        if(source == null){
            source = mgmt.makePropertyKey('source').dataType(String.class).make();
        }

        vulnerability_name = mgmt.getPropertyKey('vulnerability_name');
        if(vulnerability_name == null){
            vulnerability_name = mgmt.makePropertyKey('vulnerability_name').dataType(String.class).make();
        }

        vulnerability_published_date = mgmt.getPropertyKey('vulnerability_published_date');
        if(vulnerability_published_date == null){
            vulnerability_published_date = mgmt.makePropertyKey('vulnerability_published_date').dataType(String.class).make();
        }

        vulnerability_updated_date = mgmt.getPropertyKey('vulnerability_updated_date');
        if(vulnerability_updated_date == null){
            vulnerability_updated_date = mgmt.makePropertyKey('vulnerability_updated_date').dataType(String.class).make();
        }

        // for component search

        tokens = mgmt.getPropertyKey('tokens');
        if(tokens == null) {
            tokens = mgmt.makePropertyKey('tokens').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // for category search
        category_runtime = mgmt.getPropertyKey('category_runtime');
        if(category_runtime == null) {
            category_runtime = mgmt.makePropertyKey('category_runtime').dataType(String.class).make();
        }

        ctname = mgmt.getPropertyKey('ctname');
        if(ctname == null) {
            ctname = mgmt.makePropertyKey('ctname').dataType(String.class).make();
        }

        category_deps_count = mgmt.getPropertyKey('category_deps_count');
        if(category_deps_count == null) {
            category_deps_count = mgmt.makePropertyKey('category_deps_count').dataType(Integer.class).make();
        }

        // for intents

        topics = mgmt.getPropertyKey('topics');
        if(topics == null) {
            topics = mgmt.makePropertyKey('topics').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        categories = mgmt.getPropertyKey('categories');
        if(categories == null) {
            categories = mgmt.makePropertyKey('categories').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // for libraries.io data

        libio_dependents_projects = mgmt.getPropertyKey('libio_dependents_projects');
        if(libio_dependents_projects == null){
            libio_dependents_projects = mgmt.makePropertyKey('libio_dependents_projects').dataType(String.class).make();
        }

        libio_dependents_repos = mgmt.getPropertyKey('libio_dependents_repos');
        if(libio_dependents_repos == null){
            libio_dependents_repos = mgmt.makePropertyKey('libio_dependents_repos').dataType(String.class).make();
        }

        libio_total_releases = mgmt.getPropertyKey('libio_total_releases');
        if(libio_total_releases == null){
            libio_total_releases = mgmt.makePropertyKey('libio_total_releases').dataType(String.class).make();
        }

        libio_latest_release = mgmt.getPropertyKey('libio_latest_release');
        if(libio_latest_release == null){
            libio_latest_release = mgmt.makePropertyKey('libio_latest_release').dataType(Double.class).make();
        }

        libio_first_release = mgmt.getPropertyKey('libio_first_release');
        if(libio_first_release == null){
            libio_first_release = mgmt.makePropertyKey('libio_first_release').dataType(Double.class).make();
        }

        gh_release_date = mgmt.getPropertyKey('gh_release_date');
        if(gh_release_date == null){
            gh_release_date = mgmt.makePropertyKey('gh_release_date').dataType(Double.class).make();
        }

        libio_latest_version = mgmt.getPropertyKey('libio_latest_version');
        if(libio_latest_version == null) {
            libio_latest_version = mgmt.makePropertyKey('libio_latest_version').dataType(String.class).make();
        }

        libio_watchers = mgmt.getPropertyKey('libio_watchers');
        if(libio_watchers == null){
            libio_watchers = mgmt.makePropertyKey('libio_watchers').dataType(Double.class).make();
        }

        libio_contributors = mgmt.getPropertyKey('libio_contributors');
        if(libio_contributors == null){
            libio_contributors = mgmt.makePropertyKey('libio_contributors').dataType(Double.class).make();
        }

        libio_usedby = mgmt.getPropertyKey('libio_usedby');
        if(libio_usedby == null) {
            libio_usedby = mgmt.makePropertyKey('libio_usedby').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // user related properties

        userid = mgmt.getPropertyKey('userid');
        if(userid == null) {
            userid = mgmt.makePropertyKey('userid').dataType(String.class).make();
        }

        company = mgmt.getPropertyKey('company');
        if(company == null) {
            company = mgmt.makePropertyKey('company').dataType(String.class).make();
        }

        recent_requests = mgmt.getPropertyKey('recent_requests');
        if(recent_requests == null) {
            recent_requests = mgmt.makePropertyKey('recent_requests').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        osio_usage_count = mgmt.getPropertyKey('osio_usage_count');
        if(osio_usage_count == null) {
            osio_usage_count = mgmt.makePropertyKey('osio_usage_count').dataType(Integer.class).make();
        }

        // Manual tags related properties

        tags = mgmt.getPropertyKey('tags');
        if(tags == null) {
            tags = mgmt.makePropertyKey('tags').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        user_tags = mgmt.getPropertyKey('user_tags');
        if(user_tags == null) {
            user_tags = mgmt.makePropertyKey('user_tags').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        tags_count = mgmt.getPropertyKey('tags_count');
        if(tags_count == null) {
            tags_count = mgmt.makePropertyKey('tags_count').dataType(Integer.class).make();
        }

        manual_tagging_required = mgmt.getPropertyKey('manual_tagging_required');
        if(manual_tagging_required == null) {
            manual_tagging_required = mgmt.makePropertyKey('manual_tagging_required').dataType(Boolean.class).make();
        }

        // # for Repository Node
        repo_url = mgmt.getPropertyKey('repo_url');
        if(repo_url == null) {
            repo_url = mgmt.makePropertyKey('repo_url').dataType(String.class).make();
        }
        repo_user = mgmt.getPropertyKey('repo_user');
        if(repo_user == null) {
            repo_user = mgmt.makePropertyKey('repo_user').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // # for 3rd party ingestion
        source_repo = mgmt.getPropertyKey('source_repo');
        if(source_repo == null) {
            source_repo = mgmt.makePropertyKey('source_repo').dataType(String.class).cardinality(Cardinality.SET).make();
        }

        // # for indexes
        if(null == mgmt.getGraphIndex('SNVidIndex')) {
            mgmt.buildIndex('SNVidIndex', Vertex.class).addKey(snyk_vuln_id).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('CVEidIndex')) {
            mgmt.buildIndex('CVEidIndex', Vertex.class).addKey(cve_id).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('LicenseName')) {
            mgmt.buildIndex('LicenseName', Vertex.class).addKey(lname).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('NameEcosystemIndex')) {
            mgmt.buildIndex('NameEcosystemIndex', Vertex.class).addKey(name).addKey(ecosystem).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('NameEcosystemVersionIndex')) {
            mgmt.buildIndex('NameEcosystemVersionIndex', Vertex.class).addKey(pname).addKey(pecosystem).addKey(version).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('UserIndex')) {
            mgmt.buildIndex('UserIndex', Vertex.class).addKey(userid).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('CompanyIndex')) {
            mgmt.buildIndex('CompanyIndex', Vertex.class).addKey(company).buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('TagEcosystemIndex')) {
            mgmt.buildIndex('TagEcosystemIndex', Vertex.class).addKey(manual_tagging_required).addKey(ecosystem).buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('CategoryNameIndex')) {
            mgmt.buildIndex('CategoryNameIndex', Vertex.class).addKey(ctname).unique().buildCompositeIndex();
        }

        if(null == mgmt.getGraphIndex('RepoURLIndex')) {
            mgmt.buildIndex('RepoURLIndex', Vertex.class).addKey(repo_url).unique().buildCompositeIndex();
        }

        List<String> allKeys = [
                'ecosystem',
                'name',
                //'package_relative_used',
                //'package_dependents_count',
                //'latest_version',
                //'gh_stargazers',
                //'gh_open_issues_count',
                //'gh_subscribers_count',
                //'gh_contributors_count',
                'gh_refreshed_on',
                'pname',
                'pecosystem',
                'version',
                'latest_version_last_updated',
                //'description',
                'shipped_as_downstream',
                //'licenses',
                'libio_licenses',
                'declared_licenses',
                //'cve_ids',
                //'cm_loc',
                //'cm_num_files',
                //'cm_avg_cyclomatic_complexity',
                //'relative_used',
                //'dependents_count',
                //'is_packaged_in',
                //'is_published_in',
                'lname',
                'license_count',
                'email',
                //'cve_id',
                //'fixed_in',
                'cecosystem',
                'nvd_status',
                'cvedb_version',
                //'summary',
                //'access_authentication',
                //'access_complexity',
                //'access_vector',
                //'impact_availability ',
                //'impact_confidentiality',
                //'impact_integrity ',
                //'references',
                'vertex_label',
                'last_updated',
                'modified_date',
                //'base_score',
                //'exploitability_subscore',
                //'impact_subscore',
                //'remediation_status',
                //'remediation_updated_at',
                //'remediation_created_at',
                //'severity',
                //'source',
                'vulnerability_name',
                //'vulnerability_published_date',
                //'vulnerability_updated_date',
                'tokens',
                'topics',
                'categories',
                //'libio_dependents_projects',
                //'libio_dependents_repos',
                //'libio_total_releases',
                //'libio_latest_release',
                //'libio_watchers',
                //'libio_contributors',
                //'libio_first_release',
                'gh_release_date',
                //'libio_latest_version',
                //'libio_usedby',
                //'user_id',
                //'company',
                'recent_requests',
                //'osio_usage_count',
                'manual_tagging_required',
                'tags',
                'user_tags',
                'tags_count',
                'category_deps_count',
                'category_runtime',
                'source_repo',
                'repo_user',
                'snyk_ecosystem',
                'package_name',
                'module_name'
        ]

        allKeys.each { k ->
            keyRef = mgmt.getPropertyKey(k);
            index_key = 'index_prop_key_'+k;
            if(null == mgmt.getGraphIndex(index_key)) {
                mgmt.buildIndex(index_key, Vertex.class).addKey(keyRef).buildCompositeIndex()
            }
        }
        mgmt.commit();
