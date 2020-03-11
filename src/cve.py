"""This module encapsulates CVE related queries."""

import logging
from src.graph_populator import GraphPopulator
from src.graph_manager import BayesianGraph
from src.utils import get_timestamp, call_gremlin, update_non_cve_version

logger = logging.getLogger(__name__)


class SnykCVEPut(object):
    """Class encapsulating operations related to adding or replacing snyk CVEs."""

    def __init__(self, cve_dict):
        """Create CVEPut object based on cve_dict."""
        self._cve_dict = cve_dict
        self.validate_input()
        logger.info("Data validation done for snyk")

    def validate_input(self):
        """Validate input."""
        try:
            assert self._cve_dict
            assert 'id' in self._cve_dict
            assert 'description' in self._cve_dict
            # if CVE is new, the score doesn't have to be available
            if self._cve_dict.get('cvssScore'):
                assert type(self._cve_dict.get('cvssScore')) == float
            assert 'severity' in self._cve_dict
            assert 'malicious' in self._cve_dict
            assert 'ecosystem' in self._cve_dict
            assert 'affected' in self._cve_dict
        except AssertionError:
            raise ValueError('Invalid input')
        return True

    def create_pv_nodes(self):
        """Create Package and Version nodes, if needed."""
        nodes = []  # return (e, p, v) tuples of created/existing nodes; for easier testing
        affected_pkgs = {}
        all_epvs_created = True
        epv_dict = {
            "ecosystem": self._cve_dict.get('ecosystem'),
            "name": self._cve_dict.get('package')
        }
        for ver in self._cve_dict.get('affected'):
            epv_dict['version'] = ver
            query = GraphPopulator.construct_graph_nodes(epv_dict)
            success, json_response = BayesianGraph.execute(query)
            e = epv_dict.get('ecosystem')
            p = epv_dict.get('name')
            v = epv_dict.get('version')
            # Fetch the value of the latest_version from the query created
            latest_version = "-1"
            if "latest_version" in query:
                data = query.split("\'latest_version\'")[1].split(");")[0]
                latest_version = data.replace(",", "").strip().replace("'", "")
            if p not in affected_pkgs:
                tmp = {
                    "ecosystem": e,
                    "latest_version": latest_version
                }
                affected_pkgs[p] = tmp
            if not success:
                logger.error('CVEIngestionError - Error creating nodes for {e}/{p}/{v}: {r}'.format(
                    e=e, p=p, v=v, r=str(json_response))
                )
                all_epvs_created = False
            else:
                nodes.append((e, p, v))
        return nodes, all_epvs_created, affected_pkgs

    def _get_bindings(self):
        return {
            'sn_id': self._cve_dict.get('id'),
            'description': self._cve_dict.get('description'),
            'cvss_score': self._cve_dict.get('cvssScore') or 10.0,  # assume the worst
            'ecosystem': self._cve_dict.get('ecosystem'),
            'modified_date': get_timestamp(),
            'severity': self._cve_dict.get('severity'),
            'title': self._cve_dict.get('title'),
            'url': self._cve_dict.get('url'),
            'cvssV3': self._cve_dict.get('cvssV3'),
            'exploit': self._cve_dict.get('exploit'),
            'fixable': self._cve_dict.get('fixable'),
            'malicious': self._cve_dict.get('malicious'),
            'patch_exists': self._cve_dict.get('patchExists')
        }

    def _get_default_bindings(self):
        return {
            'sn_id': self._cve_dict.get('id'),
            'ecosystem': self._cve_dict.get('ecosystem')
        }

    def get_qstring_for_cve_node(self):
        """Construct Gremlin script that will create a CVE node.

        :return: (str, str), gremlin script and bindings
        """
        query_str = cve_snyk_node_replace_script_template

        bindings = self._get_bindings()

        if self._cve_dict.get('initiallyFixedIn'):
            for fix in self._cve_dict.get('initiallyFixedIn'):
                query_str += "cve_v.property('sfixed_in', '" + fix + "');"

        if self._cve_dict.get('cves'):
            for cve in self._cve_dict.get('cves'):
                query_str += "cve_v.property('scve_ids', '" + cve + "');"

        if self._cve_dict.get('cwes'):
            for cwe in self._cve_dict.get('cwes'):
                query_str += "cve_v.property('scwes', '" + cwe + "');"

        return query_str, bindings

    def prepare_payload(self, query_str, bindings):
        """Prepare payload for Gremlin."""
        payload = {
            'gremlin': query_str,
            'bindings': bindings
        }
        logger.debug("Payload for the generated gremlin query {p}".format(p=payload))

        return payload

    def get_qstrings_for_edges(self):
        """Construct Gremlin scripts that will connect CVE node with EPVs.

        :return: list, list of gremlin scripts
        """
        return [
            add_affected_snyk_edge_script_template.format(
                ecosystem=self._cve_dict.get('ecosystem'),
                name=self._cve_dict.get('package'),
                version=x
            ) for x in self._cve_dict.get('affected')
        ]

    def process(self):
        """Add or replace CVE node in graph."""
        # Create EPV nodes first and get a list of failed EPVs
        # If any of the EPV creation failed, then do not attempt further processing
        succesfull_epvs, all_epvs_succesfull, affected_pkgs = self.create_pv_nodes()
        logger.info("PV nodes created for snyk")

        if all_epvs_succesfull:
            try:
                # Create CVE node
                call_gremlin(
                    self.prepare_payload(*self.get_qstring_for_cve_node())
                )
            except ValueError:
                logger.error('Snyk CVEIngestionError - Error creating CVE node: {c}'.format(
                    c=self._cve_dict['id']))
            else:
                try:
                    # Connect CVE node with affected EPV nodes
                    for query_str in self.get_qstrings_for_edges():
                        call_gremlin(self.prepare_payload(query_str, self._get_default_bindings()))
                    logger.info("Snyk CVEIngestionDebug - CVE sub-graph succesfully created for "
                                "CVE node: {c}".format(c=self._cve_dict['id']))
                    logger.info("Updating non cve latest version (snyk)")
                    update_non_cve_version(affected_pkgs)
                except ValueError:
                    logger.error("Snyk CVEIngestionError - Error creating CVE edges."
                                 "Rolling back CVE node: {c}".format(c=self._cve_dict['id']))
                    call_gremlin(self.prepare_payload(snyk_roll_back_cve_template,
                                                      self._get_default_bindings()))
        else:
            logger.error('CVEIngestionError - Error creating EPV nodes for Snyk CVE node: {c}'
                         .format(c=self._cve_dict['id']))


class SnykCVEDelete(object):
    """Class encapsulating operations related to deleting Snyk CVEs."""

    def __init__(self, cve_id_dict):
        """Create CVEDelete object based on cve_id_dict."""
        self._cve_id_dict = cve_id_dict
        self.validate_input()

    def validate_input(self):
        """Validate input."""
        try:
            assert self._cve_id_dict
            assert 'id' in self._cve_id_dict
            assert self._cve_id_dict['id']
        except AssertionError:
            raise ValueError('Invalid input')
        return True

    def process(self):
        """Delete CVE node from graph."""
        json_payload = self.prepare_payload()
        call_gremlin(json_payload)

    def prepare_payload(self):
        """Prepare payload for Gremlin."""
        timestamp = get_timestamp()
        payload = {
            'gremlin': snyk_cve_node_delete_script_template,
            'bindings': {
                'sn_id': self._cve_id_dict.get('id'),
                'timestamp': timestamp
            }
        }

        return payload


class CVEPut(object):
    """Class encapsulating operations related to adding or replacing CVEs."""

    def __init__(self, cve_dict):
        """Create CVEPut object based on cve_dict."""
        self._cve_dict = cve_dict
        self.validate_input()

    def validate_input(self):
        """Validate input."""
        try:
            assert self._cve_dict
            assert 'cve_id' in self._cve_dict
            assert 'description' in self._cve_dict
            # if CVE is new, the score doesn't have to be available
            if self._cve_dict.get('cvss_v2'):
                assert type(self._cve_dict.get('cvss_v2')) == float
            assert 'affected' in self._cve_dict
            assert 'ecosystem' in self._cve_dict
            for epv_dict in self._cve_dict.get('affected'):
                assert 'name' in epv_dict
                assert 'version' in epv_dict
        except AssertionError:
            raise ValueError('Invalid input')
        return True

    def _get_default_bindings(self):
        return {
            'cve_id': self._cve_dict.get('cve_id'),
            'description': self._cve_dict.get('description'),
            'cvss_v2': self._cve_dict.get('cvss_v2') or 10.0,  # assume the worst
            'ecosystem': self._cve_dict.get('ecosystem'),
            'modified_date': get_timestamp()
        }

    def process(self):
        """Add or replace CVE node in graph."""
        # Create EPV nodes first and get a list of failed EPVs
        # If any of the EPV creation failed, then do not attempt further processing
        succesfull_epvs, all_epvs_succesfull, affected_pkgs = self.create_pv_nodes()

        if all_epvs_succesfull:
            try:
                # Create CVE node
                call_gremlin(
                    self.prepare_payload(*self.get_qstring_for_cve_node())
                )
            except ValueError:
                logger.error('CVEIngestionError - Error creating CVE node: {c}'.format(
                    c=self._cve_dict['cve_id']))
            else:
                try:
                    # Connect CVE node with affected EPV nodes
                    for query_str in self.get_qstrings_for_edges():
                        call_gremlin(self.prepare_payload(query_str, self._get_default_bindings()))
                    logger.debug("CVEIngestionDebug - CVE sub-graph succesfully created for "
                                 "CVE node: {c}".format(c=self._cve_dict['cve_id']))
                    logger.info("Updating non cve latest version")
                    update_non_cve_version(affected_pkgs)
                except ValueError:
                    logger.error("CVEIngestionError - Error creating CVE edges."
                                 "Rolling back CVE node: {c}".format(c=self._cve_dict['cve_id']))
                    call_gremlin(self.prepare_payload(cvedb_roll_back_cve_template,
                                                      self._get_default_bindings()))
        else:
            logger.error('CVEIngestionError - Error creating EPV nodes for CVE node: {c}'.format(
                c=self._cve_dict['cve_id']))

    def create_pv_nodes(self):
        """Create Package and Version nodes, if needed."""
        nodes = []  # return (e, p, v) tuples of created/existing nodes; for easier testing
        affected_pkgs = {}
        all_epvs_created = True
        for pv_dict in self._cve_dict.get('affected'):
            epv_dict = pv_dict.copy()
            epv_dict['ecosystem'] = self._cve_dict.get('ecosystem')
            query = GraphPopulator.construct_graph_nodes(epv_dict)
            latest_version = "-1"
            # Fetch the value of the latest_version from the query created
            if "latest_version" in query:
                data = query.split("\'latest_version\'")[1].split(");")[0]
                latest_version = data.replace(",", "").strip().replace("'", "")
            success, json_response = BayesianGraph.execute(query)
            e = epv_dict.get('ecosystem')
            p = epv_dict.get('name')
            v = epv_dict.get('version')
            if p not in affected_pkgs:
                tmp = {
                    "ecosystem": e,
                    "latest_version": latest_version
                }
                affected_pkgs[p] = tmp
            if not success:
                logger.error('CVEIngestionError - Error creating nodes for {e}/{p}/{v}: {r}'.format(
                    e=e, p=p, v=v, r=str(json_response))
                )
                all_epvs_created = False
            else:
                nodes.append((e, p, v))
        return nodes, all_epvs_created, affected_pkgs

    def get_qstrings_for_edges(self):
        """Construct Gremlin scripts that will connect CVE node with EPVs.

        :return: list, list of gremlin scripts
        """
        return [
            add_affected_edge_script_template.format(
                ecosystem=self._cve_dict.get('ecosystem'),
                name=x.get('name'),
                version=x.get('version')
            ) for x in self._cve_dict.get('affected')
        ]

    def get_qstring_for_cve_node(self):
        """Construct Gremlin script that will create a CVE node.

        :return: (str, str), gremlin script and bindings
        """
        query_str = cve_node_replace_script_template

        bindings = self._get_default_bindings()

        if self._cve_dict.get('nvd_status'):
            query_str += cve_node_replace_script_template_nvd_status
            bindings['nvd_status'] = self._cve_dict.get('nvd_status')

        if self._cve_dict.get('fixed_in'):
            for ver in self._cve_dict.get('fixed_in'):
                query_str += "cve_v.property('fixed_in', '" + ver + "');"

        if self._cve_dict.get('cve_sources'):
            query_str += cve_node_replace_script_template_cve_sources
            bindings['cve_sources'] = self._cve_dict.get('cve_sources')

        return query_str, bindings

    def prepare_payload(self, query_str, bindings):
        """Prepare payload for Gremlin."""
        payload = {
            'gremlin': query_str,
            'bindings': bindings
        }

        return payload


class CVEDelete(object):
    """Class encapsulating operations related to deleting CVEs."""

    def __init__(self, cve_id_dict):
        """Create CVEDelete object based on cve_id_dict."""
        self._cve_id_dict = cve_id_dict
        self.validate_input()

    def validate_input(self):
        """Validate input."""
        try:
            assert self._cve_id_dict
            assert 'cve_id' in self._cve_id_dict
            assert self._cve_id_dict['cve_id']
        except AssertionError:
            raise ValueError('Invalid input')
        return True

    def process(self):
        """Delete CVE node from graph."""
        json_payload = self.prepare_payload()
        call_gremlin(json_payload)

    def prepare_payload(self):
        """Prepare payload for Gremlin."""
        timestamp = get_timestamp()
        payload = {
            'gremlin': cve_node_delete_script_template,
            'bindings': {
                'cve_id': self._cve_id_dict.get('cve_id'),
                'timestamp': timestamp
            }
        }

        return payload


class CVEGet(object):
    """Class encapsulating operations related to retrieving information about CVEs."""

    def __init__(self, ecosystem, name, version):
        """Create CVEGet object based on epv."""
        self._ecosystem = ecosystem
        self._name = name
        self._version = version

    def get(self):
        """Get information about CVEs."""
        if self._ecosystem and self._name and self._version:
            return self.get_cves_for_ecosystem_name_version()
        elif self._ecosystem and self._name:
            return self.get_cves_for_ecosystem_name()
        elif self._ecosystem:
            return self.get_cves_for_ecosystem()

    def get_cves_for_ecosystem(self):
        """Get information about CVEs affecting (Ecosystem)."""
        script = cve_nodes_for_ecosystem_script_template
        bindings = {'ecosystem': self._ecosystem}
        return self.get_cves(script, bindings)

    def get_cves_for_ecosystem_name(self):
        """Get information about CVEs affecting (Ecosystem, Name)."""
        script = cve_nodes_for_ecosystem_name_script_template
        bindings = {'ecosystem': self._ecosystem, 'name': self._name}
        return self.get_cves(script, bindings)

    def get_cves_for_ecosystem_name_version(self):
        """Get information about CVEs affecting (Ecosystem, Name, Version)."""
        script = cve_nodes_for_ecosystem_name_version_script_template
        bindings = {'ecosystem': self._ecosystem, 'name': self._name, 'version': self._version}
        return self.get_cves(script, bindings)

    def get_cves(self, script, bindings):
        """Call Gremlin and get the CVE information."""
        json_payload = self.prepare_payload(script, bindings)
        response = call_gremlin(json_payload)
        cve_list = response.get('result', {}).get('data', [])
        return {'count': len(cve_list), 'cve_ids': cve_list}

    def prepare_payload(self, script, bindings):
        """Prepare payload."""
        payload = {
            'gremlin': script,
            'bindings': bindings
        }

        return payload


class CVEDBVersion(object):
    """Class encapsulating getter/setter methods around 'CVEDBVersion' node."""

    @staticmethod
    def get():
        """Get CVEDB version."""
        json_payload = {
            'gremlin': cvedb_version_get_script_template,
        }
        response = call_gremlin(json_payload)
        data = response.get('result', {}).get('data', [])
        return data[0] if data else None

    @staticmethod
    def put(payload):
        """Update CVEDB version."""
        json_payload = {
            'gremlin': cvedb_version_replace_script_template,
            'bindings': {
                'cvedb_version': payload.get('version')
            }
        }
        call_gremlin(json_payload)
        return payload.get('version')


# Gremlin scripts :/
# TODO: explore https://goblin.readthedocs.io/

# add or replace CVE node
cve_node_replace_script_template = """\
g.V().has('cve_id',cve_id).inE('has_cve').drop().iterate();\
cve_v=g.V().has('cve_id',cve_id).has('cecosystem', ecosystem).tryNext().orElseGet{\
graph.addVertex(label, 'CVE',\
'vertex_label', 'CVE',\
'cve_id', cve_id)};\
cve_v.property('cecosystem', ecosystem);\
cve_v.property('description', description);\
cve_v.property('cvss_v2', cvss_v2);\
cve_v.property('modified_date', modified_date);\
"""

# add or replace CVE node
cve_snyk_node_replace_script_template = """\
g.V().has('sn_id',sn_id).inE('has_snyk_cve').drop().iterate();\
cve_v=g.V().has('sn_id',sn_id).has('snecosystem', ecosystem).tryNext().orElseGet{\
graph.addVertex(label, 'SCVE',\
'vertex_label', 'SCVE',\
'sn_id', sn_id)};\
cve_v.property('snecosystem', ecosystem);\
cve_v.property('scvss_score', cvss_score);\
cve_v.property('sdescription', description);\
cve_v.property('severity', severity);\
cve_v.property('title', title);\
cve_v.property('surl', url);\
cve_v.property('scvss_v3', cvssV3);\
cve_v.property('exploit', exploit);\
cve_v.property('fixable', fixable);\
cve_v.property('malicious', malicious);\
cve_v.property('patch_exists', patch_exists);\
cve_v.property('modified_date', modified_date);\
"""

# add or replace additional non-mandatory properties for CVE node
cve_node_replace_script_template_nvd_status = """\
cve_v.property('nvd_status', nvd_status);\
"""

# add or replace additional non-mandatory properties for CVE node
cve_node_replace_script_template_cve_sources = """\
cve_v.property('cve_sources', cve_sources);\
"""

# add edge between CVE node and Version node if it does not exist previously
add_affected_edge_script_template = """\
cve_v=g.V().has('cve_id',cve_id).next();\
version_v=g.V().has('pecosystem','{ecosystem}')\
.has('pname','{name}')\
.has('version','{version}');\
version_v.out('has_cve').has('cve_id', cve_id).tryNext().orElseGet{{\
g.V().has('pecosystem','{ecosystem}')\
.has('pname','{name}')\
.has('version','{version}')\
.next().addEdge('has_cve', cve_v)}};\
"""

# add edge between CVE node and Version node if it does not exist previously
add_affected_snyk_edge_script_template = """\
cve_v=g.V().has('sn_id',sn_id).next();\
version_v=g.V().has('pecosystem','{ecosystem}')\
.has('pname','{name}')\
.has('version','{version}');\
version_v.out('has_snyk_cve').has('sn_id', sn_id).tryNext().orElseGet{{\
g.V().has('pecosystem','{ecosystem}')\
.has('pname','{name}')\
.has('version','{version}')\
.next().addEdge('has_snyk_cve', cve_v)}};\
"""

# delete CVE node
cve_node_delete_script_template = """\
g.V().has('cve_id',cve_id)\
.property('modified_date',timestamp)\
.inE('has_cve').drop().iterate();\
"""

# delete Snyk CVE node
snyk_cve_node_delete_script_template = """\
g.V().has('sn_id',sn_id)\
.property('modified_date',timestamp)\
.inE('has_snyk_cve').drop().iterate();\
"""

# get CVEs for ecosystem
cve_nodes_for_ecosystem_script_template = """\
g.V().has("vertex_label", "CVE")\
.has("cecosystem",ecosystem)\
.values("cve_id")\
.dedup();\
"""

# get CVEs for (ecosystem, name)
cve_nodes_for_ecosystem_name_script_template = """\
g.V().has("pecosystem",ecosystem)\
.has("pname",name)\
.out("has_cve")\
.values("cve_id")\
.dedup();\
"""

# get CVEs for (ecosystem, name, version)
cve_nodes_for_ecosystem_name_version_script_template = """\
g.V().has("pecosystem",ecosystem)\
.has("pname",name)\
.has("version",version)\
.out("has_cve")\
.values("cve_id")\
.dedup();\
"""

# Update CVEDB version
cvedb_version_replace_script_template = """\
cve_v=g.V().has('vertex_label', 'CVEDBVersion').tryNext().orElseGet{\
graph.addVertex('vertex_label', 'CVEDBVersion')};\
cve_v.property('cvedb_version', cvedb_version);\
"""

# Get CVEDB version
cvedb_version_get_script_template = """\
g.V().has('vertex_label', 'CVEDBVersion')\
.values("cvedb_version")\
"""

# Rollback CVE Node
cvedb_roll_back_cve_template = """
g.V().has('cve_id', cve_id).drop().iterate();
"""

# Rollback Snyk CVE Node
snyk_roll_back_cve_template = """
g.V().has('sn_id', sn_id).drop().iterate();
"""
