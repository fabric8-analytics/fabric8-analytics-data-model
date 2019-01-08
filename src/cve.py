"""This module encapsulates CVE related queries."""

import logging
from graph_populator import GraphPopulator
from graph_manager import BayesianGraph
from utils import get_timestamp, call_gremlin

logger = logging.getLogger(__name__)


class CVEPut(object):
    """Class encapsulating operations related to adding or replacing CVEs."""

    def __init__(self, cve_dict):
        """Constructor."""
        self._cve_dict = cve_dict
        self.validate_input()

    def validate_input(self):
        """Validate input."""
        try:
            assert self._cve_dict
            assert 'cve_id' in self._cve_dict
            assert 'description' in self._cve_dict
            assert 'cvss_v2' in self._cve_dict
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
            'cvss_v2': self._cve_dict.get('cvss_v2'),
            'ecosystem': self._cve_dict.get('ecosystem'),
            'modified_date': get_timestamp()
        }

    def process(self):
        """Add or replace CVE node in graph."""
        # Create EPV nodes first
        self.create_pv_nodes()
        # Create CVE node
        call_gremlin(
            self.prepare_payload(*self.get_qstring_for_cve_node())
        )
        # Connect CVE node with affected EPV nodes
        for query_str in self.get_qstrings_for_edges():
            call_gremlin(self.prepare_payload(query_str, self._get_default_bindings()))

    def create_pv_nodes(self):
        """Create Package and Version nodes, if needed."""
        for pv_dict in self._cve_dict.get('affected'):
            epv_dict = pv_dict.copy()
            epv_dict['ecosystem'] = self._cve_dict.get('ecosystem')
            query = GraphPopulator.construct_graph_nodes(epv_dict)
            success, json_response = BayesianGraph.execute(query)
            e = epv_dict.get('ecosystem')
            p = epv_dict.get('name')
            v = epv_dict.get('version')
            if not success:
                logger.error('Error creating nodes for {e}/{p}/{v}: {r}'.format(
                    e=e, p=p, v=v, r=str(json_response))
                )

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
        """Constructor."""
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
        """Constructor."""
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
cve_v=g.V().has('cve_id',cve_id).tryNext().orElseGet{\
graph.addVertex(label, 'CVE',\
'vertex_label', 'CVE',\
'cve_id', cve_id)};\
cve_v.property('ecosystem', ecosystem);\
cve_v.property('description', description);\
cve_v.property('cvss_v2', cvss_v2);\
cve_v.property('modified_date', modified_date);\
"""

# add or replace additional non-mandatory properties for CVE node
cve_node_replace_script_template_nvd_status = """\
cve_v.property('nvd_status', nvd_status);\
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

# delete CVE node
cve_node_delete_script_template = """\
g.V().has('cve_id',cve_id)\
.property('modified_date',timestamp)\
.inE('has_cve').drop().iterate();\
"""

# get CVEs for ecosystem
cve_nodes_for_ecosystem_script_template = """\
g.V().has("vertex_label", "CVE")\
.has("ecosystem",ecosystem)\
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
