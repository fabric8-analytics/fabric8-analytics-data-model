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
            assert 'affected' in self._cve_dict
            assert 'ecosystem' in self._cve_dict
            for epv_dict in self._cve_dict.get('affected'):
                assert 'name' in epv_dict
                assert 'version' in epv_dict
        except AssertionError:
            raise ValueError('Invalid input')
        return True

    def process(self):
        """Add or replace CVE node in graph."""
        self.create_pv_nodes()
        json_payload = self.prepare_payload()
        call_gremlin(json_payload)

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

    def prepare_payload(self):
        """Prepare payload for Gremlin."""
        query_str = cve_node_replace_script_template

        for epv_dict in self._cve_dict.get('affected'):
            edge_str = add_affected_edge_script_template.format(
                ecosystem=self._cve_dict.get('ecosystem'),
                name=epv_dict.get('name'),
                version=epv_dict.get('version')
            )
            query_str += edge_str

        timestamp = get_timestamp()

        payload = {
            'gremlin': query_str,
            'bindings': {
                'cve_id': self._cve_dict.get('cve_id'),
                'description': self._cve_dict.get('description'),
                'cvss_v2': self._cve_dict.get('cvss_v2'),
                'ecosystem': self._cve_dict.get('ecosystem'),
                'timestamp': timestamp
            }
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
        payload = {
            'gremlin': cve_node_delete_script_template,
            'bindings': {
                'cve_id': self._cve_id_dict.get('cve_id')
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
g.V().has('cve_id',cve_id)\
.drop()\
.iterate();\
cve_v=g.addV('CVE')\
.property('ecosystem',ecosystem)\
.property('cve_id',cve_id)\
.property('description',description)\
.property('cvss_v2',cvss_v2)\
.property('timestamp',timestamp)\
.next();\
"""

# add edge between CVE node and Version node
add_affected_edge_script_template = """\
version_v=g.V().has('pecosystem','{ecosystem}')\
.has('pname','{name}')\
.has('version','{version}')\
.next();\
version_v.addEdge('has_cve',cve_v);\
"""

# delete CVE node
cve_node_delete_script_template = """\
g.V().has('cve_id',cve_id)\
.drop();\
"""

# get CVEs for ecosystem
cve_nodes_for_ecosystem_script_template = """\
g.V().has("ecosystem",ecosystem)\
.has("cve_id")\
.values("cve_id")\
.dedup()\
"""

# get CVEs for (ecosystem, name)
cve_nodes_for_ecosystem_name_script_template = """\
g.V().has("pecosystem",ecosystem)\
.has("pname",name)
.outE("has_cve")\
.inV()\
.values("cve_id")\
.dedup()\
"""

# get CVEs for (ecosystem, name, version)
cve_nodes_for_ecosystem_name_version_script_template = """\
g.V().has("pecosystem",ecosystem)\
.has("pname",name)
.has("version",version)
.outE("has_cve")\
.inV()\
.values("cve_id")\
.dedup()\
"""


# Update CVEDB version
cvedb_version_replace_script_template = """\
g.V().hasLabel('CVEDBVersion')\
.drop()\
.iterate();\
cve_v=g.addV('CVEDBVersion')\
.property('cvedb_version',cvedb_version)\
.next();\
"""

# Get CVEDB version
cvedb_version_get_script_template = """\
g.V().hasLabel('CVEDBVersion')\
.values("cvedb_version")\
"""
