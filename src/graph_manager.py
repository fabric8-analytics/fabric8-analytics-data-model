"""Template for a singleton object which will have reference to Graph object."""

from src import config
import json
import requests
import os
import logging

logger = logging.getLogger(config.APP_NAME)


class BayesianGraph(object):
    """Template for a singleton object which will have reference to Graph object."""

    @classmethod
    def execute(cls, str_gremlin_dsl):
        """Execute the query prepared for the graph database."""
        logger.debug("BayesianGraph::execute() Gremlin DSL:  %s", str_gremlin_dsl)
        payload = {'gremlin': str_gremlin_dsl}
        response = requests.post(config.GREMLIN_SERVER_URL_REST,
                                 data=json.dumps(payload))
        json_response = response.json()

        logger.debug("BayesianGraph::execute(): %s", response)
        if response.status_code != 200:
            logger.error("ERROR %d(%s): %s" % (response.status_code, response.reason,
                                               json_response.get("message")))
            return False, json_response
        else:
            return True, json_response

    @classmethod
    def return_json_response_data(cls, json_result):
        """Return the data taken from the graph DB response (other attributes are ignored)."""
        is_created = False
        script_output = json_result.get("result", {}).get("data", [])
        if isinstance(script_output, list) and len(script_output) > 0:
            is_created = script_output[0]
        return is_created

    @classmethod
    def is_index_created(cls):
        """Check whether the index is created in the graph database."""
        str_gremlin_dsl = """
        // obtain references reference to graph management instance
        mgmt = graph.openManagement();
        i = mgmt.getGraphIndex('UseridIndex');
        mgmt.commit();
        i != null
        """
        status, json_result = cls.execute(str_gremlin_dsl)
        return cls.return_json_response_data(json_result) if status else False

    @classmethod
    def is_schema_defined(cls):
        """Check whether the schema is defined in the graph database."""
        str_gremlin_dsl = """
        // obtain references reference to graph management instance
        mgmt = graph.openManagement();
        k = mgmt.getPropertyKey('company');
        mgmt.commit()

        // if this is true then we have already created the schema
        // else schema is not yet created
        k != null
        """
        status, json_result = cls.execute(str_gremlin_dsl)
        return cls.return_json_response_data(json_result) if status else False

    @classmethod
    def populate_schema(cls):
        """Populate the schema stored in the Groovy script."""
        current_file_path = os.path.dirname(os.path.realpath(__file__))
        schema_file_path = os.path.join(current_file_path, 'schema.groovy')
        str_gremlin_dsl = ''''''
        with open(schema_file_path, 'r') as f:
            str_gremlin_dsl = f.read()
        return cls.execute(str_gremlin_dsl)
