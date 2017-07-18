import config
import json
import requests
from gremlin_python import statics
from gremlin_python.structure.graph import Graph
from gremlin_python.process.graph_traversal import __
from gremlin_python.process.strategies import *
from gremlin_python.driver.driver_remote_connection import DriverRemoteConnection
import os
import sys
import logging

logger = logging.getLogger(__name__)


# singleton object which will have reference to Graph object
class BayesianGraph(object):
    _instances = {'graph': None}

    @classmethod
    def instance(cls):
        if cls._instances['graph'] is None:
            logger.info("BayesianGraph instance creating...")
            graph = Graph()
            g = graph.traversal().withRemote(DriverRemoteConnection(config.GREMLIN_SERVER_URL_WEBSOCKET, 'g'))

            # populate schema if not already done
            if not cls.is_index_created():
                logger.info ("Index is not created as yet, checking schema creation")
                if not cls.is_schema_defined():
                    logger.info("Schema is not yet created, creating now...")
                    populate_schema = cls.populate_schema()
                    ## double check
                    schema_definition_success = cls.is_schema_defined()
                    logger.info("Double check: schema_definition_success %s" % schema_definition_success)
                    if not schema_definition_success:
                        raise RuntimeError("Failed to setup graph schema")

            cls._instances['graph'] = g
        return cls._instances['graph']


    @classmethod
    def execute(cls, str_gremlin_dsl):
        logger.debug("BayesianGraph::execute() Gremlin DSL:  %s", str_gremlin_dsl)
        payload = {'gremlin': str_gremlin_dsl}
        response = requests.post(config.GREMLIN_SERVER_URL_REST,
                                 data=json.dumps(payload))
        json_response = response.json()

        logger.debug("BayesianGraph::execute(): %s", response)
        if response.status_code != 200:
            logger.debug("ERROR %d(%s): %s" % (response.status_code, response.reason, json_response.get("message")))
            return False, json_response
        else:
            return True, json_response

    @classmethod
    def return_json_response_data(cls, json_result):
        is_created = False
        if "result" in json_result and "data" in json_result["result"]:
            script_output = json_result["result"]["data"]
            if type(script_output) is list and len(script_output) > 0:
                is_created = script_output[0] is True
        return is_created

    @classmethod
    def is_index_created(cls):
        str_gremlin_dsl = """
        // obtain references reference to graph management instance
        mgmt = graph.openManagement();
        i = mgmt.getGraphIndex('UseridIndex');
        mgmt.commit();
        i != null
        """
        status, json_result = cls.execute(str_gremlin_dsl)
        if not status:
            return False
        else:
            return cls.return_json_response_data(json_result)

    @classmethod
    def is_schema_defined(cls):
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
        if not status:
            return False
        else:
            return cls.return_json_response_data(json_result)

    @classmethod
    def populate_schema(cls):
        current_file_path = os.path.dirname(os.path.realpath(__file__))
        schema_file_path = os.path.join(current_file_path, 'schema.groovy')
        str_gremlin_dsl = ''''''
        with open(schema_file_path, 'r') as f:
            str_gremlin_dsl = f.read()
        return cls.execute(str_gremlin_dsl)



