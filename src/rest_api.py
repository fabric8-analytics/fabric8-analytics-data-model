import flask
from flask import Flask, request, redirect, make_response
from flask_cors import CORS
import json
import sys
import codecs
import urllib
import data_importer
from graph_manager import BayesianGraph

# Python2.x: Make default encoding as UTF-8
if sys.version_info.major == 2:
    reload(sys)
    sys.setdefaultencoding('UTF8')


app = Flask(__name__)
app.config.from_object('config')
CORS(app)

# Check whether schema is created or not
# populate schema if not already done
if not BayesianGraph.is_index_created():
    print("Index is not created as yet, checking schema creation")
    if not BayesianGraph.is_schema_defined():
        print("Schema is not yet created, creating now...")
        BayesianGraph.populate_schema()
        # double check
        schema_definition_success = BayesianGraph.is_schema_defined()
        print("Double check: schema_definition_success %s" % schema_definition_success)
        if not schema_definition_success:
            raise RuntimeError("Failed to setup graph schema")
        else:
            print("Ready to serve requests")

@app.route('/api/v1/import_epv_from_s3', methods=['POST'])
def import_epv_from_s3():
    input_json = request.get_json()
    app.logger.info("Importing the given list of EPVs")

    expected_keys = set(['ecosystem', 'name', 'version'])
    for epv in input_json:
        if expected_keys != set(epv.keys()):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    report = data_importer.import_epv_from_s3(list_epv=input_json)
    response = {'message': report.get('message'),
                'count_imported_EPVs': report.get('cnt_imported_EPVs')}
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


@app.route('/api/v1/ingest_to_graph', methods=['POST'])
def ingest_to_graph():
    input_json = request.get_json()
    app.logger.info("Ingesting the given list of EPVs")

    expected_keys = set(['ecosystem', 'name', 'version'])
    for epv in input_json:
        if expected_keys != set(epv.keys()):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    report = data_importer.import_epv_from_s3_http(list_epv=input_json)
    response = {'message': report.get('message'),
                'count_imported_EPVs': report.get('count_imported_EPVs')}
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


@app.route('/api/v1/import_from_s3', methods=['POST'])
def import_from_s3():
    app.logger.info("Invoking the import data from s3")
    report = data_importer.import_from_s3()

    response = {'message': report.get('message'),
                'count_imported_EPVs': report.get('cnt_imported_EPVs')}
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


if __name__ == "__main__":
    app.run()
