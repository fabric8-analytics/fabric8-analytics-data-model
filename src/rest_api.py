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
try:
    status, json_result = BayesianGraph.populate_schema()
    if status:
        app.logger.info("Ready to serve requests")
    else:
        app.logger.error(json_result)
        raise RuntimeError("Failed to setup graph schema")
except Exception:
    raise RuntimeError("Failed to initialized graph schema")


@app.route('/api/v1/readiness')
def readiness():
    return flask.jsonify({}), 200


@app.route('/api/v1/liveness')
def liveness():
    # TODO Check graph database connection
    return flask.jsonify({}), 200


@app.route('/api/v1/ingest_to_graph', methods=['POST'])
def ingest_to_graph():
    input_json = request.get_json()
    app.logger.info("Ingesting the given list of EPVs - " + json.dumps(input_json))

    expected_keys = set(['ecosystem', 'name', 'version'])
    for epv in input_json:
        if expected_keys != set(epv.keys()):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    report = data_importer.import_epv_from_s3_http(list_epv=input_json)
    response = {'message': report.get('message'),
                'epv': input_json,
                'count_imported_EPVs': report.get('count_imported_EPVs')}
    print(response)
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


@app.route('/api/v1/selective_ingest', methods=['POST'])
def selective_ingest():
    input_json = request.get_json()

    if input_json.get('package_list') is None or len(input_json.get('package_list')) == 0:
        return flask.jsonify(message='No Packages provided. Nothing to be ingested'), 400

    expected_keys = set(['ecosystem', 'name'])
    for epv in input_json.get('package_list'):
        if not expected_keys.issubset(set(epv.keys())):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    app.logger.info("Selective Ingestion with payload - " + json.dumps(input_json))

    report = data_importer.import_epv_from_s3_http(list_epv=input_json.get('package_list'),
                                                   select_doc=input_json.get('select_ingest', None))
    response = {'message': report.get('message'),
                'epv': input_json,
                'count_imported_EPVs': report.get('count_imported_EPVs')}

    app.logger.info(response)

    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


if __name__ == "__main__":
    app.run()
