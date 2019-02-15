"""Declaration of the custom REST API to graph DB."""

import os
import flask
from flask import Flask, request
from flask_cors import CORS
import json
import sys
from src import data_importer
from src.graph_manager import BayesianGraph
from src.graph_populator import GraphPopulator
from src.cve import CVEPut, CVEDelete, CVEGet, CVEDBVersion
from raven.contrib.flask import Sentry
from src import config as config
from werkzeug.contrib.fixers import ProxyFix
import logging
from flask import Blueprint, current_app


api_v1 = Blueprint('api_v1', __name__)

# TODO: https://github.com/fabric8-analytics/fabric8-analytics-data-model/issues/196
# Python2.x: Make default encoding as UTF-8
if sys.version_info.major == 2:
    reload(sys)
    sys.setdefaultencoding('UTF8')


@api_v1.route('/api/v1/readiness')
def readiness():
    """Generate response for the GET request to /api/v1/readiness."""
    return flask.jsonify({}), 200


@api_v1.route('/api/v1/liveness')
def liveness():
    """Generate response for the GET request to /api/v1/liveness."""
    # TODO Check graph database connection
    return flask.jsonify({}), 200


@api_v1.route('/api/v1/pending')
def pending():
    """Get request to enlist all the EPVs which are not yet synced to Graph."""
    current_app.logger.info("/api/v1/pending - %s" % dict(request.args))
    ecosystem_name = request.args.get('ecosystem', None)
    package_name = request.args.get('package', None)
    version_id = request.args.get('version', None)
    limit = request.args.get('limit', None)
    offset = request.args.get('offset', None)

    params = {"ecosystem": ecosystem_name, "package": package_name, "version": version_id,
              "limit": limit, "offset": offset}
    current_app.logger.info("params - %s" % params)

    pending_list = data_importer.PostgresHandler().fetch_pending_epvs(**params)

    return flask.jsonify(pending_list), 200


@api_v1.route('/api/v1/sync_all')
def sync_all():
    """Generate response for the GET request to /api/v1/sync_all."""
    current_app.logger.info("/api/v1/sync_all - %s" % dict(request.args))
    ecosystem_name = request.args.get('ecosystem', None)
    package_name = request.args.get('package', None)
    version_id = request.args.get('version', None)
    limit = request.args.get('limit', None)
    offset = request.args.get('offset', None)
    params = {"ecosystem": ecosystem_name, "package": package_name, "version": version_id,
              "limit": limit, "offset": offset}
    current_app.logger.info("params - %s" % params)

    data = data_importer.PostgresHandler().fetch_pending_epvs(**params)

    try:
        pending_list = data["pending_list"]
        report = data_importer.import_epv_from_s3_http(list_epv=pending_list)
        response = {'message': report.get('message'),
                    'epv': pending_list,
                    'count_imported_EPVs': report.get('count_imported_EPVs')}

        if report.get('status') is not 'Success':
            return flask.jsonify(response), 500
        else:
            return flask.jsonify(response)
    except RuntimeError:
        response = {'message': 'RuntimeError encountered', 'epv': pending_list}
        return flask.jsonify(response), 500


@api_v1.route('/api/v1/ingest_to_graph', methods=['POST'])
def ingest_to_graph():
    """Import e/p/v data and generate response for the POST request to /api/v1/ingest_to_graph."""
    input_json = request.get_json()
    current_app.logger.info("Ingesting the given list of EPVs - " + json.dumps(input_json))
    expected_keys = set(['ecosystem', 'name', 'version'])
    for epv in input_json:
        if not expected_keys.issubset(set(epv.keys())):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    report = data_importer.import_epv_from_s3_http(list_epv=input_json)
    response = {'message': report.get('message'),
                'epv': input_json,
                'count_imported_EPVs': report.get('count_imported_EPVs')}
    print(response)
    # TODO the previous code can raise a runtime exception, does not we need to handle that?
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


@api_v1.route('/api/v1/create_nodes', methods=['POST'])
def create_nodes():
    """Create e/p/v graph node and generate response for the POST request to/api/v1/create_nodes."""
    input_json = request.get_json()
    if not input_json:
        return flask.jsonify(message="No EPVs provided. Please provide valid list of EPVs"), 400

    expected_keys = set(['ecosystem', 'name', 'version'])
    for epv in input_json:
        # We expect alteast Ecosystem, Package and Version as a payload
        if not expected_keys.issubset(set(epv.keys())):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    current_app.logger.info("Creating the nodes for EPVs - " + json.dumps(input_json))
    report = data_importer.create_graph_nodes(list_epv=input_json)
    current_app.logger.info(report)

    if report.get('status') is not 'Success':
        return flask.jsonify(report), 500
    else:
        return flask.jsonify(report)


@api_v1.route('/api/v1/selective_ingest', methods=['POST'])
def selective_ingest():
    """Import e/p/v data and generate response for the POST request to /api/v1/selective_ingest."""
    input_json = request.get_json()

    if input_json.get('package_list') is None or len(input_json.get('package_list')) == 0:
        return flask.jsonify(message='No Packages provided. Nothing to be ingested'), 400

    expected_keys = set(['ecosystem', 'name'])
    for epv in input_json.get('package_list'):
        if not expected_keys.issubset(set(epv.keys())):
            response = {'message': 'Invalid keys found in input: ' + ','.join(epv.keys())}
            return flask.jsonify(response), 400

    current_app.logger.info("Selective Ingestion with payload - " + json.dumps(input_json))

    report = data_importer.import_epv_from_s3_http(list_epv=input_json.get('package_list'),
                                                   select_doc=input_json.get('select_ingest', None))
    response = {'message': report.get('message'),
                'epv': input_json,
                'count_imported_EPVs': report.get('count_imported_EPVs')}

    current_app.logger.info(response)

    # TODO the previous code can raise a runtime exception, does not we need to handle that?
    if report.get('status') is not 'Success':
        return flask.jsonify(response), 500
    else:
        return flask.jsonify(response)


@api_v1.route('/api/v1/vertex/<string:ecosystem>/<string:package>/<string:version>/properties',
              methods=['PUT', 'DELETE'])
def handle_properties(ecosystem, package, version):
    """
    Handle (update/delete) properties associated with given EPV.

    Update replaces properties with the same name.

    Expects JSON payload in following format:
    {
        "properties": [
            {
                "name": "cve_ids",
                "value": "CVE-3005-0001:10"
            }
        ]
    }

    "value" can be omitted in DELETE requests.

    :param ecosystem: str, ecosystem
    :param package: str, package name
    :param version: str, package version
    :return: 200 on success, 400 on failure
    """
    # TODO: reduce cyclomatic complexity
    input_json = request.get_json()
    properties = input_json.get('properties')

    error = flask.jsonify({'error': 'invalid input'})
    if not properties:
        return error, 400

    input_json = {k: GraphPopulator.sanitize_text_for_query(str(v)) for k, v in input_json.items()}

    if request.method == 'PUT':
        if [x for x in properties if not x.get('name') or x.get('value') is None]:
            return error, 400

    log_msg = '[{m}] Updating properties for {e}/{p}/{v} with payload {b}'
    current_app.logger.info(log_msg.format(m=request.method, e=ecosystem, p=package,
                                           v=version, b=input_json))

    query_statement = "g.V()" \
                      ".has('pecosystem','{ecosystem}')" \
                      ".has('pname','{pkg_name}')" \
                      ".has('version','{version}')".format(ecosystem=ecosystem,
                                                           pkg_name=package,
                                                           version=version)
    statement = ''

    if request.method in ('DELETE', 'PUT'):
        # build "delete" part of the statement
        drop_str = ""
        for prop in properties:
            drop_str += query_statement
            drop_str += ".properties('{property}').drop().iterate();".format(property=prop['name'])
        statement += drop_str

    if request.method == 'PUT':
        # build "add" part of the statement
        add_str = ""
        for prop in properties:
            add_str += ".property('{property}','{value}')".format(
                property=prop['name'], value=prop['value']
            )
        statement += query_statement + add_str + ';'

    current_app.logger.info('Gremlin statement: {s}'.format(s=statement))
    success, response_json = BayesianGraph.execute(statement)
    if not success:
        current_app.logger.error("Failed to update properties for {e}/{p}/{v}".format(
            e=ecosystem, p=package, v=version)
        )
        return flask.jsonify(response_json), 400

    return flask.jsonify(response_json), 200


@api_v1.route('/api/v1/cves', methods=['PUT', 'DELETE'])
def cves_put_delete():
    """Put or delete CVE nodes.

    Missing EPVs will be created.
    """
    payload = request.get_json(silent=True)
    try:
        if request.method == 'PUT':
            cve = CVEPut(payload)
            print(cve)
        elif request.method == 'DELETE':
            cve = CVEDelete(payload)
        else:
            # this should never happen
            return flask.jsonify({'error': 'method not allowed'}), 405
    except ValueError as e:
        return flask.jsonify({'error': str(e)}), 400

    try:
        cve.process()
    except ValueError as e:
        return flask.jsonify({'error': str(e)}), 500

    return flask.jsonify({}), 200


@api_v1.route('/api/v1/cves/<string:ecosystem>', methods=['GET'])
@api_v1.route('/api/v1/cves/<string:ecosystem>/<string:name>', methods=['GET'])
@api_v1.route('/api/v1/cves/<string:ecosystem>/<string:name>/<string:version>', methods=['GET'])
def cves_get(ecosystem, name=None, version=None):
    """Get list of CVEs for E, EP, or EPV."""
    cve = CVEGet(ecosystem, name, version)
    try:
        result = cve.get()
    except ValueError as e:
        return flask.jsonify({'error': str(e)}), 500
    return flask.jsonify(result), 200


@api_v1.route('/api/v1/cvedb-version', methods=['GET'])
def cvedb_version_get():
    """Get CVEDB version."""
    try:
        version = CVEDBVersion().get()
    except ValueError as e:
        return flask.jsonify({'error': str(e)}), 500
    return flask.jsonify({'version': version}), 200


@api_v1.route('/api/v1/cvedb-version', methods=['PUT'])
def cvedb_version_put():
    """Create or replace CVEDB version."""
    payload = request.get_json(silent=True)

    if not payload or 'version' not in payload:
        return flask.jsonify({'error': 'invalid input'}), 400
    try:
        version = CVEDBVersion().put(payload)
    except ValueError as e:
        return flask.jsonify({'error': str(e)}), 500
    return flask.jsonify({'version': version}), 200


def create_app():
    """Create Flask app object."""
    new_app = Flask(config.APP_NAME)
    new_app.config.from_object('src.config')
    CORS(new_app)
    new_app.register_blueprint(api_v1)
    return new_app


def setup_logging(flask_app):
    """Perform the setup of logging for this application."""
    if not flask_app.debug:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            '[%(asctime)s] %(levelname)s in %(module)s: %(message)s'))
        log_level = os.environ.get('FLASK_LOGGING_LEVEL', logging.getLevelName(logging.WARNING))
        handler.setLevel(log_level)

        flask_app.logger.addHandler(handler)
        flask_app.config['LOGGER_HANDLER_POLICY'] = 'never'
        flask_app.logger.setLevel(logging.DEBUG)


app = create_app()
setup_logging(app)
app.wsgi_app = ProxyFix(app.wsgi_app)
sentry = Sentry(app, dsn=config.SENTRY_DSN, logging=True, level=logging.ERROR)


if __name__ == "__main__":
    app.run()
