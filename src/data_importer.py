"""Module with functions to fetch data from the S3 data source."""

from src.graph_populator import GraphPopulator
import logging
from src import config
import json
import requests
from src.data_source.s3_data_source import S3DataSource
from botocore.exceptions import ClientError

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from f8a_utils.versions import get_latest_versions_for_ep

logger = logging.getLogger(config.APP_NAME)


def parse_int_or_none(s):
    """
    Parse string into an integer if it is valid. Otherwise return None.

    :param s: Input string
    :return: Integer value or None
    """
    if s is None:
        return None
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return None


def _first_key_info(data_source, first_key, bucket_name=None):
    obj = {}
    try:
        t = data_source.read_json_file(first_key, bucket_name)
    except ClientError as e:
        raise e
    obj["dependents_count"] = t.get("dependents_count", '-1')
    obj["package_info"] = t.get("package_info", {})
    obj["latest_version"] = t.get("latest_version", '-1')
    return obj


def _other_key_info(data_source, other_keys, bucket_name=None):
    obj = {"analyses": {}}
    for this_key in other_keys:
        value = data_source.read_json_file(this_key, bucket_name)
        this_key = this_key.split("/")[-1]
        if 'success' == value.get('status', ''):
            obj["analyses"][this_key[:-len('.json')]] = value
    return obj


def _get_exception_msg(prefix, e):
    msg = prefix + ": " + str(e)
    # logger.error(msg)
    tb = logging.exception(msg)
    logger.error("Traceback for latest failure in import call: %s" % tb)
    return msg


def _import_keys_from_s3_http(data_source, epv_list):
    # TODO: reduce cyclomatic complexity
    logger.debug("Begin import...")
    report = {'status': 'Success', 'message': 'The import finished successfully!'}
    count_imported_EPVs = 0
    last_imported_EPV = None
    epv = []
    for epv_key in epv_list:
        for key, contents in epv_key.items():
            if len(contents.get('pkg_list_keys')) == 0 and len(contents.get('ver_list_keys')) == 0:
                report['message'] = 'Nothing to be imported! No data found on S3 to be imported!'
                continue
            pkg_ecosystem = contents.get('ecosystem')
            pkg_name = contents.get('package')
            pkg_version = contents.get('version') or ''
            pkg_source = contents.get('source_repo', pkg_ecosystem)

            obj = {
                'ecosystem': pkg_ecosystem,
                'package': pkg_name,
                'version': pkg_version,
                'source_repo': pkg_source}

            latest_version = get_latest_versions_for_ep(pkg_ecosystem, pkg_name)
            if latest_version:
                latest_epv_list = [{
                    'ecosystem': pkg_ecosystem,
                    'name': pkg_name,
                    'version': latest_version
                }]
                create_graph_nodes(latest_epv_list)

            try:
                # Check other Version level information and add it to common object
                if len(contents.get('ver_list_keys')) > 0:
                    first_key = contents['ver_key_prefix'] + '.json'
                    try:
                        first_obj = _first_key_info(data_source, first_key, config.AWS_EPV_BUCKET)
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'NoSuchKey':
                            logger.info('No data found for Ecosystem: %s '
                                        'Package: %s Version: %s' %
                                        (pkg_ecosystem, pkg_name, pkg_version))
                        else:
                            logger.info('Error %r encountered' % e.response)
                        continue
                    except Exception as e:
                        logger.info('Error %r encountered while processing Ecosystem: %s '
                                    'Package: %s Version: %s' %
                                    (e.response, pkg_ecosystem, pkg_name, pkg_version))
                        continue

                    first_obj['latest_version'] = latest_version
                    obj.update(first_obj)
                    ver_obj = _other_key_info(data_source, contents.get('ver_list_keys'),
                                              config.AWS_EPV_BUCKET)
                    if 'analyses' in obj:
                        obj.get('analyses', {}).update(ver_obj['analyses'])
                    else:
                        obj.update(ver_obj)

                # Check Package related information and add it to package object
                if len(contents.get('pkg_list_keys')) > 0:
                    pkg_obj = _other_key_info(data_source, contents.get('pkg_list_keys'),
                                              config.AWS_PKG_BUCKET)
                    if 'analyses' in obj:
                        obj.get('analyses', {}).update(pkg_obj['analyses'])
                    else:
                        obj.update(pkg_obj)

                # Create Gremlin Query
                str_gremlin = GraphPopulator.create_query_string(obj)

                if str_gremlin:
                    # Fire Gremlin HTTP query now
                    epv_full = pkg_ecosystem + ":" + pkg_name + ":" + pkg_version
                    logger.info("Ingestion initialized for EPV - %s" % epv_full)
                    epv.append(epv_full)
                    payload = {
                        'gremlin': str_gremlin,
                        'bindings': {
                            # (fixme) Disable groovy script caching until we move
                            # to parameterized scripts.
                            # http://tinkerpop.apache.org/docs/current/reference/#gremlin-server-cache
                            # http://tinkerpop.apache.org/docs/current/reference/#parameterized-scripts
                            '#jsr223.groovy.engine.keep.globals': 'phantom'
                        }
                    }
                    response = requests.post(config.GREMLIN_SERVER_URL_REST,
                                             data=json.dumps(payload), timeout=30)
                    resp = response.json()

                    if resp['status']['code'] == 200:
                        count_imported_EPVs += 1
                        last_imported_EPV = (obj.get('ecosystem') + ":" + obj.get('package') +
                                             ":" + obj.get('version'))

                        # update first key with graph synced tag
                        logger.info("Mark as synced in RDS %s" % last_imported_EPV)
                        if not config.AWS_S3_IS_LOCAL:  # pragma: no cover
                            PostgresHandler().mark_epv_synced(
                                obj.get('ecosystem'),
                                obj.get('package'),
                                obj.get('version')
                            )

            except Exception as e:  # pragma: no cover
                logger.error(e)
                msg = _get_exception_msg("The import failed", e)
                report['status'] = 'Failure'
                report['message'] = msg
                report['epv'] = epv_key

    report['epv'] = epv_list
    report['count_imported_EPVs'] = count_imported_EPVs
    if count_imported_EPVs == 0 and report['status'] == 'Success':
        report['message'] = 'Nothing to be synced to Graph!'
    report['last_imported_EPV'] = last_imported_EPV

    return report


def _log_report_msg(import_type, report):
    # Log the report
    msg = """
        Report from {}:
        {}
        Total number of EPVs imported: {}
        The last successfully imported EPV: {}
    """
    msg = msg.format(import_type, report.get('message'),
                     report.get('count_imported_EPVs'),
                     report.get('last_imported_EPV'))

    if report.get('status') == 'Success':
        logger.debug(msg)
    else:  # pragma: no cover
        # TODO: retry??
        logger.error(msg)


def import_epv_http(data_source, list_epv, select_doc=None):
    """Import the ecostystem+package+version triple from S3 database using selected data source."""
    # TODO: reduce cyclomatic complexity
    if select_doc is None or len(select_doc) == 0:
        select_doc = []

    try:
        # Collect relevant files from data-source and group them by package-version.
        s3_keys_list = []
        for epv in list_epv:

            epv_ecosystem = epv.get('ecosystem', None)
            epv_name = epv.get('name', None)
            epv_version = epv.get('version', '')
            epv_source = epv.get('source_repo', epv_ecosystem)

            if not epv_ecosystem or not epv_name:  # pragma: no cover
                # this must be logged
                logger.info("Skipping %s" % epv)
                continue

            # Get Package level keys
            package_prefix = version_prefix = epv_source + "/" + epv_name + "/"

            pkg_list_keys = data_source.list_files(bucket_name=config.AWS_PKG_BUCKET,
                                                   prefix=package_prefix)

            ver_list_keys = []
            if epv_version:
                # Get EPV level keys
                version_prefix = epv_source + "/" + epv_name + "/" + epv_version
                ver_list_keys.extend(data_source.list_files(bucket_name=config.AWS_EPV_BUCKET,
                                                            prefix=version_prefix + "/"))

            if select_doc:  # select_doc is a list
                select_ver_doc = [version_prefix + '/' + x + '.json' for x in select_doc]
                select_pkg_doc = [package_prefix + x + '.json' for x in select_doc]
                ver_list_keys = list(set(ver_list_keys).intersection(set(select_ver_doc)))
                pkg_list_keys = list(set(pkg_list_keys).intersection(set(select_pkg_doc)))

            # store s3 object paths for this epv
            pkg_data = {'package': epv_name, 'version': epv_version, 'ecosystem': epv_ecosystem,
                        'ver_key_prefix': version_prefix, 'ver_list_keys': ver_list_keys,
                        'pkg_key_prefix': package_prefix, 'pkg_list_keys': pkg_list_keys,
                        'source_repo': epv_source
                        }

            object_paths = {package_prefix: pkg_data}

            s3_keys_list.append(object_paths)

        # Import EPVs data from S3
        report = _import_keys_from_s3_http(data_source, s3_keys_list)

        # Log the report
        _log_report_msg("import_epv()", report)

    except Exception as e:  # pragma: no cover
        msg = _get_exception_msg("import_epv() failed with error", e)
        raise RuntimeError(msg)
    return report


def import_epv_from_s3_http(list_epv, select_doc=None):
    """Import the ecosystem+package+version triple from the S3 database via HTTP protocol."""
    # if aws-keys are not provided we assume it is local
    access_key = config.MINIO_ACCESS_KEY if config.AWS_S3_ACCESS_KEY_ID == "" \
        else config.AWS_S3_ACCESS_KEY_ID
    secret_key = config.MINIO_SECRET_KEY if config.AWS_S3_SECRET_ACCESS_KEY == "" \
        else config.AWS_S3_SECRET_ACCESS_KEY

    return import_epv_http(S3DataSource(src_bucket_name=config.AWS_EPV_BUCKET,
                                        access_key=access_key,
                                        secret_key=secret_key),
                           list_epv, select_doc)


def create_graph_nodes(list_epv):
    """Create blank graph nodes given an EPV."""
    count_blank_epvs_created = 0
    success_epvs = []
    failure_epvs = []

    for item in list_epv:
        str_gremlin = GraphPopulator.construct_graph_nodes(item)
        epv = item.get('ecosystem') + ":" + item.get('name') + ":" + item.get('version')

        if str_gremlin:
            payload = {'gremlin': str_gremlin}
            print(json.dumps(payload))
            try:
                result = requests.post(config.GREMLIN_SERVER_URL_REST, data=json.dumps(payload),
                                       timeout=30)
                resp = result.json()
                print(json.dumps(resp))

                if resp['status']['code'] == 200:
                    count_blank_epvs_created += 1
                    success_epvs.append(epv)
            except Exception as e:  # pragma: no cover
                logger.error(e)
                failure_json = {epv: e}
                failure_epvs.append(failure_json)

    status = "Success"
    if count_blank_epvs_created == 0:
        status = "Failure"

    response = {
        "epv_nodes_created": count_blank_epvs_created,
        "success_list": success_epvs,
        "failure_list": failure_epvs,
        "status": status
    }
    return response


class PostgresHandler(object):
    """PostgresHandler for interacting with Postgres data store."""

    def __init__(self):
        """Initialize Handler with session to Postgres Database."""
        # connect to RDS only if its not local environment
        engine = create_engine(config.PGSQL_ENDPOINT_URL)
        session = sessionmaker(bind=engine)
        self.rdb = session()

    def fetch_pending_epvs(self, ecosystem=None, package=None, version=None,
                           limit=None, offset=None):
        """Enlist all the EPVs which are not yet synced to Graph."""
        def strip_or_empty(x):
            return '' if x is None else x.strip()

        ecosystem = strip_or_empty(ecosystem)
        package = strip_or_empty(package)
        version = strip_or_empty(version)
        limit = parse_int_or_none(limit) or 0
        offset = parse_int_or_none(offset) or 0

        pending_list = []
        try:
            query = self._generate_fetch_query(ecosystem, package, version, limit, offset)
            params = {"ecosystem": ecosystem, "package": package, "version": version,
                      "limit": limit, "offset": offset}
            items = self.rdb.execute(query, params)
            for e, p, v in items:
                pending_list.append({"ecosystem": e, "name": p, "version": v})
        except NoResultFound:
            logger.info("No pending EPVs found for graph sync")

        all_counts = 0
        try:
            count_query = self._generate_count_query(ecosystem, package, version)
            count_params = {"ecosystem": ecosystem, "package": package, "version": version}
            items = list(self.rdb.execute(count_query, count_params))
            all_counts = items[0][0]
        except NoResultFound:
            logger.info("No pending EPVs found for graph sync")

        data = {"pending_list": pending_list, "all_counts": all_counts}
        return data

    def mark_epv_synced(self, ecosystem, package, version):
        """Mark the given EPV as synced to Graph."""
        query = """
            UPDATE versions
            SET synced2graph = TRUE
            WHERE versions.id IN (
              SELECT v.id AS versionid
              FROM versions v
                JOIN packages p ON v.package_id = p.id
                JOIN ecosystems e ON p.ecosystem_id = e.id
              WHERE e.name = :ecosystem AND p.name = :package AND v.identifier = :version)
            """

        params = {"ecosystem": ecosystem, "package": package, "version": version}
        self.rdb.execute(query, params)
        self.rdb.commit()

    def _generate_fetch_query(self, ecosystem, package, version, limit, offset):
        query = """
                    SELECT DISTINCT e.name AS ename, p.name AS pname, v.identifier AS versionid
                    FROM analyses a
                         JOIN versions v ON a.version_id = v.id
                         JOIN packages p ON v.package_id = p.id
                         JOIN ecosystems e ON p.ecosystem_id = e.id
                    WHERE v.synced2graph = FALSE
                         AND a.finished_at IS NOT NULL
                    """

        if ecosystem:
            query += """
                      AND e.name = :ecosystem
                """

        if package:
            query += """
                      AND p.name = :package
                """

        if version:
            query += """
                      AND v.identifier = :version
                """

        if limit and int(limit) > 0:
            query += """
                      LIMIT :limit
                """

        if offset and int(offset) > 0:
            query += """
                      OFFSET :offset
                """

        return query + ";"

    def _generate_count_query(self, ecosystem, package, version):
        query = """
                    SELECT COUNT(DISTINCT(e.name, p.name, v.identifier)) as CNT
                    FROM analyses a
                         JOIN versions v ON a.version_id = v.id
                         JOIN packages p ON v.package_id = p.id
                         JOIN ecosystems e ON p.ecosystem_id = e.id
                    WHERE v.synced2graph = FALSE
                         AND a.finished_at IS NOT NULL
                    """

        if ecosystem:
            query += """
                      AND e.name = :ecosystem
                """

        if package:
            query += """
                      AND p.name = :package
                """

        if version:
            query += """
                      AND v.identifier = :version
                """

        return query + ";"
