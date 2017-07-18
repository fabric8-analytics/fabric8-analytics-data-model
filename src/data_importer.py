from graph_populator import GraphPopulator
import logging
import config
import traceback
import json
import requests
from datetime import datetime
from data_source.s3_data_source import S3DataSource

logging.basicConfig()
logger = logging.getLogger(__name__)


def _first_key_info(data_source, first_key, bucket_name=None):
    obj = {}
    t = data_source.read_json_file(first_key, bucket_name)
    cur_finished_at = t.get("finished_at")
    obj["dependents_count"] = t.get("dependents_count", '-1')
    obj["package_info"] = t.get("package_info", {})
    obj["version"] = t.get("version")
    obj["latest_version"] = t.get("latest_version", '-1')
    obj["ecosystem"] = t.get("ecosystem")
    obj["package"] = t.get("package")
    condition = [obj['package'] != None, obj['version'] != None, obj['ecosystem'] != None]
    if not all(condition):
        return None
    return obj, cur_finished_at


def _other_key_info(data_source, other_keys, bucket_name=None):
    obj = {"analyses": {}}
    for this_key in other_keys:
        value = data_source.read_json_file(this_key, bucket_name)
        this_key = this_key.split("/")[-1]
        obj["analyses"][this_key[:-len('.json')]] = value
    return obj
    

def _set_max_finished_at(max_finished_at, cur_finished_at, max_datetime, date_time_format):
    if max_finished_at is None:
        max_finished_at = cur_finished_at
    else:
        cur_datetime = datetime.strptime(cur_finished_at, date_time_format)
        if cur_datetime > max_datetime:
            max_finished_at = cur_finished_at
    return max_finished_at        


def _get_exception_msg(prefix, e):
    msg = prefix + ": " + str(e)
    logger.error(msg)
    tb = traceback.format_exc()
    logger.error("Traceback for latest failure in import call: %s" % tb)
    return msg


def _import_keys_from_s3_http(data_source, epv_list):
    logger.debug("Begin import...")
    date_time_format = "%Y-%m-%dT%H:%M:%S.%f"

    report = {'status': 'Success', 'message': 'The import finished successfully!'}
    count_imported_EPVs = 0
    max_finished_at = None
    max_datetime = None
    last_imported_EPV = None
    epv = []
    for epv_key in epv_list:
        for key, contents in epv_key.items():
            if len(contents.get('package')) == 0 and len(contents.get('version')) == 0:
                report['message'] = 'Nothing to be imported! No data found on S3 to be imported!'
                continue
            try:
                # Check whether EPV meta is present and not error out
                first_key = contents['ver_key_prefix'] + '.json'
                obj, cur_finished_at = _first_key_info(data_source, first_key, config.AWS_EPV_BUCKET)
                if obj is None:
                    continue
                # Check other Version level information and add it to common object
                if len(contents.get('version')) > 0:
                    ver_obj = _other_key_info(data_source, contents.get('version'), config.AWS_EPV_BUCKET)
                    obj.update(ver_obj)

                # Check Package related information and add it to package object
                if len(contents.get('package')) > 0:
                    pkg_obj = _other_key_info(data_source, contents.get('package'), config.AWS_PKG_BUCKET)
                    obj.update(pkg_obj)

                # Create Gremlin Query
                str_gremlin = GraphPopulator.create_query_string(obj)

                # Fire Gremlin HTTP query now
                logger.info("Ingestion initialized for EPV - " +
                            obj.get('ecosystem') + ":" + obj.get('package') + ":" + obj.get('version'))
                epv.append(obj.get('ecosystem') + ":" + obj.get('package') + ":" + obj.get('version'))
                payload = {'gremlin': str_gremlin}
                response = requests.post(config.GREMLIN_SERVER_URL_REST, data=json.dumps(payload))
                resp = response.json()

                if resp['status']['code'] == 200:
                    count_imported_EPVs += 1
                    last_imported_EPV = first_key
                    max_finished_at = _set_max_finished_at(max_finished_at, cur_finished_at, max_datetime, date_time_format)
                    max_datetime = datetime.strptime(max_finished_at, date_time_format)

            except Exception as e:
                msg = _get_exception_msg("The import failed", e)
                report['status'] = 'Failure'
                report['message'] = msg

    report['epv'] = epv
    report['count_imported_EPVs'] = count_imported_EPVs
    report['last_imported_EPV'] = last_imported_EPV
    report['max_finished_at'] = max_finished_at

    return report


def _log_report_msg(import_type, report):
    # Log the report
    msg = """
        Report from {}:
        {}
        Total number of EPVs imported: {}
        The last successfully imported EPV: {}
        Max value of 'finished_at' among all imported EPVs: {}
    """
    msg = msg.format(import_type, report.get('message'),
                     report.get('count_imported_EPVs'),
                     report.get('last_imported_EPV'),
                     report.get('max_finished_at'))

    if report.get('status') is 'Success':
        logger.debug(msg)
    else:
        # TODO: retry??
        logger.error(msg)


def import_epv_http(data_source, list_epv):
    try:
        # Collect relevant files from data-source and group them by package-version.
        list_keys = []
        for epv in list_epv:
            dict_keys = {}
            ver_list_keys = []
            pkg_list_keys = []
            # Get EPV level keys
            ver_key_prefix = epv.get('ecosystem') + "/" + epv.get('name') + "/" + epv.get('version')
            ver_list_keys.extend(data_source.list_files(bucket_name=config.AWS_EPV_BUCKET, prefix=ver_key_prefix))
            # Get Package level keys
            pkg_key_prefix = epv.get('ecosystem') + "/" + epv.get('name') + "/"
            pkg_list_keys.extend(data_source.list_files(bucket_name=config.AWS_PKG_BUCKET, prefix=pkg_key_prefix))

            dict_keys[ver_key_prefix] = {
                'version': ver_list_keys,
                'ver_key_prefix': ver_key_prefix,
                'package': pkg_list_keys,
                'pkg_key_prefix': pkg_key_prefix
            }
            list_keys.append(dict_keys)

        # end of if graph_meta is None:

        # Import the S3 data
        report = _import_keys_from_s3_http(data_source, list_keys)

        # Log the report
        _log_report_msg("import_epv()", report)

    except Exception as e:
        msg = _get_exception_msg("import_epv() failed with error", e)
        raise RuntimeError(msg)
    return report


def import_epv_from_s3_http(list_epv):
    # if aws-keys are not provided we assume it is local
    access_key = config.MINIO_ACCESS_KEY if config.AWS_S3_ACCESS_KEY_ID == "" else config.AWS_S3_ACCESS_KEY_ID
    secret_key = config.MINIO_SECRET_KEY if config.AWS_S3_SECRET_ACCESS_KEY == "" else config.AWS_S3_SECRET_ACCESS_KEY
    config.AWS_S3_IS_LOCAL = True if config.AWS_S3_ACCESS_KEY_ID == "" else False


    return import_epv_http(S3DataSource(src_bucket_name=config.AWS_EPV_BUCKET,
                                        access_key=access_key,
                                        secret_key=secret_key),
                           list_epv)
