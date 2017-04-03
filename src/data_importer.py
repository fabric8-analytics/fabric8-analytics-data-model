import glob
from graph_populator import GraphPopulator
from entities.utils import get_values as gv
import logging
import set_logging
import sys
import config
import traceback
import json
from optparse import OptionParser
from datetime import datetime
from sqlalchemy import create_engine

from data_source.local_filesystem_data_source import LocalFileSystem
from data_source.s3_data_source import S3DataSource
from data_source.rds_book_keeper import RDSBookKeeper

logger = logging.getLogger(__name__)


def _group_keys_by_epv(all_keys):
    d = {}
    c = 0
    for b in all_keys:
        if len(b.split("/")) == 3:
            c += 1
            d[c] = []
            d[c].append(b)
        else:
            d[c].append(b)
    return d


def _import_grouped_keys(data_source, dict_grouped_keys):
    logger.debug("Begin import...")
    date_time_format = "%Y-%m-%dT%H:%M:%S.%f"

    report = {'status': 'Success', 'message': 'The import finished successfully!'}
    count_imported_EPVs = 0
    max_finished_at = None
    max_datetime = None
    last_imported_EPV = None
    if len(dict_grouped_keys.items()) == 0:
        report['message'] = 'Nothing to be imported! No data found on S3 to be imported!'
    try:
        for counter, v in dict_grouped_keys.items():
            obj = {"analyses": {}}
            first_key = v[0]
            logger.debug("Importing " + first_key)
            logger.debug("File---- %s  numbered---- %d  added:" % (first_key, counter))

            t = data_source.read_json_file(first_key)
            cur_finished_at = t.get("finished_at")
            obj["dependents_count"] = t.get("dependents_count", '')
            obj["package_info"] = t.get("package_info", {})
            obj["version"] = t.get("version", '')
            obj["latest_version"] = t.get("latest_version", '')
            obj["ecosystem"] = t.get("ecosystem", '')
            obj["package"] = t.get("package", '')
            for this_key in v[1:]:
                value = data_source.read_json_file(this_key)
                if this_key.endswith("source_licenses.json"):
                    obj["analyses"]["source_licenses"] = value
                elif this_key.endswith("metadata.json"):
                    obj["analyses"]["metadata"] = value
                elif this_key.endswith("code_metrics.json"):
                    obj["analyses"]["code_metrics"] = value
                elif this_key.endswith("github_details.json"):
                    obj["analyses"]["github_details"] = value
                elif this_key.endswith("blackduck.json"):
                    obj["analyses"]["blackduck"] = value

            GraphPopulator.populate_from_json(obj)
            count_imported_EPVs += 1
            last_imported_EPV = first_key
            if max_finished_at is None:
                max_finished_at = cur_finished_at
                max_datetime = datetime.strptime(max_finished_at, date_time_format)
            else:
                cur_datetime = datetime.strptime(cur_finished_at, date_time_format)
                if cur_datetime > max_datetime:
                    max_finished_at = cur_finished_at
                    max_datetime = datetime.strptime(max_finished_at, date_time_format)

    except Exception as e:
        msg = "The import failed with error '%s'." % e
        logger.error(msg)
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import: %s" % tb)
        report['status'] = 'Failure'
        report['message'] = msg

    report['count_imported_EPVs'] = count_imported_EPVs
    report['last_imported_EPV'] = last_imported_EPV
    report['max_finished_at'] = max_finished_at
    return report


def import_bulk(data_source, book_keeper):
    """
    Imports bulk data from the given data source.
    It can perform both 'full import' as well as 'incremental update'.

    :param data_source: Data source to read input from
    :param book_keeper: Book keeper to get info about recently ingested data
    :return: None
    """
    try:
        # Now, get the last incremental update timestamp from the graph.
        graph_meta = GraphPopulator.get_metadata()

        # If the timestamp is unknown then it means graph is not populated yet and we need to do full import.
        list_keys = []
        if graph_meta is None:
            # Collect all the files from data-source and group them by package-version.
            logger.debug("Performing full import. Fetching all objects from : " + data_source.get_source_name())
            list_keys = data_source.list_files()

        # else if the timestamp is available then we need to perform incremental update.
        else:
            if book_keeper is None:
                raise RuntimeError("Cannot perform incremental update without book keeper!")

            # Collect all the package-version from RDS table that were updated recently.
            # Note: If RDS table is unreachable then we should still live with S3 data.
            min_finished_at = graph_meta.last_incr_update_ts
            list_epv = book_keeper.get_recent_epv(min_finished_at)

            # Collect relevant files from data-source and group them by package-version.
            logger.debug("Performing incremental update. Fetching some objects from : " + data_source.get_source_name())
            for epv in list_epv:
                key_prefix = epv.get('ecosystem') + "/" + epv.get('name') + "/" + epv.get('version')
                list_keys.extend(data_source.list_files(prefix=key_prefix))
        # end of if graph_meta is None:

        # Import the S3 data
        dict_grouped_keys = _group_keys_by_epv(list_keys)
        report = _import_grouped_keys(data_source, dict_grouped_keys)

        # In the end, update the meta-data in the graph.
        if report.get('max_finished_at') is not None:
            dict_graph_meta = {
                'last_incremental_update_timestamp': report.get('max_finished_at'),
                'last_imported_epv': report.get('last_imported_EPV')
            }
            GraphPopulator.update_metadata(dict_graph_meta)

        # Log the report
        msg = """
            Report from import_bulk():
            {}
            Total number of EPVs imported: {}
            The last successfully imported EPV: {}
            Max value of 'finished_at' among all imported EPVs: {}
        """
        msg = msg.format(report.get('message'),
                         report.get('count_imported_EPVs'),
                         report.get('last_imported_EPV'),
                         report.get('max_finished_at'))

        if report.get('status') is 'Success':
            logger.debug(msg)
        else:
            # TODO: retry ??
            logger.error(msg)

    except Exception as e:
        msg = "import_bulk() failed with error: %s" % e
        logger.error(msg)
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import_bulk(): %s" % tb)
        raise RuntimeError(msg)

    return report


# Note: we don't update graph meta-data for this on-line 'unknown-path' scenario.
def import_epv(data_source, list_epv):
    try:
        # Collect relevant files from data-source and group them by package-version.
        list_keys = []
        for epv in list_epv:
            key_prefix = epv.get('ecosystem') + "/" + epv.get('name') + "/" + epv.get('version')
            list_keys.extend(data_source.list_files(prefix=key_prefix))
        # end of if graph_meta is None:

        # Import the S3 data
        dict_grouped_keys = _group_keys_by_epv(list_keys)
        report = _import_grouped_keys(data_source, dict_grouped_keys)

        # Log the report
        msg = """
            Report from import_epv():
            {}
            Total number of EPVs imported: {}
            The last successfully imported EPV: {}
            Max value of 'finished_at' among all imported EPVs: {}
        """
        msg = msg.format(report.get('message'),
                         report.get('count_imported_EPVs'),
                         report.get('last_imported_EPV'),
                         report.get('max_finished_at'))

        if report.get('status') is 'Success':
            logger.debug(msg)
        else:
            # TODO: retry ??
            logger.error(msg)

    except Exception as e:
        msg = "import_epv() failed with error: %s" % e
        logger.error(msg)
        tb = traceback.format_exc()
        logger.error("Traceback for the latest failure in import_epv(): %s" % tb)
        raise RuntimeError(msg)

    return report


def update_graph_metadata(input_json):
    GraphPopulator.update_metadata(input_json)


def import_from_s3():
    return import_bulk(S3DataSource(src_bucket_name=config.AWS_BUCKET,
                                    access_key=config.AWS_S3_ACCESS_KEY_ID,
                                    secret_key=config.AWS_S3_SECRET_ACCESS_KEY),
                       RDSBookKeeper(postgres_host=config.POSTGRESQL_HOST,
                                     postgres_port=config.POSTGRESQL_PORT,
                                     postgres_user=config.POSTGRESQL_USER,
                                     postgres_pass=config.POSTGRESQL_PASSWORD,
                                     postgres_db=config.POSTGRESQL_DATABASE))


# Note: Incremental update will not happen as we are passing book_keeper=None
def import_from_folder(src_dir):
    return import_bulk(data_source=LocalFileSystem(src_dir), book_keeper=None)


def import_epv_from_s3(list_epv):
    return import_epv(S3DataSource(src_bucket_name=config.AWS_BUCKET,
                                   access_key=config.AWS_S3_ACCESS_KEY_ID,
                                   secret_key=config.AWS_S3_SECRET_ACCESS_KEY),
                      list_epv)


def import_epv_from_folder(src_dir, list_epv):
    return import_epv(LocalFileSystem(src_dir), list_epv)


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option("-s", "--source", dest="source",
                      help="Source can be S3 or DIR", metavar="SOURCE")
    parser.add_option("-d", "--directory", dest="directory",
                      help="Read from DIRECTORY", metavar="DIRECTORY")

    (options, args) = parser.parse_args()

    source = "S3"
    if options.source is None:
        logger.info ("No source provided")
    else:
        if options.source.upper() == "DIR":
            source = "DIR"
            if options.directory is None:
                logger.info ("Directory path not provided")
                sys.exit(-1)

    if source == "S3":
        import_from_s3()
    elif source == "DIR":
        import_from_folder(options.directory)
    else:
        logger.info ("Invalid CLI arguments")
        sys.exit(-1)

