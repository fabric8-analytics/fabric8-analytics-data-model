import config
import logging
import os
from data_importer import import_bulk, import_from_folder
from data_source.local_filesystem_data_source import LocalFileSystem
from data_source.json_book_keeper import JsonBookKeeper

from entities.code_metrics import CodeMetricsResult, CodeMetricsLanguage
from entities.github_details import GithubResult
from entities.graph_metadata import GraphMetaData
from entities.package import Package
from entities.people import Author, Contributor
from entities.support_vectors import LicenseDetails
from entities.version import Version
from graph_populator import GraphPopulator

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


# TODO: check various vertices/edges/properties inside graph after import is successful
def test_full_import_and_incr_update():
    data_dir = 'test/data'
    # Let us make sure that target graph has no metadata
    graph_meta = GraphPopulator.get_metadata()
    assert(graph_meta is None)

    # Full import: insert all the EPVs from the given data source
    src_dir = os.path.join(data_dir, 'full_import')
    report = import_bulk(data_source=LocalFileSystem(src_dir=src_dir), book_keeper=None)
    assert(report.get('status') == 'Success')
    assert(report.get('count_imported_EPVs') == 1)
    assert(report.get('last_imported_EPV') == 'npm/serve-static/1.7.1.json')
    assert(report.get('max_finished_at') == '2017-02-08T12:26:51.962609')

    graph_meta = GraphPopulator.get_metadata()
    assert(graph_meta is not None)
    assert(graph_meta.last_incr_update_ts == '2017-02-08T12:26:51.962609')

    # Incremental update 1:
    # Let us mimic a scenario where a new EPV was inserted recently: npm/send/0.10.1
    src_dir = os.path.join(data_dir, 'incr_update1')
    book_keeping_json = os.path.join(data_dir, 'book_keeping1.json')
    report = import_bulk(data_source=LocalFileSystem(src_dir=src_dir),
                         book_keeper=JsonBookKeeper(json_file_name=book_keeping_json))
    assert(report.get('status') == 'Success')
    assert(report.get('count_imported_EPVs') == 1)
    assert(report.get('last_imported_EPV') == 'npm/send/0.10.1.json')
    assert(report.get('max_finished_at') == '2017-02-22T15:34:59.469864')

    graph_meta = GraphPopulator.get_metadata()
    assert(graph_meta is not None)
    assert(graph_meta.last_incr_update_ts == '2017-02-22T15:34:59.469864')

    # Incremental update 2:
    # Let us mimic a scenario where a new EPV was inserted recently: npm/parseurl/1.3.1
    # and also an already existing EPV was updated recently: npm/serve-static/1.7.1
    src_dir = os.path.join(data_dir, 'incr_update2')
    book_keeping_json = os.path.join(data_dir, 'book_keeping2.json')
    report = import_bulk(data_source=LocalFileSystem(src_dir=src_dir),
                         book_keeper=JsonBookKeeper(json_file_name=book_keeping_json))
    assert(report.get('status') == 'Success')
    assert(report.get('count_imported_EPVs') == 2)
    assert(report.get('last_imported_EPV') == 'npm/serve-static/1.7.1.json')
    assert(report.get('max_finished_at') == '2017-02-22T15:35:51.962609')

    graph_meta = GraphPopulator.get_metadata()
    assert(graph_meta is not None)
    assert(graph_meta.last_incr_update_ts == '2017-02-22T15:35:51.962609')

    # Cleanup
    GraphMetaData.delete_all()
    assert (GraphMetaData.count() == 0)

    LicenseDetails.delete_all()
    assert (LicenseDetails.count() == 0)

    Author.delete_all()
    assert (Author.count() == 0)

    CodeMetricsResult.delete_all()
    assert (CodeMetricsResult.count() == 0)

    CodeMetricsLanguage.delete_all()
    assert (CodeMetricsLanguage.count() == 0)

    GithubResult.delete_all()
    assert (GithubResult.count() == 0)

    Contributor.delete_all()
    assert (Contributor.count() == 0)

    Package.delete_all()
    assert (Package.count() == 0)

    Version.delete_all()
    assert (Version.count() == 0)


def test_package_import_from_folder():
    bucket_dir = 'test/data/S3-maven'
    package_dir = 'test/data/S3-maven/maven/junit:junit'

    packages = Package.find_all()
    assert (len(packages) == 0)

    versions = Version.find_all()
    assert (len(versions) == 0)

    p = Package()
    assert (p.id is None)
    assert (p.label == "Package")
    assert p.last_updated is None

    report = import_from_folder(package_dir)

    assert(report.get('status') == 'Success')
    assert(report.get('count_imported_EPVs') == 1)
    assert(report.get('last_imported_EPV') == '4.8.2.json')
    assert(report.get('max_finished_at') == '2017-02-24T13:42:29.665786')

    criteria_dict = {'ecosystem': 'maven', 'name': 'junit:junit'}
    p1 = Package.find_by_criteria('Package', criteria_dict)

    assert p1 is not None
    assert p1.id is not None
    assert (p1.ecosystem == 'maven')
    assert (p1.latest_version == '4.12')
    assert (p1.package_dependents_count == -1)
    assert (p1.name == 'junit:junit')

    criteria_dict = {'pecosystem': 'maven', 'pname': 'junit:junit', 'version': '4.8.2'}
    v1 = Version.find_by_criteria('Version', p1, criteria_dict)

    assert v1 is not None
    assert v1.ecosystem_package is not None
    assert (v1.ecosystem_package.ecosystem == 'maven')

    packages = Package.find_all()
    assert (len(packages) == 1)

    versions = Version.find_all()
    assert (len(versions) == 1)

    Package.delete_by_id(p1.id)
    assert (Package.count() == 0)

    Version.delete_by_id(v1.id)
    assert (Version.count() == 0)

    GraphMetaData.delete_all()
    assert (GraphMetaData.count() == 0)


def test_ecosystem_import_from_folder():
    ecosystem_dir = 'test/data/S3-maven/maven'

    packages = Package.find_all()
    assert (len(packages) == 0)

    p = Package()
    assert (p.id is None)
    assert (p.label == "Package")
    assert p.last_updated is None

    report = import_from_folder(ecosystem_dir)

    assert(report.get('status') == 'Success')
    assert(report.get('count_imported_EPVs') == 2)
    assert(report.get('last_imported_EPV') == 'org.slf4j:slf4j-api/1.5.6.json')
    assert(report.get('max_finished_at') == '2017-02-24T13:43:11.872916')

    criteria_dict = {'ecosystem': 'maven', 'name': 'junit:junit'}
    p1 = Package.find_by_criteria('Package', criteria_dict)

    criteria_dict = {'pecosystem': 'maven', 'pname': 'junit:junit', 'version': '3.8.1'}
    v1 = Version.find_by_criteria('Version', p1, criteria_dict)

    assert v1 is not None
    assert v1.ecosystem_package is not None
    assert (v1.ecosystem_package.ecosystem == 'maven')

    packages = Package.find_all()
    assert (len(packages) == 2)

    versions = Version.find_all()
    assert (len(versions) == 3)

    Package.delete_all()
    assert (Package.count() == 0)

    Version.delete_all()
    assert (Version.count() == 0)

    GraphMetaData.delete_all()
    assert (GraphMetaData.count() == 0)
