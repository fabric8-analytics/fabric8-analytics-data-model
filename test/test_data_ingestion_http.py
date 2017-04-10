from data_importer import _group_keys_directory, _import_grouped_keys_http
from data_source.local_filesystem_data_source import LocalFileSystem


def test_create_package_entity():

    src_dir = 'test/data/full_import/npm/serve-static'
    data_source = LocalFileSystem(src_dir)
    list_keys = data_source.list_files()
    grouped_keys = _group_keys_directory(list_keys, data_source.src_dir)
    report = _import_grouped_keys_http(data_source, grouped_keys)
    assert report is not None
    assert report['status'] == 'Success'
    assert report['message'] == 'The import finished successfully!'
    assert report['last_imported_EPV'] == '1.7.1.json'
    assert report['count_imported_EPVs'] == 1
    assert report['max_finished_at'] == '2017-02-08T12:26:51.962609'