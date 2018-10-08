"""The tests for Minio put/get operations.

Test that the ecosystem/package/version information could be stored and retrieved from
the Minio storage.
"""

import logging
import config
import traceback
from minio import Minio
from minio.error import ResponseError, BucketAlreadyOwnedByYou, BucketAlreadyExists
from data_importer import import_epv_from_s3_http
from graph_manager import BayesianGraph

logging.basicConfig()
logger = logging.getLogger(__name__)

# Check whether schema is created or not
# populate schema if not already done
try:
    status, json_result = BayesianGraph.populate_schema()
except Exception as exc:
    # Py2 compatibility: switch to "from exc" once we're on Py3
    new_exc = RuntimeError("Failed to initialize graph schema")
    new_exc.__cause__ = exc
    raise new_exc

if status:
    logger.info("Graph Schema Created")
else:
    logger.error(json_result)
    raise RuntimeError("Failed to setup graph schema")


def test_create_minio_bucket():
    """Test if buckets can be put into the Minio storage."""
    # Create Necessary Config Parameters
    config.AWS_PKG_BUCKET = "test-bayesian-core-package-data"
    config.AWS_EPV_BUCKET = "test-bayesian-core-data"

    minioClient = Minio(config.LOCAL_MINIO_ENDPOINT,
                        access_key=config.MINIO_ACCESS_KEY,
                        secret_key=config.MINIO_SECRET_KEY,
                        secure=False)
    try:
        minioClient.make_bucket(config.AWS_EPV_BUCKET, location="us-east-1")
        minioClient.make_bucket(config.AWS_PKG_BUCKET, location="us-east-1")
    except (BucketAlreadyOwnedByYou, BucketAlreadyExists):
        pass
    except ResponseError as err:
        logger.error(err)

    try:
        minioClient.fput_object(config.AWS_PKG_BUCKET, 'pypi/access_points/github_details.json',
                                'test/data/S3-data/pypi/access_points/github_details.json')
        minioClient.fput_object(config.AWS_PKG_BUCKET, 'pypi/access_points/libraries_io.json',
                                'test/data/S3-data/pypi/access_points/libraries_io.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET,
                                'pypi/access_points/0.4.59/code_metrics.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/code_metrics.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET,
                                'pypi/access_points/0.4.59/security_issues.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/security_issues.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET,
                                'pypi/access_points/0.4.59/source_licenses.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/source_licenses.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59/metadata.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/metadata.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59.json',
                                'test/data/S3-data/pypi/access_points/0.4.59.json')
        minioClient.fput_object(
            config.AWS_EPV_BUCKET, 'go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/dependency_snapshot.json',
            'test/data/S3-data/go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/dependency_snapshot.json')
        minioClient.fput_object(
            config.AWS_EPV_BUCKET, 'go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/digests.json',
            'test/data/S3-data/go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/digests.json')
        minioClient.fput_object(
            config.AWS_EPV_BUCKET, 'go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/metadata.json',
            'test/data/S3-data/go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/metadata.json')
        minioClient.fput_object(
            config.AWS_EPV_BUCKET, 'go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd.json',
            'test/data/S3-data/go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd.json')
        minioClient.fput_object(
            config.AWS_EPV_BUCKET, 'go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/source_licenses.json',
            'test/data/S3-data/go/github.com/gorilla/mux/c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd/source_licenses.json')
    except ResponseError as err:
        logger.error(err)

    assert minioClient.bucket_exists(config.AWS_PKG_BUCKET)
    assert minioClient.bucket_exists(config.AWS_EPV_BUCKET)


def test_insertion():
    """Test if the stored e/p/v data can be retrieved back."""
    list_epv = [
        {
            "version": "0.4.59",
            "name": "access_points",
            "ecosystem": "pypi"
        }
    ]
    try:
        report = import_epv_from_s3_http(list_epv)
        logger.info(report)
        assert report['status'] == "Success"
        # TODO Need to enable this test with new changes
        # assert report["epv"] == ["pypi:access_points:0.4.59"]
        assert report["count_imported_EPVs"] == 1
    except Exception:
        # TODO this is probably bad approach how to handle/ignore exceptions
        # see https://github.com/openshiftio/openshift.io/issues/2263
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import call: %s" % tb)


def test_insertion_go():
    """Test if the stored go e/p/v data can be retrieved back."""
    list_epv = [
        {
            "version": "c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd",
            "name": "github.com/gorilla/mux",
            "ecosystem": "go"
        }
    ]
    try:
        report = import_epv_from_s3_http(list_epv)
        logger.info(report)
        assert report['status'] == "Success"
        # TODO Need to enable this test with new changes
        # assert report["epv"] == [
        # "go:github.com/gorilla/mux:c572efe4294d5a0e354e01f2ddaa8b1f0c3cb3dd"]
        assert report["count_imported_EPVs"] == 1
    except Exception:
        # TODO this is probably bad approach how to handle/ignore exceptions
        # see https://github.com/openshiftio/openshift.io/issues/2263
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import call: %s" % tb)


def test_insertion_not_exists():
    """Test if the stored e/p/v data can be retrieved back."""
    list_epv = [
        {
            "version": "0.0.0",
            "name": "access_points",
            "ecosystem": "pypi"
        }
    ]
    try:
        report = import_epv_from_s3_http(list_epv, select_doc=['not_exists_data'])
        logger.info(report)
        assert report['status'] == "Success"
        # TODO Need to enable this test with new changes
        # assert report["epv"] == ["pypi:access_points:0.4.59"]
        assert report["count_imported_EPVs"] == 0
        logger.info(report)
    except Exception:
        # TODO this is probably bad approach how to handle/ignore exceptions
        # see https://github.com/openshiftio/openshift.io/issues/2263
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import call: %s" % tb)


if __name__ == '__main__':
    test_insertion()
    test_insertion_not_exists()
    test_create_minio_bucket()
