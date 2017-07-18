import logging
import config
import traceback
from minio import Minio
from minio.error import ResponseError, BucketAlreadyOwnedByYou, BucketAlreadyExists
from data_importer import import_epv_from_s3_http
from graph_manager import BayesianGraph

logger = logging.getLogger(__name__)

# Check whether schema is created or not
# populate schema if not already done
try:
    status, json_result = BayesianGraph.populate_schema()
    if status:
        logger.info("Graph Schema Created")
    else:
        logger.error(json_result)
        raise RuntimeError("Failed to setup graph schema")
except:
    raise RuntimeError("Failed to initialize graph schema")

def test_create_minio_bucket():
    # Create Necessary Config Parameters
    config.AWS_PKG_BUCKET = "test-bayesian-core-package-data"
    config.AWS_EPV_BUCKET = "test-bayesian-core-data"
    config.LOCAL_MINIO_ENDPOINT = "localhost:33000"

    minioClient = Minio(config.LOCAL_MINIO_ENDPOINT,
                        access_key=config.MINIO_ACCESS_KEY,
                        secret_key=config.MINIO_SECRET_KEY,
                        secure=False)
    # Creates a bucket with name mybucket.
    try:
        minioClient.make_bucket(config.AWS_EPV_BUCKET, location="us-east-1")
        minioClient.make_bucket(config.AWS_PKG_BUCKET, location="us-east-1")
    except BucketAlreadyOwnedByYou as err:
        pass
    except BucketAlreadyExists as err:
        pass
    except ResponseError as err:
        logger.error(err)

    # Upload an object 'myobject.ogg' with contents from '/home/john/myfilepath.ogg'.
    try:
        minioClient.fput_object(config.AWS_PKG_BUCKET, 'pypi/access_points/github_details.json',
                                'test/data/S3-data/pypi/access_points/github_details.json')
        minioClient.fput_object(config.AWS_PKG_BUCKET, 'pypi/access_points/libraries_io.json',
                                'test/data/S3-data/pypi/access_points/libraries_io.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59/code_metrics.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/code_metrics.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59/security_issues.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/security_issues.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59/source_licenses.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/source_licenses.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59/metadata.json',
                                'test/data/S3-data/pypi/access_points/0.4.59/metadata.json')
        minioClient.fput_object(config.AWS_EPV_BUCKET, 'pypi/access_points/0.4.59.json',
                                'test/data/S3-data/pypi/access_points/0.4.59.json')

    except ResponseError as err:
        logger.error(err)

    assert(minioClient.bucket_exists(config.AWS_PKG_BUCKET) == True)
    assert(minioClient.bucket_exists(config.AWS_EPV_BUCKET) == True)

def test_insertion():

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
        assert(report['status'] == "Success")
        assert(report["epv"] == ["pypi:access_points:0.4.59"])
        assert(report["count_imported_EPVs"] == 1)
    except:
        tb = traceback.format_exc()
        logger.error("Traceback for latest failure in import call: %s" % tb)

