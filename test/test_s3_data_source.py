"""Tests for the s3_data_source module (to be done)."""

# TODO: to be implemented

from data_source.s3_data_source import S3DataSource
import config
import pytest


def test_get_source_name():
    """Test the method get_source_name()."""
    access_key = config.MINIO_ACCESS_KEY if config.AWS_S3_ACCESS_KEY_ID == "" \
        else config.AWS_S3_ACCESS_KEY_ID
    secret_key = config.MINIO_SECRET_KEY if config.AWS_S3_SECRET_ACCESS_KEY == "" \
        else config.AWS_S3_SECRET_ACCESS_KEY

    s3dataSource = S3DataSource(src_bucket_name=config.AWS_EPV_BUCKET,
                                access_key=access_key,
                                secret_key=secret_key)
    assert s3dataSource.get_source_name() == "S3"


            pkg_list_keys = data_source.list_files(bucket_name=config.AWS_PKG_BUCKET,
                                                   prefix=package_prefix)

            pkg_list_keys = data_source.list_files(bucket_name=config.AWS_PKG_BUCKET,
                                                   prefix=package_prefix)

def test_list_files():
    """Test the method list_files()."""
    access_key = config.MINIO_ACCESS_KEY if config.AWS_S3_ACCESS_KEY_ID == "" \
        else config.AWS_S3_ACCESS_KEY_ID
    secret_key = config.MINIO_SECRET_KEY if config.AWS_S3_SECRET_ACCESS_KEY == "" \
        else config.AWS_S3_SECRET_ACCESS_KEY

    s3dataSource = S3DataSource(src_bucket_name=config.AWS_EPV_BUCKET,
                                access_key=access_key,
                                secret_key=secret_key)

    files = s3dataSource.list_files(bucket_name=config.AWS_PKG_BUCKET)
    assert files
    assert len(files) > 0


if __name__ == '__main__':
    test_get_source_name()
    test_list_files()
