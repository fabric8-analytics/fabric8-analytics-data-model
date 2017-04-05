from abstract_data_source import AbstractDataSource
import botocore
import boto3
import json


class S3DataSource(AbstractDataSource):

    def __init__(self, src_bucket_name, access_key, secret_key):
        self.session = boto3.session.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
        self.s3_resource = self.session.resource('s3', config=botocore.client.Config(signature_version='s3v4'))
        self.bucket = self.s3_resource.Bucket(src_bucket_name)
        self.bucket_name = src_bucket_name

    def get_source_name(self):
        return "S3"

    def read_json_file(self, filename):
        """Read JSON file from the data source"""

        obj = self.s3_resource.Object(self.bucket_name, filename).get()['Body'].read()
        utf_data = obj.decode("utf-8")
        return json.loads(utf_data)

    def list_files(self, prefix=None):
        """List all the files in the source directory"""

        list_filenames = []
        # TODO: Pagination ??
        #   For a huge bucket, we should consider reading in chunks i.e. 'MaxKeys'
        # TODO: Marker ??
        #   For retry after a previously failed full-import,
        #   we can use 'Marker' = graph_meta.last_imported_s3_key
        if prefix is None:
            objects = self.bucket.objects.all()
            list_filenames = [x.key for x in objects]
        else:
            for obj in self.bucket.objects.filter(Prefix=prefix):
                list_filenames.append(obj.key)

        return list_filenames

