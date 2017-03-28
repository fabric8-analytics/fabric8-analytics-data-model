from graph_populator import GraphPopulator
import sys
import config
import logging
import json
from optparse import OptionParser

import os, fnmatch
import botocore
import boto3

logging.basicConfig(filename=config.LOGFILE_PATH, level=logging.DEBUG)
logger = logging.getLogger(__name__)


def grouped_keys(all_keys, split_count):
    d = {}
    c = 0
    for b in all_keys:
        if len(b.split("/")) == split_count:
            c += 1
            d[c] = []
            d[c].append(b)
        else:
            d[c].append(b)
    return d


def retrieve_blob(s3, bucket_name, object_key):
    return s3.Object(bucket_name, object_key).get()['Body'].read()


def retrieve_blob_json(s3, bucket_name, object_key):
    utf_data = retrieve_blob(s3, bucket_name, object_key).decode("utf-8")
    return json.loads(utf_data)


def find_files(directory, pattern):
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = os.path.join(root, basename)
                yield filename


def import_from_s3():

    print ("Importing from S3")

    session = boto3.session.Session(aws_access_key_id=config.AWS_S3_ACCESS_KEY_ID, aws_secret_access_key=config.AWS_S3_SECRET_ACCESS_KEY)
    s3 = session.resource('s3', config=botocore.client.Config(signature_version='s3v4'))

    try:
        s3.meta.client.head_bucket(Bucket=config.AWS_BUCKET)
    except botocore.exceptions.ClientError as exc:
        print("Failed to access the bucket: %s" % config.AWS_BUCKET)
        print("Reason: %s" % exc)
        print("Terminating gracefully...")
        logger.error("Failed to access the bucket: %s" % config.AWS_BUCKET)
        logger.error("Reason: %s" % exc)
        logger.error("Terminating gracefully...")
        sys.exit(0)

    bucket = s3.Bucket(config.AWS_BUCKET)

    print ("Created connection to S3")

    print ("Fetch all objects from bucket: %s" % config.AWS_BUCKET)
    objects = bucket.objects.all()
    all_keys = [x.key for x in objects]

    print ("Group by EPV...")
    dict_vals = grouped_keys(all_keys, 3)

    print ("Begin import...")
    for counter, v in dict_vals.items():
        obj = {}
        obj["analyses"] = {}
        first_key = v[0]
        print(first_key)
        logger.info("File---- %s  numbered---- %d  added:" % (first_key, counter))

        t = retrieve_blob_json(s3, config.AWS_BUCKET, first_key)
        obj["dependents_count"] = t.get("dependents_count", '')
        obj["package_info"] = t.get("package_info", {})
        obj["version"] = t.get("version", '')
        obj["latest_version"] = t.get("latest_version", '')
        obj["ecosystem"] = t.get("ecosystem", '')
        obj["package"] = t.get("package", '')
        for this_key in v[1:]:
            value = retrieve_blob_json(s3, config.AWS_BUCKET, this_key)
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


def import_from_folder(packages_path):
    # ensure path ends with forward slash
    packages_path = packages_path if packages_path.endswith("/") else packages_path + "/"

    aks = sorted([x for x in find_files(packages_path, "*.json")])
    all_keys = []

    for x in aks:
        if x.startswith(packages_path):
            x = x.replace(packages_path, '')
            all_keys.append(x)

    print ("Group by EPV...")
    dict_vals = grouped_keys(all_keys, 1)

    print ("Begin import...")

    for counter, v in dict_vals.items():
        obj = {}
        obj["analyses"] = {}
        first_key = v[0]
        print(first_key)
        logger.info("File---- %s  numbered---- %d  added:" % (first_key, counter))

        t = json.load(open(os.path.join(packages_path, first_key)))
        obj["dependents_count"] = t.get("dependents_count", '')
        obj["package_info"] = t.get("package_info", {})
        obj["version"] = t.get("version", '')
        obj["latest_version"] = t.get("latest_version", '')
        obj["ecosystem"] = t.get("ecosystem", '')
        obj["package"] = t.get("package", '')
        for this_key in v[1:]:
            value = json.load(open(os.path.join(packages_path, this_key)))
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


if __name__ == '__main__':

    parser = OptionParser()
    parser.add_option("-s", "--source", dest="source",
                      help="Source can be S3 or DIR", metavar="SOURCE")
    parser.add_option("-d", "--directory", dest="directory",
                      help="Read from DIRECTORY", metavar="DIRECTORY")

    (options, args) = parser.parse_args()

    source = "S3"
    if options.source is None:
        print ("No source provided")
    else:
        if options.source.upper() == "DIR":
            source = "DIR"
            if options.directory is None:
                print ("Directory path not provided")
                sys.exit(-1)

    if source == "S3":
        import_from_s3()
    elif source == "DIR":
        import_from_folder(options.directory)
    else:
        print ("Invalid CLI arguments")
        sys.exit(-1)
