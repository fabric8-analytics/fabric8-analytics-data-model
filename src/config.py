"""Configuration for the data model module."""

import os

TESTING = False
DEBUG = os.environ.get("FLASK_DEBUG", "false").lower() in ("1", "true")
LOGFILE_PATH = os.environ.get("LOGFILE_PATH", "/tmp/error.log")

# URL of Gremlin server
# Examples:
#   Gremlin server on localhost: "http://localhost:8182"
#   Gremlin server on openshift: "http://gremlin-data-model.che.ci.centos.org"
#
# GREMLIN_SERVER_URL_REST = "http://gremlin-data-model.che.ci.centos.org"

_gremlin_securely = "true" == os.environ.get("GREMLIN_USE_SECURE_CONNECTION", "false").lower()
GREMLIN_SERVER_URL_REST = "{proto}://{host}:{port}".format(
    proto="https" if _gremlin_securely else "http",
    host=os.environ.get("BAYESIAN_GREMLIN_HTTPINGESTION_SERVICE_HOST",
                        "bayesian-gremlin-httpingestion"),
    port=os.environ.get("BAYESIAN_GREMLIN_HTTPINGESTION_SERVICE_PORT", "8182"))

# To load data from S3
AWS_S3_ACCESS_KEY_ID = os.environ.get("AWS_S3_ACCESS_KEY_ID", "")
AWS_S3_SECRET_ACCESS_KEY = os.environ.get("AWS_S3_SECRET_ACCESS_KEY", "")
AWS_EPV_BUCKET = os.environ.get("AWS_EPV_BUCKET", "")
AWS_PKG_BUCKET = os.environ.get("AWS_PKG_BUCKET", "")

# Local Minio
LOCAL_MINIO_ENDPOINT = os.environ.get("LOCAL_MINIO_ENDPOINT", "localhost:33000")
MINIO_ACCESS_KEY = "GNV3SAHAHA3DOT99GQII"
MINIO_SECRET_KEY = "ZmvMwngonaDK5ymlCd6ptaalDdJsCn3aSSxASPaZ"
# if this variable is set, we are running AWS S3 locally ( via Minio )
AWS_S3_IS_LOCAL = AWS_S3_ACCESS_KEY_ID == ""

PG_USER = os.environ.get("POSTGRESQL_USER", 'coreapi')
PG_PASSWORD = os.environ.get("POSTGRESQL_PASSWORD", 'coreapi')
PG_DB = os.environ.get("POSTGRESQL_DATABASE", 'coreapi')
PG_HOST = os.environ.get("BAYESIAN_PGBOUNCER_SERVICE_HOST", 'coreapi-pgbouncer')
PG_PORT = os.environ.get("BAYESIAN_PGBOUNCER_SERVICE_PORT", 5432)

PGSQL_ENDPOINT_URL = 'postgresql://{}:{}@{}:{}/{}'.format(
    PG_USER, PG_PASSWORD, PG_HOST, PG_PORT, PG_DB)
SENTRY_DSN = os.environ.get("SENTRY_DSN", "")

APP_NAME = "data_importer_app"
