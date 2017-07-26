#!/usr/bin/env bash

# Start data model service with time out
gunicorn --pythonpath /src/ -b 0.0.0.0:$DATA_IMPORTER_SERVICE_PORT -t $DATA_IMPORTER_SERVICE_TIMEOUT -k gevent -w $NUMBER_WORKER_PROCESS rest_api:app
