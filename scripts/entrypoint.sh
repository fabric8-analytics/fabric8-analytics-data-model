#!/usr/bin/env bash

# Wait for the required to be up, before we attempt to start the web-workers.
URL="http://$BAYESIAN_GREMLIN_HTTP_SERVICE_HOST:$BAYESIAN_GREMLIN_HTTP_SERVICE_PORT"
while ! curl --data '{"gremlin":"1"}' --output /dev/null --silent --fail "$URL"
do
    sleep 2 && echo "Waiting for Gremlin HTTP Server..."
done

if [ ! -z "$SKIP_SCHEMA" ]; then
    python populate_schema.py
fi

# Start data model service with time out
gunicorn --pythonpath /src/ -b 0.0.0.0:$DATA_IMPORTER_SERVICE_PORT -t $DATA_IMPORTER_SERVICE_TIMEOUT -k gevent -w $NUMBER_WORKER_PROCESS rest_api:app
