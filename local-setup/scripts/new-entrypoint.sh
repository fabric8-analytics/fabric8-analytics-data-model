#!/usr/bin/bash

SERVER_DIR=dynamodb-titan-storage-backend/server/dynamodb-titan100-storage-backend-1.0.0-hadoop1/
PROPS=${SERVER_DIR}/conf/gremlin-server/dynamodb-local.properties
GREMLIN_CONF=${SERVER_DIR}/conf/gremlin-server/gremlin-server-local.yaml
DYNAMO_HOST="dynamodb"
GREMLIN_HOST=$HOSTNAME
SCRIPT_TIMEOUT=100000
RESPONSE_TIMEOUT=100000
export JAVA_OPTIONS="-Xms256m -Xmx8192m -javaagent:/opt/dynamodb/$SERVER_DIR/lib/jamm-0.3.0.jar"

echo "DYNAMO_HOST was ${DYNAMO_HOST}"

sed -i.bckp 's#host: .*#host: '$GREMLIN_HOST'#' ${GREMLIN_CONF}
sed -i.bckp 's#scriptEvaluationTimeout: .*#scriptEvaluationTimeout: '${SCRIPT_TIMEOUT}'#' ${GREMLIN_CONF}
sed -i.bckp 's#serializedResponseTimeout: .*#serializedResponseTimeout: '${RESPONSE_TIMEOUT}'#' ${GREMLIN_CONF}

sed -i.bckp 's#storage.dynamodb.client.endpoint=.*#storage.dynamodb.client.endpoint=http://'$DYNAMO_HOST':8000#' ${PROPS}

echo "Setup code metrics configuration"

if [ "$DEBUG_GRAPH_METRICS" == "1" ]
then

cat <<'EOF' >> ${PROPS}
# Uncomment to activate if you need the following

# Setup Metrics
#metrics.enabled=true
#metrics.prefix=t
#metrics.csv.interval=500
#metrics.csv.directory=metrics

# Graphite configuration
#metrics.graphite.hostname=graph
#metrics.graphite.interval=500
#metrics.graphite.port=2003
#metrics.graphite.prefix=gremlin

# Query Optimizations
# query.batch=true
# storage.batch-loading=true

EOF


fi

if [ "$REST" == "1" ]; then
    sed -i.bckp 's#channelizer: .*#channelizer: org.apache.tinkerpop.gremlin.server.channel.HttpChannelizer#' ${GREMLIN_CONF}
fi

cd ${SERVER_DIR}

INIT_DELAY=${INIT_DELAY:-1}

echo "Wait for $INIT_DELAY seconds for other services to initialize..."
sleep "$INIT_DELAY"



exec bin/gremlin-server.sh conf/gremlin-server/gremlin-server-local.yaml
