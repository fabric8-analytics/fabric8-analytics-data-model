#!/usr/bin/bash -ex

gc() {
  retval=$?
  sudo docker-compose -f fabric8-analytics-deployment/docker-compose.yaml down -v || :
  exit $retval
}
trap gc EXIT SIGINT

# Enter local-setup/ directory
# Run local instances for: dynamodb, gremlin-websocket, gremlin-http
function start_services {
    echo "Start Gremlin HTTP and Ingestion Workers ..."

    # pushd local-setup/
    # sudo docker-compose -f docker-compose.yaml up --force-recreate -d 
    docker-compose -f fabric8-analytics-deployment/docker-compose.yml down
    docker-compose -f fabric8-analytics-deployment/docker-compose.yml up -d gremlin-http worker-ingestion
}

function setup_virtualenv {
    echo "Create Virtualenv for Python deps ..."
    virtualenv --python /usr/bin/python2.7 env-test
    source env-test/bin/activate

    pip install -U pip
    pip install -r requirements.txt

    # Install profiling module
    pip install pytest-profiling

    # Install pytest-coverage module
    pip install pytest-cov
}

function destroy_virtualenv {
    echo "Remove Virtualenv ..."
    rm -rf env-test/
}

echo "Setup fabric8-analytics-deployment... "

if [ -d fabric8-analytics-deployment ]
then
    echo "...already exists"
else
    export GIT_SSL_NO_VERIFY=true
    git clone https://github.com/fabric8-analytics/fabric8-analytics-deployment.git
    echo "...done"
fi


echo JAVA_OPTIONS value: $JAVA_OPTIONS

start_services

setup_virtualenv

source env-test/bin/activate

export LOGFILE_PATH="all-tests.log"
rm -f "$LOGFILE_PATH"

export PYTHONPATH=`pwd`/src

echo "Create a default configuration file..."
cp src/config.py.template src/config.py

# Wait for services to be up
# echo "Wait for some time delay..."
# sleep 20

echo "Check for sanity of the connections..."

if python src/sanitycheck.py
then
    py.test --cov=src/ --cov-report term-missing -vv -s test/
else
    echo "Sanity checks failed"
fi

deactivate

destroy_virtualenv
