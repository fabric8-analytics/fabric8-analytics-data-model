#!/usr/bin/bash -ex

COVERAGE_THRESHOLD=90

export TERM=xterm
TERM=${TERM:-xterm}

# set up terminal colors
NORMAL=$(tput sgr0)
RED=$(tput bold && tput setaf 1)
GREEN=$(tput bold && tput setaf 2)
YELLOW=$(tput bold && tput setaf 3)

DOCKER_CMD="docker-compose -f docker-compose-tests.yml"

gc() {
  retval=$?
  [[ $retval -ne 0 ]] && $DOCKER_CMD logs gremlin-http || :
  $DOCKER_CMD down -v || :
  exit $retval
}

trap gc EXIT SIGINT

# Run local instances: dynamodb, gremlin, gremlin-http, worker-ingestion, pgsql
function start_services {
    echo "Start Gremlin HTTP and Ingestion Workers ..."
    $DOCKER_CMD down
    $DOCKER_CMD up -d gremlin-http
    sleep 5
    $DOCKER_CMD up -d worker-ingestion
}

function setup_virtualenv {
    echo "Create Virtualenv for Python deps ..."

    virtualenv --python /usr/bin/python2.7 env-test

    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
    printf "%sPython virtual environment initialized%s\n" "${YELLOW}" "${NORMAL}"

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

echo JAVA_OPTIONS value: "$JAVA_OPTIONS"

start_services

setup_virtualenv

source env-test/bin/activate

PYTHONPATH=$(pwd)/src
export PYTHONPATH

export BAYESIAN_PGBOUNCER_SERVICE_HOST="localhost"

# Wait for services to be up
echo "Wait for some time delay..."
sleep 20

echo "*****************************************"
echo "*** Cyclomatic complexity measurement ***"
echo "*****************************************"
radon cc -s -a -i venv src

echo "*****************************************"
echo "*** Maintainability Index measurement ***"
echo "*****************************************"
radon mi -s -i venv src

echo "*****************************************"
echo "*** Unit tests ***"
echo "*****************************************"
echo "Check for sanity of the connections..."

if python sanitycheck.py
then
    py.test --cov=src/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv -s test/
else
    echo "Sanity checks failed"
fi
printf "%stests passed%s\n\n" "${GREEN}" "${NORMAL}"

deactivate

destroy_virtualenv
