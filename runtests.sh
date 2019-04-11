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

check_python_version() {
    python3 tools/check_python_version.py 3 6
}

gc() {
  retval=$?

  if [[ $retval -ne 0 ]]; then
    docker ps -a
    echo '============ dynamodb logs ============'
    $DOCKER_CMD logs dynamodb || :
    echo
    echo
    echo '============ gremlin logs ============'
    $DOCKER_CMD logs gremlin-http || :
  fi

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

    virtualenv -p python3 venv && source venv/bin/activate

    if [ $? -ne 0 ]
    then
        printf "%sPython virtual environment can't be initialized%s" "${RED}" "${NORMAL}"
        exit 1
    fi
    printf "%sPython virtual environment initialized%s\n" "${YELLOW}" "${NORMAL}"

    pip install -U pip
    pip3.6 install -r requirements.txt

    # Install profiling module
    pip3.6 install pytest-profiling

    # Install pytest-coverage module
    pip3.6 install pytest-cov
}

function destroy_virtualenv {
    echo "Remove Virtualenv ..."
    rm -rf venv/
}

check_python_version
echo JAVA_OPTIONS value: "$JAVA_OPTIONS"

start_services

setup_virtualenv

source venv/bin/activate

PYTHONPATH=$(pwd)
export PYTHONPATH

export BAYESIAN_PGBOUNCER_SERVICE_HOST="localhost"


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

if python3 sanitycheck.py
then
    python3 populate_schema.py
    py.test --cov=src/ --cov-report term-missing --cov-fail-under=$COVERAGE_THRESHOLD -vv -s test/
    codecov --token=3c1d9638-afb6-40e6-85eb-3fb193000d4b
else
    echo "Sanity checks failed"
fi
printf "%stests passed%s\n\n" "${GREEN}" "${NORMAL}"

deactivate

destroy_virtualenv
