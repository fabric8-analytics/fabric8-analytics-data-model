# Fabric8-Analytics Data Models

This repository serves as a base for our data modeling work. You can easily connect to graphing engine (Gremlin + DynamoDB) running remotely in containers and import models to explore the graphs representing Fabric8-Analytics data.

## Contributing

See our [contributing guidelines](https://github.com/fabric8-analytics/common/blob/master/CONTRIBUTING.md) for more info.

## Configuration parameters

Keep proper configuration values handy ( preferably in `.env` file for docker compose):

```
AWS_S3_ACCESS_KEY_ID=some_key
AWS_S3_SECRET_ACCESS_KEY=some_secret
AWS_EPV_BUCKET=epv_bucket_name
AWS_PKG_BUCKET=pkg_bucket_name
DYNAMODB_PREFIX=prefix_allocated_to_you
DYNAMODB_CLIENT_CREDENTIALS_CLASS_NAME=com.amazonaws.auth.DefaultAWSCredentialsProviderChain
AWS_ACCESS_KEY_ID=<dynamodb-access-key-id>
AWS_SECRET_ACCESS_KEY=<dynamodb-secret-access-key>
```


## How to test and develop locally?
```
cd local-setup
docker-compose up
```
Now you can run the tests or the REST API

### How to run REST API:

This REST API serves as a language-independent interface to data-model functionality such as importing the given list
of EPVs (ecosystem+package+version). It enables the consumers like UI-component to easily invoke data-model APIs.

```
virtualenv --python /usr/bin/python2.7 env
source env/bin/activate
pip install -r requirements.txt
cp src/config.py.template src/config.py
#make necessary changes in config.py
gunicorn --pythonpath src/ -b 0.0.0.0:5001 rest_api:app
```
---

The HTTP-based endpoint to populate the graph is `/api/v1/ingest_to_graph`
This endpoint creates a minimalistic graph having only P(Package) and V(Version).
You can POST the following list as body of the request with `Content-Type: application/json` in the header:
```
[
    {
        "ecosystem":"maven",
        "name":"commons-collections:commons-collections",
        "version":"3.2.1"
}
]
```

### How to run the tests?

NOTE: Make sure to perform test on a fresh instance of graph. i.e `g.V().count == 0`

```
virtualenv --python /usr/bin/python2.7 env
source env/bin/activate
pip install -r requirements.txt
cp src/config.py.template src/config.py
PYTHONPATH=`pwd`/src py.test test/ -s
```

### How to run importer script? Still a WIP to import from local-file-system


To run on OpenShift see **Data Importer** section below in this document.


### How to run Gremlin Server?

#### Using Docker Compose

```
sudo docker-compose -f docker-compose-server.yml up
```

#### Using OpenShift


```
oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> -v REST_VALUE=1 -v CHANNELIZER=http | oc create -f -
```


### Deploying the application

#### Server

- `gremlin-http` deploys with the HTTP channelizer

To deploy these locally, set the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables in your local environment or store the same in the .env file in the same directory as `docker-compose-server.yml`

These variables will contain the required AWS credentials to connect on a remote DynamoDB instance. In OpenShift environment, the credentials are stored as [OpenShift secrets](https://docs.openshift.com/container-platform/3.4/dev_guide/secrets.html).


To specify a `dynamodb_prefix` use `$DYNAMODB_PREFIX` environment variable. This will allow you to create your own graph and not collide with others in a DynamoDB instance.

Now, to deploy:

- Docker Compose, run -

    `docker-compose -f docker-compose-server.yml up <service name, optional>`

    Get the endpoint from `docker inspect <container name>`

- OpenShift, run -

    -	`kompose -f docker-compose-server.yml --provider openshift up`

    -	Alternatively, you can deploy the gremlin server on OpenShift using the OpenShift template file present in the root directory.

        `oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> | oc create -f -`

        To deploy with the HTTP channelizer, add `-v REST_VALUE=1` to the above command.

	Get the endpoint from `oc get services` or `oc get routes` if you have a router configured.

### Data Importer

##### Using Docker Compose

To run Data Importer in a container, we can use following command:


```
$ sudo docker-compose -f docker-compose-importer.yml build
Building data-model
Step 1 : FROM centos:7
 ---> 970633036444
Step 2 : MAINTAINER Saleem Ansari <sansari@redhat.com>
 ---> Using cache
 ---> 73bf6ff1b3eb
Step 3 : RUN yum install -y epel-release &&     yum install -y python-pip postgresql-devel python-devel python-matplotlib gcc &&     mkdir -p /src
 ---> Using cache
 ---> e279a98a6cd6
Step 4 : COPY ./requirements.txt /
 ---> Using cache
 ---> 22b1fc5544e9
Step 5 : RUN pip install -r requirements.txt && rm requirements.txt
 ---> Using cache
 ---> 9dae7686ad3a
Step 6 : COPY ./src /src
 ---> Using cache
 ---> f405b86b1e82
Step 7 : RUN cp /src/config.py.template /src/config.py
 ---> Using cache
 ---> bcd9853b9921
Step 8 : ADD scripts/entrypoint.sh /bin/entrypoint.sh
 ---> Using cache
 ---> 85408b91857a
Step 9 : ENTRYPOINT /bin/entrypoint.sh
 ---> Using cache
 ---> 0c3eefc9ee72
Successfully built 0c3eefc9ee72
$ sudo docker-compose -f docker-compose-importer.yml up
Starting datamodel_data-model_1
Attaching to datamodel_data-model_1
data-model_1  | No source provided
data-model_1  | READ from S3
datamodel_data-model_1 exited with code 0
```

For this to work, update docker-compose-import.yml with correct values of AWS / S3 credentials and this should begin the import:

```
AWS_S3_ACCESS_KEY_ID
AWS_S3_SECRET_ACCESS_KEY
AWS_BUCKET
```

##### Using OpenShift template

When starting fresh, create secrets first:
```
set +o history
# replace 'myKey' and 'mySecretKey' in the following command
oc process -v AWS_S3_ACCESS_KEY_ID=`echo -n 'myKey' | base64` -v AWS_S3_SECRET_ACCESS_KEY=`echo -n 'mySecretKey' | base64` \
  -v AWS_DYNAMODB_ACCESS_KEY_ID=`echo -n 'myKey' | base64` -v AWS_DYNAMODB_SECRET_ACCESS_KEY=`echo -n 'mySecretKey' | base64` \
  -f secrets-openshift-template.yaml | oc apply -f -
set -o history
```

To deploy this on an OpenShift cluster, use the following command:
```
oc process -f data-model-importer-openshift-template.yaml -v AWS_BUCKET=<value> | oc create -f -
```

## How to deploy on OpenShift / Dev Cluster ?

[Dev Cluster and OpenShift setup](docs/deploy-openshift.md)

### Footnotes

#### Coding standards

- Local setup instructions and files can be found at `local-setup` directory, in case anyone wants local DynamoDB support. Note that, the container images used in the backup directory are not the same that are used to host the project in OpenShift. This directory should be removed once the local development support for DynamoDB makes its way in the current master branch.

- For any queries related to building of container images on registry.centos.org, or if some modifications are required in the Dockerfiles, then the CentOS Container Pipeline team can be contacted on the `container-build` channel under CentOS on Mattermost.

- For any queries regarding deployment of the application on OpenShift, contact the Deploy team at devtools-deploy@redhat.com or at `devtools-deploy` channel under RH-DevTools on Mattermost.

- You can use scripts `run-linter.sh` and `check-docstyle.sh` to check if the code follows [PEP 8](https://www.python.org/dev/peps/pep-0008/) and [PEP 257](https://www.python.org/dev/peps/pep-0257/) coding standards. These scripts can be run w/o any arguments:

```
./run-linter.sh
./check-docstyle.sh
```

The first script checks the indentation, line lengths, variable names, white space around operators etc. The second
script checks all documentation strings - its presence and format. Please fix any warnings and errors reported by these
scripts.

#### Code complexity measurement

The scripts `measure-cyclomatic-complexity.sh` and `measure-maintainability-index.sh` are used to measure code complexity. These scripts can be run w/o any arguments:

```
./measure-cyclomatic-complexity.sh
./measure-maintainability-index.sh
```

The first script measures cyclomatic complexity of all Python sources found in the repository. Please see [this table](https://radon.readthedocs.io/en/latest/commandline.html#the-cc-command) for further explanation how to comprehend the results.

The second script measures maintainability index of all Python sources found in the repository. Please see [the following link](https://radon.readthedocs.io/en/latest/commandline.html#the-mi-command) with explanation of this measurement.
