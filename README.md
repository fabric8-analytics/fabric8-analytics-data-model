# Fabric8-Analytics Data Models

This repository serves as a base for our data modeling work. You can easily connect to graphing engine (Gremlin + DynamoDB) running remotely in containers and import models to explore the graphs representing Fabric8-Analytics data.

*Note on naming: The Fabric8-Analytics project has evolved from 2 different projects called "cucos" and "bayesian". We're currently in process of renaming the modules and updating documentation. Until that is completed, please consider "cucos" and "bayesian" to be synonyms of "Fabric8-Analytics".*

## Contributing

See our [contributing guidelines](https://github.com/fabric8-analytics/common/blob/master/CONTRIBUTING.md) for more info.

## Configuration parameters

Keep proper configuration values handy ( preferably in `.env` file for docker compose):

```
AWS_S3_ACCESS_KEY_ID=some_key
AWS_S3_SECRET_ACCESS_KEY=some_secret
AWS_BUCKET=bucket_name
DYNAMODB_PREFIX=prefix_allocated_to_you
DYNAMODB_CLIENT_CREDENTIALS_CLASS_NAME=com.amazonaws.auth.DefaultAWSCredentialsProviderChain
AWS_ACCESS_KEY_ID=<dynamodb-access-key-id>
AWS_SECRET_ACCESS_KEY=<dynamodb-secret-access-key>
```


## How Tos

## How to test and develop locally?
```
cd local-setup
docker-compose up
```
Now you can run the tests or the REST API on another terminal

## How to run run REST API:

This REST API serves as a language-independent interface to data-model functionality such as importing the given list
of EPVs. It enables the consumers like UI-component to easily invoke data-model APIs.

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

The websocket based endpoint to populate the graph is `/api/v1/import_epv_from_s3`
This endpoint creates the entire graph.
It uses the same input format as described for the HTTP endpoint.


### How to run the tests?

```
virtualenv --python /usr/bin/python2.7 env
source env/bin/activate
pip install -r requirements.txt
cp src/config.py.template src/config.py
PYTHONPATH=`pwd`/src py.test test/ -s
```

### How to run importer script?

We can import data into graph from a directory where such JSON files are present. To prepare for such setup, we can first load data from S3 into a local directory.

Example commands that can be used are:

```
$ sudo dnf install -y awscli
$ aws configure
AWS Access Key ID [None]: ENTER ACCESS KEY HERE
AWS Secret Access Key [None]: ENTER SECRET KEY HERE
Default region name [None]: us-east-1
Default output format [None]: 
$ aws configure set s3.signature_version s3v4
$ cd ../
$ mkdir s3-data
$ aws s3 cp --recursive "s3://bayesian-bayesian-core-data/" s3-data/
$ cd -
```

If a directory with JSON files is located at `../s3-data/` we can invoke the importer script as below:

```
PYTHONPATH=`pwd`/src python src/data_importer.py -s DIR -d ../s3-data/
```

Or via configured S3 location

```
PYTHONPATH=`pwd`/src python src/data_importer.py -s S3
```

To run on OpenShift see **Data Importer** section below in this document.


### How to run Gremlin Server?

#### Using Docker Compose

```
sudo docker-compose -f docker-compose-server.yml up
```

#### Using OpenShift


 * WebSocket endpoint

```
oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> -v REST_VALUE=0 -v CHANNELIZER=ws | oc create -f -
```

 * HTTP endpoint

```
oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> -v REST_VALUE=1 -v CHANNELIZER=http | oc create -f -
```

### Building container images

All the artifacts required to build the container images are stored in a [publicly hosted repository](https://github.com/containscafeine/data-model). These are the artifacts which have been used to deploy the application on the remote OpenShift instance.

Also, the above mentioned repository is being tracked by the CentOS Container Pipeline which, each time a commit is pushed to the tracked repository, automatically builds a newer container image and pushes to registry.centos.org (read more [here](https://github.com/CentOS/container-index)), which is then deployed on the remote OpenShift instance.

To locally build the container images, one way would be to use the following command:

`docker-compose -f <path to docker compose file> build <service name, optional>`

### Deploying the application

#### Server

There are 2 Gremlin servers defined in `docker-compose-server.yml`
- `gremlin-http` deploys with the HTTP channelizer
- `gremlin-websocket` deploys with the WebSocket channelizer

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

	For instance, to deploy with both WebSocket and HTTP channelizers, the OpenShift commands will look something like -

          - WebSocket channelizer:

            `oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> -v REST_VALUE=0 -v CHANNELIZER=ws | oc create -f -`

          - HTTP channelizer:

            `oc process -f gremlin-server-openshift-template.yaml -v DYNAMODB_PREFIX=<dynamodb_prefix> -v REST_VALUE=1 -v CHANNELIZER=http | oc create -f -`

    Get the endpoint from `oc get services` or `oc get routes` if you have a router configured.

#### Client

There are 2 Gremlin clients defined in `docker-compose-client.yml`:
- `client-ipython` starts an iPython shell, using which you can connect to the server.

- `client-console` starts the gremlin console.

    It requires `$GREMLIN_HOST` and `$GREMLIN_PORT` environment variables to be set in your local environment or store the same in the .env file in the same directory as `docker-compose-client.yml`

    These variables point to the remote Gremlin server running with the WebSocket channelizer.

Now, to deploy on:

- Docker Compose, run -

    `docker-compose -f docker-compose-client.yml up -d <service name, optional>`

    `docker attach <container name>` to get access to the console/shell

- OpenShift, run -

    `kompose -f docker-compose-client.yml --provider openshift up`

    `oc attach -it <pod name>`


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

- Local setup instructions and files can be found at `local-setup` directory, in case anyone wants local DynamoDB support. Note that, the container images used in the backup directory are not the same that are used to host the project in OpenShift. This directory should be removed once the local development support for DynamoDB makes its way in the current master branch.

- For any queries related to building of container images on registry.centos.org, or if some modifications are required in the Dockerfiles, then the CentOS Container Pipeline team can be contacted on the `container-build` channel under CentOS on Mattermost.

- For any queries regarding deployment of the application on OpenShift, contact the Deploy team at devtools-deploy@redhat.com or at `devtools-deploy` channel under RH-DevTools on Mattermost.

- User a Linter and follow PEP8 coding standard. 
