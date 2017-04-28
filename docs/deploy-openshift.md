# Dev Cluster and OpenShift setup

First obtain login to Dev Cluster - https://dev.rdu2c.fabric8.io:8443/console/

Setup OpenShift CLI by downloading it from here: https://github.com/openshift/origin/releases/tag/v1.4.1

Once OpehSift CLI is setup, we do:

```
$ oc login "https://dev.rdu2c.fabric8.io:8443"
Authentication required for https://dev.rdu2c.fabric8.io:8443 (openshift)
Username: sansari
Password: 
Login successful.
```

You have access to the following projects and can switch between them with 'oc project <projectname>':

```
    sample
  * sansari-bayesian

  Using project "sansari-bayesian".
```

# Deploy Secrets

Obtain the secrets template from Bayesian core.

To deploy secrets we need to encode the secret values to Base64, which can be done as shown below:


```
$ echo -n AWS_ACCESS_KEY | base64
ZS09sSHRvWEtP=
$ echo -n AWS_ACCESS_SECRET | base64
Z0FyMEFyME1dgFyMEFyMEFyMEFyMEFyMEFyME==
```

**NOTE**: These are just dummy values. Please place correct values when running these commands.

Place these values in secrets-template.yaml, and then deploy it:

```
$ oc process -f secrets-template.yaml > sec.json
$ oc apply -f sec.json
secret "worker" created
secret "coreapi-postgres" created
secret "anitya-postgres" created
secret "aws" created
```

# Deploy Services

Obtain the Gremlin server template from [this repo](https://github.com/containscafeine/data-model/).

Finally we can deploy the services that depend on secrets:

## Gremlin WebSocket

```
$ oc process -f gremlin-server-template.yaml -v DYNAMODB_PREFIX=my_graph -v MEMORY_LIMIT=2048Mi | oc apply -f -
service "bayesian-gremlin-ws" created
deploymentconfig "bayesian-gremlin-ws" created
```

## Gremlin HTTP (REST)

```
$ oc process -f gremlin-server-template.yaml -v DYNAMODB_PREFIX=my_graph -v MEMORY_LIMIT=2048Mi -v CHANNELIZER=http -v REST_VALUE=1 | oc apply -f -
service "bayesian-gremlin-http" created
deploymentconfig "bayesian-gremlin-http" created
```

Now both services (HTTP and WebSocket) are deployed. We can follow same process for any OpenShift service template.

