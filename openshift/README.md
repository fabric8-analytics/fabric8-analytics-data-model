# Deploying Bayesian data-importer

First make sure you're logged in to the right cluster and on the right project:

```
$ oc project
```

Note this guide assumes that secrets and config maps have already been deployed.

To deploy the data-importer, simply run:

```
./deploy.sh
```

