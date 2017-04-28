# Local Development Setup

```
sudo docker-compose up dynamodb gremlin-websocket
```

## Graphite + Grafana

 * Get graphite-grafana image
 * Start graphite

### Get graphite-grafana image

Ensure you have `docker.io/ohamada/graphite-grafana` image available:

```
git clone https://github.com/ohamada/docker-graphite-grafana.git
cd docker-graphite-grafana
sudo docker build -t docker.io/ohamada/graphite-grafana .
```
### Start graphite

Start only Postgres and Graphite containers

```
sudo docker-compose up db graph
```
