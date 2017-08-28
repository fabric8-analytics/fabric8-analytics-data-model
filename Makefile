REGISTRY?=registry.devshift.net
REPOSITORY?=bayesian/data-model-importer
DEFAULT_TAG=latest

.PHONY: all docker-build fast-docker-build test get-image-name get-image-repository

all: fast-docker-build

docker-build:
	docker build --no-cache -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f Dockerfile.data-model .

fast-docker-build:
	docker build -t $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG) -f Dockerfile.data-model .

test:
	./runtests.sh

get-image-name:
	@echo $(REGISTRY)/$(REPOSITORY):$(DEFAULT_TAG)

get-image-repository:
	@echo $(REPOSITORY)

