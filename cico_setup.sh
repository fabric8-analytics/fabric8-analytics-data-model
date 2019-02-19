#!/bin/bash -ex

REGISTRY="quay.io"

load_jenkins_vars() {
    if [ -e "jenkins-env.json" ]; then
        eval "$(./env-toolkit load -f jenkins-env.json \
                DEVSHIFT_TAG_LEN \
                QUAY_USERNAME \
                QUAY_PASSWORD \
                JENKINS_URL \
                GIT_BRANCH \
                GIT_COMMIT \
                BUILD_NUMBER \
                ghprbSourceBranch \
                ghprbActualCommit \
                BUILD_URL \
                ghprbPullId)"
    fi
}

docker_login() {
    if [ -n "${QUAY_USERNAME}" -a -n "${QUAY_PASSWORD}" ]; then
        docker login -u "${QUAY_USERNAME}" -p "${QUAY_PASSWORD}" "${REGISTRY}"
    else
        echo "Could not login, missing credentials for the registry"
        exit 1
    fi
}

prep() {
    yum -y update
    yum -y install docker git which epel-release python-virtualenv postgresql
    yum -y install python34-pip python34-devel
    pip3 install docker-compose
    systemctl start docker
}

build_image() {
    make docker-build
}

tag_push() {
    local target=$1
    local source=$2
    docker tag "${source}" "${target}"
    docker push "${target}"
}

push_image() {
    local image_name
    local image_repository
    local short_commit

    image_name=$(make get-image-name)
    image_repository=$(make get-image-repository)
    short_commit=$(git rev-parse --short=7 HEAD)

    if [ "$TARGET" = "rhel" ]; then
        IMAGE_URL="${REGISTRY}/openshiftio/rhel-bayesian-data-model-importer"
    else
        IMAGE_URL="${REGISTRY}/openshiftio/bayesian-data-model-importer"
    fi

    if [ -n "${ghprbPullId}" ]; then
        # PR build
        pr_id="SNAPSHOT-PR-${ghprbPullId}"
        tag_push "${IMAGE_URL}:${pr_id}" "${image_name}"
        tag_push "${IMAGE_URL}:${pr_id}-${short_commit}" "${image_name}"
    else
        # master branch build
        tag_push "${IMAGE_URL}:latest" "${image_name}"
        tag_push "${IMAGE_URL}:${short_commit}" "${image_name}"
    fi

    echo 'CICO: Image pushed, ready to update deployed app'
}

load_jenkins_vars
prep