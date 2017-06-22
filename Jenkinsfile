#!/usr/bin/env groovy
@Library('github.com/msrb/cicd-pipeline-helpers')

def commitId
node('gremlin') {

    def image = docker.image('bayesian/data-model-importer')

    stage('Checkout') {
        checkout scm
        commitId = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
        dir('openshift') {
            stash name: 'template', includes: 'template.yaml'
        }
    }

    stage('Tests') {
        dockerCleanup()
        timeout(30) {
            sh './runtests.sh'
        }
    }

    stage('Build') {
        docker.build(image.id, '-f Dockerfile.data-model --pull --no-cache .')
    }

    if (env.BRANCH_NAME == 'master') {
        stage('Push Images') {
            docker.withRegistry('https://docker-registry.usersys.redhat.com/') {
                image.push('latest')
                image.push(commitId)
            }
            docker.withRegistry('https://registry.devshift.net/') {
                image.push('latest')
                image.push(commitId)
            }
        }
    }
}

if (env.BRANCH_NAME == 'master') {
    node('oc') {
        stage('Deploy - dev') {
            unstash 'template'
            sh "oc --context=dev process -v IMAGE_TAG=${commitId} -f template.yaml | oc --context=dev apply -f -"
        }

        stage('Deploy - rh-idev') {
            unstash 'template'
            sh "oc --context=rh-idev process -v IMAGE_TAG=${commitId} -f template.yaml | oc --context=rh-idev apply -f -"
        }
    }
}
