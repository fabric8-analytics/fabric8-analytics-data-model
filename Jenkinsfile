#!/usr/bin/env groovy

node('gremlin') {

    def image = docker.image('bayesian/data-model-importer')
    def commitId

    stage('Checkout') {
        checkout scm
        commitId = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
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

        stage('Prepare Template') {
            dir('openshift') {
                sh "sed -i \"/image-tag\$/ s|latest|${commitId}|\" template.yaml"
                stash name: 'template', includes: 'template.yaml'
                archiveArtifacts artifacts: 'template.yaml'
            }
        }
    }
}

if (env.BRANCH_NAME == 'master') {
    node('oc') {
        def bucket = 'bayesian-core-data'

        stage('Deploy - dev') {
            unstash 'template'
            sh "oc --context=dev process -v AWS_BUCKET=DEV-${bucket} -f template.yaml | oc --context=dev apply -f -"
        }

        stage('Deploy - rh-idev') {
            unstash 'template'
            sh "oc --context=rh-idev process -v AWS_BUCKET=STAGE-${bucket} -f template.yaml | oc --context=rh-idev apply -f -"
        }
    }
}
