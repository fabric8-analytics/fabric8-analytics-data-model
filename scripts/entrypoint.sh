#!/usr/bin/env bash

# Copy environmental variables into a file
printenv | sed 's/^\(.*\)$/export \1/g' > /root/project_env.sh

# Start cron daemon
crond

# Start data model service with time out of 15 min !
gunicorn --pythonpath /src/ -b 0.0.0.0:5001 -t 900 rest_api:app

