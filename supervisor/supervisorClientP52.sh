#!/bin/bash

mkdir -p logs

# Wrap the 'supervisorctl' command
OPTIONS="$@"
CONF_FILE="supervisor/supervisordClientP52.conf"
if [ ! -e /tmp/supervisor.sock ]; then
    supervisord -c $CONF_FILE
fi
supervisorctl -c $CONF_FILE $OPTIONS

