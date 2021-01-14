#!/bin/bash

SCRIPT=supervisor/supervisorAS110_AS112.sh

if [ $1 == AS111 ]; then
    echo $1
    SCRIPT=supervisor/supervisorAS111.sh
fi

for line in $($SCRIPT status | tr -s ' ' | tr ' ' '#'); do

    PROGRAM=$(echo $line | cut -f1 -d'#')
    #echo $PROGRAM

    STATUS=$(echo $line | cut -f2 -d'#')
    #echo $STATUS

    if [ "$STATUS" != RUNNING ]; then
        if [ "$PROGRAM" != dispatcher ]; then
            echo "Restarting" $PROGRAM
            supervisor/supervisorAS110_AS112.sh start $PROGRAM
        fi
    fi

done
