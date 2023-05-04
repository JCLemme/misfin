#!/bin/bash

# Simplest possible way to send a Misfin message.
# Doesn't even show the return code.

if [ $# -lt 5 ]
then
    echo "usage: misfin-send.sh <sender.pem> <destination> <host> <subject> <message>"
    exit -1
fi

printf "misfin://$2@$3 text/gemini $4\r\n$5" | openssl s_client -cert $1 -key $1 -connect $3:1958 
