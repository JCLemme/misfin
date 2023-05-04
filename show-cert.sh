#!/bin/bash

# Shortcut that displays information about a Misfin cert.

if [ $# -lt 1 ]
then
    echo "usage: show-cert.sh <cert.pem>"
    exit -1
fi

SCRAPED=$(openssl x509 -in $1 -subject -ext subjectAltName -noout -nameopt multiline)

# This could prolly be replaced with an Awk one-liner, but my beard is not long enough yet :(
BLURB=$(echo "$SCRAPED" | grep commonName | awk -F= '{sub(" ", "", $NF); print $NF}')
MAILBOX=$(echo "$SCRAPED" | grep userId | awk -F= '{sub(" ", "", $NF); print $NF}')
HOSTNAME=$(echo "$SCRAPED" | grep DNS | awk -F: '{print $NF}')

if [ -z "$BLURB" ] || [ -z "$MAILBOX" ] || [ -z "$HOSTNAME" ]
then
    echo "That doesn't look like a valid Misfin cert"
else
    echo "$BLURB ($MAILBOX@$HOSTNAME)"
fi
