#!/bin/bash

# Simplest way to make a Misfin certificate.

if [ $# -lt 4 ] 
then
    echo "usage: make-cert.sh <mailbox> <blurb> <hostname> <output.pem>"
    exit 
fi

openssl req -x509 -newkey rsa:2048 -keyout $4 -out $4 -sha256 -days 8192 -nodes -subj "/CN=$2/UID=$1" -addext "subjectAltName = DNS:$3"

echo "$2 ($1@$3): saved to $4"
