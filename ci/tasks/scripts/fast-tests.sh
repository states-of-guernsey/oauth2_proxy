#!/bin/sh

set -e -u -x

# Following tests as per CONTRIBUTING.md

mkdir -p $GOPATH/src/github.com/pusher
cp -R oauth2_proxy $GOPATH/src/github.com/pusher/oauth2_proxy

cd $GOPATH/src/github.com/pusher/oauth2_proxy
./configure

echo
echo "Running tests..."
make tests