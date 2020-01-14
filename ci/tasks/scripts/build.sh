#!/bin/bash

set -e -u

BINARY="oauth2_proxy"

VERSION="$(shell git describe --always --dirty --tags 2>/dev/null || echo '0.0.0-dev')"
if [ -d version ]; then
  VERSION="$(cat version/version)"
fi

mkdir -p $GOPATH/src/github.com/pusher
cp -R oauth2_proxy $GOPATH/src/github.com/pusher/oauth2_proxy


mkdir assets/$BINARY-$VERSION.linux-amd64

cd $GOPATH/src/github.com/pusher/oauth2_proxy

GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=$VERSION" \
	-o assets/$BINARY-$VERSION.linux-amd64/$BINARY github.com/pusher/oauth2_proxy

shasum -a 256 assets/$BINARY-$VERSION.linux-amd64/$BINARY > assets/$BINARY-$VERSION.linux-amd64-sha256sum.txt
tar -C assets -czvf assets/$BINARY-$VERSION.linux-amd64.tar.gz $BINARY-$VERSION.linux-amd64

echo "printing VERSION..."
./assets/$BINARY-$VERSION.linux-amd64/$BINARY -version
