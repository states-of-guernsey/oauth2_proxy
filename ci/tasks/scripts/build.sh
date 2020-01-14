#!/bin/bash

set -e -u

BASE_DIR=$PWD
BINARY="oauth2_proxy"

VERSION="$(shell git describe --always --dirty --tags 2>/dev/null || echo '0.0.0-dev')"
if [ -d version ]; then
  VERSION="$(cat version/version)"
fi

mkdir -p $GOPATH/src/github.com/pusher
cp -R oauth2_proxy $GOPATH/src/github.com/pusher/oauth2_proxy

ASSETS_DIR="$BASE_DIR/assets/"
OUTPUT_PATH="/tmp/$BINARY-$VERSION.linux-amd64"

mkdir $OUTPUT_PATH

cd $GOPATH/src/github.com/pusher/oauth2_proxy

GO111MODULE=on GOOS=linux GOARCH=amd64 go build -ldflags="-X main.VERSION=$VERSION" \
  -o "$OUTPUT_PATH/$BINARY" github.com/pusher/oauth2_proxy

shasum -a 256 $OUTPUT_PATH/$BINARY >$ASSETS_DIR/$BINARY-$VERSION.linux-amd64-sha256sum.txt
tar -C $OUTPUT_PATH -czvf $ASSETS_DIR/$BINARY-$VERSION.linux-amd64.tar.gz $BINARY

echo "printing VERSION..."
$OUTPUT_PATH/$BINARY -version
