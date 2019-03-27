#!/bin/sh

set -e
set -x

##
# Package version needs to be decimal
##
GITREV="$(git rev-parse --short=10 HEAD)"
PKGVER="$(printf '%u\n' 0x$GITREV)"

docker build \
	--pull \
	--file=docker/alpine/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:alpine-builder-$GITREV" \
	--target=alpine-builder \
	.

CONTAINER_ID="$(docker create "frr:alpine-builder-$GITREV")"
docker cp "${CONTAINER_ID}:/pkgs/" docker/alpine
docker rm "${CONTAINER_ID}"

docker build \
	--file=docker/alpine/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:alpine-$GITREV" \
	.

docker rmi "frr:alpine-builder-$GITREV"
