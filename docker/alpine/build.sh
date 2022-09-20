#!/bin/sh

set -e
set -x

##
# Package version needs to be decimal
##

##
# Set GITREV=0 or similar in ENV if you want the tag to just be updated to -0
# everytime for automation usage/scripts/etc locally.
#
# Ex) GITREV=0 ./build.sh
##

GITREV="${GITREV:=$(git rev-parse --short=10 HEAD)}"
PKGVER="$(printf '%u\n' 0x$GITREV)"

docker build \
	--pull \
	--file=docker/alpine/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:alpine-builder-$GITREV" \
	--target=alpine-builder \
	.

# Keep .apk files for debugging purposes, docker image as well.
docker build \
	--pull \
	--file=docker/alpine/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:alpine-apk-builder-$GITREV" \
	--target=alpine-apk-builder \
	.

CONTAINER_ID="$(docker create "frr:alpine-apk-builder-$GITREV")"
docker cp "${CONTAINER_ID}:/pkgs/" docker/alpine
docker rm "${CONTAINER_ID}"

docker build \
	--file=docker/alpine/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:alpine-$GITREV" \
	.

docker rmi "frr:alpine-builder-$GITREV"
docker rmi "frr:alpine-apk-builder-$GITREV"
