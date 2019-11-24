#!/bin/sh

set -e

##
# Package version needs to be decimal
##
GITREV="$(git rev-parse --short=10 HEAD)"
PKGVER="$(printf '%u\n' 0x$GITREV)"

mkdir -p docker/centos/pkgs
docker build \
	--file=docker/centos/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:centos-builder-$GITREV" \
	--target=centos-builder \
	.

# Copy RPM package from container to host
CONTAINER_ID="$(docker create "frr:centos-builder-$GITREV")"
docker cp "${CONTAINER_ID}:/rpmbuild/RPMS/x86_64/" docker/centos/pkgs
docker rm "${CONTAINER_ID}"

docker build \
	--cache-from="frr:centos-builder-$GITREV" \
	--file=docker/centos/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:centos-$GITREV" \
	.

docker rmi "frr:centos-builder-$GITREV"
