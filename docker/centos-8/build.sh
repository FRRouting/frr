#!/bin/sh

set -e

##
# Package version needs to be decimal
##
GITREV="$(git rev-parse --short=10 HEAD)"
PKGVER="$(printf '%u\n' 0x$GITREV)"

mkdir -p docker/centos-8/pkgs
docker build \
	--file=docker/centos-8/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:centos-8-builder-$GITREV" \
	--target=centos-8-builder \
	.

# Copy RPM package from container to host
CONTAINER_ID="$(docker create "frr:centos-8-builder-$GITREV")"
docker cp "${CONTAINER_ID}:/rpmbuild/RPMS/x86_64/" docker/centos-8/pkgs
docker rm "${CONTAINER_ID}"

docker build \
	--cache-from="frr:centos-8-builder-$GITREV" \
	--file=docker/centos-8/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--tag="frr:centos-8-$GITREV" \
	.

docker rmi "frr:centos-8-builder-$GITREV"
