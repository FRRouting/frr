#!/bin/sh

set -e

##
# Package version needs to be decimal
##
DISTRO=ubi8-minimal

UBI8_MINIMAL_VERSION=$1
if [ -z "$UBI8_MINIMAL_VERSION" ]; then
	UBI8_MINIMAL_VERSION="latest"
fi

GITREV="$2"
if [ -z "$GITREV" ];then
	GITREV="$(git rev-parse --short=10 HEAD)"
fi

FRR_IMAGE_TAG="$3"
if [ -z $FRR_IMAGE_TAG ];then
	FRR_IMAGE_TAG="frr:ubi8-minimal-$GITREV"
fi
PKGVER="$(printf '%u\n' 0x$GITREV)"

FRR_RELEASE="$4"
if [ -z $FRR_RELEASE ];then
	FRR_RELEASE=$(git describe --tags --abbrev=0)
fi

FRR_NAME=$5
if [ -z $FRR_NAME ];then
	FRR_NAME=frr
fi

FRR_VENDOR=$6
if [ -z $FRR_VENDOR ];then
	FRR_VENDOR=frr
fi

DOCKERFILE_PATH="$(dirname $(realpath $0))/Dockerfile"

docker build \
	--cache-from="frr:$DISTRO-builder-$GITREV" \
	--file="$DOCKERFILE_PATH" \
	--build-arg="UBI8_MINIMAL_VERSION=$UBI8_MINIMAL_VERSION" \
	--build-arg="PKGVER=$PKGVER" \
	--build-arg="FRR_IMAGE_TAG=$FRR_IMAGE_TAG" \
	--build-arg="FRR_RELEASE=$FRR_RELEASE" \
	--build-arg="FRR_NAME=$FRR_NAME" \
	--build-arg="FRR_VENDOR=$FRR_VENDOR" \
	--tag="$FRR_IMAGE_TAG" \
	.

