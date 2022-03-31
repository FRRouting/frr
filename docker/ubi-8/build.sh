#!/bin/sh

set -e

##
# Package version needs to be decimal
##
DISTRO=ubi-8

GITREV="$2"
if [ -z "$GITREV" ];then
	GITREV="$(git rev-parse --short=10 HEAD)"
fi

FRR_IMAGE_TAG="$1"
if [ -z $FRR_IMAGE_TAG ];then
	FRR_IMAGE_TAG="frr:ubi-8-$GITREV"
fi
PKGVER="$(printf '%u\n' 0x$GITREV)"

FRR_RELEASE="$3"
if [ -z $FRR_RELEASE ];then
	FRR_RELEASE=$(git describe --tags --abbrev=0)
fi

FRR_NAME=$4
if [ -z $FRR_NAME ];then
	FRR_NAME=frr
fi

FRR_VENDOR=$5
if [ -z $FRR_VENDOR ];then
	FRR_VENDOR=frr
fi

docker build \
	--cache-from="frr:$DISTRO-builder-$GITREV" \
	--file=docker/$DISTRO/Dockerfile \
	--build-arg="PKGVER=$PKGVER" \
	--build-arg="FRR_IMAGE_TAG=$FRR_IMAGE_TAG" \
	--build-arg="FRR_RELEASE=$FRR_RELEASE" \
	--build-arg="FRR_NAME=$FRR_NAME" \
	--build-arg="FRR_VENDOR=$FRR_VENDOR" \
	--tag="$FRR_IMAGE_TAG" \
	.

