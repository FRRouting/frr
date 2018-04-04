#!/bin/sh

set -e
set -v
set -x

##
# commit must be converted to decimal
##
c=`git rev-parse --short=10 HEAD`
commit=`printf '%u\n' 0x$c`
docker build -f docker/alpine/Dockerfile \
	--build-arg commit=$commit -t frr:alpine-$c .
id=`docker create frr:alpine-$c`
docker cp ${id}:/pkgs/ docker
docker rm $id
docker rmi frr:alpine-$c
