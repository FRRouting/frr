#!/bin/sh

set -e
set -v
set -x

##
# commit must be converted to decimal
##
c=`git rev-parse --short=10 HEAD`
commit=`printf '%u\n' 0x$c`
git archive --format=tar $c > docker/alpine/src.tar
(cd docker/alpine && \
	docker build --build-arg commit=$commit --rm --force-rm -t \
		frr:alpine-$c . && \
	rm -f src.tar)

id=`docker create frr:alpine-$c`
docker cp ${id}:/pkgs/ docker
docker rm $id
docker rmi frr:alpine-$c
