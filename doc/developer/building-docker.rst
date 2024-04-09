Docker
======

This page covers how to build FRR Docker images.

Images
""""""
FRR has Docker build infrastructure to produce Docker images containing
source-built FRR on the following base platforms:

* Alpine
* Centos 7
* Centos 8

The following platform images are used to support Travis CI and can also
be used to reproduce topotest failures when the docker host is Ubuntu
(tested on 20.04 and 22.04):

* Ubuntu 20.04
* Ubuntu 22.04

The following platform images may also be built, but these simply install a
binary package from an existing repository and do not perform source builds:

* Debian 10

Some of these are available on `DockerHub
<https://hub.docker.com/repository/docker/frrouting/frr/tags?page=1>`_.

There is no guarantee on what is and is not available from DockerHub at time of
writing.

Scripts
"""""""

Some platforms contain an included build script that may be run from the host.
This will set appropriate packaging environment variables and clean up
intermediate build images.

These scripts serve another purpose. They allow building platform packages
without needing the platform. For example, the Centos 8 docker image can also
be leveraged to build Centos 8 RPMs that can then be used separately from
Docker.

If you are only interested in the Docker images and don't want the cleanup
functionality of the scripts you can ignore them and perform a normal Docker
build. If you want to build multi-arch docker images this is required as the
scripts do not support using Buildkit for multi-arch builds.

Building Alpine Image
---------------------

Script::

   ./docker/alpine/build.sh

No script::

   docker build -f docker/alpine/Dockerfile .

No script, multi-arch (ex. amd64, arm64, armv7)::

   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -f docker/alpine/Dockerfile -t frr:latest .


Building Debian Image
---------------------

::

   cd docker/debian
   docker build .

Multi-arch (ex. amd64, arm64, armv7)::

   cd docker/debian
   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t frr-debian:latest .

Building Centos 7 Image
-----------------------

Script::

   ./docker/centos-7/build.sh

No script::

   docker build -f docker/centos-7/Dockerfile .

No script, multi-arch (ex. amd64, arm64)::

   docker buildx build --platform linux/amd64,linux/arm64 -f docker/centos-7/Dockerfile -t frr-centos7:latest .


Building Centos 8 Image
-----------------------

Script::

   ./docker/centos-8/build.sh

No script::

   docker build -f docker/centos-8/Dockerfile .

No script, multi-arch (ex. amd64, arm64)::

   docker buildx build --platform linux/amd64,linux/arm64 -f docker/centos-8/Dockerfile -t frr-centos8:latest .



Building ubi 8 Image
-----------------------

Script::

   ./docker/ubi-8/build.sh

Script with params, an example could be this (all that info will go to docker label) ::

   ./docker/ubi-8/build.sh  frr:ubi-8-my-test "$(git rev-parse --short=10 HEAD)" my_release my_name my_vendor

No script::

   docker build -f docker/ubi-8/Dockerfile .

No script, multi-arch (ex. amd64, arm64)::

   docker buildx build --platform linux/amd64,linux/arm64 -f docker/ubi-8/Dockerfile -t frr-ubi-8:latest .



Building Ubuntu 20.04 Image
---------------------------

Build image (from project root directory)::

   docker build -t frr-ubuntu20:latest --build-arg=UBUNTU_VERSION=20.04 -f docker/ubuntu-ci/Dockerfile .

Running Full Topotest::

   docker run --init -it --privileged --name frr-ubuntu20 -v /lib/modules:/lib/modules \
       frr-ubuntu20:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'

Extract results from the above run into `run-results` dir and analyze::

   tests/topotests/analyze.py -C frr-ubuntu20 -Ar run-results

Start the container::

   docker run -d --init --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest

Running a topotest (when the docker host is Ubuntu)::

   docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf_topo1 ; sudo pytest test_ospf_topo1.py'

Starting an interactive bash session::

   docker exec -it frr-ubuntu20 bash

Stopping an removing a container::

   docker stop frr-ubuntu20 ; docker rm frr-ubuntu20

Removing the built image::

   docker rmi frr-ubuntu20:latest


Building Ubuntu 22.04 Image
---------------------------

Build image (from project root directory)::

   docker build -t frr-ubuntu22:latest -f docker/ubuntu-ci/Dockerfile .

Running Full Topotest::

   docker run --init -it --privileged --name frr-ubuntu22 -v /lib/modules:/lib/modules \
       frr-ubuntu22:latest bash -c 'cd ~/frr/tests/topotests ; sudo pytest -nauto --dist=loadfile'

Extract results from the above run into `run-results` dir and analyze::

   tests/topotests/analyze.py -C frr-ubuntu22 -Ar run-results

Start the container::

   docker run -d --init --privileged --name frr-ubuntu22 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu22:latest

Running a topotest (when the docker host is Ubuntu)::

   docker exec frr-ubuntu22 bash -c 'cd ~/frr/tests/topotests/ospf_topo1 ; sudo pytest test_ospf_topo1.py'

Starting an interactive bash session::

   docker exec -it frr-ubuntu22 bash

Stopping an removing a container::

   docker stop frr-ubuntu22 ; docker rm frr-ubuntu22

Removing the built image::

   docker rmi frr-ubuntu22:latest
