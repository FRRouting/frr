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
(tested on 18.04 and 20.04):

* Ubuntu 18.04
* Ubuntu 20.04

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



Building Ubuntu 18.04 Image
---------------------------

Build image (from project root directory)::

   docker build -t frr-ubuntu18:latest  -f docker/ubuntu18-ci/Dockerfile .

Start the container::

   docker run -d --privileged --name frr-ubuntu18 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu18:latest

Running a topotest (when the docker host is Ubuntu)::

   docker exec frr-ubuntu18 bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'

Starting an interactive bash session::

   docker exec -it frr-ubuntu18 bash

Stopping an removing a container::

   docker stop frr-ubuntu18 ; docker rm frr-ubuntu18

Removing the built image::

   docker rmi frr-ubuntu18:latest


Building Ubuntu 20.04 Image
---------------------------

Build image (from project root directory)::

   docker build -t frr-ubuntu20:latest  -f docker/ubuntu20-ci/Dockerfile .

Start the container::

   docker run -d --privileged --name frr-ubuntu20 --mount type=bind,source=/lib/modules,target=/lib/modules frr-ubuntu20:latest

Running a topotest (when the docker host is Ubuntu)::

   docker exec frr-ubuntu20 bash -c 'cd ~/frr/tests/topotests/ospf-topo1 ; sudo pytest test_ospf_topo1.py'

Starting an interactive bash session::

   docker exec -it frr-ubuntu20 bash

Stopping an removing a container::

   docker stop frr-ubuntu20 ; docker rm frr-ubuntu20

Removing the built image::

   docker rmi frr-ubuntu20:latest
