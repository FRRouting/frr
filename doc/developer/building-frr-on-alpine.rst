Alpine Linux 3.7+
=========================================================

For building Alpine Linux dev packages, we use docker.

Install docker 17.05 or later
-----------------------------

Depending on your host, there are different ways of installing docker.  Refer
to the documentation here for instructions on how to install a free version of
docker: https://www.docker.com/community-edition

Pre-built packages and docker images
------------------------------------

The master branch of https://github.com/frrouting/frr.git has a
continuous delivery of docker images to docker hub at:
https://hub.docker.com/r/ajones17/frr/. These images have the frr packages
in /pkgs/apk and have the frr package pre-installed.  To copy Alpine
packages out of these images:

::

   id=`docker create ajones17/frr:latest`
   docker cp ${id}:/pkgs _some_directory_
   docker rm $id

To run the frr daemons (see below for how to configure them):

::

   docker run -it --rm --name frr ajones17/frr:latest
   docker exec -it frr /bin/sh

Work with sources
-----------------

::

   git clone https://github.com/frrouting/frr.git frr
   cd frr

Build apk packages
------------------

::

   ./docker/alpine/build.sh

This will put the apk packages in:

::

   ./docker/pkgs/apk/x86_64/

Usage
-----

To create a base image with the frr packages installed:

::

   docker build --rm -f docker/alpine/Dockerfile -t frr:latest .

Or, if you don't have a git checkout of the sources, you can build a base
image directly off the github account:

::

   docker build --rm -f docker/alpine/Dockerfile -t frr:latest \
	https://github.com/frrouting/frr.git

And to run the image:

::

   docker run -it --rm --name frr frr:latest

In the default configuration, none of the frr daemons will  be running.
To configure the daemons, exec into the container and edit the configuration
files or mount a volume with configuration files into the container on
startup.  To configure by hand:

::

   docker exec -it frr /bin/sh
   vi /etc/frr/daemons
   vi /etc/frr/daemons.conf
   cp /etc/frr/zebra.conf.sample /etc/frr/zebra.conf
   vi /etc/frr/zebra.conf
   /etc/init.d/frr start

Or, to configure the daemons using /etc/frr from a host volume, put the
config files in, say, ./docker/etc and bind mount that into the
container:

::

   docker run -it --rm -v `pwd`/docker/etc:/etc/frr frr:latest

We can also build the base image directly from docker-compose, with a
docker-compose.yml file like this one:

::

   version: '2.2'

   services:
      frr:
         build:
            context: https://github.com/frrouting/frr.git
            dockerfile: docker/alpine/Dockerfile
