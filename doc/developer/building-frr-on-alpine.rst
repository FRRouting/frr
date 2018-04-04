Alpine Linux 3.7+
=========================================================

For building Alpine Linux dev packages, we use docker.

Install docker 17.05 or later
-----------------------------

Depending on your host, there are different ways of installing docker.  Refer
to the documentation here for instructions on how to install a free version of
docker: https://www.docker.com/community-edition

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

   docker run -it --rm frr:latest /bin/sh

Currently, we only package the raw daemons and example files, so, you'll
need to run the daemons by hand (or, better, orchestrate in the Dockerfile).

We can also build directly from docker-compose, with a docker-compose.yml file
like this one:

::

   version: '2.2'

   services:
      frr:
         build:
            context: https://github.com/frrouting/frr.git
            dockerfile: docker/alpine/Dockerfile
