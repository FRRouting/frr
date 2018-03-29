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

To add the packages to a docker image, create a Dockerfile in ./docker/pkgs:

::

   FROM alpine:3.7
   RUN mkdir -p /pkgs
   ADD apk/ /pkgs/
   RUN apk add --no-cache --allow-untrusted /pkgs/x86_64/*.apk

And build a docker image:

::

   docker build --rm --force-rm -t alpine-dev-pkgs:latest docker/pkgs

And run the image:

::

   docker run -it --rm alpine-dev-pkgs:latest /bin/sh

Currently, we only package the raw daemons and example files, so, you'll
need to run the daemons by hand (or, better, orchestrate in the Dockerfile).
