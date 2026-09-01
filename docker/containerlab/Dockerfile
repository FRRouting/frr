# syntax=docker/dockerfile:1

# FRR image for use with containerlab (https://containerlab.dev).
#
# This is the released FRR image with an SSH server added. The stock image has
# none, so a running FRR container cannot be reached with ssh, which
# containerlab's "frr" kind expects to be possible.
#
# The base is the release image built from docker/alpine/Dockerfile, so this
# image must be built after that one. TAG selects which release to build on
# top of and defaults to the latest published release.
#
# See doc/developer/frr-release-procedure.rst for how this is built and pushed
# as part of a release.

ARG TAG=latest
FROM quay.io/frrouting/frr:${TAG}

RUN apk add --no-cache openssh

# Starts sshd alongside watchfrr. The base image's script starts watchfrr only.
COPY docker/containerlab/docker-start /usr/lib/frr/docker-start

EXPOSE 22

# ENTRYPOINT (tini) is inherited from the base image.
CMD ["/usr/lib/frr/docker-start"]
