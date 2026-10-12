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

# An "admin" user whose login shell is vtysh, so that "ssh admin@node" reaches
# the routing CLI rather than a shell. frr and frrvty are the groups that let
# vtysh open the daemons' sockets and write the configuration, which is what
# separates a usable CLI from a read-only one.
#
# The image ships no password for it: a well-known one would be open to
# anything that reaches the container, containerlab or not. containerlab sets
# one when it deploys the node, from the node's credentials. The shadow entry is
# "*" rather than the "!" adduser leaves, because sshd treats "!" as a locked
# account and then refuses even key logins.
RUN adduser -D -s /usr/bin/vtysh -G frr admin \
    && addgroup admin frrvty \
    && echo 'admin:*' | chpasswd -e \
    && echo '/usr/bin/vtysh' >> /etc/shells

# Replaces the stock Alpine motd, which says nothing about FRR.
COPY docker/containerlab/motd /etc/motd

# Starts sshd alongside watchfrr. The base image's script starts watchfrr only.
COPY docker/containerlab/docker-start /usr/lib/frr/docker-start

EXPOSE 22

# ENTRYPOINT (tini) is inherited from the base image.
CMD ["/usr/lib/frr/docker-start"]
