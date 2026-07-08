#!/usr/bin/env bash
# =============================================================================
# BGP_ASSIGNMENT — Docker build + run helper
#
# Run this script from the BGP_ASSIGNMENT/ directory (the repo root):
#
#   cd /path/to/BGP_ASSIGNMENT
#   bash frr/docker/bgp-assignment/build.sh
#
# Or use the individual commands below directly.
# =============================================================================

set -euo pipefail

IMAGE=frr-bgp-assignment

echo "====================================================================="
echo " Step 1: Build the Docker image"
echo " Context : BGP_ASSIGNMENT/frr/docker/bgp-assignment/"
echo " Tag     : $IMAGE"
echo "====================================================================="

docker build \
  --tag "$IMAGE" \
  --file frr/docker/bgp-assignment/Dockerfile \
  frr/docker/bgp-assignment

echo ""
echo "====================================================================="
echo " Step 2: Run the container"
echo " Mount  : $(pwd)/frr -> /home/frr/frr  (read-write)"
echo " User   : frr (uid 1010)"
echo " Shell  : /bin/bash"
echo "====================================================================="

docker run \
  --rm \
  --interactive \
  --tty \
  --volume "$(pwd)/frr:/home/frr/frr" \
  --workdir /home/frr/frr \
  --user frr \
  "$IMAGE" \
  /bin/bash

# =============================================================================
# Once inside the container the full build sequence is:
#
#   ./bootstrap.sh
#
#   ./configure \
#     --prefix=/usr \
#     --sysconfdir=/etc/frr \
#     --localstatedir=/var/run/frr \
#     --sbindir=/usr/lib/frr \
#     --enable-bgpd \
#     --disable-doc \
#     --disable-grpc \
#     --disable-rpki \
#     --disable-ospfapi \
#     --disable-vrrpd \
#     --disable-bgp-vnc \
#     --disable-scripting
#
#   make -j"$(nproc)" bgpd/bgpd
#
# To compile only the changed files individually for faster iteration:
#
#   make bgpd/bgp_crypto_routes.o
#   make bgpd/bgp_packet.o
#   make bgpd/bgp_attr.o
#   make bgpd/bgp_vty.o
# =============================================================================
