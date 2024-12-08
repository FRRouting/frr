<<<<<<< HEAD
#!/bin/bash
=======
#!/usr/bin/env bash
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

cd "$(dirname "$0")"/..

<<<<<<< HEAD
exec docker build --pull \
=======
exec $(command -v docker || command -v podman) build --pull \
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
		  --compress \
		  -t frrouting/topotests:latest \
		  .
