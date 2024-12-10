<<<<<<< HEAD
#!/bin/bash
=======
#!/usr/bin/env bash
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

cd "$(dirname "$0")"/..

<<<<<<< HEAD
exec docker build --pull \
=======
exec $(command -v docker || command -v podman) build --pull \
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
		  --compress \
		  -t frrouting/topotests:latest \
		  .
