#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Copyright 2018 Network Device Education Foundation, Inc. ("NetDEF")

cd "$(dirname "$0")"/..

exec $(command -v docker || command -v podman) build --pull \
		  --compress \
		  -t frrouting/topotests:latest \
		  .
