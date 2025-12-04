#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# <template>.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
<template>.py: Test <template>.
"""

import sys

import pytest
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

pytestmark = [
    pytest.mark.ospfd,
]


# New form of setup/teardown using pytest fixture
@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s0": ("r1", "r2"),
        "s1": ("r2", "r3"),
    }

    tgen = Topogen(topodef, request.module.__name__)

    tgen.start_topology()
    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()

    yield tgen
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


# ===================
# The tests functions
# ===================


def test_get_version(tgen):
    "Test the logs the FRR version"

    # tgen.gears["r1"].net.cmd_nostatus(
    #     "vtysh -c 'debug ospfd client frontend' " "-c 'debug ospfd client backend' "
    # )

    # stepf("about to get version")

    r1 = tgen.gears["r1"]
    version = r1.vtysh_cmd("show version")
    logger.info("FRR version is: " + version)
