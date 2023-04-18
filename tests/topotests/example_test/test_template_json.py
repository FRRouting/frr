#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# September 5 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
<template>.py: Test <template>.
"""

import pytest

# Import topogen and topotest helpers
from lib import bgp
from lib import fixtures


# TODO: select markers based on daemons used during test
pytestmark = [
    pytest.mark.bgpd,
    # pytest.mark.ospfd,
    # pytest.mark.ospf6d
    # ...
]

# Use tgen_json fixture (invoked by use test arg of same name) to
# setup/teardown standard JSON topotest
tgen = pytest.fixture(fixtures.tgen_json, scope="module")


# tgen is defined above
# topo is a fixture defined in ../conftest.py
def test_bgp_convergence(tgen, topo):
    "Test for BGP convergence."

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    bgp_convergence = bgp.verify_bgp_convergence(tgen, topo)
    assert bgp_convergence


# Memory leak test template
def test_memory_leak(tgen):
    "Run the memory leak test and report results."

    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()
