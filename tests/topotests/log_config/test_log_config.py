# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# June 13 2025, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2025, LabN Consulting, L.L.C.
#
"""
Test Logging Config
"""
import logging
import re

import pytest
from basic import do_test_filter_file, do_test_log, do_test_syslog, setup_test
from lib.topogen import Topogen

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

#
# OSPFd is unconverted daemon
# MGMTd is special daemon that is modern but not a mgmtd backend
# StaticD is a modern converted-to mgmtd backend
#
# Test all three
#


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(scope="module", autouse=True)
def setup_watchlogs(tgen):
    setup_test(tgen.net)


def test_log(tgen):
    do_test_log(tgen.net, topotest_started=True)


def test_filter_file(tgen):
    do_test_filter_file(tgen.net)
