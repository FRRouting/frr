# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# May 2 2023, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2023, LabN Consulting, L.L.C.
#
"""
Test static route startup functionality
"""

import datetime
import logging
import os

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter
from munet.base import Timeout
from util import check_kernel, check_vtysh_up, write_big_route_conf

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


track = Timeout(0)
ROUTE_COUNT = 2500
ROUTE_RANGE = [None, None]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    global start_time
    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    prologue = open(f"{CWD}/r1/mgmtd.conf").read()

    confpath = f"{tgen.gears['r1'].gearlogdir}/r1-late-big.conf"
    start, end = write_big_route_conf("10.0.0.0/8", ROUTE_COUNT, confpath, prologue)
    ROUTE_RANGE[0] = start
    ROUTE_RANGE[1] = end

    # configure mgmtd using current mgmtd config file
    tgen.gears["r1"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r1"].load_config(TopoRouter.RD_MGMTD, confpath)

    track.started_on = datetime.datetime.now()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_staticd_latestart(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.routers()["r1"]

    step(f"Verifying {ROUTE_COUNT} startup routes are present")

    check_vtysh_up(r1)
    logging.info("r1: vtysh connected after %ss", track.elapsed())

    result = check_kernel(r1, ROUTE_RANGE[0], retry_timeout=60)
    assert result is None
    logging.info("r1: first route installed after %ss", track.elapsed())

    result = check_kernel(r1, ROUTE_RANGE[1], retry_timeout=60)
    assert result is None
    logging.info("r1: last route installed after %ss", track.elapsed())
