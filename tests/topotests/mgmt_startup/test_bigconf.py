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
import ipaddress
import logging
import math
import os
import re

import pytest
from lib.common_config import retry, step
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger
from munet.base import Timeout

CWD = os.path.dirname(os.path.realpath(__file__))

# pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]
pytestmark = [pytest.mark.staticd]


def get_ip_networks(super_prefix, count):
    count_log2 = math.log(count, 2)
    if count_log2 != int(count_log2):
        count_log2 = int(count_log2) + 1
    else:
        count_log2 = int(count_log2)
    network = ipaddress.ip_network(super_prefix)
    return tuple(network.subnets(count_log2))[0:count]


track = Timeout(0)
ROUTE_COUNT = 5000
ROUTE_RANGE = [None, None]


def write_big_route_conf(rtr, super_prefix, count):
    start = None
    end = None
    with open(f"{CWD}/{rtr.name}/big.conf", "w+", encoding="ascii") as f:
        for net in get_ip_networks(super_prefix, count):
            end = net
            if not start:
                start = net
            f.write(f"ip route {net} lo\n")

    return start, end


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    global start_time
    topodef = {
        "s1": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    start, end = write_big_route_conf(tgen.gears["r1"].net, "10.0.0.0/8", ROUTE_COUNT)
    ROUTE_RANGE[0] = start
    ROUTE_RANGE[1] = end

    # configure mgmtd using current mgmtd config file
    tgen.gears["r1"].load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
    tgen.gears["r1"].load_config(TopoRouter.RD_MGMTD, "big.conf")

    track.started_on = datetime.datetime.now()

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@retry(retry_timeout=3, initial_wait=0.1)
def check_kernel(r1, prefix, expected=True):
    net = ipaddress.ip_network(prefix)
    if net.version == 6:
        kernel = r1.net.cmd_nostatus("ip -6 route show", warn=not expected)
    else:
        kernel = r1.net.cmd_nostatus("ip -4 route show", warn=not expected)

    logger.debug("checking kernel routing table:\n%s", kernel)
    route = f"{str(net)}(?: nhid [0-9]+)?.*proto (static|196)"
    m = re.search(route, kernel)
    if expected and not m:
        return f"Failed to find \n'{route}'\n in \n'{kernel}'"
    elif not expected and m:
        return f"Failed found \n'{route}'\n in \n'{kernel}'"
    return None


def test_staticd_late_start(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.routers()["r1"]

    step(f"Verifying {ROUTE_COUNT} startup routes are present")

    timeo = Timeout(30)
    for remaining in timeo:
        rc, o, e = r1.net.cmd_status("vtysh -c 'show version'")
        if not rc:
            break
        print("nogo: ", rc, o, e)
    assert not timeo.is_expired()
    logging.info("r1: vtysh connected after %ss", track.elapsed())

    result = check_kernel(r1, ROUTE_RANGE[0], retry_timeout=20)
    assert result is None
    logging.info("r1: first route installed after %ss", track.elapsed())

    result = check_kernel(r1, ROUTE_RANGE[1], retry_timeout=20)
    assert result is None
    logging.info("r1: last route installed after %ss", track.elapsed())
