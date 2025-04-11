#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 Nvidia Inc.
# Donald Sharp
#
"""
Test zebra ipv6 nd nat64 advertisement

Requires scapy 2.6.1 or greater
"""

import os
import pytest
import json
from lib.topogen import Topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r2")}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_zebra_rapref64_sent(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.cmd_raises("{}/rx_ipv6_ra_8781.py r2-eth0 64:ff9b::/96 16 10".format(CWD))
    r2.cmd_raises("{}/rx_ipv6_ra_8781.py r2-eth1 64:ff9b::/64 16 10".format(CWD))


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
