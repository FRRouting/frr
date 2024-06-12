#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Takemasa Imada <takemasa.imada@gmail.com>
#

"""
Test if minimum-holdtime works.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_minimum_holdtime():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_neighbor_check_if_notification_sent():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp neighbor 192.168.255.2 json")
        )
        expected = {
            "192.168.255.2": {
                "connectionsEstablished": 0,
                "lastNotificationReason": "OPEN Message Error/Unacceptable Hold Time",
                "lastResetDueTo": "BGP Notification send",
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_neighbor_check_if_notification_sent)
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)
    assert result is None, "Failed to send notification message\n"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
