#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_bfd_down_cease_notification_shutdown.py
#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if Cease/BFD Down notification message is sent/received
when the BFD is down (administratively).
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
from lib.common_config import kill_router_daemons, step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


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

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_bfd_down_notification_shutdown():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
                "peerBfdInfo": {"status": "Up"},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_bfd_down_notification():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "lastNotificationReason": "Cease/BFD Down",
                "lastNotificationHardReset": True,
                "peerBfdInfo": {
                    "status": "Down",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see BGP convergence on R2"

    r1.vtysh_cmd(
        """
    configure
     bfd
      profile r1
       shutdown
    """
    )

    step("Check if we received Cease/BFD Down notification message")
    test_func = functools.partial(_bgp_bfd_down_notification)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see BGP Cease/BFD Down notification message on R2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
