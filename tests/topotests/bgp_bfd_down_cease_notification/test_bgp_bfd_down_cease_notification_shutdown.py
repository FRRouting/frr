#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_bfd_down_cease_notification_shutdown.py
#
# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test BGP behavior when BFD profile is administratively shutdown.

When a BFD profile is shutdown, it sends Admin Down to the remote peer.
The remote peer receives Admin Down and maintains the BGP session (no teardown).
This is by design - Admin Down from peer means BFD is administratively disabled
but protocols should remain up.
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
from lib.common_config import step

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

    def _bgp_stays_established_on_r2():
        """
        On R2, when R1's BFD profile is shutdown, R2 receives Admin Down.
        BGP session should STAY UP (not tear down) because Admin Down from
        peer indicates administrative BFD shutdown but protocols should remain up.
        """
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "peerBfdInfo": {
                    "status": "Admin Down",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_stays_established_on_r1():
        """
        On R1, BFD profile is shutdown locally. BGP session should remain up.
        Local BFD status will show Admin Down, but BGP is not affected.
        """
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "peerBfdInfo": {
                    "status": "Admin Down",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Shutdown BFD profile on R1")
    r1.vtysh_cmd(
        """
    configure
     bfd
      profile r1
       shutdown
    """
    )

    step("Check if BGP session stays Established on R2 after R1 BFD profile shutdown")
    test_func = functools.partial(_bgp_stays_established_on_r2)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BGP session should stay Established on R2 when R1 BFD profile is shutdown"

    step("Check if BGP session stays Established on R1 after local BFD profile shutdown")
    test_func = functools.partial(_bgp_stays_established_on_r1)
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "BGP session should stay Established on R1 after local BFD profile shutdown"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
