#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if labeled-unicast works correctly with addpath capability.
Initially R3 MUST announce 10.0.0.1/32 multipath(2) from R1 + R2.
Later, we enable R5 and 10.0.0.1/32 multipath(3) MUST be announced,
R1 + R2 + R5.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])


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


def test_bgp_addpath_labeled_unicast():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_check_received_routes(pfxcount):
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 labeled-unicast summary json"))
        expected = {
            "peers": {
                "192.168.34.3": {
                    "pfxRcd": pfxcount,
                    "state": "Established",
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to receive labeled-unicast with addpath (multipath=2)"

    step("Enable BGP session for R5")
    r3.vtysh_cmd(
        """
          configure terminal
            router bgp 65003
              no neighbor 192.168.35.5 shutdown
        """
    )

    test_func = functools.partial(_bgp_check_received_routes, 3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to receive labeled-unicast with addpath (multipath=3)"

    step("Disable BGP session for R5")
    r3.vtysh_cmd(
        """
          configure terminal
            router bgp 65003
              neighbor 192.168.35.5 shutdown
        """
    )

    test_func = functools.partial(_bgp_check_received_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to receive labeled-unicast with addpath (multipath=2)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
