#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

#
# Copyright (C) 2024 Palo Alto Networks, Inc. All Rights Reserved,
# contribution by Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test to make sure the nexthop being tracked is resolved recursivley to a
non-BGP route so that the right IGP metric is given to BGP for bestpath
calculation.

In this test, on r2/r3, the "next-hop-self" is not configured, and the
connected routes are redistributed into BGP for the nexthop reachability
of the EBGP routes.

IP Addresses for the loopback interfaces:

  r1: 10.0.0.1/32
  r2: 10.0.0.2/32
  r3: 10.0.0.3/32
  r4: 10.0.0.4/32

10.0.0.4/32 is redistributed into BGP on r4, and is advertised to both
r2 and r3.  Then r1 receives 10.0.0.4/32 from both r2 and r3, and each of
the nexthops is resolved to another BGP route which is then resolved to
an OSPF route.


                    10               30
              r2  ------- r1 (UUT) ------- r3
              |                            |
         ebgp |                            | ebgp
              |                            |
              +----------- r4 -------------+
                     .24.4    .34.4


On r1 (UUT):

[BGP] 10.0.0.4/32: nexthop 192.168.24.4
                   nexthop 192.168.34.4

192.168.24.4 --> [BGP] 192.168.24.0/24
192.168.34.4 --> [BGP] 192.168.34.0/24

[BGP] 192.168.24.0/24: nexthop 10.0.0.2
[BGP] 192.168.34.0/24: nexthop 10.0.0.3

10.0.0.2 --> [OSPF] 10.0.0.2/32, nexthop xxx, intf xxx
10.0.0.3 --> [OSPF] 10.0.0.3/32, nexthop xxx, intf xxx
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
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_nht_recursive():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_check_igp_metric_bestpath():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.4/32 json"))
        expected = {
            "paths": [
                {
                    "bestpath": {"selectionReason": "IGP Metric"},
                    "nexthops": [{"ip": "192.168.24.4", "hostname": "r2", "metric": 10, "accessible": True}],
                },
                {
                    "nexthops": [{"ip": "192.168.34.4", "hostname": "r3", "metric": 30, "accessible": True}],
                },
            ]
        }
        return topotest.json_cmp(output, expected)


    # Check BGP bestpath selected on IGP metric
    test_func = functools.partial(_bgp_check_igp_metric_bestpath)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=2)
    assert result is None, "BGP bestpath not selected on igp metric"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
