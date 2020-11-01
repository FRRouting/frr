#!/usr/bin/env python
#
# Copyright 2021 Broadcom.  The term Broadcom refers to Broadcom Inc. and/or
# its subsidiaries.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""
Test link-local address as a BGP peer over VRF.
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
from lib.topolog import logger
from lib.topotest import iproute2_is_vrf_capable
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 3):
            tgen.add_router("r{}".format(routern))
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        # r1-r2 2
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    # iproute2 needs to support VRFs for this suite to run.
    if not iproute2_is_vrf_capable():
        pytest.skip("Installed iproute2 version does not support VRFs")

    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # blue vrf
    r1.run("ip link add blue type vrf table 1001")
    r1.run("ip link set up dev blue")
    r2.run("ip link add blue type vrf table 1001")
    r2.run("ip link set up dev blue")

    r1.run("ip link add lo1 type dummy")
    r1.run("ip link set lo1 master blue")
    r1.run("ip link set up dev lo1")
    r2.run("ip link add lo1 type dummy")
    r2.run("ip link set up dev lo1")
    r2.run("ip link set lo1 master blue")

    r1.run("ip link set r1-eth1 master blue")
    r2.run("ip link set r2-eth1 master blue")

    r1.run("ip link set up dev  r1-eth1")
    r2.run("ip link set up dev  r2-eth1")
    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_vrf_link_local():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_ll_neighbor_configured():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp vrf blue neighbor json")
        )
        expected = {
            "fe80:1::2": {"bgpState": "Established"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_ll_neighbor_configured)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r1"])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

