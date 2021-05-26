#!/usr/bin/env python

#
# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Test if `bgp default ipv4-unicast` and `bgp default ipv6-unicast`
commands work as expected.

STEP 1: 'Check if neighbor 192.168.255.254 is enabled for ipv4 address-family only'
STEP 2: 'Check if neighbor 192.168.255.254 is enabled for ipv6 address-family only'
STEP 3: 'Check if neighbor 192.168.255.254 is enabled for ipv4 and ipv6 address-families'
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo
from lib.common_config import step


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 5):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])
        switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

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


def test_bgp_default_ipv4_ipv6_unicast():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check if neighbor 192.168.255.254 is enabled for ipv4 address-family only")

    def _bgp_neighbor_ipv4_af_only():
        tgen.gears["r1"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp summary json"))

        if "ipv4Unicast" in output and "ipv6Unicast" not in output:
            return True
        return False

    assert _bgp_neighbor_ipv4_af_only() == True

    step("Check if neighbor 192.168.255.254 is enabled for ipv6 address-family only")

    def _bgp_neighbor_ipv6_af_only():
        tgen.gears["r2"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp summary json"))

        if "ipv4Unicast" not in output and "ipv6Unicast" in output:
            return True
        return False

    assert _bgp_neighbor_ipv6_af_only() == True

    step(
        "Check if neighbor 192.168.255.254 is enabled for ipv4 and ipv6 address-families"
    )

    def _bgp_neighbor_ipv4_and_ipv6_af():
        tgen.gears["r3"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r3"].vtysh_cmd("show bgp summary json"))

        if "ipv4Unicast" in output and "ipv6Unicast" in output:
            return True
        return False

    assert _bgp_neighbor_ipv4_and_ipv6_af() == True


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
