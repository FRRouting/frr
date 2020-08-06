#!/usr/bin/env python

#
# test_bgp_show_ip_bgp_fqdn.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
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
test_bgp_show_ip_bgp_fqdn.py:
Test if FQND is visible in `show [ip] bgp` output if
`bgp default show-hostname` is toggled.

Topology:
r1 <-- eBGP --> r2 <-- iBGP --> r3

1. Check if both hostname and ip are added to JSON output
for 172.16.255.254/32 on r2.
2. Check if only ip is added to JSON output for 172.16.255.254/32 on r3.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from mininet.topo import Topo


class TemplateTopo(Topo):
    def build(self, *_args, **_opts):
        tgen = get_topogen(self)

        for routern in range(1, 4):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(TemplateTopo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.iteritems(), 1):
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


def test_bgp_show_ip_bgp_hostname():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.255.254/32 json"))
        expected = {"prefix": "172.16.255.254/32"}
        return topotest.json_cmp(output, expected)

    def _bgp_show_nexthop_hostname_and_ip(router):
        output = json.loads(router.vtysh_cmd("show ip bgp json"))
        for nh in output["routes"]["172.16.255.254/32"][0]["nexthops"]:
            if "hostname" in nh and "ip" in nh:
                return True
        return False

    def _bgp_show_nexthop_ip_only(router):
        output = json.loads(router.vtysh_cmd("show ip bgp json"))
        for nh in output["routes"]["172.16.255.254/32"][0]["nexthops"]:
            if "ip" in nh and not "hostname" in nh:
                return True
        return False

    test_func = functools.partial(_bgp_converge, tgen.gears["r2"])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    test_func = functools.partial(_bgp_converge, tgen.gears["r3"])
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r2"])
    assert _bgp_show_nexthop_hostname_and_ip(tgen.gears["r2"]) == True

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r3"])
    assert _bgp_show_nexthop_ip_only(tgen.gears["r3"]) == True


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
