#!/usr/bin/env python

#
# bgp_ebgp_requires_policy.py
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
bgp_ebgp_requires_policy.py:

Test if eBGP sender without a filter applied to the peer is allowed
to send advertisements.

Scenario 1:
  r1 has a filter applied for outgoing direction,
  r2 receives 192.168.255.1/32.
Scenario 2:
  r3 hasn't a filter appied for outgoing direction,
  r4 does not receive 192.168.255.1/32.
Scenario 3:
  r5 and r6 establish iBGP session which in turn should ignore
  RFC8212. All routes for both directions MUST work.
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

        for routern in range(1, 7):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r3"])
        switch.add_link(tgen.gears["r4"])

        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r5"])
        switch.add_link(tgen.gears["r6"])


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


def test_ebgp_requires_policy():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge(router):
        output = json.loads(
            tgen.gears[router].vtysh_cmd("show ip bgp neighbor 192.168.255.1 json")
        )
        expected = {"192.168.255.1": {"bgpState": "Established"}}
        return topotest.json_cmp(output, expected)

    def _bgp_has_routes(router):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show ip bgp neighbor 192.168.255.1 routes json"
            )
        )
        expected = {"routes": {"172.16.255.254/32": [{"valid": True}]}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, "r2")
    success, result = topotest.run_and_expect(test_func, None, count=65, wait=2)
    assert success is True, 'Failed bgp convergence (r2) in "{}"'.format(tgen.gears["r2"])

    test_func = functools.partial(_bgp_has_routes, "r2")
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert success is True, 'eBGP policy is not working (r2) in "{}"'.format(tgen.gears["r2"])

    test_func = functools.partial(_bgp_converge, "r4")
    success, result = topotest.run_and_expect(test_func, None, count=65, wait=2)
    assert success is True, 'Failed bgp convergence (r4) in "{}"'.format(tgen.gears["r4"])

    test_func = functools.partial(_bgp_has_routes, "r4")
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert success is False, 'eBGP policy is not working (r4) in "{}"'.format(tgen.gears["r4"])

    test_func = functools.partial(_bgp_converge, "r6")
    success, result = topotest.run_and_expect(test_func, None, count=65, wait=2)
    assert success is True, 'Failed bgp convergence (r6) in "{}"'.format(tgen.gears["r6"])

    test_func = functools.partial(_bgp_has_routes, "r6")
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert success is True, 'eBGP policy is not working (r6) in "{}"'.format(tgen.gears["r6"])


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
