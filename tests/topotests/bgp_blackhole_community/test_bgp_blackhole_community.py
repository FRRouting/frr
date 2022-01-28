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
Test if 172.16.255.254/32 tagged with BLACKHOLE community is not
re-advertised downstream outside local AS.
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
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
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
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_blackhole_community():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd("show ip bgp 172.16.255.254/32 json")
        )
        expected = {"paths": [{"community": {"list": ["blackhole", "noExport"]}}]}
        return topotest.json_cmp(output, expected)

    def _bgp_no_advertise_ebgp():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd(
                "show ip bgp neighbor r2-eth1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {},
            "totalPrefixCounter": 0,
            "filteredPrefixCounter": 0,
        }

        return topotest.json_cmp(output, expected)

    def _bgp_no_advertise_ibgp():
        output = json.loads(
            tgen.gears["r2"].vtysh_cmd(
                "show ip bgp neighbor r2-eth2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {"172.16.255.254/32": {}},
            "totalPrefixCounter": 2,
        }

        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(tgen.gears["r2"])

    step("Check if 172.16.255.254/32 is not advertised to eBGP peers")

    test_func = functools.partial(_bgp_no_advertise_ebgp)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert (
        result is None
    ), 'Advertised blackhole tagged prefix to eBGP peers in "{}"'.format(
        tgen.gears["r2"]
    )

    step("Check if 172.16.255.254/32 is advertised to iBGP peers")

    test_func = functools.partial(_bgp_no_advertise_ibgp)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert (
        result is None
    ), 'Withdrawn blackhole tagged prefix to iBGP peers in "{}"'.format(
        tgen.gears["r2"]
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
