#!/usr/bin/env python

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
1. If two paths exist with a different router-id, prefer the older one.
2. If two patsh exist with the same router-id, prefer higher neighbor IP.
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


def test_bgp_routerid_prefer_older():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_prefer_older_path(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.1.1/32 json")
        )
        expected = {
            "paths": [
                {"valid": True, "bestpath": {"selectionReason": "Older Path"}},
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_prefer_older_path, r2)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "The selected path is not an older path"

    r2.vtysh_cmd("conf t\nrouter bgp\nneighbor 192.168.1.1 shutdown")

    def _bgp_prefer_neighbor_ip(router):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv4 unicast 172.16.1.1/32 json")
        )
        expected = {
            "paths": [
                {"valid": True, "bestpath": {"selectionReason": "Neighbor IP"}},
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_prefer_neighbor_ip, r2)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "The selected path is not by neighbor's IP"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
