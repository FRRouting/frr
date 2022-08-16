#!/usr/bin/env python

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
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
Test if basic BGP community-list filtering works correctly.
"""

import os
import sys
import json
import pytest
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd]


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

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_clist():
    tgen = get_topogen()

    router = tgen.gears["r2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(router.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {"192.168.255.1": {"state": "Established", "pfxRcd": 1}}
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP can't converge"

    def _bgp_clist_match():
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "172.16.255.253/32": [
                    {"valid": True, "community": {"string": "3:1 123:123"}}
                ],
                "172.16.255.254/32": None,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_clist_match)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP community-list filtering doesn't work"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
