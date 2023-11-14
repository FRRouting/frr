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
Check if labeled-unicast works correctly with addpath capability.
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
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
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

    def _bgp_check_advertised_routes():
        output = json.loads(
            r3.vtysh_cmd(
                "show bgp ipv4 labeled-unicast neighbors 192.168.34.4 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.0.0.1/32": {
                    "appliedStatusSymbols": {
                        "*": True,
                        ">": True,
                        "=": True,
                    }
                }
            },
            "totalPrefixCounter": 2,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_advertised_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "Failed to advertise labeled-unicast with addpath (multipath)"

    def _bgp_check_received_routes():
        output = json.loads(r4.vtysh_cmd("show bgp ipv4 labeled-unicast json"))
        expected = {
            "routes": {
                "10.0.0.1/32": [
                    {
                        "valid": True,
                        "path": "65003 65001",
                    },
                    {
                        "valid": True,
                        "path": "65003 65002",
                    },
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_received_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to receive labeled-unicast with addpath (multipath)"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
