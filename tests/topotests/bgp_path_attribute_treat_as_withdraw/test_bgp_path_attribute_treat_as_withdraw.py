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
Test if `neighbor path-attribute treat-as-withdraw` command works correctly,
can withdraw unwanted prefixes from BGP table.
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
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    r1.start()

    r2 = tgen.gears["r2"]
    r2.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r2/zebra.conf"))
    r2.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r2/bgpd.conf"))
    r2.start()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_path_attribute_treat_as_withdraw():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "10.10.10.10/32": {
                    "paths": [
                        {
                            "valid": True,
                            "atomicAggregate": True,
                        }
                    ],
                },
                "10.10.10.20/32": {
                    "paths": [
                        {
                            "valid": True,
                        }
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed bgp convergence"

    step("Withdraw prefixes with atomic-aggregate from r1")
    r2.vtysh_cmd(
        """
    configure terminal
        router bgp
            neighbor 10.0.0.1 path-attribute treat-as-withdraw 6
    """
    )

    def _bgp_check_if_route_withdrawn():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast json detail"))
        expected = {
            "routes": {
                "10.10.10.10/32": None,
                "10.10.10.20/32": {
                    "paths": [
                        {
                            "valid": True,
                        }
                    ],
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_if_route_withdrawn)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to withdraw prefixes with atomic-aggregate attribute"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
