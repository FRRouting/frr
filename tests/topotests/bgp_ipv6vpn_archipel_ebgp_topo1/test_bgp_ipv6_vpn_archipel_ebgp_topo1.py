#!/usr/bin/env python

#
# test_bgp_ipv6_vpn_archipel_ebgp_topo1.py
#
# Copyright 2023 6WIND S.A.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND 6WIND DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL 6WIND BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_ipv6_vpn_archipel_topo1.py: Test the FRR BGP 6VPE functionality
"""

import os
import sys
import json
import functools
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    """
    +---+    +---+    +---+    +---+
    | h1|----|pe1|----|pe2|----| h2|
    +---+    +---+    +---+    +---+
    """

    def connect_routers(tgen, left, right):
        pe = None
        host = None
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)
            if "pe" in rname:
                pe = tgen.gears[rname]
            if "h" in rname:
                host = tgen.gears[rname]

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

        if pe and host:
            pe.cmd("ip link add vrf1 type vrf table 10")
            pe.cmd("ip link set vrf1 up")
            pe.cmd("ip link set dev eth-{} master vrf1".format(host.name))

        if "p" in left and "p" in right:
            # PE <-> P or P <-> P
            tgen.gears[left].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(right))
            tgen.gears[right].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(left))

    connect_routers(tgen, "h1", "pe1")
    connect_routers(tgen, "pe1", "pe2")
    connect_routers(tgen, "pe2", "h2")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    logger.info("setup_module")

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if "h" in rname:
            # hosts
            continue

        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Assert that BGP is converging."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers to go up")

    router_list = ["pe1", "pe2"]

    for name in router_list:
        router = tgen.gears[name]
        ref_file = "{}/{}/bgp_summary.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show bgp summary json", expected
        )
        _, res = topotest.run_and_expect(test_func, None, count=90, wait=1)
        assertmsg = "{}: bgp did not converge".format(router.name)
        assert res is None, assertmsg


def test_bgp_ipv6_vpn():
    "Assert that BGP is exchanging BGP route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers exchanging UPDATES")

    router_list = ["pe1", "pe2"]

    for name in router_list:
        router = tgen.gears[name]
        ref_file = "{}/{}/bgp_vrf_ipv6.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp vrf vrf1 ipv6 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP UPDATE exchange failure".format(router.name)
        assert res is None, assertmsg


def test_zebra_ipv6_installed():
    "Assert that routes are installed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    pe1 = tgen.gears["pe1"]
    logger.info("check ipv6 routes installed on pe1")

    ref_file = "{}/{}/ipv6_routes_vrf.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(
        topotest.router_json_cmp, pe1, "show ipv6 route vrf vrf1 json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: Zebra Installation failure on vrf vrf1".format(pe1.name)
    assert res is None, assertmsg


def test_bgp_ping6_ok():
    "Assert that routes are installed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _check_ping_launch():
        h1 = tgen.gears["h1"]

        ping_launch = "ping6 fd00:200::6 -I fd00:100::1 -c 1"
        selected_lines = h1.run(ping_launch).splitlines()[-2:-1]
        rtx_stats = "".join(selected_lines[0].split(",")[0:3])
        current = topotest.normalize_text(rtx_stats)

        expected_stats = "1 packets transmitted 1 received 0% packet loss"
        expected = topotest.normalize_text(expected_stats)

        return current == expected

    logger.info("check ping ipv6 between IPv6 islands")
    test_func = functools.partial(_check_ping_launch)
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert res, "Failed to verify the ping connectivity between IPv6 islands"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
