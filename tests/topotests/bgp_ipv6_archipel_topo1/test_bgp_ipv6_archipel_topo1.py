#!/usr/bin/env python

#
# test_bgp_ipv6_archipel_topo1.py
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
test_bgp_ipv6_archipel_topo1.py: Test the FRR BGP 6PE feature
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
    +---+    +---+    +---+
    | h1|----|pe1|----| p1|
    +---+    +---+    +---+
               |        |
               |        |
             +---+    +---+    +---+
             | p2|----| p3|----|pe2|
             +---+    +---+    +---+
                                 |
                               +---+
                               | h2|
                               +---+
    """

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

        if "p" in left and "p" in right:
            # PE <-> P or P <-> P
            tgen.gears[left].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(right))
            tgen.gears[right].run("sysctl -w net.mpls.conf.eth-{}.input=1".format(left))

    connect_routers(tgen, "h1", "pe1")
    connect_routers(tgen, "pe1", "p1")
    connect_routers(tgen, "pe1", "p2")
    connect_routers(tgen, "p1", "p3")
    connect_routers(tgen, "p2", "p3")
    connect_routers(tgen, "p3", "pe2")
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

        # PE and P
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

        if "pe" in rname:
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


def test_bgp_ipv6_labeled_unicast():
    "Assert that BGP is exchanging BGP route."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers exchanging UPDATES")

    router_list = ["pe1", "pe2"]

    for name in router_list:
        router = tgen.gears[name]
        ref_file = "{}/{}/bgp_ipv6_labeled_unicast.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show bgp ipv6 unicast json", expected
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
    ref_file = "{}/{}/ipv6_routes.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(topotest.router_json_cmp, pe1, "show ipv6 route json", expected)
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: Zebra Installation failure".format(pe1.name)
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
    test_func2 = functools.partial(_check_ping_launch)
    _, result2 = topotest.run_and_expect(test_func2, True, count=60, wait=1)
    assert result2, "Failed to verify the ping connectivity between IPv6 islands"


def test_bgp_remove_advertised_prefix():
    "Assert that removing a prefix is ok."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("remove a advertised prefix")

    tgen = get_topogen()

    tgen.gears["pe2"].vtysh_cmd(
        """
configure
router bgp 65500
 address-family ipv6 unicast
  no network fd01:200::/64
"""
    )

    pe1 = tgen.gears["pe1"]
    ref_file = "{}/{}/bgp_ipv6_labeled_unicast.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())

    # modify expected to check fd01:200::/64 no more present
    expected["routes"]["fd01:200::/64"] = None

    test_func = partial(
        topotest.router_json_cmp, pe1, "show bgp ipv6 unicast json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: BGP DEL PREFIX failure".format(pe1.name)
    assert res is None, assertmsg


def test_if_remove_ipv6_addr():
    "Assert that removing mapped ipv6 address on pe1 is ok."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("remove ipv6 mapped address on pe1")

    pe1 = tgen.gears["pe1"]

    pe1.vtysh_cmd(
        """
configure
interface eth-p2
 no ipv6 address ::ffff:192.0.2.2/120
"""
    )

    logger.info("Verify that invalid IPv6 routes are not set")

    def _ip_route_not_found_func(pe1, parta, partb):
        out = json.loads(
            pe1.vtysh_cmd("show ipv6 route {}:{}::/64 json".format(parta, partb))
        )
        expected = {}

        return topotest.json_cmp(out, expected, exact=True)

    test_func = partial(_ip_route_not_found_func, pe1, "fd00", "200")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV6 MAPPED REMOVAL failure ".format(pe1.name)
    assert res is None, assertmsg

    test_func = partial(_ip_route_not_found_func, pe1, "fd00", "201")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV6 MAPPED REMOVAL failure".format(pe1.name)
    assert res is None, assertmsg

    test_func = partial(_ip_route_not_found_func, pe1, "fd00", "300")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV6 MAPPED REMOVAL failure".format(pe1.name)
    assert res is None, assertmsg

    test_func = partial(_ip_route_not_found_func, pe1, "fd00", "400")
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV6 MAPPED REMOVAL failure".format(pe1.name)
    assert res is None, assertmsg


def test_if_reset_ipv6_addr():
    "Assert that resetting mapped ipv6 add on pe1 is ok."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("reset ipv6 mapped address on pe1")

    pe1 = tgen.gears["pe1"]

    pe1.vtysh_cmd(
        """
configure
interface eth-p2
 ipv6 address ::ffff:192.0.2.2/120
"""
    )

    ref_file = "{}/{}/ipv6_routes_2.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(topotest.router_json_cmp, pe1, "show ipv6 route json", expected)

    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV6 MAPPED RESET failure".format(pe1.name)
    assert res is None, assertmsg


def test_if_remove_support_ipv4_addr():
    "Assert that removing ipv4 local address implies ipv6 fake route change"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("remove ipv4 local address on pe1")

    pe1 = tgen.gears["pe1"]

    pe1.vtysh_cmd(
        """
configure
interface eth-p2
 no ip address 192.0.2.2/31
"""
    )

    ref_file = "{}/{}/ipv6_routes_fd00400_3.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(
        topotest.router_json_cmp, pe1, "show ipv6 route fd00:400::/64 json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = (
        "{}: use IPv6 route change due to ipv4 support address removal failure".format(
            pe1.name
        )
    )
    assert res is None, assertmsg


def test_if_reset_support_ipv4_addr():
    "Assert that resetting the local ipv4 addr create ipv6 routes to pe2."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("reset ipv4 local address on pe1")

    pe1 = tgen.gears["pe1"]

    pe1.vtysh_cmd(
        """
configure
interface eth-p2
 ip address 192.0.2.2/31
"""
    )

    ref_file = "{}/{}/ipv6_routes_2.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(topotest.router_json_cmp, pe1, "show ipv6 route json", expected)

    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: INTERFACE IPV4 RESET failure".format(pe1.name)
    assert res is None, assertmsg


def test_bgp_change_mpls_label():
    "Assert that changing label configuration on pe2 is ok."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("change mpls label value for pe2")

    pe1 = tgen.gears["pe1"]

    tgen.gears["pe2"].vtysh_cmd(
        """
configure
router isis 1
 segment-routing prefix 198.51.100.5/32 index 66
"""
    )

    pe1 = tgen.gears["pe1"]
    ref_file = "{}/{}/ipv6_routes_fd00400.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(
        topotest.router_json_cmp, pe1, "show ipv6 route fd00:400::/64 json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: BGP CHANGE MPLS LABEL failure".format(pe1.name)
    assert res is None, assertmsg


def test_bgp_use_secondary_path():
    "Turning down p2 interface should make pe1 use p1 uplink"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("use p1 instead of p2 pe1")

    tgen.gears["p2"].vtysh_cmd(
        """
configure
interface eth-pe1
 shutdown
"""
    )

    pe1 = tgen.gears["pe1"]
    ref_file = "{}/{}/ipv6_routes_fd00400_2.json".format(CWD, pe1.name)
    expected = json.loads(open(ref_file).read())
    test_func = partial(
        topotest.router_json_cmp, pe1, "show ipv6 route fd00:400::/64 json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: use p1 instead of p2 pe1 failure".format(pe1.name)
    assert res is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
