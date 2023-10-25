#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_flowspec_prefix_list.py
# Part of NetDEF Topology Tests
#
# Copyright 2023 6WIND S.A.
#

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
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    #
    # Define FRR Routers
    #
    for routern in range(2, 4):
        tgen.add_router("r{}".format(routern))

    ## Add eBGP ExaBGP neighbors
    r1 = tgen.add_exabgp_peer("r1", ip="192.168.1.1", defaultRoute="via 192.168.1.2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    peer_dir = os.path.join(CWD, "r1")
    env_file = os.path.join(CWD, "exabgp.env")
    tgen.gears["r1"].start(peer_dir, env_file)
    tgen.gears["r1"].run("ip address add dev lo 192.0.2.1/32")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bgp_prefixes(rname, count):
    tgen = get_topogen()

    if rname == "r2":
        expected = {
            "ipv4Flowspec": {
                "peers": {"192.0.2.1": {"pfxRcd": count, "state": "Established"}},
                "peers": {"192.0.2.3": {"pfxSnt": count, "state": "Established"}},
            },
            "ipv6Flowspec": {
                "peers": {"192.0.2.1": {"pfxRcd": count, "state": "Established"}},
                "peers": {"192.0.2.3": {"pfxSnt": count, "state": "Established"}},
            },
        }
    elif rname == "r3":
        expected = {
            "ipv4Flowspec": {
                "peers": {"192.0.2.2": {"pfxRcd": count, "state": "Established"}},
            },
            "ipv6Flowspec": {
                "peers": {"192.0.2.2": {"pfxRcd": count, "state": "Established"}},
            },
        }
    else:
        assert False, "Wrong router name"

    router = tgen.gears[rname]
    output = router.vtysh_cmd("show bgp summary json")
    json_output = json.loads(output)

    return topotest.json_cmp(json_output, expected)


def test_bgp_flowspec_prefix_list_convergence():
    """
    Test BGP Flowspec convergence with route-map containing prefix-list on r3
    that matches the flowspec destination.

    Two Flowspec prefixes are sent by exabgp by address family: IPv4 and IPv6.
    One prefix contains a source and a destination. On other contain a source
    only.

    Only the Flowspec prefixes containing a source and a destination must be
    accepted on r3.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initial topology - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initial topology - error on r3"


def test_bgp_flowspec_prefix_list_test1():
    """
    Prefix-list whose IP addresses do not match the Flowspec source and
    destination must result in all Flowspec prefixes being filtered on r3.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 3.3.3.0/32
ipv6 prefix-list PLIST_FLOWSPEC_6 seq 5 permit 3::/128
"""
    )

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"


def test_bgp_flowspec_prefix_list_test2():
    """
    Prefix-list whose IP subnets match the Flowspec source and
    destination must result in all Flowspec prefixes being accepted on r3.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 0.0.0.0/0 ge 25
ipv6 prefix-list PLIST_FLOWSPEC_6 seq 5 permit ::/0 ge 64
"""
    )

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"


def test_bgp_flowspec_prefix_list_test3():
    """
    Prefix-list whose IP subnets do not match the Flowspec source and
    destination must result in all Flowspec prefixes being filtered on r3.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 0.0.0.0/0 le 25
ipv6 prefix-list PLIST_FLOWSPEC_6 seq 5 permit ::/0 le 64
"""
    )

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 0)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"


def test_bgp_flowspec_prefix_list_test4():
    """
    Prefix-list whose IP addresses match the Flowspec source but not the
    destination must result in:
    - Flowspec prefixes containing the matching source but not the matching
      destination being FILTERED.
    - Flowspec prefixes containing the matching source and not containing
      destination being ACCEPTED.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
ip prefix-list PLIST_FLOWSPEC_4 seq 5 permit 1.1.1.2/32
ipv6 prefix-list PLIST_FLOWSPEC_6 seq 5 permit 1::2/128
"""
    )

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"


def test_bgp_flowspec_prefix_list_test5():
    """
    Test route-map removal on r3. All flowspec prefixes must be accepted.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r3"].vtysh_cmd(
        """
configure
router bgp 65003
 address-family ipv4 flowspec
  no neighbor 192.0.2.2 route-map RMAP_FLOWSPEC_4 in
 exit-address-family
 address-family ipv6 flowspec
  no neighbor 192.0.2.2 route-map RMAP_FLOWSPEC_6 in
 exit-address-family
"""
    )

    test_func = functools.partial(bgp_prefixes, "r2", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r2"

    test_func = functools.partial(bgp_prefixes, "r3", 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Prefix list update failed - error on r3"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
