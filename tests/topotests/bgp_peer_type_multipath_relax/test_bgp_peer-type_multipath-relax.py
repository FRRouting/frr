#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 Arista Networks, Inc.
#

"""
test_bgp_peer-type_multipath-relax.py:

Test the effects of the "bgp bestpath peer-type multipath-relax" command

- enabling the command allows eBGP, iBGP, and confed routes to be multipath
- the choice of best path is not affected
- disabling the command removes iBGP/confed routes from multipath
- enabling the command does not forgive eBGP routes of the requirement
  (when enabled) that next hops resolve over connected routes
- a mixed-type multipath next hop, when published to zebra, does not
  require resolving next hops over connected routes
- with the command enabled, an all-eBGP multipath next hop still requires
  resolving next hops over connected routes when published to zebra

Topology used by the test:

                 eBGP  +------+  iBGP
          peer1  ----  |  r1  |  ----  peer3
                       |      |
peer2  ----  r2  ----  |      |  ----  peer4
       iBGP     confed +------+  eBGP

r2 is present in this topology because ExaBGP does not currently support
confederations so we use FRR to advertise the required AS_CONFED_SEQUENCE.

Routes are advertised from different peers to form interesting multipaths.

                 peer1    peer2    peer3    peer4     multipath on r1

203.0.113.0/30   x        x                 x         all 3
203.0.113.4/30   x        x                           confed-iBGP
203.0.113.8/30                     x        x         eBGP-only

There is also a BGP-advertised route used only for recursively resolving
next hops.
"""

import functools
import json
import os
import pytest
import sys

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Prefixes used in the test
prefix1 = "203.0.113.0/30"
prefix2 = "203.0.113.4/30"
prefix3 = "203.0.113.8/30"
# Next hops used for iBGP/confed routes
resolved_nh1 = "198.51.100.1"
resolved_nh2 = "198.51.100.2"
# BGP route used for recursive resolution
bgp_resolving_prefix = "198.51.100.0/24"
# Next hop that will require non-connected recursive resolution
ebgp_resolved_nh = "198.51.100.10"


def build_topo(tgen):
    "Build function"

    # Set up routers
    tgen.add_router("r1")  # DUT
    tgen.add_router("r2")

    # Set up peers
    for peern in range(1, 5):
        peer = tgen.add_exabgp_peer(
            "peer{}".format(peern),
            ip="10.0.{}.2/24".format(peern),
            defaultRoute="via 10.0.{}.1".format(peern),
        )
        if peern == 2:
            tgen.add_link(tgen.gears["r2"], peer)
        else:
            tgen.add_link(tgen.gears["r1"], peer)
    tgen.add_link(tgen.gears["r1"], tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra configuration file
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    # Start up exabgp peers
    peers = tgen.exabgp_peers()
    for peer in peers:
        fifo_in = "/var/run/exabgp_{}.in".format(peer)
        if os.path.exists(fifo_in):
            os.remove(fifo_in)
        os.mkfifo(fifo_in, 0o777)
        logger.info("Starting ExaBGP on peer {}".format(peer))
        peer_dir = os.path.join(CWD, peer)
        env_file = os.path.join(CWD, "exabgp.env")
        peers[peer].start(peer_dir, env_file)


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def exabgp_cmd(peer, cmd):
    pipe = open("/run/exabgp_{}.in".format(peer), "w")
    with pipe:
        pipe.write(cmd)
        pipe.close()


def test_bgp_peer_type_multipath_relax_test1():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Send a non-connected route to resolve others
    exabgp_cmd(
        "peer3", "announce route {} next-hop self\n".format(bgp_resolving_prefix)
    )

    # It seems that if you write to the exabgp socket too quickly in
    #  succession, requests get lost. So verify prefix1 now instead of
    # after all the prefixes are advertised.
    logger.info("Create and verify mixed-type multipaths")
    exabgp_cmd(
        "peer1",
        "announce route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix1, resolved_nh1
        ),
    )
    exabgp_cmd(
        "peer2",
        "announce route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix1, resolved_nh2
        ),
    )
    exabgp_cmd("peer4", "announce route {} next-hop self\n".format(prefix1))
    reffile = os.path.join(CWD, "r1/prefix1.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip bgp {} json".format(prefix1),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Mixed-type multipath not found"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test2():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Create and verify eBGP and iBGP+confed multipaths")
    exabgp_cmd(
        "peer1",
        "announce route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix2, resolved_nh1
        ),
    )
    exabgp_cmd(
        "peer2",
        "announce route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix2, resolved_nh2
        ),
    )
    exabgp_cmd("peer3", "announce route {} next-hop self".format(prefix3))
    exabgp_cmd("peer4", "announce route {} next-hop self".format(prefix3))
    reffile = os.path.join(CWD, "r1/multipath.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Not all expected multipaths found"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test3():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Toggle peer-type multipath-relax and verify the changes")
    r1.vtysh_cmd(
        "conf\n router bgp 64510\n no bgp bestpath peer-type multipath-relax\n"
    )
    # This file verifies "multipath" is not set
    reffile = os.path.join(CWD, "r1/not-multipath.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Disabling peer-type multipath-relax did not take effect"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test4():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("conf\n router bgp 64510\n bgp bestpath peer-type multipath-relax\n")
    reffile = os.path.join(CWD, "r1/multipath.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip bgp json", expected
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Reenabling peer-type multipath-relax did not take effect"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test5():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Check recursive resolution of eBGP next hops is not affected")
    # eBGP next hop resolution rejects recursively resolved next hops by
    # default, even with peer-type multipath-relax
    exabgp_cmd(
        "peer4", "announce route {} next-hop {}\n".format(prefix3, ebgp_resolved_nh)
    )
    reffile = os.path.join(CWD, "r1/prefix3-no-recursive.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip bgp {} json".format(prefix3),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Recursive eBGP next hop not as expected for {}".format(prefix3)
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test6():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    exabgp_cmd(
        "peer4", "announce route {} next-hop {}\n".format(prefix1, ebgp_resolved_nh)
    )
    reffile = os.path.join(CWD, "r1/prefix1-no-recursive.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip bgp {} json".format(prefix1),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Recursive eBGP next hop not as expected for {}".format(prefix1)
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test7():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # When other config allows recursively resolved eBGP next hops,
    # such next hops in all-eBGP multipaths should be valid
    r1.vtysh_cmd("conf\n router bgp 64510\n neighbor 10.0.4.2 ebgp-multihop\n")
    reffile = os.path.join(CWD, "r1/prefix3-recursive.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip bgp {} json".format(prefix3),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Recursive eBGP next hop not as expected for {}".format(prefix3)
    assert res is None, assertMsg

    reffile = os.path.join(CWD, "r1/prefix1-recursive.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip bgp {} json".format(prefix1),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "Recursive eBGP next hop not as expected for {}".format(prefix1)
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test8():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Check mixed-type multipath next hop recursive resolution in FIB")
    # There are now two eBGP-learned routes with a recursively resolved next;
    # hop; one is all-eBGP multipath, and the other is iBGP/eBGP/
    # confed-external. The peer-type multipath-relax feature only enables
    # recursive resolution in FIB if any next hop is iBGP/confed-learned. The
    # all-eBGP multipath will have only one valid next hop in the FIB.
    reffile = os.path.join(CWD, "r1/prefix3-ip-route.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route {} json".format(prefix3),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "FIB next hops mismatch for all-eBGP multipath"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test9():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # check confed-external enables recursively resolved next hops by itself
    exabgp_cmd(
        "peer1",
        "withdraw route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix1, resolved_nh1
        ),
    )
    reffile = os.path.join(CWD, "r1/prefix1-eBGP-confed.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route {} json".format(prefix1),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "FIB next hops mismatch for eBGP+confed-external multipath"
    assert res is None, assertMsg


def test_bgp_peer_type_multipath_relax_test10():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # check iBGP by itself
    exabgp_cmd(
        "peer1",
        "announce route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix1, resolved_nh1
        ),
    )
    exabgp_cmd(
        "peer2",
        "withdraw route {} next-hop {} as-path [ 64499 ]\n".format(
            prefix1, resolved_nh2
        ),
    )
    reffile = os.path.join(CWD, "r1/prefix1-eBGP-iBGP.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route {} json".format(prefix1),
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assertMsg = "FIB next hops mismatch for eBGP+iBGP multipath"
    assert res is None, assertMsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
