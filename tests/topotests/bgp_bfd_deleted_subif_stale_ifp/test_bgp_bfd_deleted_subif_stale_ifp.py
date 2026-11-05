#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_bfd_deleted_subif_stale_ifp.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#                       Sougata Barik <sougatab@nvidia.com>
#

"""
test_bgp_bfd_deleted_subif_stale_ifp.py:

A BGP neighbor stays configured after its sub-interface is deleted. Its BFD
session must not move to a sub-interface created afterwards.

Topology:

    r1 ----------- r2
          s1

    rX-eth0.100: fd00:bfd::/127   r1 fd00:bfd::0, r2 fd00:bfd::1

1. test_bgp_bfd_convergence: BGP and BFD up to fd00:bfd::1.
2. test_ipv4_address_on_new_subif: delete r1-eth0.100, create r1-eth0.102
   and add 10.254.0.1/30 on it; the session to fd00:bfd::1 stays off
   r1-eth0.102.
3. test_bfd_unset_set: unset and restore BFD on neighbor fd00:bfd::1; the
   session still stays off r1-eth0.102.
4. test_recreate_subif: recreate r1-eth0.100 with its address; BGP and BFD
   come back up on it.
5. test_subif_shut_noshut: shut r1-eth0.100; BGP and BFD go down. Bring it
   back up; both come back up on it.
6. test_bfd_remove_add: remove BFD from the neighbor; the BFD session goes
   away. Add it back; it comes up on r1-eth0.100.
7. test_neighbor_remove_add: remove the neighbor; BGP and BFD go away. Add
   it back; both come back up on r1-eth0.100.
8. test_zebra_shut_noshut: "shutdown" / "no shutdown" r1-eth0.100 in zebra;
   BGP and BFD go down, then come back up on it.
9. test_zebra_configured_subif_delete_create: configure r1-eth0.100 and its
   address in zebra, delete the kernel interface, then recreate it without
   an address; zebra re-applies the address and BGP and BFD come back up
   on it.

Adding an address re-runs the BFD source/interface update for every peer,
and re-applying "neighbor bfd" builds the session again; both read the peer's
nexthop interface, which must not refer to the deleted r1-eth0.100.
"""

import os
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

ADDRS = {
    "r1": {100: "fd00:bfd::/127"},
    "r2": {100: "fd00:bfd::1/127"},
}
PEER = "fd00:bfd::1"
OLD_IF = "r1-eth0.100"
NEW_IF = "r1-eth0.102"


def build_topo(tgen):
    "Build the topology"

    for rname in ("r1", "r2"):
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def _add_subif(router, vid, addr=None):
    ifname = "{}-eth0.{}".format(router.name, vid)
    router.run(
        "ip link add link {}-eth0 name {} type vlan id {}".format(
            router.name, ifname, vid
        )
    )
    if addr:
        router.run("ip -6 addr add {} dev {} nodad".format(addr, ifname))
    router.run("ip link set {} up".format(ifname))


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        for vid, addr in ADDRS[rname].items():
            _add_subif(router, vid, addr)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def _bfd_peer(router, peer):
    for session in router.vtysh_cmd("show bfd peers json", isjson=True):
        if session.get("peer") == peer:
            return session
    return None


def _check_up(router, peers):
    neighbors = router.vtysh_cmd("show bgp neighbors json", isjson=True)
    for peer in peers:
        state = neighbors.get(peer, {}).get("bgpState")
        if state != "Established":
            return "{}: BGP {} is {}".format(router.name, peer, state)
        session = _bfd_peer(router, peer)
        if not session or session.get("status") != "up":
            return "{}: BFD {} is {}".format(router.name, peer, session)
    return None


def _check_not_moved(r1):
    session = _bfd_peer(r1, PEER)
    logger.info("r1 BFD session to %s: %s", PEER, session)
    if not session:
        return "no BFD session to {}".format(PEER)
    if session.get("interface", OLD_IF) != OLD_IF:
        return "BFD session to {} is on {}".format(PEER, session["interface"])
    return None


def _stays_not_moved(r1, seconds=5):
    "The session must stay off other interfaces for the whole window"
    for _ in range(seconds):
        result = _check_not_moved(r1)
        if result:
            return result
        time.sleep(1)
    return _check_not_moved(r1)


def test_bgp_bfd_convergence():
    "BGP and BFD come up to both neighbors"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for BGP and BFD to fd00:bfd::1 and fd00:bfd::3")
    r1 = tgen.gears["r1"]
    _, result = topotest.run_and_expect(
        lambda: _check_up(r1, (PEER,)), None, count=60, wait=1
    )
    assert result is None, result
    logger.info("r1 BFD session to %s: %s", PEER, _bfd_peer(r1, PEER))


def test_ipv4_address_on_new_subif():
    "Delete r1-eth0.100, create r1-eth0.102 and add an IPv4 address on it"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Delete r1-eth0.100 and leave neighbor fd00:bfd::1 configured")
    r1.run("ip link del r1-eth0.100")

    def _peer_down():
        neighbors = r1.vtysh_cmd("show bgp neighbors json", isjson=True)
        if neighbors.get(PEER, {}).get("bgpState") == "Established":
            return "still Established"
        return None

    _, result = topotest.run_and_expect(_peer_down, None, count=30, wait=1)
    assert result is None, result

    step("Create r1-eth0.102 and add 10.254.0.1/30 on it")
    _add_subif(r1, 102)
    r1.run("ip addr add 10.254.0.1/30 dev {}".format(NEW_IF))

    def _address_seen():
        output = r1.vtysh_cmd("show interface {} json".format(NEW_IF), isjson=True)
        addrs = [
            a.get("address") for a in output.get(NEW_IF, {}).get("ipAddresses", [])
        ]
        if "10.254.0.1/30" not in addrs:
            return "10.254.0.1/30 not on {}: {}".format(NEW_IF, addrs)
        return None

    _, result = topotest.run_and_expect(_address_seen, None, count=10, wait=1)
    assert result is None, result

    result = _stays_not_moved(r1)
    assert result is None, result


def test_bfd_unset_set():
    "Unset and restore BFD on neighbor fd00:bfd::1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Unset and restore BFD on neighbor fd00:bfd::1")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          no neighbor fd00:bfd::1 bfd
        """)
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          neighbor fd00:bfd::1 bfd
          neighbor fd00:bfd::1 bfd profile p1
        """)

    result = _stays_not_moved(r1)
    assert result is None, result


def _check_back_on_old_if(tgen):
    r1 = tgen.gears["r1"]
    result = _check_up(r1, (PEER,))
    if result:
        return result
    session = _bfd_peer(r1, PEER)
    if session.get("interface") != OLD_IF:
        return "BFD session to {} is on {}".format(PEER, session.get("interface"))
    return _check_up(tgen.gears["r2"], ("fd00:bfd::",))


def _check_down(r1):
    neighbors = r1.vtysh_cmd("show bgp neighbors json", isjson=True)
    if neighbors.get(PEER, {}).get("bgpState") == "Established":
        return "BGP {} still Established".format(PEER)
    session = _bfd_peer(r1, PEER)
    if session and session.get("status") == "up":
        return "BFD {} still up".format(PEER)
    return None


def _expect_back_on_old_if(tgen):
    _, result = topotest.run_and_expect(
        lambda: _check_back_on_old_if(tgen), None, count=60, wait=1
    )
    assert result is None, result


def test_recreate_subif():
    "Recreate r1-eth0.100; BGP and BFD come back up on it"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Recreate r1-eth0.100 with fd00:bfd::/127")
    _add_subif(r1, 100, ADDRS["r1"][100])

    _expect_back_on_old_if(tgen)
    logger.info("r1 BFD session to %s: %s", PEER, _bfd_peer(r1, PEER))


def test_subif_shut_noshut():
    "Shut and no-shut r1-eth0.100"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Shut r1-eth0.100: BGP and BFD to fd00:bfd::1 go down")
    r1.run("ip link set {} down".format(OLD_IF))

    _, result = topotest.run_and_expect(lambda: _check_down(r1), None, count=30, wait=1)
    assert result is None, result

    step("No-shut r1-eth0.100: BGP and BFD come back up on it")
    r1.run("ip link set {} up".format(OLD_IF))
    _expect_back_on_old_if(tgen)


def test_bfd_remove_add():
    "Remove and re-add BFD on neighbor fd00:bfd::1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove BFD from neighbor fd00:bfd::1: its BFD session goes away")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          no neighbor fd00:bfd::1 bfd
        """)

    def _no_session():
        session = _bfd_peer(r1, PEER)
        if session:
            return "BFD session to {} still present: {}".format(PEER, session)
        return None

    _, result = topotest.run_and_expect(_no_session, None, count=30, wait=1)
    assert result is None, result

    step("Add BFD back: the session comes up on r1-eth0.100")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          neighbor fd00:bfd::1 bfd
          neighbor fd00:bfd::1 bfd profile p1
        """)
    _expect_back_on_old_if(tgen)


def test_neighbor_remove_add():
    "Remove and re-add neighbor fd00:bfd::1"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Remove neighbor fd00:bfd::1: BGP and BFD to it go away")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          no neighbor fd00:bfd::1
        """)

    def _gone():
        neighbors = r1.vtysh_cmd("show bgp neighbors json", isjson=True)
        if PEER in neighbors:
            return "BGP neighbor {} still present".format(PEER)
        session = _bfd_peer(r1, PEER)
        if session:
            return "BFD session to {} still present: {}".format(PEER, session)
        return None

    _, result = topotest.run_and_expect(_gone, None, count=30, wait=1)
    assert result is None, result

    step("Add neighbor fd00:bfd::1 back: BGP and BFD come up on r1-eth0.100")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65001
          neighbor fd00:bfd::1 remote-as 65002
          neighbor fd00:bfd::1 timers 3 9
          neighbor fd00:bfd::1 timers connect 2
          neighbor fd00:bfd::1 bfd
          neighbor fd00:bfd::1 bfd profile p1
          address-family ipv6 unicast
           neighbor fd00:bfd::1 activate
        """)
    _expect_back_on_old_if(tgen)


def test_zebra_shut_noshut():
    "Shut and no-shut r1-eth0.100 through zebra"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("shutdown r1-eth0.100 in zebra: BGP and BFD to fd00:bfd::1 go down")
    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0.100
          shutdown
        """)
    _, result = topotest.run_and_expect(lambda: _check_down(r1), None, count=30, wait=1)
    assert result is None, result

    step("no shutdown r1-eth0.100 in zebra: BGP and BFD come back up on it")
    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0.100
          no shutdown
        """)
    _expect_back_on_old_if(tgen)


def test_zebra_configured_subif_delete_create():
    "Delete and recreate r1-eth0.100 while zebra holds its configuration"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure r1-eth0.100 and fd00:bfd::/127 in zebra")
    r1.vtysh_cmd("""
        configure terminal
         interface r1-eth0.100
          ipv6 address {}
        """.format(ADDRS["r1"][100]))

    step("Delete r1-eth0.100: BGP and BFD go down, the session does not move")
    r1.run("ip link del {}".format(OLD_IF))
    _, result = topotest.run_and_expect(lambda: _check_down(r1), None, count=30, wait=1)
    assert result is None, result
    result = _stays_not_moved(r1)
    assert result is None, result

    step("Recreate r1-eth0.100 without an address: zebra re-applies it")
    _add_subif(r1, 100)

    def _address_back():
        output = r1.vtysh_cmd("show interface {} json".format(OLD_IF), isjson=True)
        addrs = [
            a.get("address") for a in output.get(OLD_IF, {}).get("ipAddresses", [])
        ]
        if ADDRS["r1"][100] not in addrs:
            return "{} not on {}: {}".format(ADDRS["r1"][100], OLD_IF, addrs)
        return None

    _, result = topotest.run_and_expect(_address_back, None, count=30, wait=1)
    assert result is None, result

    step("BGP and BFD come back up on r1-eth0.100")
    _expect_back_on_old_if(tgen)


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
