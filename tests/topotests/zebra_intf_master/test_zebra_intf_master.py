#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_intf_master.py
#
# Copyright (C) 2026 Aviz Networks
#
# Exercise zebra's interface master dataplane operation
# (DPLANE_OP_INTF_SET_MASTER) through the hidden
# "zebra test interface IFNAME ..." command:
#
# - enslave and release through the dataplane, and synchronously;
# - "down-first": the admin-down travels in the same request as the master
#   change and is applied before it;
# - "release ... up mac X": the interface is brought up and given a MAC
#   address in a second request after the release;
# - a request the kernel refuses is counted as a dataplane error;
# - with a bond (when the kernel has bonding): enslaving an up interface
#   only works with "down-first", and the bond brings it up itself.
#

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = []

MAC1 = "02:00:00:aa:bb:01"


def build_topo(tgen):
    "Single router."
    tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Set up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    # A bridge as master, and veth ends as members.
    r1.run("ip link add br0 type bridge")
    r1.run("ip link set br0 up")
    for a, b in (("m1", "p1"), ("m2", "p2")):
        r1.run("ip link add {} type veth peer name {}".format(a, b))
        r1.run("ip link set {} up".format(b))

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Tear down the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _link(router, ifname):
    out = router.run("ip -j -d link show dev {}".format(ifname))
    try:
        return json.loads(out)[0]
    except (ValueError, IndexError):
        return {}


def _check_link(router, ifname, master=None, up=None, mac=None):
    """Return None when the kernel state matches, else a description."""
    link = _link(router, ifname)
    if not link:
        return "{} not found".format(ifname)
    if master is not None and link.get("master") != (master or None):
        return "{} master is {}, expected {}".format(ifname, link.get("master"), master)
    if up is not None and ("UP" in link.get("flags", [])) != up:
        return "{} flags {}, expected up={}".format(ifname, link.get("flags"), up)
    if mac is not None and link.get("address") != mac:
        return "{} address {}, expected {}".format(ifname, link.get("address"), mac)
    return None


def _expect_link(router, ifname, **kwargs):
    test_func = functools.partial(_check_link, router, ifname, **kwargs)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, result


def _dplane_counters(router):
    out = router.vtysh_cmd("show zebra dplane detailed")
    counters = {}
    for line in out.splitlines():
        if line.startswith("Intf master updates:"):
            counters["in"] = int(line.split(":")[1])
        elif line.startswith("Intf master errors:"):
            counters["errors"] = int(line.split(":")[1])
    return counters


def _wait_zebra_knows(router, *ifnames):
    def _check():
        for ifname in ifnames:
            out = router.vtysh_cmd("show interface {} json".format(ifname))
            if ifname not in json.loads(out):
                return "{} unknown to zebra".format(ifname)
        return None

    _, result = topotest.run_and_expect(_check, None, count=20, wait=0.5)
    assert result is None, result


def test_enslave_and_release_dplane():
    "Enslave and release through the dataplane."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    _wait_zebra_knows(r1, "br0", "m1", "m2")

    step("Enslave m1 to br0")
    r1.vtysh_cmd("zebra test interface m1 master br0")
    _expect_link(r1, "m1", master="br0")

    step("Release m1")
    r1.vtysh_cmd("zebra test interface m1 release")
    _expect_link(r1, "m1", master="")

    # Plain release is a single request, and nothing failed.
    counters = _dplane_counters(r1)
    assert counters == {"in": 2, "errors": 0}, counters


def test_down_first():
    "down-first: the admin-down is applied before the master change."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.run("ip link set m1 up")
    _expect_link(r1, "m1", up=True)

    step("Enslave m1 to br0 with down-first")
    r1.vtysh_cmd("zebra test interface m1 master br0 down-first")
    # A bridge does not open its ports, so m1 stays down.
    _expect_link(r1, "m1", master="br0", up=False)

    r1.vtysh_cmd("zebra test interface m1 release")
    _expect_link(r1, "m1", master="")


def test_release_up_mac():
    "release up mac: the second request sets the interface up and its MAC."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("zebra test interface m1 master br0")
    _expect_link(r1, "m1", master="br0")
    r1.run("ip link set m1 down")
    _expect_link(r1, "m1", up=False)

    step("Release m1, set it up and give it a MAC address")
    r1.vtysh_cmd("zebra test interface m1 release up mac {}".format(MAC1))
    _expect_link(r1, "m1", master="", up=True, mac=MAC1)


def test_sync_variant():
    "The synchronous (shutdown) variant behaves the same."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    before = _dplane_counters(r1)

    step("Enslave m2 synchronously with down-first")
    r1.run("ip link set m2 up")
    r1.vtysh_cmd("zebra test interface m2 master br0 down-first sync")
    _expect_link(r1, "m2", master="br0", up=False)

    step("Release m2 synchronously, set it up")
    r1.vtysh_cmd("zebra test interface m2 release up sync")
    _expect_link(r1, "m2", master="", up=True)

    # The synchronous path does not go through the dataplane.
    assert _dplane_counters(r1) == before


def test_refused_request_counted():
    "A request the kernel refuses is counted as a dataplane error."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    before = _dplane_counters(r1)

    step("Make br0 a member of itself (refused by the kernel)")
    r1.vtysh_cmd("zebra test interface br0 master br0")

    def _check():
        now = _dplane_counters(r1)
        if now.get("in") != before.get("in", 0) + 1:
            return "updates {} -> {}".format(before, now)
        if now.get("errors") != before.get("errors", 0) + 1:
            return "errors {} -> {}".format(before, now)
        return None

    _, result = topotest.run_and_expect(_check, None, count=20, wait=0.5)
    assert result is None, result
    _expect_link(r1, "br0", master="")


def test_bond_down_first():
    "With a bond: an up interface is only enslaved with down-first."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    r1.run("ip link add bond0 type bond mode 802.3ad")
    if not _link(r1, "bond0"):
        pytest.skip("kernel has no bonding support")
    r1.run("ip link set bond0 up")
    _wait_zebra_knows(r1, "bond0")

    r1.run("ip link set m2 up")
    _expect_link(r1, "m2", up=True)

    step("Enslaving an up interface without down-first is refused")
    r1.vtysh_cmd("zebra test interface m2 master bond0")
    _expect_link(r1, "m2", master="")

    step("With down-first the bond enslaves it and brings it up")
    r1.vtysh_cmd("zebra test interface m2 master bond0 down-first")
    _expect_link(r1, "m2", master="bond0", up=True)

    step("Release closes it; up + MAC restore it")
    r1.vtysh_cmd("zebra test interface m2 release up mac {}".format(MAC1))
    _expect_link(r1, "m2", master="", up=True, mac=MAC1)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
