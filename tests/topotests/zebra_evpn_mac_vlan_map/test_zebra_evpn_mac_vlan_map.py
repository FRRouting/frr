#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_evpn_mac_vlan_map.py
#
# Copyright (c) 2026 by the FRRouting project
#
"""
A locally learned MAC must only be attributed to an EVPN when its (port, VLAN)
actually maps to a VNI.

zebra_evpn_map_vlan() looks the VLAN up in the VLAN-VNI map of a VLAN-aware
bridge. On a miss it falls through to zebra_evpn_map_vlan_ns(), a walk that
matches on "is a VXLAN interface, is operative, same bridge" and ignores the
VLAN. Every MAC on every VLAN of that bridge is therefore attributed to
whichever VNI the bridge's VXLAN interface carries -- and with
`advertise-all-vni` it is advertised as an EVPN type-2 route.

Topology:

    r2 --- r1-eth0 --+                bridge (VLAN-aware)
                     |                  +-- vxlan5000  VNI 5000, VLAN 3745
    r3 --- r1-eth1 --+                  +-- r1-eth0    VLAN 3745  (mapped)
                                        +-- r1-eth1    VLAN 12    (NOT mapped)

r2's MAC must appear in VNI 5000; r3's MAC must not.
"""

import os
import re
import sys
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    tgen.start_router()
    tgen.gears["r1"].run(f"/bin/bash {CWD}/r1/setup.sh")

    # r2 sits on the mapped VLAN, r3 on the unmapped one.
    tgen.gears["r2"].run("ip addr add 10.37.0.2/24 dev r2-eth0")
    tgen.gears["r3"].run("ip addr add 10.12.0.2/24 dev r3-eth0")

    # Traffic so the bridge learns a MAC on each VLAN.
    tgen.gears["r2"].run("ping -c 3 -W 1 10.37.0.1")
    tgen.gears["r3"].run("ping -c 3 -W 1 10.12.0.1")


def teardown_module(mod):
    get_topogen().stop_topology()


def _mac_of(tgen, rname):
    out = tgen.gears[rname].run(f"cat /sys/class/net/{rname}-eth0/address")
    return out.strip().lower()


def _macs_in_vni(r1, vni=5000):
    out = r1.vtysh_cmd(f"show evpn mac vni {vni} json", isjson=True)
    return {m.lower() for m in out.get("macs", {}).keys()}


def test_mac_on_mapped_vlan_is_in_vni():
    """Positive control: a MAC on VLAN 3745 must be learned into VNI 5000."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2_mac = _mac_of(tgen, "r2")

    def _check():
        macs = _macs_in_vni(r1)
        if r2_mac in macs:
            return None
        return f"{r2_mac} not in VNI 5000 (have: {sorted(macs)})"

    _, result = topotest.run_and_expect(functools.partial(_check), None, count=30, wait=2)
    assert result is None, f"MAC on mapped VLAN 3745 was not learned into VNI 5000: {result}"


def test_mac_on_unmapped_vlan_is_not_in_vni():
    """A MAC on VLAN 12, which maps to no VNI, must not be attributed to VNI 5000."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r3_mac = _mac_of(tgen, "r3")

    # The kernel must actually have learned it, or this test proves nothing.
    # Match the MAC and the VLAN within a SINGLE fdb record: searching the whole
    # multiline output independently would let two unrelated entries satisfy the
    # two checks, and the negative assertion below would then pass without the
    # r3 MAC ever having been learned on the unmapped VLAN.
    fdb = r1.run("bridge fdb show br bridge")
    learned_on_vlan12 = any(
        r3_mac in line.lower() and re.search(r"\bvlan\s+12\b", line.lower())
        for line in fdb.splitlines()
    )
    assert learned_on_vlan12, (
        f"precondition failed: no single fdb entry has {r3_mac} on vlan 12; "
        f"fdb:\n{fdb}"
    )

    macs = _macs_in_vni(r1)
    assert r3_mac not in macs, (
        f"MAC {r3_mac} learned on VLAN 12 (which has no VNI mapping) was "
        f"attributed to VNI 5000; macs in VNI 5000: {sorted(macs)}"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
