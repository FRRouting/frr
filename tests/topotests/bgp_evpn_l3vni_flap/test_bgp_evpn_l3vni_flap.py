#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Flap the L3VNI SVI or VxLAN device of r1 (traditional VxLAN device) or r4
(single VxLAN device) faster than bgpd processes the L3VNI delete, then
check that the next hops and router MACs of the remote VTEPs are back in
the kernel. Also check that a VTEP withdrawn while the L3VNI is down does
not come back.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

VTEP = {"r1": "10.0.0.1", "r2": "10.0.0.2", "r3": "10.0.0.3", "r4": "10.0.0.4"}
RMAC = {
    "r1": "44:38:39:ff:00:01",
    "r2": "44:38:39:ff:00:02",
    "r3": "44:38:39:ff:00:03",
    "r4": "44:38:39:ff:00:04",
}
SVI = {"r1": "bridge-101", "r4": "vlan101"}
VXLAN = {"r1": "vxlan-101", "r4": "vxlan0"}


def build_topo(tgen):
    switch = tgen.add_switch("s1")
    for name in VTEP:
        switch.add_link(tgen.add_router(name))


def setup_module(mod):
    if not topotest.platform_has_vrf():
        pytest.skip("platform does not support VRF")
    if not topotest.platform_has_evpn():
        pytest.skip("platform does not support EVPN")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for name, router in tgen.routers().items():
        if name == "r4":
            continue
        router.cmd_raises(f"""
ip link add vrf-101 type vrf table 101
ip link set dev vrf-101 up
ip link add bridge-101 address {RMAC[name]} type bridge stp_state 0
ip link set dev bridge-101 master vrf-101
ip link set dev bridge-101 up
ip link add vxlan-101 type vxlan id 101 dstport 4789 local {VTEP[name]} nolearning
ip link set dev vxlan-101 master bridge-101
ip link set dev vxlan-101 up type bridge_slave learning off flood off mcast_flood off
""")
        router.load_frr_config()

    tgen.gears["r4"].cmd_raises(f"""
ip link add vrf-101 type vrf table 101
ip link set dev vrf-101 up
ip link add br0 type bridge stp_state 0 vlan_filtering 1
ip link set dev br0 up
bridge vlan add vid 101 dev br0 self
ip link add link br0 name vlan101 address {RMAC["r4"]} type vlan id 101
ip link set dev vlan101 master vrf-101
ip link set dev vlan101 up
ip link add vxlan0 type vxlan dstport 4789 local {VTEP["r4"]} nolearning external
ip link set dev vxlan0 master br0
bridge link set dev vxlan0 vlan_tunnel on learning off
bridge vlan add dev vxlan0 vid 101
bridge vlan add dev vxlan0 vid 101 tunnel_info id 101
ip link set dev vxlan0 up
""")
    tgen.gears["r4"].load_frr_config()

    # Keeps the SVIs up while the VxLAN devices are down.
    for name, bridge in (("r1", "bridge-101"), ("r4", "br0")):
        tgen.gears[name].cmd_raises(f"""
ip link add dummy101 type dummy
ip link set dev dummy101 master {bridge}
ip link set dev dummy101 up
""")

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _remote_vteps(router):
    """Per remote VTEP (r2, r3), whether the router's kernel has the next hop
    neighbor on the SVI, the router MAC's VxLAN FDB entry and, on r4, the
    next hop neighbor on the single VxLAN device."""

    def _show(cmd):
        return [line.split() for line in router.run(cmd).splitlines()]

    def _neigh(dev, ip, mac):
        return any(
            t[:3] == [ip, "lladdr", mac] and "extern_learn" in t
            for t in _show(f"ip neigh show dev {dev}")
        )

    fdb = _show(f"bridge fdb show dev {VXLAN[router.name]}")
    state = {}
    for name in ("r2", "r3"):
        ip, mac = VTEP[name], RMAC[name]
        state[name] = (
            _neigh(SVI[router.name], ip, mac),
            any(t[:3] == [mac, "dst", ip] for t in fdb),
        )
        if router.name == "r4":
            state[name] += (_neigh(VXLAN[router.name], ip, mac),)
    return state


def _check_remote_vteps(router, r2_present, r3_present):
    n = 3 if router.name == "r4" else 2
    expected = {"r2": (r2_present,) * n, "r3": (r3_present,) * n}
    _, state = topotest.run_and_expect(
        partial(_remote_vteps, router), expected, count=60, wait=1
    )
    assert state == expected, f"{router.name} kernel state per VTEP: {state}"


def _flap(name, dev):
    router = get_topogen().gears[name]
    _check_remote_vteps(router, True, True)
    router.cmd_raises(f"ip link set dev {dev} down && ip link set dev {dev} up")
    _check_remote_vteps(router, True, True)


def test_l3vni_vxlan_flap():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _flap("r1", VXLAN["r1"])


def test_l3vni_svd_svi_flap():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _flap("r4", SVI["r4"])


def test_l3vni_svd_vxlan_flap():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    _flap("r4", VXLAN["r4"])


def test_l3vni_down_remote_withdrawn():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    routers = [tgen.gears[name] for name in SVI]
    for router in routers:
        _check_remote_vteps(router, True, True)

    for router in routers:
        router.cmd_raises(f"ip link set dev {SVI[router.name]} down")
    tgen.gears["r3"].vtysh_cmd("""
configure terminal
router bgp 65000 vrf vrf-101
 address-family ipv4 unicast
  no network 10.0.101.3/32
""")
    for router in routers:
        _, present = topotest.run_and_expect(
            lambda: "10.0.101.3"
            in router.vtysh_cmd("show bgp l2vpn evpn route type prefix"),
            False,
            count=30,
            wait=1,
        )
        assert not present, f"{router.name} still has r3's type-5 route"

    for router in routers:
        router.cmd_raises(f"ip link set dev {SVI[router.name]} up")
    for router in routers:
        _check_remote_vteps(router, True, False)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
