#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_reconnect_route_replay_vrf.py
#
# Copyright (c) 2026 by
# Adriano Cordova <adrianox@gmail.com>
#
# */

#
# """ VRF counterpart of test_zebra_reconnect_route_replay.py:
#
# when zebra restarts while a routing daemon keeps running, the daemon must
# replay its already computed/selected routes to zebra on reconnect. This
# variant exercises every replay-capable daemon inside a tenant VRF:
#
# vr1 originates one distinct prefix into each of OSPF, RIP, IS-IS and BGP
# inside VRF "blue" and advertises them to vr2's VRF-blue instances over a
# shared link:
#
#     [ vr1 ] --- vr1-eth0(blue) --- sw0 --- vr2-eth0(blue) --- [ vr2 ]
#
#     vr1 stubs (vrf blue):  OSPF 198.51.100.0/24, RIP 198.51.101.0/24,
#                            IS-IS 198.51.102.0/24
#     vr1 BGP network (vrf blue): 203.0.113.0/24
#
# After vr2 has installed all four, only zebra is restarted on vr2. The test
# verifies every prefix is reinstalled in vr2's VRF RIB after zebra comes
# back, which only happens if each daemon replays its routes for the VRF
# instance on the zebra reconnect.
# """

import os
import sys
import pytest
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import kill_router_daemons, start_router_daemons

pytestmark = [
    pytest.mark.bgpd,
    pytest.mark.ospfd,
    pytest.mark.ripd,
    pytest.mark.isisd,
]

VRF = "blue"

# prefix -> protocol that should install it on vr2 (in VRF blue)
PREFIXES = {
    "198.51.100.0/24": "ospf",
    "198.51.101.0/24": "rip",
    "198.51.102.0/24": "isis",
    "203.0.113.0/24": "bgp",
}


def build_topo(tgen):
    tgen.add_router("vr1")
    tgen.add_router("vr2")

    # Shared link carrying every protocol adjacency, both sides in VRF blue.
    sw0 = tgen.add_switch("sw0")
    sw0.add_link(tgen.gears["vr1"])
    sw0.add_link(tgen.gears["vr2"])

    # vr1 stub interfaces, one per IGP prefix (vr1-eth1/2/3), also in VRF blue.
    for i in range(1, 4):
        sw = tgen.add_switch("sw{}".format(i))
        sw.add_link(tgen.gears["vr1"])


VRF_L3MDEV_SYSCTL = "/proc/sys/net/ipv4/udp_l3mdev_accept"
_udp_l3mdev_original = None


def setup_module(module):
    global _udp_l3mdev_original

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    logger.info("Testing with Linux VRF support")
    try:
        with open(VRF_L3MDEV_SYSCTL, "r") as f:
            _udp_l3mdev_original = f.read().strip()
        with open(VRF_L3MDEV_SYSCTL, "w") as f:
            f.write("0")
    except OSError as e:
        return pytest.skip("Skipping VRF test. Linux VRF not available on System: {}".format(e))

    # Create the tenant VRF in each router's netns and move the peer interface
    # and vr1's stub interfaces into it, so each daemon runs per-VRF.
    for rname, router in tgen.routers().items():
        router.net.add_l3vrf(VRF, 10)
        router.net.attach_iface_to_l3vrf(rname + "-eth0", VRF)
        if rname == "vr1":
            for i in range(1, 4):
                router.net.attach_iface_to_l3vrf(rname + "-eth{}".format(i), VRF)

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    if _udp_l3mdev_original is not None:
        try:
            with open(VRF_L3MDEV_SYSCTL, "w") as f:
                f.write(_udp_l3mdev_original)
        except OSError:
            pass

    tgen = get_topogen()
    tgen.stop_topology()


def _route_installed(router, prefix, proto):
    """Return None when prefix is installed on router in VRF blue via proto with
    a selected, active nexthop."""
    output = router.vtysh_cmd(
        "show ip route vrf {} {} json".format(VRF, prefix), isjson=True
    )
    if not output or prefix not in output:
        return "{} missing from {} RIB".format(prefix, router.name)
    for entry in output[prefix]:
        if entry.get("protocol") != proto:
            continue
        if not entry.get("selected"):
            continue
        for nh in entry.get("nexthops", []):
            if nh.get("ip") and nh.get("active"):
                return None
    return "{} on {} not installed via {}".format(prefix, router.name, proto)


def _all_routes_installed(router):
    for prefix, proto in PREFIXES.items():
        err = _route_installed(router, prefix, proto)
        if err:
            return err
    return None


def test_converge():
    "All four prefixes must be installed on vr2 in VRF blue via their protocols."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vr2 = tgen.gears["vr2"]
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, vr2), None, count=120, wait=1
    )
    assert result is None, "vr2 did not install all prefixes initially: {}".format(result)
    logger.info("vr2 initial routes:\n{}".format(vr2.vtysh_cmd("show ip route vrf {}".format(VRF))))


def test_zebra_reconnect_replays_routes():
    "After only zebra restarts on vr2, every protocol must replay its VRF routes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    vr2 = tgen.gears["vr2"]

    # Make sure we start from a fully converged state.
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, vr2), None, count=120, wait=1
    )
    assert result is None, "preconditions not met: {}".format(result)

    logger.info("Restarting only zebra on vr2 (protocol daemons keep running)")
    kill_router_daemons(tgen, "vr2", ["zebra"])
    start_router_daemons(tgen, "vr2", ["zebra"])

    # The protocol tables are stable, so each prefix is only reinstalled if the
    # owning daemon replays its routes for the VRF instance on reconnect.
    _, result = topotest.run_and_expect(
        partial(_all_routes_installed, vr2), None, count=120, wait=1
    )
    assert result is None, "vr2 did not get routes replayed after zebra restart: {}".format(
        result
    )
    logger.info("vr2 routes after zebra restart:\n{}".format(vr2.vtysh_cmd("show ip route vrf {}".format(VRF))))


def test_shutdown_check_stderr():
    if os.environ.get("TOPOTESTS_CHECK_STDERR") is None:
        pytest.skip("Skipping test for Stderr output and memory leaks")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for router in tgen.routers().values():
        router.stop()
        for daemon in ["zebra", "ospfd", "ripd", "isisd", "bgpd"]:
            log = tgen.net[router.name].getStdErr(daemon)
            if log:
                logger.error("{} {} StdErr Log:\n{}".format(router.name, daemon, log))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
