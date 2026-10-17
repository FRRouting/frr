#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_rt5_dvni.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Google LLC
#

"""
test_bgp_evpn_rt5_dvni.py: Leak a type-5 route between two VRFs with
different L3VNIs by importing one VRF's route-target into the other, without
a single VXLAN device. Each VNI has its own VXLAN device, the way SONiC builds
them. The leaked route has to be installed with a downstream VNI (D-VNI): on
the importing VRF's L3VNI SVI, and sent to the FPM with the VNI of the VRF
that originated it, which is the VNI the remote VTEP decapsulates into.
"""

import os
import platform
import re
import sys
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.fpm]

# r1 advertises this prefix in vrf-101 as an EVPN type-5 route.
EVPN_PREFIX = "10.0.101.1/32"
# r1's VTEP address, the nexthop of the type-5 route on r2.
REMOTE_VTEP = "192.168.1.1"
L3VNI = 101
# r2's vrf-102 (L3VNI 102) imports vrf-101's route-target.
IMPORTING_VRF = "vrf-102"
IMPORTING_SVI = "bridge-102"
VRF_101_RT = "65000:101"


def build_topo(tgen):
    "Build function"

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    connect_routers(tgen, "rr", "r1")
    connect_routers(tgen, "rr", "r2")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN RT5 NETNS tests will not run (have kernel "{}", but it requires 4.18)'.format(
                krel
            )
        )
        return pytest.skip("Skipping BGP EVPN RT5 NETNS Test. Kernel not supported")

    r1 = tgen.net["r1"]
    for vrf in (101, 102):
        ns = "vrf-{}".format(vrf)
        r1.add_netns(ns)
        r1.cmd_raises(
            """
ip link add loop{0} type dummy
ip link add vxlan-{0} type vxlan id {0} dstport 4789 dev eth-rr local 192.168.1.1
""".format(
                vrf
            )
        )
        r1.set_intf_netns("loop{}".format(vrf), ns, up=True)
        r1.set_intf_netns("vxlan-{}".format(vrf), ns, up=True)
        r1.cmd_raises(
            """
ip -n vrf-{0} link set lo up
ip -n vrf-{0} link add bridge-{0} up address {1} type bridge stp_state 0
ip -n vrf-{0} link set dev vxlan-{0} master bridge-{0}
ip -n vrf-{0} link set bridge-{0} up
ip -n vrf-{0} link set vxlan-{0} up
""".format(
                vrf, _create_rmac(1, vrf)
            )
        )

        tgen.gears["r2"].cmd(
            """
ip link add vrf-{0} type vrf table {0}
ip link set dev vrf-{0} up
ip link add loop{0} type dummy
ip link set dev loop{0} master vrf-{0}
ip link set dev loop{0} up
ip link add bridge-{0} up address {1} type bridge stp_state 0
ip link set bridge-{0} master vrf-{0}
ip link set dev bridge-{0} up
ip link add vxlan-{0} type vxlan id {0} dstport 4789 dev eth-rr local 192.168.2.2
ip link set dev vxlan-{0} master bridge-{0}
ip link set vxlan-{0} up type bridge_slave learning off flood off mcast_flood off
""".format(
                vrf, _create_rmac(2, vrf)
            )
        )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        if rname == "r1":
            router.use_netns_vrf()
            router.load_frr_config()
        elif rname == "r2":
            # r2's zebra sends its routes to an FPM listener, which logs
            # every message it receives.
            router.load_frr_config(
                extra_daemons=[
                    ("zebra", "-M dplane_fpm_nl"),
                    ("fpm_listener", "-o {}".format(_fpm_log_path(router))),
                ]
            )
        else:
            router.load_frr_config()

    # Initialize all routers.
    tgen.start_router()

    # Send the routes with their nexthops inline rather than as nexthop
    # groups, so that each route message carries the nexthop encapsulation.
    tgen.gears["r2"].vtysh_cmd(
        """
configure terminal
 fpm address 127.0.0.1
 no fpm use-next-hop-groups
"""
    )


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("vrf-101")
    tgen.net["r1"].delete_netns("vrf-102")
    tgen.stop_topology()


def _create_rmac(router, vrf):
    """
    Creates RMAC for a given router and vrf
    """
    return "52:54:00:00:{:02x}:{:02x}".format(router, vrf)


def _fpm_log_path(router):
    "Path of the file the FPM listener logs the messages it receives to."
    return os.path.join(router.gearlogdir, "fpm_listener_messages.log")


def _fpm_route_messages(router, prefix):
    """
    Return the route messages the FPM listener received for ``prefix``,
    oldest first. Each one reads "New route <prefix>, ..." or
    "Del route <prefix>, ..." followed by one line per nexthop, which ends
    with ", Encap Type: <type> Vxlan vni <vni>" when the nexthop carries a
    VXLAN encapsulation (see netlink_msg_ctx_snprint() in
    zebra/fpm_listener.c).
    """
    try:
        with open(_fpm_log_path(router), "r") as f:
            log = f.read()
    except FileNotFoundError:
        return []

    return [
        message.strip()
        for message in re.findall(
            r"^\[[^\]]*\] ((?:New|Del) route {}, .*?)(?=^\[|\Z)".format(
                re.escape(prefix)
            ),
            log,
            re.MULTILINE | re.DOTALL,
        )
    ]


def _ifindex(router, ifname):
    "ifindex of ``ifname`` on ``router``."
    return int(router.cmd("cat /sys/class/net/{}/ifindex".format(ifname)).strip())


def _fpm_route_nexthops(router, prefix, ifname):
    """
    Nexthops out of ``ifname`` in the newest FPM route message for
    ``prefix`` that has any, as (gateway, vni) pairs where vni is None for
    a nexthop without a VXLAN encapsulation. Returns None if that message
    is a delete, or if there is no such message. The listener logs no
    table id, so the interface is what tells the VRFs apart.
    """
    nexthop = re.compile(
        r"^ +(\S+) via interface {}(?:, Encap Type: \d+ Vxlan vni (\d+))?$".format(
            _ifindex(router, ifname)
        ),
        re.MULTILINE,
    )
    for message in reversed(_fpm_route_messages(router, prefix)):
        nexthops = [
            (gateway, int(vni) if vni else None)
            for gateway, vni in nexthop.findall(message)
        ]
        if nexthops:
            return nexthops if message.startswith("New route") else None
    return None


def _check_fpm_route_encap(router, prefix, gateway, vni, ifname):
    """
    Check that the newest FPM route message for ``prefix`` with a nexthop
    out of ``ifname`` installs it through ``gateway`` with the VXLAN
    encapsulation of ``vni``, so that a later update that loses the VNI
    fails. Returns None on success, otherwise what the FPM received.
    """
    nexthops = _fpm_route_nexthops(router, prefix, ifname)
    if nexthops != [(gateway, vni)]:
        return "FPM nexthops for {} out of {} are {}, want [({}, {})]".format(
            prefix, ifname, nexthops, gateway, vni
        )
    return None


def _fpm_nexthop_groups(router):
    """
    The newest FPM nexthop group message for each id, as
    id -> (is_install, nexthops text). For a single nexthop the text reads
    "Singleton <gateway> via interface <ifindex>", followed by
    ", Encap Type: <type> Vxlan vni <vni>" when it carries a VXLAN
    encapsulation (see parse_nexthop_msg() in zebra/fpm_listener.c). For a
    group it lists the ids of its members.
    """
    try:
        with open(_fpm_log_path(router), "r") as f:
            log = f.read()
    except FileNotFoundError:
        return {}

    groups = {}
    for op, nhgid, nexthops in re.findall(
        r"^\[[^\]]*\] (New|Del) Nexthop Group ID: (\d+), .*\n +Nexthops: (.*)$",
        log,
        re.MULTILINE,
    ):
        groups[int(nhgid)] = (op == "New", nexthops.strip())
    return groups


def _fpm_nhg_nexthops(groups, nhgid):
    """
    The single nexthops of nexthop group ``nhgid``, following its members,
    as (is_install, nexthop text) pairs.
    """
    installed, nexthops = groups.get(nhgid, (False, ""))
    if not nexthops or nexthops.startswith("Singleton"):
        return [(installed, nexthops)]
    members = []
    for member in re.findall(r"(\d+)(?:\(w:\d+\))?", nexthops):
        member_installed, member_nexthops = groups.get(int(member), (False, ""))
        members.append((installed and member_installed, member_nexthops))
    return members


def _check_fpm_nhg_encap(router, prefix, gateway, vni, ifname):
    """
    With nexthop groups, a route message carries only the id of its
    nexthop group, and the encapsulation travels in the group. Check that
    the newest route message for ``prefix`` whose group is out of
    ``ifname`` is an install, and that the group has a single nexthop,
    through ``gateway`` with the VXLAN encapsulation of ``vni``. Returns
    None on success, otherwise what the FPM received.
    """
    groups = _fpm_nexthop_groups(router)
    via = "Singleton {} via interface {}".format(gateway, _ifindex(router, ifname))
    for message in reversed(_fpm_route_messages(router, prefix)):
        match = re.search(r"nhgid: (\d+)$", message.splitlines()[0])
        if not match:
            continue
        nhgid = int(match.group(1))
        nexthops = _fpm_nhg_nexthops(groups, nhgid)
        if not any(text.startswith(via) for _, text in nexthops):
            continue
        if not message.startswith("New route") or not all(
            installed for installed, _ in nexthops
        ):
            return "{} or its nexthop group {} is not installed: {} / {}".format(
                prefix, nhgid, message, nexthops
            )
        want = r"{}, Encap Type: \d+ Vxlan vni {}".format(re.escape(via), vni)
        if len(nexthops) != 1 or not re.fullmatch(want, nexthops[0][1]):
            return "nexthop group {} of {} is not one nexthop with VNI {}: {}".format(
                nhgid, prefix, vni, nexthops
            )
        return None

    return "no FPM route message for {} with a nexthop group out of {}".format(
        prefix, ifname
    )


def _set_fpm_use_nhg(router, use_nhg):
    "Turn FPM nexthop groups on or off and wait for zebra to reconnect."
    router.vtysh_cmd(
        """
configure terminal
 {}fpm use-next-hop-groups
""".format(
            "" if use_nhg else "no "
        )
    )
    expected = {"connected": True, "useNHG": use_nhg}
    test_func = partial(
        topotest.router_json_cmp, router, "show fpm status json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "FPM useNHG {} did not take effect:\n{}".format(
        use_nhg, result
    )


def test_protocols_convergence():
    """
    Check that r2 installed the type-5 route from r1 in vrf-101 and that its
    zebra is connected to the FPM listener without nexthop groups.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    expected = {
        EVPN_PREFIX: [
            {
                "protocol": "bgp",
                "vrfName": "vrf-101",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": REMOTE_VTEP,
                        "interfaceName": "bridge-101",
                        "active": True,
                        "onLink": True,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-101 {} json".format(EVPN_PREFIX),
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not install the EVPN route {}:\n{}".format(
        EVPN_PREFIX, result
    )

    expected = {"connected": True, "useNHG": False}
    test_func = partial(topotest.router_json_cmp, r2, "show fpm status json", expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 is not connected to the FPM listener:\n{}".format(result)


def test_evpn_route_fpm_encap():
    """
    Baseline: the type-5 route in its own VRF reaches the FPM with that VRF's
    L3VNI, so the listener does see nexthop encapsulations.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = partial(
        _check_fpm_route_encap, r2, EVPN_PREFIX, REMOTE_VTEP, L3VNI, "bridge-101"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_dvni_route_installed():
    """
    Importing vrf-101's route-target into vrf-102 leaks the type-5 route with
    VNI 101 into a VRF whose L3VNI is 102. Without an SVD it must still be
    installed, on vrf-102's L3VNI SVI.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
configure terminal
 router bgp 65000 vrf {}
  address-family l2vpn evpn
   route-target import {}
""".format(
            IMPORTING_VRF, VRF_101_RT
        )
    )

    expected = {
        EVPN_PREFIX: [
            {
                "protocol": "bgp",
                "vrfName": IMPORTING_VRF,
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": REMOTE_VTEP,
                        "interfaceName": IMPORTING_SVI,
                        "active": True,
                        "onLink": True,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf {} {} json".format(IMPORTING_VRF, EVPN_PREFIX),
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not install the D-VNI route {} in {}:\n{}".format(
        EVPN_PREFIX, IMPORTING_VRF, result
    )


def test_dvni_route_fpm_encap():
    """
    The leaked route reaches the FPM out of vrf-102's SVI with the VXLAN
    encapsulation of VNI 101, the originating VRF's L3VNI, not 102.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = partial(
        _check_fpm_route_encap, r2, EVPN_PREFIX, REMOTE_VTEP, L3VNI, IMPORTING_SVI
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_dvni_route_fpm_nhg_encap():
    """
    With FPM nexthop groups, FRR's default, the leaked route's nexthop
    group must carry VNI 101 out of vrf-102's SVI, even though the kernel
    gets the same nexthop without an encapsulation.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    _set_fpm_use_nhg(r2, True)
    test_func = partial(
        _check_fpm_nhg_encap, r2, EVPN_PREFIX, REMOTE_VTEP, L3VNI, IMPORTING_SVI
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    _set_fpm_use_nhg(r2, False)
    assert result is None, result


def test_dvni_route_withdrawn():
    """
    Removing the route-target import withdraws the leaked route from vrf-102
    and leaves it installed in vrf-101.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
configure terminal
 router bgp 65000 vrf {}
  address-family l2vpn evpn
   no route-target import {}
""".format(
            IMPORTING_VRF, VRF_101_RT
        )
    )

    def _route_removed():
        # A route that dplane_fpm_nl sent in its walk after a reconnect, as
        # test_dvni_route_fpm_nhg_encap() makes it do, keeps its route node
        # once it is gone, and zebra shows it with an empty list.
        output = r2.vtysh_cmd(
            "show ip route vrf {} {} json".format(IMPORTING_VRF, EVPN_PREFIX),
            isjson=True,
        )
        return output.get(EVPN_PREFIX) or None

    _, result = topotest.run_and_expect(_route_removed, None, count=30, wait=1)
    assert result is None, "r2 did not remove {} from {}:\n{}".format(
        EVPN_PREFIX, IMPORTING_VRF, result
    )

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-101 {} json".format(EVPN_PREFIX),
        {EVPN_PREFIX: [{"vrfName": "vrf-101", "installed": True}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
    assert result is None, "{} left vrf-101:\n{}".format(EVPN_PREFIX, result)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
