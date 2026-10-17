#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_rt5_recursive_nh.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Google LLC
#

"""
test_bgp_evpn_rt5_recursive_nh.py: Check that a route whose gateway resolves
recursively through an EVPN type-5 route is sent to the FPM with the VXLAN
encapsulation of the L3VNI, like the EVPN route itself.

The kernel route is the same whether or not the resolved nexthop keeps its
EVPN attributes, so the check is done on the route messages an FPM listener
receives from r2, with the nexthops inline the way a hardware dataplane
consumes them.
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
EVPN_GATEWAY = "10.0.101.1"
# r1's VTEP address, the nexthop of the type-5 route on r2.
REMOTE_VTEP = "192.168.1.1"
L3VNI = 101
# Static route on r2 whose gateway resolves through the type-5 route.
RECURSIVE_PREFIX = "10.199.1.0/24"


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


def _check_fpm_route_encap(router, prefix, gateway, vni):
    """
    Check that the last FPM message for ``prefix`` installs it through
    ``gateway`` with the VXLAN encapsulation of ``vni``. Returns None on
    success, otherwise what the FPM listener received.
    """
    messages = _fpm_route_messages(router, prefix)
    if not messages:
        return "FPM listener received no message for {}".format(prefix)

    last = messages[-1]
    if not last.startswith("New route"):
        return "last FPM message for {} is not an install: {}".format(prefix, last)

    nexthop = r"^ +{} via interface \d+, Encap Type: \d+ Vxlan vni {}$".format(
        re.escape(gateway), vni
    )
    if not re.search(nexthop, last, re.MULTILINE):
        return "FPM message for {} has no VXLAN nexthop {} for VNI {}: {}".format(
            prefix, gateway, vni, last
        )

    return None


def _check_fpm_route_withdrawn(router, prefix):
    """
    Check that the last FPM message for ``prefix`` withdraws it. Returns None
    on success, otherwise what the FPM listener received.
    """
    messages = _fpm_route_messages(router, prefix)
    if not messages:
        return "FPM listener received no message for {}".format(prefix)

    last = messages[-1]
    if not last.startswith("Del route"):
        return "{} was not withdrawn from the FPM, last message: {}".format(
            prefix, last
        )

    return None


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
    Baseline: the type-5 route reaches the FPM with the VXLAN encapsulation
    of the L3VNI, so the listener does see nexthop encapsulations.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = partial(_check_fpm_route_encap, r2, EVPN_PREFIX, REMOTE_VTEP, L3VNI)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_recursive_route_fpm_encap():
    """
    A static route whose gateway resolves through the type-5 route reaches
    the FPM with the same VXLAN encapsulation as the type-5 route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
configure terminal
 ip route {} {} vrf vrf-101
""".format(
            RECURSIVE_PREFIX, EVPN_GATEWAY
        )
    )

    expected = {
        RECURSIVE_PREFIX: [
            {
                "protocol": "static",
                "vrfName": "vrf-101",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {"ip": EVPN_GATEWAY, "active": True, "recursive": True},
                    {
                        "ip": REMOTE_VTEP,
                        "interfaceName": "bridge-101",
                        "resolver": True,
                        "active": True,
                        "onLink": True,
                    },
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-101 {} json".format(RECURSIVE_PREFIX),
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not install {} recursively through {}:\n{}".format(
        RECURSIVE_PREFIX, EVPN_PREFIX, result
    )

    test_func = partial(
        _check_fpm_route_encap, r2, RECURSIVE_PREFIX, REMOTE_VTEP, L3VNI
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result


def test_recursive_route_fpm_withdraw():
    """
    Removing the static route withdraws it from the FPM.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
configure terminal
 no ip route {} {} vrf vrf-101
""".format(
            RECURSIVE_PREFIX, EVPN_GATEWAY
        )
    )

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip route vrf vrf-101 {} json".format(RECURSIVE_PREFIX),
        {RECURSIVE_PREFIX: None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not remove {}:\n{}".format(RECURSIVE_PREFIX, result)

    test_func = partial(_check_fpm_route_withdrawn, r2, RECURSIVE_PREFIX)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
