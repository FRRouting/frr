#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test EVPN RT2 and RT5 when the VXLAN interface has implicit local
address, meaning the command to create the interface
"ip link add <ifname> type vxlan id <vni> dstport 4789 dev <output-iface>"
has no "local <ip>" to force the source address of the VXLAN traffic.

The test checks:
 - Nexthops for RT2 and RT5 prefixes
 - Nexthops for import of RT5 prefixes into the RIB
 - The RMAC remote VTEP IP address
"""

from functools import partial
import os
import platform
import sys


import pytest

CWD = os.path.dirname(os.path.realpath(__file__))

# pylint: disable=C0413
from lib import topotest
from lib.topolog import logger
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def build_topo(tgen):
    "Build function"

    def connect_routers(tgen, left, right):
        switch = tgen.add_switch(
            "s-{}-{}".format(left.replace("vtep", "vt"), right.replace("vtep", "vt"))
        )
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    tgen.add_router("h1")
    tgen.add_router("h3")
    tgen.add_router("h5")

    tgen.add_router("vtep1")
    tgen.add_router("vtep2")

    tgen.add_router("h2")
    tgen.add_router("h4")
    tgen.add_router("h6")

    connect_routers(tgen, "vtep1", "vtep2")

    connect_routers(tgen, "h1", "vtep1")
    connect_routers(tgen, "h3", "vtep1")
    connect_routers(tgen, "h5", "vtep1")

    connect_routers(tgen, "h2", "vtep2")
    connect_routers(tgen, "h4", "vtep2")
    connect_routers(tgen, "h6", "vtep2")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(f'Skipping EVPN VTEP test, kernel "{krel}" is too old')

    for i in range(1, 7):
        vtep = "vtep1" if i % 2 == 1 else "vtep2"
        tgen.gears[f"h{i}"].cmd(
            f"""
        ip link set dev eth-{vtep} down
        ip link set dev eth-{vtep} address de:ed:01:0{i}:00:0{i}
        ip link set dev eth-{vtep} up
        """
        )

    for rname in ("vtep1", "vtep2"):
        remote = "vtep2" if rname == "vtep1" else "vtep1"
        i = rname.replace("vtep", "")
        local_param = f"local 10.125.0.{i}" if "explicit" in mod.__name__ else ""
        tgen.gears[rname].cmd(
            f"""
ip link add overlay type vrf table 10
ip link set overlay up

ip link add br100 type bridge
ip link set br100 master overlay up

ip link add br101 type bridge
ip link set br101 master overlay up

ip link add br300 type bridge
ip link set br300 master overlay up

ip link add vxlan100 type vxlan id 100 {local_param} dstport 4789 dev eth-{remote} nolearning
ip link set vxlan100 master br100 up
ip link set vxlan100 type bridge_slave neigh_suppress on

ip link add vxlan101 type vxlan id 101 {local_param} dstport 4789 dev eth-{remote} nolearning
ip link set vxlan101 master br101 up
ip link set vxlan101 type bridge_slave neigh_suppress on

ip link add vxlan300 type vxlan id 300 {local_param} dstport 4789 dev eth-{remote} nolearning
ip link set vxlan300 address f2:6f:90:d3:65:0{i} master br300 up
"""
        )

    tgen.gears["vtep1"].cmd(
        f"""
ip link set eth-h1 master br100 up
ip link set eth-h3 master br101 up
ip link set eth-h5 master overlay up
"""
    )

    tgen.gears["vtep2"].cmd(
        f"""
ip link set eth-h2 master br100 up
ip link set eth-h4 master br101 up
ip link set eth-h6 master overlay up
"""
    )

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged
    statuses as they depend on it.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info(
            "Checking BGP L2VPN EVPN routes for convergence on {}".format(router.name)
        )
        peer = "10.125.0.2" if rname == "vtep1" else "10.125.0.1"
        expected = {
            "l2VpnEvpn": {
                "peers": {
                    peer: {
                        "state": "Established",
                    }
                },
                "failedPeers": 0,
                "totalPeers": 1,
            }
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp summary json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_rmac_vni_all():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info("Checking evpn rmac vni on {}".format(router.name))

        rmac = "f2:6f:90:d3:65:02" if rname == "vtep1" else "f2:6f:90:d3:65:01"
        vtep = "10.125.0.2" if rname == "vtep1" else "10.125.0.1"
        expected = {
            "300": {
                "numRmacs": 1,
                rmac: {
                    "routerMac": rmac,
                    "vtepIp": vtep,
                },
            }
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show evpn rmac vni all json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_bgp_evpn_rt5_nexthop():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info("Checking BGP EVPN RT5 Nexthops on {}".format(router.name))

        addr4 = "192.168.3.0" if rname == "vtep1" else "192.168.2.0"
        addr6 = "2001:db8:3::" if rname == "vtep1" else "2001:db8:2::"
        peer = "10.125.0.2" if rname == "vtep1" else "10.125.0.1"
        expected = {
            f"{peer}:300": {
                f"[5]:[0]:[24]:[{addr4}]": {
                    "paths": [
                        {
                            "valid": True,
                            "nexthops": [{"ip": peer, "afi": "ipv4", "used": True}],
                        }
                    ],
                    "pathCount": 1,
                },
                f"[5]:[0]:[64]:[{addr6}]": {
                    "paths": [
                        {
                            "valid": True,
                            "nexthops": [{"ip": peer, "afi": "ipv4", "used": True}],
                        }
                    ],
                    "pathCount": 1,
                },
            },
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            f"show bgp l2vpn evpn rd {peer}:300 json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_ip_route_vrf_overlay():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info("Checking VRF overlay IPv4 RIB on {}".format(router.name))

        pfx = "192.168.3.0/24" if rname == "vtep1" else "192.168.2.0/24"
        nh = "10.125.0.2" if rname == "vtep1" else "10.125.0.1"
        expected = {
            pfx: [
                {
                    "selected": True,
                    "nexthops": [
                        {
                            "fib": True,
                            "ip": nh,
                            "afi": "ipv4",
                            "interfaceName": "br300",
                            "active": True,
                            "onLink": True,
                        }
                    ],
                }
            ]
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ip route vrf overlay bgp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_ipv6_route_vrf_overlay():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info("Checking VRF overlay IPv6 RIB on {}".format(router.name))

        pfx = "2001:db8:3::/64" if rname == "vtep1" else "2001:db8:2::/64"
        nh = "::ffff:10.125.0.2" if rname == "vtep1" else "::ffff:10.125.0.1"
        expected = {
            pfx: [
                {
                    "selected": True,
                    "nexthops": [
                        {
                            "fib": True,
                            "ip": nh,
                            "afi": "ipv6",
                            "interfaceName": "br300",
                            "active": True,
                            "onLink": True,
                        }
                    ],
                }
            ]
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show ipv6 route vrf overlay bgp json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_bgp_evpn_rt2_nexthop():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for hname in ("h1", "h2"):
        host = tgen.gears[hname]
        host.cmd("ping -c 1 192.168.0.254")
        host.cmd("ping -c 1 2001:db8::ff")

    for rname in ("vtep1", "vtep2"):
        router = tgen.gears[rname]
        logger.info("Checking BGP EVPN RT2 Nexthops on {}".format(router.name))

        peer = "10.125.0.2" if rname == "vtep1" else "10.125.0.1"
        i = 2 if rname == "vtep1" else 1
        expected = {
            f"{peer}:100": {
                f"[2]:[0]:[48]:[de:ed:01:0{i}:00:0{i}]": {
                    "paths": [
                        {
                            "valid": True,
                            "nexthops": [{"ip": peer, "afi": "ipv4", "used": True}],
                        }
                    ],
                    "pathCount": 1,
                },
                f"[2]:[0]:[48]:[de:ed:01:0{i}:00:0{i}]:[32]:[192.168.0.{i}]": {
                    "paths": [
                        {
                            "valid": True,
                            "nexthops": [
                                {
                                    "ip": peer,
                                    "afi": "ipv4",
                                    "used": True,
                                }
                            ],
                        }
                    ],
                    "pathCount": 1,
                },
                f"[2]:[0]:[48]:[de:ed:01:0{i}:00:0{i}]:[128]:[2001:db8::{i}]": {
                    "paths": [
                        {
                            "valid": True,
                            "nexthops": [{"ip": peer, "afi": "ipv4", "used": True}],
                        }
                    ],
                    "pathCount": 1,
                },
            }
        }

        test_func = partial(
            topotest.router_json_cmp,
            router,
            f"show bgp l2vpn evpn rd {peer}:100 json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
