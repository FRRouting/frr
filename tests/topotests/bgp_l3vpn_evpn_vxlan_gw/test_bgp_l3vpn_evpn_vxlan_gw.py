#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_l3vpn_evpn_vxlan_gw.py
#
# Copyright 2026 6WIND
#

"""
Check a BGP L3VPN MPLS / BGP EVPN VXLAN gateway.

     AS 65501                                          AS 65502
  +----+  MPLS  +----+  MPLS   +----+  VXLAN (VNI 1000) +----+
  | r1 |--------| r2 |---------| r3 |-------------------| r4 |
  +----+        +----+ vlan100 +----+      vlan200      +----+
    | vrf1                        vrf1                     | vrf1
  +----+                                                 +----+
  | h1 |                                                 | h4 |
  +----+                                                 +----+

r1, r2 and r3 exchange their loopbacks with iBGP labeled-unicast on the
physical interfaces; r2 reflects them with next-hop-self. r1 and r3 exchange
the vrf1 prefixes with an iBGP L3VPN session between their loopbacks. r3 and
r4 exchange the vrf1 prefixes with eBGP EVPN type-5 routes over VXLAN.
r2/r3 and r3/r4 use separate VLANs on the same segment.
"""

import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.checkping import check_ping
from lib.common_config import retry
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rname in ("r1", "r2", "r3", "r4"):
        tgen.add_router(rname)
    tgen.add_host("h1", "172.31.1.10/24", "via 172.31.1.1")
    tgen.add_host("h4", "172.31.4.10/24", "via 172.31.4.1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r2-eth1.100 / r3-eth0.100 and r3-eth0.200 / r4-eth0.200
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["h4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    for router in (r1, r2, r3):
        router.cmd_raises("sysctl -w net.mpls.platform_labels=1048575")

    r1.cmd_raises(
        """
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r1-eth1 master vrf1
sysctl -w net.mpls.conf.r1-eth0.input=1
"""
    )

    r2.cmd_raises(
        """
ip link add link r2-eth1 name r2-eth1.100 type vlan id 100
ip link set r2-eth1.100 up
sysctl -w net.mpls.conf.r2-eth0.input=1
echo 1 > /proc/sys/net/mpls/conf/r2-eth1.100/input
"""
    )

    r3.cmd_raises(
        """
ip link add link r3-eth0 name r3-eth0.100 type vlan id 100
ip link set r3-eth0.100 up
ip link add link r3-eth0 name r3-eth0.200 type vlan id 200
ip link set r3-eth0.200 up
echo 1 > /proc/sys/net/mpls/conf/r3-eth0.100/input
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link add br1000 address 52:54:00:00:03:e8 type bridge stp_state 0
ip link set br1000 master vrf1
ip link set br1000 up
ip link add vxlan1000 type vxlan id 1000 dstport 4789 local 10.0.34.3 dev r3-eth0.200 nolearning
ip link set vxlan1000 master br1000
ip link set vxlan1000 type bridge_slave learning off
ip link set vxlan1000 up
"""
    )

    r4.cmd_raises(
        """
ip link add link r4-eth0 name r4-eth0.200 type vlan id 200
ip link set r4-eth0.200 up
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r4-eth1 master vrf1
ip link add br1000 address 52:54:00:00:04:e8 type bridge stp_state 0
ip link set br1000 master vrf1
ip link set br1000 up
ip link add vxlan1000 type vxlan id 1000 dstport 4789 local 10.0.34.4 dev r4-eth0.200 nolearning
ip link set vxlan1000 master br1000
ip link set vxlan1000 type bridge_slave learning off
ip link set vxlan1000 up
"""
    )

    for router in (r1, r2, r3, r4):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@retry(retry_timeout=60)
def check_route(router, prefix, vrf=None, labeled=False):
    cmd = "show ip route {}".format(prefix)
    if vrf:
        cmd = "show ip route vrf {} {}".format(vrf, prefix)
    output = router.vtysh_cmd(cmd + " json", isjson=True)
    for route in output.get(prefix, []):
        if route.get("protocol") != "bgp" or not route.get("installed"):
            continue
        if not labeled:
            return True
        for nexthop in route.get("nexthops", []):
            if nexthop.get("labels"):
                return True
    return "{}: no {}BGP route installed for {}{}".format(
        router.name,
        "labeled " if labeled else "",
        prefix,
        " in {}".format(vrf) if vrf else "",
    )


def test_bgp_sessions():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    @retry(retry_timeout=60)
    def check_bgp_peers_established(router, peers):
        output = router.vtysh_cmd("show bgp neighbors json", isjson=True)
        for peer in peers:
            state = output.get(peer, {}).get("bgpState")
            if state != "Established":
                return "{}: peer {} is {}".format(router.name, peer, state)
        return True

    for rname, peers in (
        ("r1", ["10.0.12.2", "192.0.2.3"]),
        ("r2", ["10.0.12.1", "10.0.23.3"]),
        ("r3", ["10.0.23.2", "192.0.2.1", "10.0.34.4"]),
        ("r4", ["10.0.34.3"]),
    ):
        result = check_bgp_peers_established(tgen.gears[rname], peers)
        assert result is True, result


def test_labeled_unicast_loopbacks():
    """
    Check that r1 and r3 reach each other's loopback with a labeled
    nexthop, learned with iBGP labeled-unicast through r2.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_route(tgen.gears["r1"], "192.0.2.3/32", labeled=True)
    assert result is True, result
    result = check_route(tgen.gears["r3"], "192.0.2.1/32", labeled=True)
    assert result is True, result


def test_l3vpn_routes():
    """
    Check that the prefix of h1 is imported in vrf1 of r3 from L3VPN, and
    that the prefix of h4, learned by r3 with EVPN, is imported in vrf1 of r1
    from L3VPN with a labeled nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_route(tgen.gears["r3"], "172.31.1.0/24", vrf="vrf1", labeled=True)
    assert result is True, result
    result = check_route(tgen.gears["r1"], "172.31.4.0/24", vrf="vrf1", labeled=True)
    assert result is True, result


def test_evpn_routes():
    """
    Check that the prefix of h4 is installed in vrf1 of r3 from EVPN, and
    that the prefix of h1, learned by r3 with L3VPN, is installed in vrf1 of
    r4 from EVPN.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_route(tgen.gears["r3"], "172.31.4.0/24", vrf="vrf1")
    assert result is True, result
    result = check_route(tgen.gears["r4"], "172.31.1.0/24", vrf="vrf1")
    assert result is True, result


def test_ping_h1_h4():
    """
    Check the traffic between h1 and h4: MPLS between r1 and r3, VXLAN
    between r3 and r4.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("h1", "172.31.4.10", True, 10, 1)
    check_ping("h4", "172.31.1.10", True, 10, 1)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
