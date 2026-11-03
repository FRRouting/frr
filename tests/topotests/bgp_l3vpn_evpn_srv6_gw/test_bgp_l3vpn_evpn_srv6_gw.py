#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_l3vpn_evpn_srv6_gw.py
#
# Copyright 2026 6WIND
#

"""
Check a BGP L3VPN MPLS / BGP EVPN SRv6 gateway.

     AS 65501                                          AS 65502
  +----+  MPLS  +----+  MPLS   +----+    EVPN SRv6      +----+
  | r1 |--------| r2 |---------| r3 |-------------------| r4 |
  +----+        +----+ vlan100 +----+      vlan200      +----+
    | vrf1                        vrf1                     | vrf1
  +----+                                                 +----+
  | h1 |                                                 | h4 |
  +----+                                                 +----+

r1, r2 and r3 exchange their loopbacks with iBGP labeled-unicast on the
physical interfaces; r2 reflects them with next-hop-self. r1 and r3 exchange
the vrf1 prefixes with an iBGP L3VPN session between their loopbacks. r3 and
r4 exchange the vrf1 prefixes with eBGP EVPN type-5 routes carrying an SRv6
SID ('advertise ipv4 vpn'); 'no srv6-only' lets r3 accept the L3VPN MPLS
routes while a SRv6 locator is configured. r2/r3 and r3/r4 use separate VLANs
on the same segment.

r3 re-originates the L3VPN routes of vrf1 as EVPN type-5 routes
('advertise ipv4 vpn reoriginate'). Only this direction is checked: the EVPN
routes are not re-originated as L3VPN MPLS routes.
"""

import os
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import required_linux_kernel_version, retry
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

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
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    if not topotest.module_present("vrf"):
        pytest.skip("VRF kernel module is not available")

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
sysctl -w net.vrf.strict_mode=1
ip link add link r3-eth0 name r3-eth0.100 type vlan id 100
ip link set r3-eth0.100 up
ip link add link r3-eth0 name r3-eth0.200 type vlan id 200
ip link set r3-eth0.200 up
echo 1 > /proc/sys/net/mpls/conf/r3-eth0.100/input
ip link add vrf1 type vrf table 10
ip link set vrf1 up
"""
    )

    r4.cmd_raises(
        """
sysctl -w net.vrf.strict_mode=1
ip link add link r4-eth0 name r4-eth0.200 type vlan id 200
ip link set r4-eth0.200 up
ip link add vrf1 type vrf table 10
ip link set vrf1 up
ip link set r4-eth1 master vrf1
"""
    )

    for router in (r1, r2, r3, r4):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(router.name)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@retry(retry_timeout=60)
def check_route(router, prefix, vrf=None, labeled=False, srv6=False):
    cmd = "show ip route {}".format(prefix)
    if vrf:
        cmd = "show ip route vrf {} {}".format(vrf, prefix)
    output = router.vtysh_cmd(cmd + " json", isjson=True)
    for route in output.get(prefix, []):
        if route.get("protocol") != "bgp" or not route.get("installed"):
            continue
        if not labeled and not srv6:
            return True
        for nexthop in route.get("nexthops", []):
            if labeled and nexthop.get("labels"):
                return True
            if srv6 and nexthop.get("seg6"):
                return True
    return "{}: no {}BGP route installed for {}{}".format(
        router.name,
        "labeled " if labeled else "SRv6 " if srv6 else "",
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
        ("r3", ["10.0.23.2", "192.0.2.1", "2001:db8:34::4"]),
        ("r4", ["2001:db8:34::3"]),
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


def test_l3vpn_route_h1():
    """
    Check that the prefix of h1 is imported in vrf1 of r3 from L3VPN, with
    a labeled nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_route(tgen.gears["r3"], "172.31.1.0/24", vrf="vrf1", labeled=True)
    assert result is True, result


def test_evpn_srv6_route_h4():
    """
    Check that the prefix of h4 is imported in vrf1 of r3 from EVPN, with an
    SRv6 nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_route(tgen.gears["r3"], "172.31.4.0/24", vrf="vrf1", srv6=True)
    assert result is True, result


def evpn_prefix_paths(router, rd, prefix):
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route rd {} type prefix json".format(rd), isjson=True
    )
    evpn_prefix = "[5]:[0]:[{}]:[{}]".format(prefix.split("/")[1], prefix.split("/")[0])
    rd_output = output.get(rd, {})
    if evpn_prefix not in rd_output:
        return None
    return [path for paths in rd_output[evpn_prefix].get("paths", []) for path in paths]


@retry(retry_timeout=60)
def check_reoriginated_route_h1(present):
    r4 = get_topogen().gears["r4"]
    paths = evpn_prefix_paths(r4, "65501:13", "172.31.1.0/24")
    if not present:
        if paths:
            return "r4: 172.31.1.0/24 of RD 65501:13 still received"
        return True
    if not paths:
        return "r4: 172.31.1.0/24 of RD 65501:13 not received"
    sids = [
        prefix_sid.get("remoteSid")
        for path in paths
        for prefix_sid in path.get("prefixSids", [])
    ]
    if "fcbb:bbbb:3::" not in sids:
        return "r4: 172.31.1.0/24 of RD 65501:13 received with SIDs {}".format(sids)
    return check_route(r4, "172.31.1.0/24", vrf="vrf1", srv6=True)


def test_evpn_reoriginated_route_h1():
    """
    Check that r3 re-originates the prefix of h1, learned with L3VPN MPLS, as
    an EVPN type-5 route with the RD and the SRv6 SID of its vrf1, and that
    r4 installs it in vrf1 with an SRv6 nexthop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_reoriginated_route_h1(True)
    for rname in ("r3", "r4"):
        output = tgen.gears[rname].vtysh_cmd("show bgp l2vpn evpn route type prefix")
        logger.info("%s:\n%s", rname, output)
    assert result is True, result


def test_evpn_route_h4_not_reoriginated():
    """
    Check that r3 does not export back the prefix of h4, learned with EVPN,
    as a type-5 route: neither with the RD of r4, nor with the RD of its vrf1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    paths = evpn_prefix_paths(r3, "65502:14", "172.31.4.0/24")
    assert paths, "r3: 172.31.4.0/24 of RD 65502:14 not received"
    assert not [
        path for path in paths if path.get("local")
    ], "r3: 172.31.4.0/24 of RD 65502:14 exported back to EVPN"

    paths = evpn_prefix_paths(r3, "65501:13", "172.31.4.0/24")
    assert not paths, "r3: 172.31.4.0/24 re-originated with RD 65501:13"


def test_evpn_reoriginate_disable():
    """
    Check that r4 loses the prefix of h1 when the re-origination is disabled
    on r3, and receives it again when the re-origination is enabled.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501
 address-family l2vpn evpn
  no advertise ipv4 vpn reoriginate
"""
    )
    output = r3.vtysh_cmd("show running-config")
    assert "  advertise ipv4 vpn\n" in output, "r3: 'advertise ipv4 vpn' not found"
    result = check_reoriginated_route_h1(False)
    assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501
 address-family l2vpn evpn
  advertise ipv4 vpn reoriginate
"""
    )
    output = r3.vtysh_cmd("show running-config")
    assert (
        "  advertise ipv4 vpn reoriginate\n" in output
    ), "r3: 'advertise ipv4 vpn reoriginate' not found"
    result = check_reoriginated_route_h1(True)
    assert result is True, result


def test_evpn_reoriginate_route_map():
    """
    Check that r3 does not re-originate the prefix of h1 as an EVPN type-5
    route when the route-map of 'advertise ipv4 vpn' denies it, and that the
    prefix comes back when the route-map permits it, then when the route-map
    is removed from the command.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    r3.vtysh_cmd(
        """
configure terminal
ip prefix-list h1 seq 5 permit 172.31.1.0/24
route-map FILTER deny 10
 match ip address prefix-list h1
route-map FILTER permit 20
router bgp 65501
 address-family l2vpn evpn
  advertise ipv4 vpn route-map FILTER
"""
    )
    result = check_reoriginated_route_h1(False)
    assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
no route-map FILTER deny 10
route-map FILTER permit 10
 match ip address prefix-list h1
"""
    )
    result = check_reoriginated_route_h1(True)
    assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
no route-map FILTER permit 10
route-map FILTER deny 10
 match ip address prefix-list h1
"""
    )
    result = check_reoriginated_route_h1(False)
    assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501
 address-family l2vpn evpn
  no advertise ipv4 vpn route-map FILTER
"""
    )
    output = r3.vtysh_cmd("show running-config")
    assert (
        "  advertise ipv4 vpn reoriginate\n" in output
    ), "r3: 'advertise ipv4 vpn reoriginate' not found"
    result = check_reoriginated_route_h1(True)
    assert result is True, result


def test_evpn_reoriginate_label_change():
    """
    Check that r3 keeps re-originating the prefix of h1 as an EVPN type-5
    route when the VPN export label of vrf1 changes. The label change
    withdraws then re-advertises the route with the same attributes: the
    route must stay advertised once the withdrawal is processed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501 vrf vrf1
 address-family ipv4 unicast
  label vpn export 1111
"""
    )
    for _ in range(5):
        time.sleep(1)
        result = check_reoriginated_route_h1(True)
        assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501 vrf vrf1
 address-family ipv4 unicast
  label vpn export auto
"""
    )
    result = check_reoriginated_route_h1(True)
    assert result is True, result


def test_evpn_reoriginate_sid_change():
    """
    Check that r3 re-originates the prefix of h1 as an EVPN type-5 route with
    the new SRv6 SID function when the SID of vrf1 changes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    @retry(retry_timeout=60)
    def check_reoriginated_route_h1_sid(explicit):
        paths = evpn_prefix_paths(r4, "65501:13", "172.31.1.0/24")
        if not paths:
            return "r4: 172.31.1.0/24 of RD 65501:13 not received"
        sids = [
            prefix_sid.get("remoteTransposedSid")
            for path in paths
            for prefix_sid in path.get("prefixSids", [])
        ]
        if not sids or ("fcbb:bbbb:3:fe10::" in sids) != explicit:
            return "r4: 172.31.1.0/24 of RD 65501:13 received with SIDs {}".format(sids)
        return True

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501 vrf vrf1
 no sid vpn per-vrf export
 sid vpn per-vrf export explicit fcbb:bbbb:3:fe10::
"""
    )
    result = check_reoriginated_route_h1_sid(True)
    assert result is True, result

    r3.vtysh_cmd(
        """
configure terminal
router bgp 65501 vrf vrf1
 no sid vpn per-vrf export
 sid vpn per-vrf export auto
"""
    )
    result = check_reoriginated_route_h1_sid(False)
    assert result is True, result
    result = check_reoriginated_route_h1(True)
    assert result is True, result


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
