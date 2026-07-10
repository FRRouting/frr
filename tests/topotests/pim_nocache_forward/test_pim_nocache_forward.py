#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_nocache_forward.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#

"""
Topotests for pimd NOCACHE / WRONGVIF ingress handling:

1. Non-connected source on LHR: (S,G) must forward when iif == RPF_interface(S)
   and local receivers exist (RFC 4601 section 4.2).  Source 10.10.4.2 is not on
   l1-eth1 (10.10.2.0/24).

2. Interface static mroute (ip mroute OIF GROUP [SOURCE] on IIF): traffic must
   flow through the static MFC entry installed by pim_static_nocache_resolve()'s
   configuration path.

3. Edge router with PIM passive neighbor: foreign-domain source (10.50.1.2) is
   not on the LAN subnet of fhr-eth3 (10.10.6.0/24) but RPF points there via
   static route through r_passive.  Static ip mroute is required because IGMP
   from a non-connected source on the receive interface is dropped (efe6f18);
   data on that path uses NOCACHE forwarding (test 1) and static mroutes
   (tests 2-3).

4. ECMP RPF on LHR: when MRIB lists multiple valid nexthops to the source,
   NOCACHE must prefer the kernel ingress interface so (S,G) forwarding
   survives after MFC flush.

5. WRONGVIF ingress prefer on FHR: parent has a broad secondary prefix that
   also covers the tunnel source subnet (e.g. /16 on the parent while GRE
   tunnels carry the same /16).  Join/FHR installs MFC iif on the parent; a
   more-specific static via the tunnel does not change that connected RPF.
   Data then arrives on the passive tunnel -> WRONGVIF.  pimd must realign
   MFC iif to the kernel ingress.  NOCACHE does not apply because the MFC
   already exists.
"""

import json
import os
import sys
import time
from functools import partial

import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import step, write_test_footer, write_test_header
from lib.pim import (
    McastTesterHelper,
    clear_mroute,
    verify_igmp_groups,
    verify_mroutes,
    verify_pim_neighbors,
)
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

TOPOLOGY = """
                              h_recv
                                |
                               l1
                                |
                               rp
                                |
                           fhr-eth0
                                |
                               fhr
              +--------+--------+-----------------+
              |        |        |                 |
           h_src    h_src    h_local    r_passive [passive->fhr]
         fhr-eth1  fhr-eth4  fhr-eth2           fhr-eth3
         (parent)  (tunnel)                       |
                                             h_foreign

    RP 10.255.0.1 (rp lo)

    WRONGVIF overlapping-prefix shape (test_wrongvif_prefer_kernel_ingress):
      fhr-eth1 primary 10.10.4.1/24 + secondary 10.20.0.1/16
      fhr-eth4          10.20.2.253/16  (PIM passive tunnel stand-in)
      static            10.20.1.0/24 via tunnel
      source            10.20.1.4 on h_src-eth1 (data on tunnel)
      Connected /16 on parent makes RPF stick to fhr-eth1 while packets
      arrive on fhr-eth4.
"""

SOURCE = "10.10.4.2"
FOREIGN_SOURCE = "10.50.1.2"
RP_ADDR = "10.255.0.1"

# WRONGVIF source covered by parent secondary /16; data arrives on tunnel.
WRONGVIF_SOURCE = "10.20.1.4"
WRONGVIF_SRC_PREFIX = "10.20.1.0/24"
WRONGVIF_OVERLAP = "10.20.0.0/16"
WRONGVIF_PARENT_SEC = "10.20.0.1/16"
WRONGVIF_TUNNEL_ADDR = "10.20.2.253/16"
WRONGVIF_TUNNEL_GW = "10.20.2.253"

GROUP_LHR_NOCACHE = "225.1.3.1"
GROUP_STATIC = "239.77.1.1"
GROUP_PASSIVE_EDGE = "225.1.3.2"
GROUP_ECMP_INGRESS = "225.1.3.3"
GROUP_WRONGVIF_INGRESS = "225.1.3.4"

L1_RECV_NH = "10.10.1.2"
SOURCE_PREFIX = "10.10.4.0/24"

L1_TO_RP = "l1-eth1"
L1_TO_RECV = "l1-eth0"
RP_TO_FHR = "rp-eth1"
FHR_TO_RP = "fhr-eth0"
FHR_TO_SRC = "fhr-eth1"
FHR_TO_LOCAL = "fhr-eth2"
FHR_TO_PASSIVE = "fhr-eth3"
FHR_TO_TUNNEL = "fhr-eth4"
R_PASSIVE_TO_FHR = "r_passive-eth0"
R_PASSIVE_TO_FOREIGN = "r_passive-eth1"

PIM_TOPO = {
    "routers": {
        "l1": {
            "links": {
                "rp": {"interface": L1_TO_RP, "ipv4": "10.10.2.1/24", "pim": "enable"},
            }
        },
        "rp": {
            "links": {
                "l1": {"interface": "rp-eth0", "ipv4": "10.10.2.2/24", "pim": "enable"},
                "fhr": {
                    "interface": RP_TO_FHR,
                    "ipv4": "10.10.3.2/24",
                    "pim": "enable",
                },
            }
        },
        "fhr": {
            "links": {
                "rp": {"interface": FHR_TO_RP, "ipv4": "10.10.3.1/24", "pim": "enable"},
            }
        },
        "r_passive": {"links": {}},
    }
}

app_helper = McastTesterHelper()


def build_topo(tgen):
    tgen.add_router("l1")
    tgen.add_router("rp")
    tgen.add_router("fhr")
    tgen.add_router("r_passive")

    tgen.add_host("h_recv", "10.10.1.2/24", "via 10.10.1.1")
    tgen.add_host("h_src", "10.10.4.2/24", "via 10.10.4.1")
    tgen.add_host("h_local", "10.10.5.2/24", "via 10.10.5.1")
    tgen.add_host("h_foreign", "10.50.1.2/24", "via 10.50.1.1")

    tgen.add_link(tgen.gears["h_recv"], tgen.gears["l1"], "h_recv-eth0", "l1-eth0")
    tgen.add_link(tgen.gears["l1"], tgen.gears["rp"], "l1-eth1", "rp-eth0")
    tgen.add_link(tgen.gears["rp"], tgen.gears["fhr"], "rp-eth1", "fhr-eth0")
    tgen.add_link(tgen.gears["h_src"], tgen.gears["fhr"], "h_src-eth0", "fhr-eth1")
    tgen.add_link(tgen.gears["h_local"], tgen.gears["fhr"], "h_local-eth0", "fhr-eth2")
    tgen.add_link(
        tgen.gears["r_passive"], tgen.gears["fhr"], R_PASSIVE_TO_FHR, FHR_TO_PASSIVE
    )
    tgen.add_link(
        tgen.gears["h_foreign"],
        tgen.gears["r_passive"],
        "h_foreign-eth0",
        R_PASSIVE_TO_FOREIGN,
    )
    # Second path from source host to FHR (tunnel stand-in for WRONGVIF test).
    tgen.add_link(tgen.gears["h_src"], tgen.gears["fhr"], "h_src-eth1", FHR_TO_TUNNEL)


def setup_module(mod):
    logger.info("Testsuite start time: %s", time.asctime(time.localtime(time.time())))
    logger.info("Topology:\n%s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    app_helper.init(tgen)

    for _, router in tgen.routers().items():
        router.load_frr_config()

    tgen.start_router()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_pim_neighbors(tgen, PIM_TOPO)
    assert result is True, "PIM neighbors failed to establish: {}".format(result)


def teardown_module():
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def prepare_test(tgen):
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    tgen.errors = ""
    tgen.errorsd = {}


def start_remote_join_and_traffic(tgen, group):
    assert app_helper.run_join("h_recv", group, join_intf="h_recv-eth0") is True
    assert verify_igmp_groups(tgen, "l1", L1_TO_RECV, group) is True
    assert verify_mroutes(tgen, "l1", "*", group, L1_TO_RP, L1_TO_RECV) is True
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True


def verify_upstream_json(tgen, dut, source, group, expected_fields):
    router = tgen.routers()[dut]

    def _check():
        output = router.vtysh_cmd("show ip pim upstream json", isjson=True)
        upstream = output.get(group, {}).get(source)
        if not upstream:
            return False
        for key, val in expected_fields.items():
            if upstream.get(key) != val:
                return False
        return True

    _, result = topotest.run_and_expect(_check, True, count=60, wait=1)
    return result


def verify_receiver_traffic(host, group, recv_intf, source, min_pkts=1):
    report = app_helper.collect_receiver_sources(
        host, group, recv_intf, duration=3, source=source
    )
    count = report.get("sources", {}).get(source, 0)
    return count >= min_pkts, report


def verify_mroute_json(router, expected, count=30, wait=1):
    test_func = partial(
        topotest.router_json_cmp, router, "show ip mroute json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=wait)
    return result


def verify_static_route_ecmp(router, prefix, num_nhs=2, count=30, wait=1):
    def _check():
        output = router.vtysh_cmd("show ip route {} json".format(prefix), isjson=True)
        for route in output.get(prefix, []):
            if route.get("protocol") == "static":
                nhs = route.get("nexthops", [])
                if len(nhs) == num_nhs:
                    return True
        return False

    _, result = topotest.run_and_expect(_check, True, count=count, wait=wait)
    return result


def test_nocache_non_connected_lhr_forwarding(request):
    """
    LHR receives (S,G) on the RP-facing interface where the source address is
    not locally connected.  Forwarding and upstream state must reflect the SPT
    path (iif == RPF_interface(S), not FHR).
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_LHR_NOCACHE

    step("Establish remote IGMP join and source traffic")
    start_remote_join_and_traffic(tgen, group)

    step("Verify (S,G) on LHR with non-connected source on {}".format(L1_TO_RP))
    result = verify_mroutes(tgen, "l1", SOURCE, group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: (S,G) mroute failed: {}".format(tc_name, result)

    step("Verify LHR upstream uses RP-facing IIF and is not marked FHR")
    result = verify_upstream_json(
        tgen,
        "l1",
        SOURCE,
        group,
        {
            "inboundInterface": L1_TO_RP,
            "firstHopRouter": False,
            "joinState": "Joined",
        },
    )
    assert result is True, "{}: upstream check failed: {}".format(tc_name, result)

    step("Verify receiver gets traffic from non-connected source through LHR")
    ok, report = verify_receiver_traffic("h_recv", group, "h_recv-eth0", SOURCE)
    assert ok is True, "{}: no end-to-end traffic: {}".format(
        tc_name, json.dumps(report)
    )

    write_test_footer(tc_name)


def test_nocache_ecmp_prefer_kernel_ingress(request):
    """
    LHR with ECMP static routes to the source prefix must pick the kernel
    ingress interface on NOCACHE so existing (S,G) state forwards after MFC
    flush even when another equal-cost nexthop exists on the receiver LAN.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    l1 = tgen.gears["l1"]
    group = GROUP_ECMP_INGRESS

    step("Establish remote IGMP join and source traffic")
    start_remote_join_and_traffic(tgen, group)

    step("Verify baseline (S,G) on LHR before ECMP is introduced")
    result = verify_mroutes(tgen, "l1", SOURCE, group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: baseline (S,G) failed: {}".format(tc_name, result)

    step("Install equal-cost ECMP static route via receiver LAN on l1")
    l1.vtysh_cmd(
        f"""
        conf t
           router pim
              ecmp
           ip route {SOURCE_PREFIX} {L1_RECV_NH}
    """
    )
    result = verify_static_route_ecmp(l1, SOURCE_PREFIX, num_nhs=2)
    assert result is True, "{}: ECMP static route not installed: {}".format(
        tc_name, result
    )

    step("Flush MFC on LHR to force NOCACHE with ECMP RPF ambiguity")
    clear_mroute(tgen, "l1")

    step("Verify (S,G) reinstalled with RP-facing IIF after NOCACHE")
    result = verify_mroutes(tgen, "l1", SOURCE, group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: (S,G) mroute failed after MFC flush: {}".format(
        tc_name, result
    )

    step("Verify upstream RPF still uses kernel ingress interface")
    result = verify_upstream_json(
        tgen,
        "l1",
        SOURCE,
        group,
        {
            "inboundInterface": L1_TO_RP,
            "firstHopRouter": False,
            "joinState": "Joined",
        },
    )
    assert result is True, "{}: upstream check failed: {}".format(tc_name, result)

    step("Verify receiver still gets traffic after MFC flush with ECMP RPF")
    ok, report = verify_receiver_traffic("h_recv", group, "h_recv-eth0", SOURCE)
    assert ok is True, "{}: no end-to-end traffic: {}".format(
        tc_name, json.dumps(report)
    )

    step("Remove ECMP static route and PIM ECMP configuration")
    l1.vtysh_cmd(
        f"""
        conf t
           no ip route {SOURCE_PREFIX} {L1_RECV_NH}
           router pim
              no ecmp
    """
    )

    write_test_footer(tc_name)


def test_nocache_non_connected_passive_edge_forwarding(request):
    """
    Edge router (fhr) receives multicast from a foreign domain via a PIM passive
    neighbor.  Source 10.50.1.2 is not on fhr-eth3 (10.10.6.0/24) but URIB RPF
    points there via r_passive.  Register/FHR cannot apply (non-connected on IIF),
    so a static MFC on the ingress interface bootstraps forwarding.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    fhr = tgen.gears["fhr"]
    group = GROUP_PASSIVE_EDGE

    step("Verify PIM passive is enabled toward fhr on r_passive")
    output = tgen.gears["r_passive"].vtysh_cmd("show running-config")
    assert "ip pim passive" in output, "{}: passive PIM not configured".format(tc_name)

    step("Configure static mroutes on passive router and edge fhr")
    r_passive = tgen.gears["r_passive"]
    r_passive.vtysh_cmd(
        f"""
        conf t
           interface {R_PASSIVE_TO_FOREIGN}
              ip mroute {R_PASSIVE_TO_FHR} {group} {FOREIGN_SOURCE}
    """
    )
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_PASSIVE}
              ip mroute {FHR_TO_LOCAL} {group} {FOREIGN_SOURCE}
    """
    )

    expected = {group: {FOREIGN_SOURCE: {"oil": {FHR_TO_LOCAL: "*"}}}}
    result = verify_mroute_json(fhr, expected)
    assert result is None, "{}: static edge mroute not installed: {}".format(
        tc_name, result
    )

    step("Join local receiver and start foreign-domain source traffic")
    assert app_helper.run_join("h_local", group, join_intf="h_local-eth0") is True
    assert (
        app_helper.run_traffic("h_foreign", group, bind_intf="h_foreign-eth0") is True
    )

    step(
        "Verify static (S,G) on edge fhr with foreign source on {}".format(
            FHR_TO_PASSIVE
        )
    )
    result = verify_mroute_json(fhr, expected)
    assert result is None, "{}: (S,G) mroute failed: {}".format(tc_name, result)

    step("Verify local receiver gets traffic from foreign source")
    ok, report = verify_receiver_traffic(
        "h_local", group, "h_local-eth0", FOREIGN_SOURCE
    )
    assert ok is True, "{}: no traffic from foreign source: {}".format(
        tc_name, json.dumps(report)
    )

    step("Remove static mroute configuration")
    r_passive.vtysh_cmd(
        f"""
        conf t
           interface {R_PASSIVE_TO_FOREIGN}
              no ip mroute {R_PASSIVE_TO_FHR} {group} {FOREIGN_SOURCE}
    """
    )
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_PASSIVE}
              no ip mroute {FHR_TO_LOCAL} {group} {FOREIGN_SOURCE}
    """
    )

    write_test_footer(tc_name)


def test_static_mroute_forward_with_traffic(request):
    """
    Interface static mroute on FHR (ip mroute fhr-eth2 GROUP SOURCE on fhr-eth1)
    must forward source traffic to the local receiver without PIM joins on the
    shared tree.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    fhr = tgen.gears["fhr"]
    group = GROUP_STATIC

    step("Configure static mroute on FHR ingress interface")
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_SRC}
              ip mroute {FHR_TO_LOCAL} {group} {SOURCE}
    """
    )

    expected = {group: {SOURCE: {"oil": {FHR_TO_LOCAL: "*"}}}}
    result = verify_mroute_json(fhr, expected)
    assert result is None, "{}: static mroute not installed: {}".format(tc_name, result)

    step("Join local receiver and start source traffic")
    assert app_helper.run_join("h_local", group, join_intf="h_local-eth0") is True
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True

    step("Verify local receiver gets traffic via static mroute")
    ok, report = verify_receiver_traffic("h_local", group, "h_local-eth0", SOURCE)
    assert ok is True, "{}: no static forward traffic: {}".format(
        tc_name, json.dumps(report)
    )

    step("Remove static mroute configuration")
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_SRC}
              no ip mroute {FHR_TO_LOCAL} {group} {SOURCE}
    """
    )

    write_test_footer(tc_name)


def test_wrongvif_prefer_kernel_ingress(request):
    """
    Overlapping connected prefix on parent vs PIM-passive tunnel:

      - Parent (fhr-eth1) has primary LAN plus secondary overlapping /16
      - Tunnel stand-in (fhr-eth4) is PIM passive on the same /16
      - More-specific static points the source prefix at the tunnel
      - Connected /16 on parent still makes join/FHR RPF stick to parent

    Traffic arrives on the tunnel while MFC iif is parent -> WRONGVIF.
    pimd must realign MFC iif / upstream RPF to the kernel ingress.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    fhr = tgen.gears["fhr"]
    h_src = tgen.gears["h_src"]
    group = GROUP_WRONGVIF_INGRESS
    source = WRONGVIF_SOURCE

    step("Configure parent secondary /16 overlapping tunnel source space")
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_SRC}
              ip address {WRONGVIF_PARENT_SEC}
    """
    )

    step("Readdress source host on parent path to overlapping-prefix source")
    # SO_BINDTODEVICE uses the interface primary address; temporarily replace
    # 10.10.4.2 so packets are sourced as WRONGVIF_SOURCE toward the parent.
    h_src.run("ip addr del 10.10.4.2/24 dev h_src-eth0 || true")
    h_src.run(f"ip addr add {source}/16 dev h_src-eth0")
    h_src.run(f"ip route replace default via {WRONGVIF_PARENT_SEC.split('/')[0]} || true")

    step("Join local receiver and start traffic on parent path {}".format(FHR_TO_SRC))
    assert app_helper.run_join("h_local", group, join_intf="h_local-eth0") is True
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True

    step("Verify baseline (S,G) MFC iif is parent via overlapping secondary")
    result = verify_mroutes(tgen, "fhr", source, group, FHR_TO_SRC, FHR_TO_LOCAL)
    assert result is True, "{}: baseline parent iif failed: {}".format(tc_name, result)

    result = verify_upstream_json(
        tgen,
        "fhr",
        source,
        group,
        {
            "inboundInterface": FHR_TO_SRC,
            "firstHopRouter": True,
        },
    )
    assert result is True, "{}: baseline upstream on parent failed: {}".format(
        tc_name, result
    )

    step("Bring up PIM-passive tunnel stand-in and more-specific static via tunnel")
    # Install after baseline so join/FHR RPF is already stuck on the parent.
    fhr.vtysh_cmd(
        f"""
        conf t
           interface {FHR_TO_TUNNEL}
              ip address {WRONGVIF_TUNNEL_ADDR}
              ip pim
              ip pim passive
           ip route {WRONGVIF_SRC_PREFIX} {source} {FHR_TO_TUNNEL}
    """
    )

    step("Confirm overlapping connected /16 is present on parent and tunnel")

    def _check_overlap_routes():
        output = fhr.vtysh_cmd(
            "show ip route {} json".format(WRONGVIF_OVERLAP), isjson=True
        )
        routes = output.get(WRONGVIF_OVERLAP, [])
        ifaces = set()
        for route in routes:
            for nh in route.get("nexthops", []):
                if nh.get("directlyConnected") or route.get("protocol") == "connected":
                    ifaces.add(nh.get("interfaceName"))
        return FHR_TO_SRC in ifaces and FHR_TO_TUNNEL in ifaces

    _, ok = topotest.run_and_expect(_check_overlap_routes, True, count=30, wait=1)
    assert ok is True, "{}: overlapping /16 not on parent+tunnel".format(tc_name)

    step("Confirm MFC iif remains stuck on parent after tunnel/static install")
    result = verify_mroutes(tgen, "fhr", source, group, FHR_TO_SRC, FHR_TO_LOCAL)
    assert result is True, "{}: parent iif not sticky after tunnel: {}".format(
        tc_name, result
    )

    step("Move source traffic to tunnel stand-in {}".format(FHR_TO_TUNNEL))
    h_src.run(f"ip addr add {source}/16 dev h_src-eth1 || true")
    h_src.run("ip link set h_src-eth1 up")
    h_src.run(f"ip route replace {WRONGVIF_TUNNEL_GW}/32 dev h_src-eth1 || true")
    app_helper.stop_traffic_senders()
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth1") is True

    step("Verify WRONGVIF realigned MFC iif to tunnel stand-in")
    result = verify_mroutes(tgen, "fhr", source, group, FHR_TO_TUNNEL, FHR_TO_LOCAL)
    assert result is True, "{}: tunnel iif not installed after WRONGVIF: {}".format(
        tc_name, result
    )

    result = verify_upstream_json(
        tgen,
        "fhr",
        source,
        group,
        {
            "inboundInterface": FHR_TO_TUNNEL,
            "firstHopRouter": True,
        },
    )
    assert result is True, "{}: upstream not realigned to tunnel: {}".format(
        tc_name, result
    )

    step("Verify local receiver still gets traffic after WRONGVIF realignment")
    ok, report = verify_receiver_traffic("h_local", group, "h_local-eth0", source)
    assert ok is True, "{}: no traffic after WRONGVIF realignment: {}".format(
        tc_name, json.dumps(report)
    )

    step("Remove overlapping secondary / tunnel configuration")
    fhr.vtysh_cmd(
        f"""
        conf t
           no ip route {WRONGVIF_SRC_PREFIX} {source} {FHR_TO_TUNNEL}
           interface {FHR_TO_TUNNEL}
              no ip pim
              no ip address {WRONGVIF_TUNNEL_ADDR}
           interface {FHR_TO_SRC}
              no ip address {WRONGVIF_PARENT_SEC}
    """
    )
    h_src.run(f"ip route del {WRONGVIF_TUNNEL_GW}/32 || true")
    h_src.run(f"ip addr del {source}/16 dev h_src-eth1 || true")
    h_src.run(f"ip addr del {source}/16 dev h_src-eth0 || true")
    h_src.run("ip addr add 10.10.4.2/24 dev h_src-eth0 || true")
    h_src.run("ip route replace default via 10.10.4.1 || true")

    write_test_footer(tc_name)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
