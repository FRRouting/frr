#!/usr/bin/env python
# SPDX-License-Identifier: ISC


#
# test_pim_wrongvif_compat.py
#
# Copyright (c) 2026 ATCorp
# Jafar Al-Gharaibeh
#


"""
Topotest for pimd WRONGVIF compensation when IGMPMSG_WRVIFWHOLE is unavailable
(kernels before 4.19).  Also runs on newer kernels where WRVIFWHOLE handles
first-packet events; no minimum kernel version skip is applied here.

Topology (see frr.conf under l1/, rp/, fhr/):

    h_recv ---- l1 ---- rp ---- fhr ---- h_src
                             +---- h_local

Scenarios (issue #11411 + commit 648e747325 extensions):

1. Join-before-data at FHR (partial MFC promotion via pim_upstream_activate_stream)
2. Bidirectional same-LAN on FHR (*,G) only until data
3. LHR / SPT path on transit router (pim_upstream_wrongvif_wrvifwhole_compat)
4. FHR FRR restart -> (S,G) state and mroutes recover via WRONGVIF compensation
5. LHR FRR restart -> (S,G) state and mroutes recover via WRONGVIF compensation
"""

import os
import sys
import time

import pytest

pytestmark = [pytest.mark.pimd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import (
    restart_frr,
    step,
    write_test_footer,
    write_test_header,
)
from lib.pim import (
    McastTesterHelper,
    clear_mroute,
    verify_igmp_groups,
    verify_mroutes,
    verify_pim_neighbors,
    verify_upstream_iif,
)
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

TOPOLOGY = """
    h_recv ---- l1 (LHR) ---- rp (RP) ---- fhr (FHR) ---- h_src
                                        +---- h_local

    RP address: 10.255.0.1 (rp lo)
    Source:     10.10.4.2 (h_src)
"""

SOURCE = "10.10.4.2"
RP_ADDR = "10.255.0.1"

# One group per test so state does not collide across cases.
GROUP_JOIN_BEFORE = "225.1.1.1"
GROUP_BIDIR = "225.1.1.2"
GROUP_LHR_COMPAT = "225.1.1.3"
GROUP_FHR_RESTART = "225.1.1.4"
GROUP_LHR_RESTART = "225.1.1.5"

# Interface names from build_topo() below.
L1_TO_RP = "l1-eth1"
L1_TO_RECV = "l1-eth0"
RP_TO_L1 = "rp-eth0"
RP_TO_FHR = "rp-eth1"
FHR_TO_RP = "fhr-eth0"
FHR_TO_SRC = "fhr-eth1"
FHR_TO_LOCAL = "fhr-eth2"

PIM_TOPO = {
    "routers": {
        "l1": {
            "links": {
                "rp": {"interface": L1_TO_RP, "ipv4": "10.10.2.1/24", "pim": "enable"},
            }
        },
        "rp": {
            "links": {
                "l1": {"interface": RP_TO_L1, "ipv4": "10.10.2.2/24", "pim": "enable"},
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
    }
}

app_helper = McastTesterHelper()


def build_topo(tgen):
    """Build LHR / RP / FHR chain with three host nodes."""

    tgen.add_router("l1")
    tgen.add_router("rp")
    tgen.add_router("fhr")

    tgen.add_host("h_recv", "10.10.1.2/24", "via 10.10.1.1")
    tgen.add_host("h_src", "10.10.4.2/24", "via 10.10.4.1")
    tgen.add_host("h_local", "10.10.5.2/24", "via 10.10.5.1")

    tgen.add_link(tgen.gears["h_recv"], tgen.gears["l1"], "h_recv-eth0", "l1-eth0")
    tgen.add_link(tgen.gears["l1"], tgen.gears["rp"], "l1-eth1", "rp-eth0")
    tgen.add_link(tgen.gears["rp"], tgen.gears["fhr"], "rp-eth1", "fhr-eth0")
    tgen.add_link(tgen.gears["h_src"], tgen.gears["fhr"], "h_src-eth0", "fhr-eth1")
    tgen.add_link(tgen.gears["h_local"], tgen.gears["fhr"], "h_local-eth0", "fhr-eth2")


def setup_module(mod):
    """Create topology and load per-router frr.conf files."""

    logger.info("Testsuite start time: %s", time.asctime(time.localtime(time.time())))
    logger.info("Topology:\n%s", TOPOLOGY)

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    app_helper.init(tgen)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = verify_pim_neighbors(tgen, PIM_TOPO)
    assert result is True, "PIM neighbors failed to establish: {}".format(result)


def teardown_module():
    """Tear down topology."""

    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def prepare_test(tgen):
    """Reset host traffic and kernel mroutes before each testcase."""

    app_helper.stop_all_hosts()
    clear_mroute(tgen)


def verify_register_tx(tgen, dut, interface, min_count=1):
    """Poll until registerTx on the given interface reaches min_count."""

    router = tgen.routers()[dut]

    def _check():
        stats = router.vtysh_cmd("show ip pim interface traffic json", isjson=True)
        return stats[interface]["registerTx"] >= min_count

    _, result = topotest.run_and_expect(_check, True, count=30, wait=1)
    return result


def verify_upstream_json(tgen, dut, source, group, expected_fields):
    """
    Poll show ip pim upstream json until expected fields match for (S,G).

    expected_fields example:
        {"inboundInterface": "fhr-eth1", "firstHopRouter": True,
         "sourceStream": True, "joinState": "Joined"}
    """

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


def verify_fhr_sg_pimreg_iif(tgen, dut, source, group):
    """Return True when (S,G) IIF is pimreg (optional join-before-data state)."""

    router = tgen.routers()[dut]

    def _check():
        mroutes = router.vtysh_cmd("show ip mroute json", isjson=True)
        entry = mroutes.get(group, {}).get(source)
        if not entry:
            return False
        return entry.get("iif") == "pimreg"

    _, result = topotest.run_and_expect(_check, True, count=60, wait=1)
    return result


def verify_end_to_end_path(tgen, group, tc_name):
    """Verify (*,G) and (S,G) mroutes on l1, rp, and fhr."""

    checks = [
        {"dut": "l1", "src": SOURCE, "iif": L1_TO_RP, "oil": L1_TO_RECV},
        {"dut": "l1", "src": "*", "iif": L1_TO_RP, "oil": L1_TO_RECV},
        {"dut": "rp", "src": SOURCE, "iif": RP_TO_FHR, "oil": RP_TO_L1},
        {"dut": "fhr", "src": SOURCE, "iif": FHR_TO_SRC, "oil": FHR_TO_RP},
    ]
    for check in checks:
        result = verify_mroutes(
            tgen, check["dut"], check["src"], group, check["iif"], check["oil"]
        )
        assert result is True, "{}: mroute check failed: {}".format(tc_name, result)


def start_remote_join_and_traffic(tgen, group):
    """IGMP join on h_recv, then source traffic on h_src."""

    assert app_helper.run_join("h_recv", group, join_intf="h_recv-eth0") is True
    assert verify_igmp_groups(tgen, "l1", L1_TO_RECV, group) is True
    assert verify_mroutes(tgen, "l1", "*", group, L1_TO_RP, L1_TO_RECV) is True
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True


def test_wrongvif_compensation_join_before_data(request):
    """
    Case 1: join-before-data at FHR.  Partial MFC from join processing is
    promoted to FHR when WRONGVIF arrives on the source-connected interface.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_JOIN_BEFORE

    step("Send IGMP join from h_recv on LHR before any source traffic")
    assert app_helper.run_join("h_recv", group, join_intf="h_recv-eth0") is True

    step("Verify IGMP join and (*,G) on LHR before source traffic")
    assert verify_igmp_groups(tgen, "l1", L1_TO_RECV, group) is True
    assert verify_mroutes(tgen, "l1", "*", group, L1_TO_RP, L1_TO_RECV) is True

    step("Verify FHR partial (S,G) with pimreg IIF when installed pre-traffic")
    if not verify_fhr_sg_pimreg_iif(tgen, "fhr", SOURCE, group):
        logger.info("%s: no pre-traffic (S,G)/pimreg on FHR; continuing", tc_name)

    step("Start multicast source traffic on FHR-connected host h_src")
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True

    step("Verify end-to-end mroutes after WRONGVIF compensation on FHR")
    verify_end_to_end_path(tgen, group, tc_name)

    step("Verify FHR upstream promoted to FHR with active source stream")
    result = verify_upstream_json(
        tgen,
        "fhr",
        SOURCE,
        group,
        {
            "inboundInterface": FHR_TO_SRC,
            "firstHopRouter": True,
            "sourceStream": True,
        },
    )
    assert result is True, "{}: FHR upstream flags failed: {}".format(tc_name, result)

    step("Verify FHR sent PIM Register toward RP after data arrival")
    assert verify_register_tx(tgen, "fhr", FHR_TO_RP) is True

    write_test_footer(tc_name)


def test_wrongvif_compensation_bidirectional_same_lan(request):
    """
    Case 2: source and receiver on FHR.  Only (*,G) ifchannel exists until
    (S,G) data triggers pim_upstream_activate_stream() on the source LAN.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_BIDIR

    step("Send IGMP join from local receiver h_local on FHR")
    assert app_helper.run_join("h_local", group, join_intf="h_local-eth0") is True

    step("Verify IGMP group on FHR local receiver interface")
    assert verify_igmp_groups(tgen, "fhr", FHR_TO_LOCAL, group) is True

    step("Start multicast source on FHR source interface")
    assert app_helper.run_traffic("h_src", group, bind_intf="h_src-eth0") is True

    step("Verify (S,G) on FHR forwards from source IIF to local receiver OIF")
    result = verify_mroutes(tgen, "fhr", SOURCE, group, FHR_TO_SRC, FHR_TO_LOCAL)
    assert result is True, "{}: FHR (S,G) mroute failed: {}".format(tc_name, result)

    step("Verify (*,G) on FHR also includes local receiver OIF")
    result = verify_mroutes(tgen, "fhr", "*", group, FHR_TO_RP, FHR_TO_LOCAL)
    assert result is True, "{}: FHR (*,G) mroute failed: {}".format(tc_name, result)

    step("Verify FHR upstream for (S,G) uses source-connected IIF")
    result = verify_upstream_iif(tgen, "fhr", FHR_TO_SRC, SOURCE, group)
    assert result is True, "{}: upstream IIF check failed: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_wrongvif_compensation_lhr_compat(request):
    """
    LHR / SPT path: WRONGVIF on l1 (not source-connected) with only (*,G)
    ifchannel is handled by pim_upstream_wrongvif_wrvifwhole_compat().
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_LHR_COMPAT

    step("Establish remote join and source traffic through LHR")
    start_remote_join_and_traffic(tgen, group)
    verify_end_to_end_path(tgen, group, tc_name)

    step("Verify LHR (S,G) upstream uses RP-facing IIF, not FHR role")
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
    assert result is True, "{}: LHR upstream check failed: {}".format(tc_name, result)

    step("Verify LHR is not incorrectly marked as FHR for this (S,G)")
    upstream = tgen.routers()["l1"].vtysh_cmd("show ip pim upstream json", isjson=True)
    assert not upstream[group][SOURCE].get(
        "firstHopRouter"
    ), "{}: LHR must not be FHR for ({},{})".format(tc_name, SOURCE, group)

    write_test_footer(tc_name)


def test_wrongvif_compensation_fhr_frr_restart(request):
    """
    FHR FRR restart: after stop/start, ongoing source traffic must drive
    WRONGVIF compensation to restore (S,G) upstream and mroutes on FHR.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_FHR_RESTART

    step("Establish join-before-data flow and verify baseline mroutes")
    start_remote_join_and_traffic(tgen, group)
    verify_end_to_end_path(tgen, group, tc_name)

    step("Restart FRR on FHR while source traffic continues")
    restart_frr(tgen, "fhr")

    step("Verify FHR (S,G) mroute recovers after FRR restart")
    result = verify_mroutes(tgen, "fhr", SOURCE, group, FHR_TO_SRC, FHR_TO_RP)
    assert result is True, "{}: FHR (S,G) after restart failed: {}".format(
        tc_name, result
    )

    step("Verify FHR upstream and source stream restored after restart")
    result = verify_upstream_json(
        tgen,
        "fhr",
        SOURCE,
        group,
        {
            "inboundInterface": FHR_TO_SRC,
            "firstHopRouter": True,
            "sourceStream": True,
        },
    )
    assert result is True, "{}: FHR upstream after restart failed: {}".format(
        tc_name, result
    )

    step("Verify downstream LHR still receives (S,G) after FHR restart")
    result = verify_mroutes(tgen, "l1", SOURCE, group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: LHR (S,G) after FHR restart failed: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)


def test_wrongvif_compensation_lhr_frr_restart(request):
    """
    LHR FRR restart: WRONGVIF compat must restore (S,G) on the transit LHR
    when FRR state is lost but IGMP join and source traffic continue.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    prepare_test(tgen)
    group = GROUP_LHR_RESTART

    step("Establish join-before-data flow and verify baseline mroutes")
    start_remote_join_and_traffic(tgen, group)
    verify_end_to_end_path(tgen, group, tc_name)

    step("Restart FRR on LHR while join and source traffic continue")
    restart_frr(tgen, "l1")

    step("Re-verify IGMP group on LHR after FRR restart")
    assert verify_igmp_groups(tgen, "l1", L1_TO_RECV, group) is True

    step("Verify LHR (*,G) and (S,G) mroutes recover after FRR restart")
    result = verify_mroutes(tgen, "l1", "*", group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: LHR (*,G) after restart failed: {}".format(
        tc_name, result
    )
    result = verify_mroutes(tgen, "l1", SOURCE, group, L1_TO_RP, L1_TO_RECV)
    assert result is True, "{}: LHR (S,G) after restart failed: {}".format(
        tc_name, result
    )

    step("Verify LHR upstream (S,G) on RP-facing IIF after restart")
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
    assert result is True, "{}: LHR upstream after restart failed: {}".format(
        tc_name, result
    )

    write_test_footer(tc_name)
