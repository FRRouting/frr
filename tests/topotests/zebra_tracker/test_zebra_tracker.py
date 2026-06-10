#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_tracker.py
#
# Copyright (c) 2026 by
# Nvidia Corporation
# Donald Sharp
#

"""
test_zebra_tracker.py: Testing five routers with BGP and RIP peering.

Topology:

              10.0.1.0/24
        .1 +------------+ .2
    +------+ r1-eth0     r2-eth0 [r2]
    |      +------------+
    |
    |      10.0.2.0/24
    |  .1 +------------+ .3
    + r1--+ r1-eth1     r3-eth0 [r3]
    |     +------------+
    |
    |      10.0.3.0/24
    |  .1 +------------+ .4
    +-----+ r1-eth2     r4-eth0 [r4]
    |     +------------+
    |
    |      10.0.4.0/24
    |  .1 +------------+ .5
    +-----+ r1-eth3     r5-eth0 [r5]
          +------------+
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd, pytest.mark.ripd, pytest.mark.sharpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    for rname in ["r1", "r2", "r3", "r4", "r5"]:
        tgen.add_router(rname)

    r1 = tgen.gears["r1"]

    # r1-eth0 <-> r2-eth0 via sw1
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(r1)
    sw1.add_link(tgen.gears["r2"])

    # r1-eth1 <-> r3-eth0 via sw2
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(r1)
    sw2.add_link(tgen.gears["r3"])

    # r1-eth2 <-> r4-eth0 via sw3
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(r1)
    sw3.add_link(tgen.gears["r4"])

    # r1-eth3 <-> r5-eth0 via sw4
    sw4 = tgen.add_switch("sw4")
    sw4.add_link(r1)
    sw4.add_link(tgen.gears["r5"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_RIP, None),
                (TopoRouter.RD_SHARP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Verify that all BGP sessions reach Established state"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that all 4 EBGP sessions on r1 reach Established state")

    r1 = tgen.gears["r1"]

    expected_peers = {
        "10.0.1.2": {"state": "Established"},
        "10.0.2.3": {"state": "Established"},
        "10.0.3.4": {"state": "Established"},
        "10.0.4.5": {"state": "Established"},
    }

    def check_bgp_peers():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast summary json"))
        peers = output.get("peers", {})
        for peer_addr, expected in expected_peers.items():
            if peer_addr not in peers:
                return "peer {} not found".format(peer_addr)
            if peers[peer_addr].get("state") != expected["state"]:
                return "peer {} state is {} expected {}".format(
                    peer_addr,
                    peers[peer_addr].get("state"),
                    expected["state"],
                )
        return None

    _, result = topotest.run_and_expect(check_bgp_peers, None, count=30, wait=1)
    assert result is None, "BGP convergence failed: {}".format(result)


def test_rip_convergence():
    "Verify that RIP routes are learned on all routers"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking that r2-r5 each learn remote networks via RIP")

    # r2 should learn routes to 10.0.2.0/24, 10.0.3.0/24, 10.0.4.0/24 via RIP
    # (it already knows 10.0.1.0/24 as directly connected)
    rip_expected = {
        "r2": ["10.0.2.0/24", "10.0.3.0/24", "10.0.4.0/24"],
        "r3": ["10.0.1.0/24", "10.0.3.0/24", "10.0.4.0/24"],
        "r4": ["10.0.1.0/24", "10.0.2.0/24", "10.0.4.0/24"],
        "r5": ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"],
    }

    def check_rip_routes(rname, expected_routes):
        router = tgen.gears[rname]
        output = json.loads(router.vtysh_cmd("show ip route rip json"))
        for route in expected_routes:
            if route not in output:
                return "{}: RIP route {} not found".format(rname, route)
        return None

    for rname, expected_routes in rip_expected.items():
        _, result = topotest.run_and_expect(
            functools.partial(check_rip_routes, rname, expected_routes),
            None,
            count=30,
            wait=2,
        )
        assert result is None, "RIP convergence failed: {}".format(result)


@pytest.mark.skip
def test_nhg_tracker_show_run():
    "Verify that zebra nexthop-group tracker 20 appears in show running-config on r1"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Verifying 'zebra nexthop-group tracker 20' is present in r1 show running-config"
    )

    r1 = tgen.gears["r1"]

    def check_tracker_present():
        output = r1.vtysh_cmd("show running-config")
        if "zebra nexthop-group tracker 20" not in output:
            return "zebra nexthop-group tracker 20 not found in show run"
        return None

    _, result = topotest.run_and_expect(check_tracker_present, None, count=20, wait=1)
    assert result is None, "NHG tracker show run failed: {}".format(result)

    logger.info(
        "Verifying 'show zebra' on r1 reports NHG Tracker Timeout as 20 seconds"
    )

    def check_show_zebra_tracker_20():
        output = r1.vtysh_cmd("show zebra")
        if not re.search(r"NHG Tracker Timeout\s+20 seconds", output):
            return "NHG Tracker Timeout 20 seconds not found in show zebra"
        return None

    _, result = topotest.run_and_expect(
        check_show_zebra_tracker_20, None, count=20, wait=1
    )
    assert result is None, "show zebra tracker timeout check failed: {}".format(result)


@pytest.mark.skip
def test_nhg_tracker_no_form():
    "Verify that 'no zebra nexthop-group tracker' removes the config from show run"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Issuing 'no zebra nexthop-group tracker' and verifying it is removed from r1 show running-config"
    )

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("configure terminal\nno zebra nexthop-group tracker\nend")

    def check_tracker_absent():
        output = r1.vtysh_cmd("show running-config")
        if "zebra nexthop-group tracker" in output:
            return "zebra nexthop-group tracker still found in show run"
        return None

    _, result = topotest.run_and_expect(check_tracker_absent, None, count=20, wait=1)
    assert result is None, "NHG tracker negation failed: {}".format(result)

    logger.info(
        "Verifying 'show zebra' on r1 reports NHG Tracker Timeout back to default 60 seconds"
    )

    def check_show_zebra_tracker_default():
        output = r1.vtysh_cmd("show zebra")
        if not re.search(r"NHG Tracker Timeout\s+60 seconds", output):
            return "NHG Tracker Timeout 60 seconds not found in show zebra"
        return None

    _, result = topotest.run_and_expect(
        check_show_zebra_tracker_default, None, count=20, wait=1
    )
    assert result is None, "show zebra tracker default timeout check failed: {}".format(
        result
    )


def _check_tracker_routes(router, nhg_id, tracker_id, expected_prefixes, table):
    """
    Verify the named tracker's matched/unmatched route table contains
    exactly the expected_prefixes set.

    router            : topogen router gear (e.g. tgen.gears["r1"]).
    nhg_id            : installed NHG id whose trackers are being inspected.
    tracker_id        : trackerId of the target tracker (multiple trackers
                        may be present, e.g. when one is flushing).
    expected_prefixes : list of prefix strings, e.g. ["45.1.1.1/32", ...].
    table             : "matched" or "unmatched".

    Returns None on success or an error string suitable for use with
    topotest.run_and_expect.
    """
    out = router.vtysh_cmd(
        "show nexthop-group rib {} tracker routes json".format(nhg_id)
    )
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "tracker routes json parse failed: {}".format(out[:200])

    trackers = data.get("trackers", [])
    t = next((tt for tt in trackers if tt.get("trackerId") == tracker_id), None)
    if t is None:
        return "trackerId {} not found among {} tracker(s)".format(
            tracker_id, len(trackers)
        )

    routes_key = "matchedRoutes" if table == "matched" else "unmatchedRoutes"
    routes = t.get(routes_key, [])
    found = sorted(r.get("prefix") for r in routes)
    expected = sorted(expected_prefixes)
    if found != expected:
        return "{} table content mismatch: expected {} ({} entries), got {} ({} entries)".format(
            table, expected, len(expected), found, len(found)
        )
    return None


def _check_tracker_state(
    router,
    nhg_id,
    tracker_id,
    iface_name=None,
    ifindex=None,
    event=None,
    expected_re_count=None,
    matched_count=None,
    unmatched_count=None,
    snapshot=None,
):
    """
    Verify selected fields of a specific tracker (by trackerId).  Any
    argument passed as None is skipped.

    router            : topogen router gear.
    nhg_id            : NHG id whose trackers are being inspected.
    tracker_id        : trackerId of the target tracker.
    iface_name        : expected interfaceName (e.g. "r1-eth3").  Note
                        the JSON field is only emitted when the
                        tracker's ifindex resolves to a known
                        interface (ECMP_CHANGE trackers have
                        ifindex=0 and no "interfaceName" field).
    ifindex           : expected ifindex (integer); use 0 for the
                        ECMP_CHANGE / no-interface case.
    event             : expected event string ("UP" / "DOWN" /
                        "ECMP_CHANGE").
    expected_re_count : expected expectedReCount value.
    matched_count     : expected matchedRoutes count.
    unmatched_count   : expected unmatchedRoutes count.
    snapshot          : list of bool, one per nexthop, expressing the
                        expected "active" flag for snapshotNexthops[i].

    Returns None on success or an error string.
    """
    out = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show nexthop-group rib json parse failed: {}".format(out[:200])

    nhe = data.get(str(nhg_id))
    if not nhe:
        return "NHE id {} not found".format(nhg_id)
    trackers = nhe.get("trackers", [])
    t = next((tt for tt in trackers if tt.get("trackerId") == tracker_id), None)
    if t is None:
        return "trackerId {} not found among {} tracker(s)".format(
            tracker_id, len(trackers)
        )

    if iface_name is not None and t.get("interfaceName") != iface_name:
        return "T{} interfaceName expected {}, got {}".format(
            tracker_id, iface_name, t.get("interfaceName")
        )
    if ifindex is not None and t.get("ifindex") != ifindex:
        return "T{} ifindex expected {}, got {}".format(
            tracker_id, ifindex, t.get("ifindex")
        )
    if event is not None and t.get("event") != event:
        return "T{} event expected {}, got {}".format(
            tracker_id, event, t.get("event")
        )
    if expected_re_count is not None and t.get("expectedReCount") != expected_re_count:
        return "T{} expectedReCount expected {}, got {}".format(
            tracker_id, expected_re_count, t.get("expectedReCount")
        )
    if matched_count is not None and t.get("matchedRoutes") != matched_count:
        return "T{} matchedRoutes expected {}, got {}".format(
            tracker_id, matched_count, t.get("matchedRoutes")
        )
    if unmatched_count is not None and t.get("unmatchedRoutes") != unmatched_count:
        return "T{} unmatchedRoutes expected {}, got {}".format(
            tracker_id, unmatched_count, t.get("unmatchedRoutes")
        )
    if snapshot is not None:
        snap = t.get("snapshotNexthops", [])
        if len(snap) != len(snapshot):
            return "T{} snapshot length expected {}, got {}".format(
                tracker_id, len(snapshot), len(snap)
            )
        for i, want_active in enumerate(snapshot):
            got_active = snap[i].get("active", False)
            if got_active != want_active:
                return "T{} snapshot NH{} active expected {}, got {}".format(
                    tracker_id, i, want_active, got_active
                )
    return None


def _check_nhg_deletion_pending_or_gone(router, nhg_id):
    """
    Verify the NHG either no longer exists in the RIB (already
    released) or has its deletion timer scheduled (the JSON output
    exposes this as a non-empty "timeToDeletion" string).  This is
    the expected post-state after dup-consolidation migrates all REs
    out of the losing NHE.  `refCount` alone is not reliable -- a
    keep-around NHG can sit at refCount=1 indefinitely.
    """
    out = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show nexthop-group rib json parse failed: {}".format(out[:200])
    if not data:
        return None
    nhe = data.get(str(nhg_id))
    if not nhe:
        return None
    ttd = nhe.get("timeToDeletion")
    if not ttd:
        return (
            "NHG {} expected deletion timer (timeToDeletion field "
            "non-empty) or NHE absent; got refCount={}, "
            "timeToDeletion={!r}".format(nhg_id, nhe.get("refCount"), ttd)
        )
    return None


def _check_no_trackers(router, nhg_id):
    """
    Verify the NHE has no active trackers.  The `trackers` JSON field
    is omitted entirely when the tracker list is empty.
    """
    out = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show nexthop-group rib json parse failed: {}".format(out[:200])
    nhe = data.get(str(nhg_id))
    if not nhe:
        return "NHE id {} not found".format(nhg_id)
    trackers = nhe.get("trackers", [])
    if trackers:
        ids = [t.get("trackerId") for t in trackers]
        return "expected no trackers on NHG {}, found {}: {}".format(
            nhg_id, len(trackers), ids
        )
    return None


def _check_nhg_nexthops(router, nhg_id, expected_ips):
    """
    Verify the NHG's resolved nexthop list contains exactly expected_ips
    """
    out = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show nexthop-group rib json parse failed: {}".format(out[:200])
    nhe = data.get(str(nhg_id))
    if not nhe:
        return "NHE id {} not found".format(nhg_id)
    nhs = nhe.get("nexthops", [])
    found = sorted(n.get("ip") for n in nhs if n.get("ip"))
    expected = sorted(expected_ips)
    if len(found) != len(expected):
        return "NHG {} nexthop count mismatch: expected {} ({}), got {} ({})".format(
            nhg_id, len(expected), expected, len(found), found
        )
    if found != expected:
        return "NHG {} nexthop set mismatch: expected {}, got {}".format(
            nhg_id, expected, found
        )
    return None


def _scale_weights_to_kernel(weights):
    """Mirror zebra's weight rescaling: largest weight maps to 255."""
    if not weights:
        return weights
    max_w = max(weights)
    if max_w == 0:
        return [0] * len(weights)
    return [(w * 255) // max_w for w in weights]


def _check_nhg_nexthop_weights(router, nhg_id, expected_weights):
    """Verify per-NH weights in `nhg_id` match `expected_weights` (already kernel-scaled)."""
    out = router.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show nexthop-group rib json parse failed: {}".format(out[:200])
    nhe = data.get(str(nhg_id))
    if not nhe:
        return "NHE id {} not found".format(nhg_id)
    found = {n.get("ip"): n.get("weight") for n in nhe.get("nexthops", [])
             if n.get("ip")}
    for ip, expected in expected_weights.items():
        got = found.get(ip)
        if got != expected:
            return "NHG {} nh {} weight mismatch: expected {}, got {}".format(
                nhg_id, ip, expected, got
            )
    return None


def _check_routes_use_nhg(router, prefixes, nhg_id):
    """
    Verify each prefix in `prefixes` is installed with
    installedNexthopGroupId == nhg_id.
    """
    out = router.vtysh_cmd("show ip route nexthop-group json")
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show ip route nexthop-group json parse failed: {}".format(out[:200])
    for prefix in prefixes:
        entries = data.get(prefix)
        if not entries:
            return "route {} not found in nexthop-group routes".format(prefix)
        got = entries[0].get("installedNexthopGroupId")
        if got != nhg_id:
            return "route {} expected installedNexthopGroupId={}, got {}".format(
                prefix, nhg_id, got
            )
    return None


# -----------------------------------------------------------------------------
# Kernel-side verification helpers
# -----------------------------------------------------------------------------
# These query the Linux kernel FIB / NHG table directly via `ip -j ...` and
# confirm that what zebra reports matches what's actually programmed.  We add
# them alongside the zebra-side helpers so each flush / dup-consolidation
# checkpoint validates both layers.


def _check_kernel_routes_use_nhid(router, prefixes, expected_nhid):
    """
    Verify every prefix in `prefixes` is present in the kernel FIB and bound
    to nhid == expected_nhid.
    """
    for prefix in prefixes:
        out = router.cmd("ip -j route show {}".format(prefix))
        try:
            data = json.loads(out) if out.strip() else []
        except (json.JSONDecodeError, ValueError):
            return "kernel: `ip -j route show {}` parse failed: {}".format(
                prefix, out[:200]
            )
        if not data:
            return "kernel: route {} not present".format(prefix)
        got = data[0].get("nhid")
        if got != expected_nhid:
            return "kernel: route {} expected nhid={}, got nhid={}".format(
                prefix, expected_nhid, got
            )
    return None


def _check_kernel_nhg_nexthops(router, nhid, expected_ips):
    """
    Verify the kernel NHG `nhid` resolves to exactly `expected_ips`
    """
    out = router.cmd("ip -j nexthop show id {}".format(nhid))
    try:
        data = json.loads(out) if out.strip() else []
    except (json.JSONDecodeError, ValueError):
        return "kernel: `ip -j nexthop show id {}` parse failed: {}".format(
            nhid, out[:200]
        )
    if not data:
        return "kernel: NHG id {} not present".format(nhid)
    entry = data[0]
    group = entry.get("group", [])
    if group:
        found_ips = []
        for member in group:
            sid = member.get("id")
            sout = router.cmd("ip -j nexthop show id {}".format(sid))
            try:
                sdata = json.loads(sout) if sout.strip() else []
            except (json.JSONDecodeError, ValueError):
                return "kernel: NHG {} singleton id {} parse failed".format(
                    nhid, sid
                )
            if not sdata:
                return "kernel: NHG {} member singleton id {} not present".format(
                    nhid, sid
                )
            gw = sdata[0].get("gateway")
            if gw:
                found_ips.append(gw)
    else:
        gw = entry.get("gateway")
        found_ips = [gw] if gw else []
    found = sorted(found_ips)
    expected = sorted(expected_ips)
    if found != expected:
        return (
            "kernel: NHG {} nexthop mismatch: expected {} ({} entries), "
            "got {} ({} entries)".format(
                nhid, expected, len(expected), found, len(found)
            )
        )
    return None


def _check_kernel_state(router, nhid, expected_ips, prefixes):
    """
    Combined helper: verify (a) the kernel NHG `nhid` resolves to
    `expected_ips`, and (b) every prefix in `prefixes` is bound to that nhid.
    Returns None on success or an error string.
    """
    err = _check_kernel_nhg_nexthops(router, nhid, expected_ips)
    if err:
        return err
    return _check_kernel_routes_use_nhid(router, prefixes, nhid)


def test_nhg_tracker_sharp_routes_parking():
    """
    Verify tracker creation, RE parking in a tracker, tracker absorption
    during new tracker creation, tracker flush, and NHG rework.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Set tracker timer to 600 seconds so trackers do not expire during the test
    r1.vtysh_cmd("configure terminal\nzebra nexthop-group tracker 3600\nend")

    # Step 1: Install 8 routes with 4-way ECMP (nexthops = peer IPs on r1's links)
    logger.info("Step 1: Install 8 sharp routes with 4-way ECMP")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.5 10"
    )

    def check_route_installed():
        out = r1.vtysh_cmd("show ip route 45.1.1.1 json")
        try:
            data = json.loads(out)
        except json.JSONDecodeError:
            return "show ip route 45.1.1.1 json failed or invalid"
        key = "45.1.1.1/32"
        if key not in data or not data[key]:
            return "route 45.1.1.1/32 not found"
        entry = data[key][0]
        if not entry.get("installed", False):
            return "route 45.1.1.1/32 not installed"
        return None

    _, result = topotest.run_and_expect(check_route_installed, None, count=30, wait=1)
    assert result is None, "Route 45.1.1.1 not installed: {}".format(result)

    out = r1.vtysh_cmd("show ip route 45.1.1.1 json")
    data = json.loads(out)
    installed_nhg_id = data["45.1.1.1/32"][0].get("installedNexthopGroupId")
    assert installed_nhg_id is not None, "installedNexthopGroupId not found"
    logger.info("installedNexthopGroupId = %s", installed_nhg_id)

    # Kernel sanity: all 10 prefixes should be installed on installed_nhg_id
    # with the original 4-way ECMP content.
    all_10_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]

    def check_kernel_initial():
        return _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.5"],
            all_10_prefixes,
        )

    _, result = topotest.run_and_expect(check_kernel_initial, None, count=30, wait=1)
    assert result is None, "kernel initial state check failed: {}".format(result)

    # Step 2: Link r1-eth3 down -> tracker T1 created
    logger.info("Step 2: Shut r1-eth3 to create tracker T1")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth3\nshutdown\nend")

    def check_t1_created():
        # T1 created on r1-eth3 down; snapshot has eth0/1/2 active, eth3 inactive.
        return _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            iface_name="r1-eth3",
            event="DOWN",
            snapshot=[True, True, True, False],
        )

    _, result = topotest.run_and_expect(check_t1_created, None, count=20, wait=1)
    assert result is None, "T1 creation check failed: {}".format(result)

    expected_prefixes_6 = ["45.1.1.{}/32".format(i) for i in range(1, 7)]

    # Send 6 routes with 3-way ECMP matching T1's snapshot (eth0, eth1,
    # eth2 active).  These should park into T1's matched table.
    logger.info("Send 6 sharp routes with 3-way ECMP (match T1)")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4 6"
    )

    def check_t1_matched_6():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            iface_name="r1-eth3",
            event="DOWN",
            expected_re_count=10,
            matched_count=6,
            unmatched_count=0,
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_prefixes_6, "matched"
        )
        if err:
            return "T1 matched table: " + err
        return None

    _, result = topotest.run_and_expect(check_t1_matched_6, None, count=30, wait=1)
    assert result is None, "T1 matched=6 check failed: {}".format(result)

    # Step 3: Shut r1-eth2 -> T2 is created on the same NHE. T1 is absorbed into T2.
    # All REs form T1's should move into T2's unmatched table
    logger.info("Step 3: Shut r1-eth2 to create tracker T2 (T1 absorbs into T2)")
    r1.vtysh_cmd("configure terminal\ninterface r1-eth2\nshutdown\nend")

    def check_t2_absorbed_t1():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=2,
            iface_name="r1-eth2",
            event="DOWN",
            expected_re_count=10,
            matched_count=0,
            unmatched_count=6,
            snapshot=[True, True, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 2, expected_prefixes_6, "unmatched"
        )
        if err:
            return "T2 unmatched table: " + err
        return None

    _, result = topotest.run_and_expect(check_t2_absorbed_t1, None, count=30, wait=1)
    assert result is None, "T2 absorb-T1 check failed: {}".format(result)

    # Step 4: Re-install the same 6 prefixes (45.1.1.1..6) with 2-way
    # ECMP matching T2's snapshot (eth0, eth1).  The 6 REs previously in
    # T2's unmatched table are evicted and re-parked into T2's matched
    # table.
    logger.info("Step 4: Send 6 sharp routes with 2-way ECMP (match T2)")
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3 6"
    )

    def check_t2_matched_6():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=2,
            iface_name="r1-eth2",
            event="DOWN",
            expected_re_count=10,
            matched_count=6,
            unmatched_count=0,
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 2, expected_prefixes_6, "matched"
        )
        if err:
            return "T2 matched table: " + err
        return None

    _, result = topotest.run_and_expect(check_t2_matched_6, None, count=30, wait=1)
    assert result is None, "T2 matched=6 check failed: {}".format(result)

    # Step 5: Send the remaining 4 routes (45.1.1.7..10) with the same
    # 2-way ECMP.  Total parked REs reach expectedReCount=10, which
    # triggers the tracker flush.  After flush:
    #   - T2 is freed (tracker chain empty).
    #   - NHG (id installed_nhg_id) is reworked in-place to 2-way ECMP
    #     [10.0.1.2 (r1-eth0), 10.0.2.3 (r1-eth1)] -- NHG id preserved.
    #   - All 10 routes (45.1.1.1..10) point to the same NHG id.
    logger.info(
        "Step 5: Send 4 sharp routes (45.1.1.7..10) to fill T2 and trigger flush"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.7 nexthops 10.0.1.2,10.0.2.3 4"
    )

    def check_flush_completed():
        # NHG reworked to 2-way ECMP (id preserved).
        err = _check_nhg_nexthops(
            r1, installed_nhg_id, ["10.0.1.2", "10.0.2.3"]
        )
        if err:
            return err
        # All 10 sharp routes point to the same (preserved) NHG id.
        expected_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]
        err = _check_routes_use_nhg(r1, expected_prefixes, installed_nhg_id)
        if err:
            return err
        # Flush freed the tracker chain -- no trackers should remain.
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # Kernel must agree: NHG bound to 2-way, all 10 routes use it.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3"],
            expected_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(check_flush_completed, None, count=60, wait=1)
    assert result is None, "Tracker flush completion check failed: {}".format(result)

    # Step 6: NHG (installed_nhg_id) is now 2-way [10.0.1.2 (eth0),
    # 10.0.2.3 (eth1)] with no active trackers.  Install 1 route with
    # 3-way ECMP [10.0.1.2, 10.0.2.3, 10.0.3.4].
    # NHG -- an ECMP change.  A new tracker T1 is created on the same
    # NHE with:
    #   - event=ECMP_CHANGE (no interface; ifindex=0, "interfaceName"
    #     field is omitted from JSON).
    #   - snapshot = the incoming 3-way NHG; nexthops captured before
    #     activation so all three are inactive.
    #   - expectedReCount = 10 (the count of REs currently consuming
    #     the parent NHE = installed_nhg_id, used to gate the flush).
    # The incoming RE (45.1.1.1) is parked in T1's matched table.
    logger.info(
        "Step 6: Send 1 sharp route with 3-way ECMP (10.0.3.4 on DOWN eth2) "
        "to create new T1 (ECMP_CHANGE) on the same NHG"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4 1"
    )

    def check_t1_ecmp_change_created():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=10,
            matched_count=1,
            unmatched_count=0,
            snapshot=[False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, ["45.1.1.1/32"], "matched"
        )
        if err:
            return "T1 matched table: " + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_ecmp_change_created, None, count=30, wait=1
    )
    assert result is None, "T1 (ECMP_CHANGE) creation+park check failed: {}".format(
        result
    )

    # Step 7: T1 is the ECMP_CHANGE tracker with a 3-way snapshot
    # [10.0.1.2, 10.0.2.3, 10.0.3.4].  Install 45.1.1.1..9 with the
    # 2-way ECMP [10.0.1.2, 10.0.2.3].  Every RE that touches the
    # parent NHE (installed_nhg_id) while a tracker is active is
    # parked; the incoming 2-way NHG does NOT match T1's 3-way
    # snapshot, so all 9 REs land in T1's unmatched table.  The
    # previously-matched 45.1.1.1 is rewritten as 2-way and moves
    # from matched to unmatched.  Net result: matched=0, unmatched=9.
    logger.info(
        "Step 7: Send 9 sharp routes (45.1.1.1..9) with 2-way ECMP "
        "(do not match T1's 3-way snapshot)"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3 9"
    )
    expected_unmatched_9 = ["45.1.1.{}/32".format(i) for i in range(1, 10)]

    def check_t1_unmatched_9():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=10,
            matched_count=0,
            unmatched_count=9,
            snapshot=[False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_unmatched_9, "unmatched"
        )
        if err:
            return "T1 unmatched table: " + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_unmatched_9, None, count=30, wait=1
    )
    assert result is None, "T1 unmatched=9 check failed: {}".format(result)

    # Step 8: Install the 10th RE (45.1.1.10) with the same 2-way
    # ECMP.  Total parked REs reach expectedReCount=10 which triggers
    # the tracker flush.  Afterwards:
    #   - T1 is freed (no trackers remain).
    #   - NHG (installed_nhg_id) stays 2-way [10.0.1.2, 10.0.2.3]
    #   - All 10 routes (45.1.1.1..10) point to that same NHG id.
    logger.info(
        "Step 8: Send 1 sharp route (45.1.1.10) to fill T1 and trigger flush"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.10 nexthops 10.0.1.2,10.0.2.3 1"
    )

    def check_t1_flush_completed():
        err = _check_nhg_nexthops(
            r1, installed_nhg_id, ["10.0.1.2", "10.0.2.3"]
        )
        if err:
            return err
        expected_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]
        err = _check_routes_use_nhg(r1, expected_prefixes, installed_nhg_id)
        if err:
            return err
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # Kernel must agree: NHG still 2-way, all 10 routes use it.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3"],
            expected_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        check_t1_flush_completed, None, count=60, wait=1
    )
    assert result is None, "T1 (ECMP_CHANGE) flush completion check failed: {}".format(
        result
    )

    # Step 9: Bring r1-eth2 and r1-eth3 back UP. No tracker should be created.
    # because the installed NHG holds only NHs on r1-eth0 and r1-eth1.
    logger.info("Step 9: Bring r1-eth2 and r1-eth3 UP (no tracker expected)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth2\nno shutdown\n"
        "interface r1-eth3\nno shutdown\n"
        "end"
    )

    def check_no_tracker_on_ifup():
        err = _check_nhg_nexthops(
            r1, installed_nhg_id, ["10.0.1.2", "10.0.2.3"]
        )
        if err:
            return err
        expected_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]
        err = _check_routes_use_nhg(r1, expected_prefixes, installed_nhg_id)
        if err:
            return err
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # Kernel must not have changed -- still 2-way, all routes use it.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3"],
            expected_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        check_no_tracker_on_ifup, None, count=30, wait=1
    )
    assert result is None, "eth2/eth3 UP no-tracker check failed: {}".format(result)

    # Step 10: All 10 routes currently use installed_nhg_id (2-way
    # [10.0.1.2, 10.0.2.3]) and all 4 interfaces are UP.  Install
    # 45.1.1.1..6 with 4-way ECMP [eth0, eth1, eth2, eth3].  The
    # incoming NHG content differs from the installed NHG -- an
    # ECMP_CHANGE.  A new tracker T1 is created on installed_nhg_id:
    #   - event=ECMP_CHANGE, ifindex=0.
    #   - snapshot = the incoming 4-way NHG (nexthops captured before
    #     activation, so all four show as inactive).
    #   - expectedReCount = 10 (count of REs on the parent NHE).
    # All 6 incoming REs match T1's 4-way snapshot, so they land in
    # matched.
    logger.info(
        "Step 10: Send 6 sharp routes (45.1.1.1..6) with 4-way ECMP "
        "to create new T1 (ECMP_CHANGE)"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.4 6"
    )
    expected_matched_4way_6 = ["45.1.1.{}/32".format(i) for i in range(1, 7)]

    def check_t1_4way_matched_6():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=10,
            matched_count=6,
            unmatched_count=0,
            snapshot=[False, False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_matched_4way_6, "matched"
        )
        if err:
            return "T1 matched table: " + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_4way_matched_6, None, count=30, wait=1
    )
    assert result is None, "T1 (4-way) matched=6 check failed: {}".format(result)

    # Step 11: Install 45.1.1.3..9 with 3-way ECMP
    # [10.0.1.2, 10.0.2.3, 10.0.3.4].  The 3-way NHG does NOT match
    # T1's 4-way snapshot, so:
    #   - 45.1.1.3..6 (previously matched as 4-way) get rewritten to
    #     3-way and move from matched to unmatched.
    #   - 45.1.1.7..9 (previously direct consumers of the parent NHE)
    #     get parked into unmatched.
    # After: matched = [45.1.1.1, 45.1.1.2], unmatched = [45.1.1.3..9].
    logger.info(
        "Step 11: Send 7 sharp routes (45.1.1.3..9) with 3-way ECMP "
        "(do not match T1's 4-way snapshot)"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.3 nexthops 10.0.1.2,10.0.2.3,10.0.3.4 7"
    )
    expected_matched_4way_2 = ["45.1.1.{}/32".format(i) for i in range(1, 3)]
    expected_unmatched_3way_7 = ["45.1.1.{}/32".format(i) for i in range(3, 10)]

    def check_t1_partial_unmatched():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=10,
            matched_count=2,
            unmatched_count=7,
            snapshot=[False, False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_matched_4way_2, "matched"
        )
        if err:
            return "T1 matched table: " + err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_unmatched_3way_7, "unmatched"
        )
        if err:
            return "T1 unmatched table: " + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_partial_unmatched, None, count=30, wait=1
    )
    assert result is None, "T1 matched=2/unmatched=7 check failed: {}".format(result)

    # Step 12: Install 45.1.1.10 with 3-way ECMP.  Total parked REs
    # reach expectedReCount=10 (matched=2 + unmatched=8) which
    # triggers the tracker flush.  The unmatched group is the larger
    # bucket (8 vs 2), so it wins: NHG (installed_nhg_id) is reworked
    # in-place to 3-way [10.0.1.2, 10.0.2.3, 10.0.3.4] -- NHG id is
    # preserved.  Tracker is freed.  The 8 unmatched REs
    # (45.1.1.3..10) use installed_nhg_id; the 2 losing 4-way REs
    # (45.1.1.1, 45.1.1.2) are re-resolved to a separate NHE.
    logger.info(
        "Step 12: Send 1 sharp route (45.1.1.10) with 3-way ECMP "
        "to fill T1 and trigger flush"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.10 nexthops 10.0.1.2,10.0.2.3,10.0.3.4 1"
    )

    def check_t1_3way_flush_completed():
        err = _check_nhg_nexthops(
            r1, installed_nhg_id, ["10.0.1.2", "10.0.2.3", "10.0.3.4"]
        )
        if err:
            return err
        expected_3way_prefixes = ["45.1.1.{}/32".format(i) for i in range(3, 11)]
        err = _check_routes_use_nhg(r1, expected_3way_prefixes, installed_nhg_id)
        if err:
            return err
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # Kernel: NHG reworked to 3-way; 45.1.1.3..10 bound to it.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4"],
            expected_3way_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        check_t1_3way_flush_completed, None, count=60, wait=1
    )
    assert result is None, "T1 (3-way winner) flush check failed: {}".format(result)

    # Capture the NHG id used by the 4-way losers (45.1.1.1, 45.1.1.2).
    # They no longer match installed_nhg_id (now 3-way) so zebra
    # re-resolves them to a separate NHE that carries their 4-way
    # content.  Record that id for any follow-up steps and assert
    # both losers share the same NHG (they were installed with the
    # same content).
    loser_nhg_ids = {}
    out = r1.vtysh_cmd("show ip route nexthop-group json")
    rib = json.loads(out)
    for p in ("45.1.1.1/32", "45.1.1.2/32"):
        entry = rib.get(p, [])
        assert entry, "loser prefix {} not in RIB".format(p)
        loser_nhg_ids[p] = entry[0].get("installedNexthopGroupId")
    logger.info(
        "4-way loser NHG ids: 45.1.1.1=%s 45.1.1.2=%s (parent 3-way NHG id=%s)",
        loser_nhg_ids["45.1.1.1/32"],
        loser_nhg_ids["45.1.1.2/32"],
        installed_nhg_id,
    )
    assert loser_nhg_ids["45.1.1.1/32"] == loser_nhg_ids["45.1.1.2/32"], (
        "4-way losers expected to share an NHG id, got {}".format(loser_nhg_ids)
    )
    loser_nhg_id_4way = loser_nhg_ids["45.1.1.1/32"]
    assert loser_nhg_id_4way is not None, "loser NHG id is None"
    assert loser_nhg_id_4way != installed_nhg_id, (
        "losers expected to be on a separate NHE; got the parent id {}".format(
            installed_nhg_id
        )
    )

    # Kernel: loser NHG-A is 4-way and binds 45.1.1.1, 45.1.1.2.
    def check_kernel_loser_4way():
        return _check_kernel_state(
            r1,
            loser_nhg_id_4way,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.4"],
            ["45.1.1.1/32", "45.1.1.2/32"],
        )

    _, result = topotest.run_and_expect(
        check_kernel_loser_4way, None, count=30, wait=1
    )
    assert result is None, "kernel loser-4way state check failed: {}".format(result)

    # Step 13: Current state:
    #   - installed_nhg_id is 3-way [10.0.1.2, 10.0.2.3, 10.0.3.4] with
    #     8 consumers (45.1.1.3..10).
    #   - loser_nhg_id_4way (NHG-A) is 4-way with 2 consumers
    #     (45.1.1.1, 45.1.1.2).
    # Install 45.1.1.1..8 with 4-way ECMP [eth0, eth1, eth2, eth3]:
    #   - 45.1.1.1, 45.1.1.2 are already 4-way on NHG-A; their
    #     content does not change, so no tracker is created on
    #     NHG-A.
    #   - 45.1.1.3..8 transition from 3-way to 4-way -- an
    #     ECMP_CHANGE on installed_nhg_id.  A new T1 is created on
    #     installed_nhg_id with:
    #       expected_re=8 (current consumers of the parent NHE),
    #       snapshot = the incoming 4-way NHG (all four inactive),
    #       matched=6 (45.1.1.3..8), unmatched=0.
    logger.info(
        "Step 13: Send 8 sharp routes (45.1.1.1..8) with 4-way ECMP "
        "to create new T1 on installed_nhg_id"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.4 8"
    )
    expected_matched_4way_3to8 = ["45.1.1.{}/32".format(i) for i in range(3, 9)]

    def check_t1_4way_on_parent():
        err = _check_tracker_state(
            r1,
            installed_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=8,
            matched_count=6,
            unmatched_count=0,
            snapshot=[False, False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, installed_nhg_id, 1, expected_matched_4way_3to8, "matched"
        )
        if err:
            return "T1 matched table: " + err
        # NHG-A (the existing 4-way NHE) must NOT get a tracker:
        # 45.1.1.1, 45.1.1.2 already have its content so there is
        # no ECMP change on that NHE.
        err = _check_no_trackers(r1, loser_nhg_id_4way)
        if err:
            return "NHG-A (loser 4-way) unexpected tracker: " + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_4way_on_parent, None, count=30, wait=1
    )
    assert result is None, "T1 (4-way on parent) check failed: {}".format(result)

    # Step 14: Install 45.1.1.9, 45.1.1.10 with 3-way ECMP -- same
    # content as the current parent NHG.  T1's snapshot is 4-way, so
    # these 2 REs do NOT match and land in unmatched.  Total parked
    # reaches matched=6 + unmatched=2 = 8 = expected_re_count which
    # triggers the flush.
    # The matched group (6) is the larger bucket so it wins:
    #   - installed_nhg_id is reworked in-place to 4-way
    #     [10.0.1.2, 10.0.2.3, 10.0.3.4, 10.0.4.4]; id preserved.
    #   - 45.1.1.9, 45.1.1.10 (the 3-way losers) are re-resolved to
    #     a fresh 3-way NHE -- captured as new_nhg_id_3way.
    # After the rework, installed_nhg_id is content-identical to
    # NHG-A (loser_nhg_id_4way); the consolidation event migrates
    # NHG-A's two REs (45.1.1.1, 45.1.1.2) onto installed_nhg_id and
    # arms NHG-A's deletion timer (refCount drops to 0).
    logger.info(
        "Step 14: Send 2 sharp routes (45.1.1.9, 45.1.1.10) with 3-way ECMP "
        "to fill T1 and trigger flush + dup consolidation"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.9 nexthops 10.0.1.2,10.0.2.3,10.0.3.4 2"
    )

    def check_t1_4way_winner_flush():
        # Parent NHE reworked to 4-way, id preserved.
        err = _check_nhg_nexthops(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.4"],
        )
        if err:
            return err
        # After dup-consolidation, 45.1.1.1..8 all use installed_nhg_id.
        expected_4way_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 9)]
        err = _check_routes_use_nhg(r1, expected_4way_prefixes, installed_nhg_id)
        if err:
            return err
        # Tracker chain is empty on installed_nhg_id.
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # NHG-A lost all its consumers -- either already released or
        # sitting at refCount=0 with the deletion timer running.
        err = _check_nhg_deletion_pending_or_gone(r1, loser_nhg_id_4way)
        if err:
            return "NHG-A deletion-pending check: " + err
        # Kernel: installed_nhg_id is 4-way and binds 45.1.1.1..8.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.4"],
            expected_4way_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        check_t1_4way_winner_flush, None, count=60, wait=1
    )
    assert result is None, "T1 (4-way winner) flush + dup-consolidation check failed: {}".format(
        result
    )

    # Capture the new 3-way NHG used by the losers (45.1.1.9,
    # 45.1.1.10) for any follow-up steps.  Assert both losers share
    # one NHG and that it is distinct from installed_nhg_id.
    loser_nhg_ids_3way = {}
    out = r1.vtysh_cmd("show ip route nexthop-group json")
    rib = json.loads(out)
    for p in ("45.1.1.9/32", "45.1.1.10/32"):
        entry = rib.get(p, [])
        assert entry, "loser prefix {} not in RIB".format(p)
        loser_nhg_ids_3way[p] = entry[0].get("installedNexthopGroupId")
    logger.info(
        "3-way loser NHG ids: 45.1.1.9=%s 45.1.1.10=%s (parent 4-way NHG id=%s)",
        loser_nhg_ids_3way["45.1.1.9/32"],
        loser_nhg_ids_3way["45.1.1.10/32"],
        installed_nhg_id,
    )
    assert (
        loser_nhg_ids_3way["45.1.1.9/32"]
        == loser_nhg_ids_3way["45.1.1.10/32"]
    ), "3-way losers expected to share an NHG id, got {}".format(loser_nhg_ids_3way)
    new_nhg_id_3way = loser_nhg_ids_3way["45.1.1.9/32"]
    assert new_nhg_id_3way is not None, "new 3-way NHG id is None"
    assert new_nhg_id_3way != installed_nhg_id, (
        "3-way losers expected to be on a separate NHE; got the parent id {}".format(
            installed_nhg_id
        )
    )

    # Kernel: new 3-way loser NHG is 3-way and binds 45.1.1.9, 45.1.1.10.
    def check_kernel_new_loser_3way():
        return _check_kernel_state(
            r1,
            new_nhg_id_3way,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4"],
            ["45.1.1.9/32", "45.1.1.10/32"],
        )

    _, result = topotest.run_and_expect(
        check_kernel_new_loser_3way, None, count=30, wait=1
    )
    assert result is None, "kernel new-3way-loser state check failed: {}".format(
        result
    )

    # Step 15: Current state:
    #   - installed_nhg_id is 4-way; 45.1.1.1..8 on it.
    #   - new_nhg_id_3way is 3-way; 45.1.1.9, 45.1.1.10 on it.
    # Install 45.1.1.1..9 with 4-way ECMP:
    #   - 45.1.1.1..8 already have this content on installed_nhg_id;
    #     no ECMP change on that NHE so no tracker is created there.
    #   - 45.1.1.9 transitions from 3-way to 4-way -- an ECMP_CHANGE
    #     on new_nhg_id_3way.  T1 is created on new_nhg_id_3way:
    #       expected_re=2 (consumers of that NHE),
    #       snapshot = incoming 4-way (all inactive),
    #       matched=1 (45.1.1.9), unmatched=0.
    logger.info(
        "Step 15: Send 9 sharp routes (45.1.1.1..9) with 4-way ECMP -- "
        "T1 created on prior loser NHG %s for 45.1.1.9",
        new_nhg_id_3way,
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.4 9"
    )

    def check_t1_on_prior_loser():
        err = _check_tracker_state(
            r1,
            new_nhg_id_3way,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=2,
            matched_count=1,
            unmatched_count=0,
            snapshot=[False, False, False, False],
        )
        if err:
            return err
        err = _check_tracker_routes(
            r1, new_nhg_id_3way, 1, ["45.1.1.9/32"], "matched"
        )
        if err:
            return "T1(prior-loser) matched table: " + err
        # Critical invariant: NO tracker is created on the OLD NHG
        # (installed_nhg_id, the 4-way winner) -- 45.1.1.1..8 already
        # had the requested 4-way content, so the NH comparison
        # detected no ECMP change on that NHE.  Only the prior-loser
        # NHE (new_nhg_id_3way) sees the ECMP change.
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return "old NHG (installed_nhg_id={}) unexpected tracker: ".format(
                installed_nhg_id
            ) + err
        return None

    _, result = topotest.run_and_expect(
        check_t1_on_prior_loser, None, count=30, wait=1
    )
    assert result is None, "T1 (on prior loser NHG) check failed: {}".format(result)

    # Step 16: Install 45.1.1.10 with the same 4-way ECMP.  It joins
    # T1's matched (matches the 4-way snapshot).  Total parked = 2 =
    # expectedReCount -> flush.  matched (2) is the only bucket so
    # it wins:
    #   - new_nhg_id_3way is reworked in-place to 4-way; id is
    #     preserved.
    # That reworked NHG is now content-identical to installed_nhg_id
    # (the majority winner with 8 REs).  Dup-consolidation collapses
    # the duplicate:
    #   - 45.1.1.9, 45.1.1.10 migrate to installed_nhg_id.
    #   - new_nhg_id_3way loses both consumers; its deletion timer
    #     is armed (timeToDeletion field appears).
    # End state: all 10 REs (45.1.1.1..10) use installed_nhg_id.
    logger.info(
        "Step 16: Send 1 sharp route (45.1.1.10) with 4-way ECMP "
        "to fill T1 and trigger flush + dup-consolidation"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.10 nexthops 10.0.1.2,10.0.2.3,10.0.3.4,10.0.4.4 1"
    )

    def check_t1_loser_merged_into_winner():
        err = _check_nhg_nexthops(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.4"],
        )
        if err:
            return err
        expected_prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]
        err = _check_routes_use_nhg(r1, expected_prefixes, installed_nhg_id)
        if err:
            return err
        err = _check_no_trackers(r1, installed_nhg_id)
        if err:
            return err
        # The prior 3-way loser NHG (now content-duplicate of the
        # winner after rework) has lost both consumers and must be
        # deletion-pending or already gone.
        err = _check_nhg_deletion_pending_or_gone(r1, new_nhg_id_3way)
        if err:
            return "prior-loser NHG deletion-pending check: " + err
        # Kernel: all 10 routes use installed_nhg_id (4-way) in the FIB.
        err = _check_kernel_state(
            r1,
            installed_nhg_id,
            ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.4"],
            expected_prefixes,
        )
        if err:
            return err
        return None

    _, result = topotest.run_and_expect(
        check_t1_loser_merged_into_winner, None, count=60, wait=1
    )
    assert result is None, "T1 (prior-loser merged) flush + dup-consolidation check failed: {}".format(
        result
    )


# -----------------------------------------------------------------------------
# Multi-protocol RIB / kernel verification helpers (used by
# test_nhg_tracker_two_protocols): validate per-protocol entries and which
# one wins bestpath when a prefix is offered by multiple protocols.
# -----------------------------------------------------------------------------


def _check_route_multiprotocol_winner(
    router,
    prefix,
    winner_protocol,
    nexthops_by_protocol,
):
    """
    Verify a prefix is learned from multiple protocols and the expected
    one wins bestpath selection.

    router               : topogen router gear (e.g. tgen.gears["r1"]).
    prefix               : prefix string, e.g. "45.1.1.1/32".
    winner_protocol      : protocol whose entry must be selected=true
                           AND installed=true (e.g. "bgp").
    nexthops_by_protocol : dict {protocol_name: [expected_nexthop_ips]}.
                           Every protocol listed here must appear in
                           the RIB with exactly those resolved
                           (active) nexthop IPs, and no other
                           protocols may be present for the prefix.

    Returns None on success or an error string suitable for
    topotest.run_and_expect.
    """
    out = router.vtysh_cmd("show ip route {} json".format(prefix))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return "show ip route {} json parse failed: {}".format(prefix, out[:200])

    entries = data.get(prefix)
    if not entries:
        return "route {} not present in RIB".format(prefix)

    expected_protos = sorted(nexthops_by_protocol.keys())
    got_protos = sorted(e.get("protocol") for e in entries)
    if got_protos != expected_protos:
        return "route {} protocol set mismatch: expected {}, got {}".format(
            prefix, expected_protos, got_protos
        )

    winner = next((e for e in entries if e.get("protocol") == winner_protocol), None)
    if winner is None:
        return "route {} winner protocol {} not present".format(
            prefix, winner_protocol
        )
    if not winner.get("selected"):
        return "route {} winner protocol {} not selected: entry={}".format(
            prefix, winner_protocol, winner
        )
    if not winner.get("installed"):
        return "route {} winner protocol {} not installed: entry={}".format(
            prefix, winner_protocol, winner
        )

    # Every losing protocol entry must exist but must NOT be selected
    # or installed (zebra only programs the bestpath in the FIB).
    for e in entries:
        proto = e.get("protocol")
        if proto == winner_protocol:
            continue
        if e.get("selected"):
            return "route {} losing protocol {} unexpectedly selected".format(
                prefix, proto
            )
        if e.get("installed"):
            return "route {} losing protocol {} unexpectedly installed".format(
                prefix, proto
            )

    # Per-protocol resolved-nexthop set check.  We only count active
    # nexthops so we don't accidentally accept a route whose entry
    # carries the right addresses but with some of them inactive
    # (e.g. an unresolved recursive nexthop, a down interface).
    for e in entries:
        proto = e.get("protocol")
        expected_nhs = sorted(nexthops_by_protocol.get(proto, []))
        nhs = e.get("nexthops", [])
        found = sorted(
            n.get("ip") for n in nhs if n.get("ip") and n.get("active")
        )
        if found != expected_nhs:
            return (
                "route {} {} active nexthop mismatch: "
                "expected {} ({} entries), got {} ({} entries)".format(
                    prefix,
                    proto,
                    expected_nhs,
                    len(expected_nhs),
                    found,
                    len(found),
                )
            )

    return None


def _get_route_installed_nhg_id(router, prefix, protocol):
    """
    Return the installedNexthopGroupId for the given prefix's entry from
    the specified protocol, or (None, error_string) on failure.

    Useful when a prefix has multiple RIB entries (e.g. learned from BGP
    and Sharpd) and we need the NHG id for a specific protocol's entry.

    Falls back to `nexthopGroupId` when the entry is not the bestpath
    (installed=false), so this works for losing entries too.
    """
    out = router.vtysh_cmd("show ip route {} json".format(prefix))
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return None, "show ip route {} json parse failed".format(prefix)

    entries = data.get(prefix)
    if not entries:
        return None, "route {} not present".format(prefix)

    e = next((x for x in entries if x.get("protocol") == protocol), None)
    if e is None:
        return None, "route {} has no {} entry".format(prefix, protocol)

    nhg_id = e.get("installedNexthopGroupId") or e.get("nexthopGroupId")
    if nhg_id is None:
        return None, "route {} {} entry has no NHG id: {}".format(
            prefix, protocol, e
        )
    return nhg_id, None


def _check_route_protocol_uses_nhg(router, prefix, protocol, expected_nhg_id):
    """
    Verify the prefix's entry for the given protocol references
    `expected_nhg_id` (matching `installedNexthopGroupId` for the
    winning entry or `nexthopGroupId` for a losing/non-installed
    entry).  Returns None or an error string.
    """
    got, err = _get_route_installed_nhg_id(router, prefix, protocol)
    if err is not None:
        return err
    if got != expected_nhg_id:
        return "route {} {} entry uses NHG {}, expected {}".format(
            prefix, protocol, got, expected_nhg_id
        )
    return None


def _get_tracker_global_counters(router):
    """
    Fetch the global NHG-tracker counters from
    `show zebra tracker-nhg json`.  Returns the parsed dict or None
    on parse failure.
    """
    out = router.vtysh_cmd("show zebra tracker-nhg json")
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


# Counter keys whose movement implies "a tracker did something" --
# allocated/freed cover lifecycle, the trackerFull* family covers
# flushes, and trackersCollapsedReMatch / loop / timer cover the
# auxiliary state transitions.  Anything not in this list (e.g. the
# flushEvents list) is intentionally excluded because its shape can
# change for reasons unrelated to *new* tracker activity (e.g. a
# bounded ring buffer that already contains entries from the prior
# test).
_TRACKER_LIFECYCLE_COUNTERS = (
    "trackersAllocated",
    "trackersFreed",
    "trackersCollapsedReMatch",
    "trackerLoopDetected",
    "trackerTimerExpired",
    "trackerFullMatched",
    "trackerFullUnmatched",
    "trackerFullCombined",
    "trackerFullCombinedMatchedGt",
    "trackerFullCombinedUnmatchedGt",
    "trackerFullTotal",
)


def _check_tracker_counters_unchanged(router, baseline, counters=None):
    """
    Verify the listed tracker counters match `baseline`.  Useful to
    assert "nothing tracker-related happened" across an event (e.g.
    an ECMP change on a route entry that the tracker does not watch
    because it is not the bestpath).
    """
    if counters is None:
        counters = _TRACKER_LIFECYCLE_COUNTERS
    cur = _get_tracker_global_counters(router)
    if cur is None:
        return "could not parse `show zebra tracker-nhg json`"
    for c in counters:
        if cur.get(c) != baseline.get(c):
            return "tracker counter {} changed: baseline={}, current={}".format(
                c, baseline.get(c), cur.get(c)
            )
    return None


def _check_tracker_counter_deltas(router, baseline, deltas):
    """
    Verify that specific tracker counters incremented by specific
    amounts vs `baseline`.  `deltas` is a dict {counter_name: int}.
    Counters not listed in `deltas` are not checked.

    Returns None on success or an error string suitable for
    topotest.run_and_expect.
    """
    cur = _get_tracker_global_counters(router)
    if cur is None:
        return "could not parse `show zebra tracker-nhg json`"
    for counter, expected_delta in deltas.items():
        base = baseline.get(counter, 0) or 0
        now = cur.get(counter, 0) or 0
        if now - base != expected_delta:
            return (
                "tracker counter {} delta mismatch: expected +{}, got +{} "
                "(baseline={}, current={})".format(
                    counter, expected_delta, now - base, base, now
                )
            )
    return None


def _check_tracker_latest_flush_event(router, expected):
    """
    Verify the latest `flushEvents` ring entry matches `expected`
    (dict of any of {nhgId, trackerId, matched, unmatched, deleted, origReCount}).
    """
    cur = _get_tracker_global_counters(router)
    if cur is None:
        return "could not parse `show zebra tracker-nhg json`"
    events = cur.get("flushEvents", [])
    if not events:
        return "flushEvents ring buffer is empty"
    last = events[-1]
    for k, v in expected.items():
        if last.get(k) != v:
            return (
                "flushEvents[-1] {} expected {}, got {} (full event: {})"
                .format(k, v, last.get(k), last)
            )
    return None


def test_nhg_tracker_two_protocols():
    """
    Verify zebra's bestpath behaviour and kernel install when the same
    prefix is offered to r1 from two different protocols (BGP and
    SHARP), each carrying the *same* 4-way ECMP nexthop set:

      - BGP: every peer (r2-r5) redistributes static 45.1.1.X/32; r1
        receives one path per peer and -- with multipath-relax +
        maximum-paths 4 -- installs a single bgp entry with 4-way ECMP
        (10.0.1.2, 10.0.2.3, 10.0.3.4, 10.0.4.5).
      - SHARP: sharpd on r1 installs the same 10 prefixes locally with
        an explicit 4-way nexthop list matching the BGP set.

    Expected outcome on r1, for every prefix 45.1.1.1..10/32:
      * the RIB has two entries -- bgp and sharp -- each with the same
        4-way ECMP nexthop set;
      * the bgp entry is selected=true, installed=true (BGP distance
        20 beats SHARP's 150);
      * the sharp entry is present but neither selected nor installed
        (zebra only programs the bestpath in the FIB);
      * the kernel route is bound to a 4-way ECMP NHG whose nexthops
        are exactly the four peers.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    peers = ["r2", "r3", "r4", "r5"]
    peer_as = {"r2": 65002, "r3": 65003, "r4": 65004, "r5": 65005}
    peer_nhs = ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.5"]
    prefixes = ["45.1.1.{}/32".format(i) for i in range(1, 11)]

    # Step 0a: Enable BGP multipath on r1 so eBGP paths from the four
    # peers (each in a distinct AS: 65002-65005) coexist as a single
    # 4-way ECMP bestpath set rather than collapsing to one bestpath.
    # `multipath-relax` is required because the peers have distinct
    # AS_PATHs; `maximum-paths 4` enables eBGP multipath in IPv4
    # unicast.
    logger.info("Step 0a: Enable BGP multipath (relax + max-paths 4) on r1")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65001\n"
        " bgp bestpath as-path multipath-relax\n"
        " address-family ipv4 unicast\n"
        "  maximum-paths 4\n"
        " exit-address-family\n"
        "end\n"
    )

    # Step 0b: Wipe any sharp routes left over from the prior test --
    # the previous test installs 45.1.1.1..10/32 as SHARP routes on r1.
    # We re-install them below with the exact nexthop list this test
    # needs, so start from a clean slate.
    logger.info(
        "Step 0b: Remove leftover sharp routes 45.1.1.1..10/32 from r1"
    )
    r1.vtysh_cmd("sharp remove routes 45.1.1.1 10")

    def check_sharp_gone():
        out = r1.vtysh_cmd("show ip route sharp json")
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return "sharp route json parse failed: {}".format(out[:200])
        for p in prefixes:
            if p in data:
                return "sharp route {} still present".format(p)
        return None

    _, result = topotest.run_and_expect(check_sharp_gone, None, count=20, wait=1)
    assert result is None, "leftover sharp routes still present: {}".format(result)

    # Step 1: On every peer, add 10 static routes (45.1.1.1..10/32 ->
    # Null0) and enable `redistribute static` under router bgp so r1
    # learns every prefix from BGP, one path per peer.  We deliberately
    # do NOT touch RIP here -- this test pits BGP against SHARP so we
    # can guarantee the loser carries the same 4-way nexthop set as
    # the winner.
    logger.info(
        "Step 1: Configure static + 'redistribute static' (bgp only) on peers r2-r5"
    )
    for pname in peers:
        peer = tgen.gears[pname]
        cmds = ["configure terminal"]
        for i in range(1, 11):
            cmds.append("ip route 45.1.1.{}/32 Null0".format(i))
        cmds.extend(
            [
                "router bgp {}".format(peer_as[pname]),
                " address-family ipv4 unicast",
                "  redistribute static",
                " exit-address-family",
                "!",
                "end",
            ]
        )
        peer.vtysh_cmd("\n".join(cmds))

    # Step 2: Wait for BGP on r1 to converge with the full 4-way ECMP
    # set for every prefix.  At this point sharp is not yet installed,
    # so we use the single-protocol form of the check
    # (`nexthops_by_protocol={"bgp": peer_nhs}`).
    logger.info(
        "Step 2: Wait for r1's BGP to install 4-way ECMP for 45.1.1.0/24-ish prefixes"
    )

    def check_bgp_converged_4way():
        for p in (prefixes[0], prefixes[-1]):
            err = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={"bgp": peer_nhs},
            )
            if err:
                return err
        return None

    _, result = topotest.run_and_expect(
        check_bgp_converged_4way, None, count=60, wait=2
    )
    assert result is None, "BGP 4-way ECMP convergence failed: {}".format(result)

    # Step 3: Add the second protocol.  Install 10 sharp routes on r1
    # with the SAME 4-way ECMP nexthop set as BGP.  Each prefix now has
    # two RIB entries (bgp + sharp) with content-identical resolved
    # nexthops; BGP must keep selected/installed (distance 20 < 150).
    logger.info(
        "Step 3: sharp install 10 routes (45.1.1.1..10/32) with the same 4-way ECMP"
    )
    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops {} 10".format(",".join(peer_nhs))
    )

    # Step 4: Full per-prefix check -- every prefix must have bgp and
    # sharp entries each resolving to the same 4-way nexthop set; bgp
    # must be selected+installed, sharp must be present-but-loser.
    logger.info(
        "Step 4: Validate every prefix has bgp+sharp REs, both 4-way, "
        "bgp=winner / sharp=loser"
    )

    def check_all_prefixes_two_protocols():
        for p in prefixes:
            err = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={
                    "bgp": peer_nhs,
                    "sharp": peer_nhs,
                },
            )
            if err:
                return err
        return None

    _, result = topotest.run_and_expect(
        check_all_prefixes_two_protocols, None, count=30, wait=2
    )
    assert result is None, "per-prefix bgp-vs-sharp check failed: {}".format(result)

    # Step 5: Pull the installed NHG id from BGP's entry on the first
    # prefix and verify the *kernel* FIB binds every prefix to that
    # same NHG, and that NHG resolves to the four peer nexthops.
    logger.info("Step 5: Validate kernel FIB / NHG state for the BGP winner")

    installed_reuse_nhg_id, err = _get_route_installed_nhg_id(r1, prefixes[0], "bgp")
    assert err is None, "failed to read BGP-winner NHG id: {}".format(err)
    logger.info("BGP winner installed NHG id on r1 = %s", installed_reuse_nhg_id)

    def check_kernel_bgp_winner():
        return _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, prefixes)

    _, result = topotest.run_and_expect(
        check_kernel_bgp_winner, None, count=30, wait=1
    )
    assert result is None, "kernel BGP-winner state check failed: {}".format(result)

    # Step 6: Loser-side ECMP change must NOT arm a tracker.
    #
    # The NHG tracker only watches *installed* (selected/bestpath)
    # consumers of an NHE.  Sharp's RIB entries are losers here (BGP
    # beats them on admin distance), so any ECMP change to a sharp
    # RE alone must:
    #   (a) leave global tracker counters unchanged,
    #   (b) leave BGP's NHG without any parked tracker,
    #   (c) leave BGP's RIB-and-kernel state completely untouched,
    #   (d) re-home the changing sharp REs onto a *different* NHG
    #       whose content matches the new (shrunk) nexthop set.
    #
    # We shrink the first 5 sharp REs from 4-way to 2-way ECMP.  Last
    # 5 sharp REs stay on the original 4-way NHG (same NHG BGP uses).
    logger.info(
        "Step 6: Shrink 5 sharp REs (loser side) from 4-way to 2-way ECMP "
        "-- must NOT arm a tracker"
    )

    baseline_counters_6 = _get_tracker_global_counters(r1)
    assert baseline_counters_6 is not None, "could not snapshot tracker counters"
    logger.info(
        "Step 6 baseline tracker counters: alloc=%s freed=%s fullTotal=%s",
        baseline_counters_6.get("trackersAllocated"),
        baseline_counters_6.get("trackersFreed"),
        baseline_counters_6.get("trackerFullTotal"),
    )

    first5 = prefixes[:5]
    last5 = prefixes[5:]
    twoway_nhs = ["10.0.1.2", "10.0.2.3"]

    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops {} 5".format(",".join(twoway_nhs))
    )

    def check_loser_ecmp_change_no_tracker():
        # (a) tracker counters frozen
        err = _check_tracker_counters_unchanged(r1, baseline_counters_6)
        if err:
            return err
        # (b) no tracker parked on the BGP-winner NHG
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # (c) BGP RIB + kernel state unchanged on the 4-way NHG
        err = _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, prefixes)
        if err:
            return err
        # First 5 prefixes: BGP=4-way winner, SHARP=2-way loser
        for p in first5:
            err = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={"bgp": peer_nhs, "sharp": twoway_nhs},
            )
            if err:
                return err
        # Last 5 prefixes: BGP=4-way winner, SHARP=4-way loser
        # (unchanged -- still on installed_reuse_nhg_id)
        for p in last5:
            err = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={"bgp": peer_nhs, "sharp": peer_nhs},
            )
            if err:
                return err
            err = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if err:
                return err
        return None

    _, result = topotest.run_and_expect(
        check_loser_ecmp_change_no_tracker, None, count=30, wait=1
    )
    assert result is None, (
        "loser-side ECMP change unexpectedly disturbed tracker / "
        "winner state: {}".format(result)
    )

    # (d) The 5 shrunk sharp REs must land on a *different* NHG whose
    # content matches the 2-way set.
    sharp_2way_nhg_id, err = _get_route_installed_nhg_id(r1, first5[0], "sharp")
    assert err is None, "could not read sharp 2-way NHG id: {}".format(err)
    assert sharp_2way_nhg_id != installed_reuse_nhg_id, (
        "sharp 2-way NHG id ({}) must differ from BGP's 4-way NHG id ({})".format(
            sharp_2way_nhg_id, installed_reuse_nhg_id
        )
    )
    logger.info(
        "Step 6: sharp 2-way NHG id allocated = %s (BGP winner NHG = %s)",
        sharp_2way_nhg_id,
        installed_reuse_nhg_id,
    )

    def check_sharp_2way_nhg_content():
        err = _check_nhg_nexthops(r1, sharp_2way_nhg_id, twoway_nhs)
        if err:
            return err
        # And every shrunk sharp RE must reference that 2-way NHG.
        for p in first5:
            err = _check_route_protocol_uses_nhg(
                r1, p, "sharp", sharp_2way_nhg_id
            )
            if err:
                return err
        return None

    _, result = topotest.run_and_expect(
        check_sharp_2way_nhg_content, None, count=20, wait=1
    )
    assert result is None, "sharp 2-way NHG content / binding check failed: {}".format(
        result
    )

    # Step 7: Revert -- restore the 5 sharp REs to the original 4-way
    # set.  Two things must hold:
    #   (a) Tracker counters still don't move (the changing
    #       consumers are still losers; tracker doesn't care).
    #   (b) The new 4-way NHG content is identical to BGP's 4-way
    #       NHG, so zebra must *reuse* it: all 10 sharp REs end up
    #       back on installed_reuse_nhg_id, and the 2-way NHG (sharp_2way_nhg_id)
    #       loses its last consumer and goes deletion-pending or
    #       disappears.
    logger.info(
        "Step 7: Restore the 5 sharp REs to 4-way ECMP -- expect NHG reuse, "
        "still no tracker"
    )

    baseline_counters_7 = _get_tracker_global_counters(r1)
    assert baseline_counters_7 is not None, (
        "could not snapshot tracker counters before Step 7"
    )

    r1.vtysh_cmd(
        "sharp install routes 45.1.1.1 nexthops {} 5".format(",".join(peer_nhs))
    )

    def check_loser_ecmp_revert():
        err = _check_tracker_counters_unchanged(r1, baseline_counters_7)
        if err:
            return err
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # All 10 prefixes: BGP=4-way winner, SHARP=4-way loser, BOTH
        # on installed_reuse_nhg_id (content reuse).
        for p in prefixes:
            err = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={"bgp": peer_nhs, "sharp": peer_nhs},
            )
            if err:
                return err
            err = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if err:
                return err
        # Kernel still bound to installed_reuse_nhg_id with the same 4-way set.
        err = _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, prefixes)
        if err:
            return err
        # The transient 2-way NHG has lost its last consumer; it
        # should now be deletion-pending (timeToDeletion field set)
        # or already gone.
        err = _check_nhg_deletion_pending_or_gone(r1, sharp_2way_nhg_id)
        if err:
            return "transient 2-way NHG cleanup check: " + err
        return None

    _, result = topotest.run_and_expect(
        check_loser_ecmp_revert, None, count=30, wait=1
    )
    assert result is None, (
        "loser-side ECMP revert / NHG reuse check failed: {}".format(result)
    )

    # Step 8: Installed-RE ECMP shrink on a SUBSET of consumers.
    # Peer r2 withdraws its statics for the last 6 prefixes
    # (45.1.1.5..10), so r1's BGP-bestpath for each of those shrinks
    # from 4-way to 3-way (the remaining peers r3, r4, r5).  This is
    # an ECMP change on 6 *installed* (selected) consumers of
    # installed_reuse_nhg_id, so a tracker arms there:
    #   - matched     = 6 (the 6 changed BGP REs)
    #   - expected_re = 10 (the 10 installed BGP REs on installed_reuse_nhg_id
    #                       at tracker creation time)
    #   - snapshot    = 3-way inactive (r3 / r4 / r5)
    # Timer expires (matched=6 < expected_re=10) → silent wins:
    # silent_count = 4 unchanged BGP + 10 non-bestpath SHARP siblings
    # = 14, silent_plus_matched=14 >= matched=6, so silent keeps
    # parent_nhe's content (4-way).  Phase 2 fires only the 4 SELECTED
    # silent BGP REs (45.1.1.1..4); the 10 non-selected SHARP silents
    # are skipped by the phase 2 silent RE flush filter.
    logger.info(
        "Step 8: Installed-RE ECMP shrink -- r2 withdraws 45.1.1.5..10; "
        "tracker fires on installed_reuse_nhg_id=%s, 6 BGP REs migrate to a "
        "new 3-way NHG",
        installed_reuse_nhg_id,
    )

    baseline_counters_8 = _get_tracker_global_counters(r1)
    assert baseline_counters_8 is not None, (
        "could not snapshot tracker counters before Step 8"
    )

    # Reduce the tracker timer from 3600s (set by the prior test) to
    # 10s so this step finishes in a reasonable wall-clock window.
    # The Step 8 tracker times out (matched=6 < expected_re=10).
    r1.vtysh_cmd(
        "configure terminal\nzebra nexthop-group tracker 10\nend"
    )

    first4 = ["45.1.1.{}/32".format(i) for i in range(1, 5)]
    last6 = ["45.1.1.{}/32".format(i) for i in range(5, 11)]
    shrink_nh_set = ["10.0.2.3", "10.0.3.4", "10.0.4.5"]

    r2 = tgen.gears["r2"]
    cmds = ["configure terminal"]
    for i in range(5, 11):
        cmds.append("no ip route 45.1.1.{}/32 Null0".format(i))
    cmds.append("end")
    r2.vtysh_cmd("\n".join(cmds))

    # Step 8a: tracker armed on installed_reuse_nhg_id with matched=6 and the
    # 3-way snapshot.
    def check_tracker_armed_for_shrink():
        return _check_tracker_state(
            r1,
            installed_reuse_nhg_id,
            tracker_id=1,
            ifindex=0,
            event="ECMP_CHANGE",
            expected_re_count=10,
            matched_count=6,
            unmatched_count=0,
            snapshot=[False, False, False],
        )

    _, result = topotest.run_and_expect(
        check_tracker_armed_for_shrink, None, count=30, wait=1
    )
    assert result is None, (
        "tracker did not arm for installed-RE shrink: {}".format(result)
    )

    # Step 8b: wait for tracker timer to expire and the flush to settle.
    def check_shrink_flushed():
        # Tracker on installed_reuse_nhg_id is gone.
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # installed_reuse_nhg_id's content is unchanged: silent won → keep parent.
        err = _check_nhg_nexthops(r1, installed_reuse_nhg_id, peer_nhs)
        if err:
            return err
        # Counter delta: 1 alloc + 1 freed + 1 timer-expire + 1
        # combined-flush + 1 matched>unmatched (matched=6, unmatched=0,
        # orig_re=10 → bucket "combined", with matched > unmatched).
        err = _check_tracker_counter_deltas(
            r1,
            baseline_counters_8,
            {
                "trackersAllocated": 1,
                "trackersFreed": 1,
                "trackerTimerExpired": 1,
                "trackerFullCombined": 1,
                "trackerFullCombinedMatchedGt": 1,
                "trackerFullTotal": 1,
            },
        )
        if err:
            return err
        # The latest flushEvent must describe THIS tracker.
        err = _check_tracker_latest_flush_event(
            r1,
            {
                "nhgId": installed_reuse_nhg_id,
                "matched": 6,
                "unmatched": 0,
                "deleted": 0,
                "origReCount": 10,
            },
        )
        if err:
            return err
        # All 10 SHARP REs still on installed_reuse_nhg_id (their content didn't
        # change).
        for p in prefixes:
            e = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if e:
                return e
        # The 4 unchanged-BGP prefixes (45.1.1.1..4) still on installed_reuse_nhg_id.
        for p in first4:
            e = _check_route_protocol_uses_nhg(r1, p, "bgp", installed_reuse_nhg_id)
            if e:
                return e
        # The 6 changed-BGP prefixes (45.1.1.5..10) must each be on a
        # DIFFERENT NHG (the new 3-way), and they all must share the
        # same NHG (content-hash dedup).
        first_id = None
        for p in last6:
            nhg_id, e = _get_route_installed_nhg_id(r1, p, "bgp")
            if e:
                return e
            if nhg_id == installed_reuse_nhg_id:
                return (
                    "BGP {} still on installed_reuse_nhg_id={}, expected a new "
                    "3-way NHG".format(p, installed_reuse_nhg_id)
                )
            if first_id is None:
                first_id = nhg_id
            elif nhg_id != first_id:
                return (
                    "BGP {} on NHG {}, expected shared transient {} "
                    "(content-hash dedup miss)".format(p, nhg_id, first_id)
                )
        return None

    _, result = topotest.run_and_expect(
        check_shrink_flushed, None, count=60, wait=2
    )
    assert result is None, (
        "post-shrink flush validation failed: {}".format(result)
    )

    # Capture the transient 3-way NHG id for the post-Step-9 cleanup
    # check.  Also confirm its content is exactly the shrunk peer set.
    transient_3way_nhg_id, err = _get_route_installed_nhg_id(
        r1, last6[0], "bgp"
    )
    assert err is None, (
        "could not read transient 3-way NHG id: {}".format(err)
    )
    logger.info(
        "Step 8: transient 3-way NHG id = %s (BGP %s..%s), installed_reuse_nhg_id=%s untouched",
        transient_3way_nhg_id, last6[0], last6[-1], installed_reuse_nhg_id,
    )
    err = _check_nhg_nexthops(r1, transient_3way_nhg_id, shrink_nh_set)
    assert err is None, (
        "transient 3-way NHG content mismatch: {}".format(err)
    )

    # Kernel: the first 4 prefixes are bound to installed_reuse_nhg_id (4-way) and
    # the last 6 are bound to the transient 3-way NHG.  Validate both
    # splits.
    def check_kernel_after_shrink():
        err = _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, first4)
        if err:
            return "first4-on-installed_reuse_nhg_id: " + err
        err = _check_kernel_state(
            r1, transient_3way_nhg_id, shrink_nh_set, last6
        )
        if err:
            return "last6-on-transient_3way_nhg_id: " + err
        return None

    _, result = topotest.run_and_expect(
        check_kernel_after_shrink, None, count=30, wait=1
    )
    assert result is None, "kernel state after Step 8 shrink: {}".format(result)

    # Step 9: ECMP re-expand.  r2 re-adds the 6 statics, the 6 BGP
    # REs go back to 4-way.  A tracker arms on the transient 3-way
    # NHG (matched grows from 1..6, expected_re=6).  Once matched
    # reaches 6 it triggers flush_if_full.  Phase 2 reworks the
    # 3-way NHG in-place to 4-way → content-matches installed_reuse_nhg_id →
    # mark_duplicate(transient, bgp).  Consolidation fires (it needs
    # installed_reuse_nhg_id.tracker_pending_winners == 0, which Step 8 guarantees
    # via the bestpath filter) and migrates the 6 BGP REs back to
    # installed_reuse_nhg_id.  The transient NHG goes deletion-pending or gone.
    logger.info(
        "Step 9: ECMP re-expand -- r2 re-adds 45.1.1.5..10; expect "
        "all 6 BGP REs to return to installed_reuse_nhg_id=%s via dup-consolidation",
        installed_reuse_nhg_id,
    )

    baseline_counters_9 = _get_tracker_global_counters(r1)
    assert baseline_counters_9 is not None, (
        "could not snapshot tracker counters before Step 9"
    )

    cmds = ["configure terminal"]
    for i in range(5, 11):
        cmds.append("ip route 45.1.1.{}/32 Null0".format(i))
    cmds.append("end")
    r2.vtysh_cmd("\n".join(cmds))

    def check_reexpand_consolidated():
        # New tracker on the transient 3-way NHG: matched=6 ==
        # orig_re=6 → trackerFullMatched bumps; flush_if_full so
        # NO timer expiry.
        err = _check_tracker_counter_deltas(
            r1,
            baseline_counters_9,
            {
                "trackersAllocated": 1,
                "trackersFreed": 1,
                "trackerTimerExpired": 0,
                "trackerFullMatched": 1,
                "trackerFullTotal": 1,
            },
        )
        if err:
            return err
        # The latest flushEvent must describe THIS tracker (on the
        # transient 3-way NHG, all 6 BGP REs in matched).
        err = _check_tracker_latest_flush_event(
            r1,
            {
                "nhgId": transient_3way_nhg_id,
                "matched": 6,
                "unmatched": 0,
                "deleted": 0,
                "origReCount": 6,
            },
        )
        if err:
            return err
        # All 10 prefixes (BGP + SHARP) back on installed_reuse_nhg_id.
        for p in prefixes:
            e = _check_route_protocol_uses_nhg(r1, p, "bgp", installed_reuse_nhg_id)
            if e:
                return e
            e = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if e:
                return e
        # installed_reuse_nhg_id content still 4-way.
        err = _check_nhg_nexthops(r1, installed_reuse_nhg_id, peer_nhs)
        if err:
            return err
        # No trackers on installed_reuse_nhg_id.
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # Per-prefix winner check: BGP selected/installed, SHARP loser,
        # both with the same 4-way nexthop set.
        for p in prefixes:
            e = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={
                    "bgp": peer_nhs,
                    "sharp": peer_nhs,
                },
            )
            if e:
                return e
        # Kernel FIB: all 10 prefixes bound to installed_reuse_nhg_id, 4-way.
        err = _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, prefixes)
        if err:
            return err
        # The transient 3-way NHG lost its consumers in dup-consolidation;
        # it must be deletion-pending or already gone.  This is the key
        err = _check_nhg_deletion_pending_or_gone(r1, transient_3way_nhg_id)
        if err:
            return "transient 3-way NHG cleanup: " + err
        return None

    _, result = topotest.run_and_expect(
        check_reexpand_consolidated, None, count=60, wait=2
    )
    assert result is None, (
        "post-re-expand consolidation failed: "
        "{}".format(result)
    )

    # Step 10: Withdraw ALL 10 statics from r2.  This is the "no
    # selected silents" silent-winner path:
    #   - matched     = 10 (all 10 BGP REs changed)
    #   - expected_re = 10
    #   - silent      = 10 (the 10 non-bestpath SHARP siblings on
    #                       installed_reuse_nhg_id; none of them is selected)
    # flush_if_full triggers immediately (matched=10 == expected=10).
    # silent_plus_matched=10 >= matched=10 → silent wins (silent_count
    # legitimately includes the SHARP siblings; without that the
    # winner would flip to matched and the 10 SHARP REs would be
    # needlessly migrated).
    # Phase 2 fires zero selected silents (none of the silents has
    # ZEBRA_FLAG_SELECTED) → consumers=0 → REUSE/REINSTALL is NOT
    # armed (no stranded flags).  The "no consumer" branch then
    # re-inserts installed_reuse_nhg_id into the content hash via
    # zebra_nhg_rework_content_rehash so future content lookups
    # (Step 11's re-add) can dedup against it.
    #
    # End state: all 10 BGP REs land on a NEW 3-way NHG (allocated
    # during phase 1 drain); all 10 SHARP REs stay on installed_reuse_nhg_id
    # (4-way, still in content hash).
    logger.info(
        "Step 10: r2 withdraws ALL 10 statics; expect silent winner / "
        "0 consumers; installed_reuse_nhg_id=%s stays in content hash via rehash",
        installed_reuse_nhg_id,
    )

    baseline_counters_10 = _get_tracker_global_counters(r1)
    assert baseline_counters_10 is not None, (
        "could not snapshot tracker counters before Step 10"
    )

    cmds = ["configure terminal"]
    for i in range(1, 11):
        cmds.append("no ip route 45.1.1.{}/32 Null0".format(i))
    cmds.append("end")
    r2.vtysh_cmd("\n".join(cmds))

    def check_withdraw_all_flushed():
        # No tracker on installed_reuse_nhg_id.
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # Counter delta: 1 alloc + 1 freed + 1 matched-full + 1 total;
        # flush_if_full means NO timer expiry.
        err = _check_tracker_counter_deltas(
            r1,
            baseline_counters_10,
            {
                "trackersAllocated": 1,
                "trackersFreed": 1,
                "trackerTimerExpired": 0,
                "trackerFullMatched": 1,
                "trackerFullTotal": 1,
            },
        )
        if err:
            return err
        # The latest flushEvent must describe THIS tracker (on
        # installed_reuse_nhg_id, all 10 REs landed in matched, no
        # unmatched / deleted, orig_re=10).
        err = _check_tracker_latest_flush_event(
            r1,
            {
                "nhgId": installed_reuse_nhg_id,
                "matched": 10,
                "unmatched": 0,
                "deleted": 0,
                "origReCount": 10,
            },
        )
        if err:
            return err
        # installed_reuse_nhg_id content unchanged (silent winner = keep parent).
        err = _check_nhg_nexthops(r1, installed_reuse_nhg_id, peer_nhs)
        if err:
            return err
        # All 10 SHARP REs still on installed_reuse_nhg_id.
        for p in prefixes:
            e = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if e:
                return e
        # All 10 BGP REs migrated to a NEW NHG (3-way), and they share
        # the same one (content-hash dedup).
        first_id = None
        for p in prefixes:
            nhg_id, e = _get_route_installed_nhg_id(r1, p, "bgp")
            if e:
                return e
            if nhg_id == installed_reuse_nhg_id:
                return (
                    "BGP {} still on installed_reuse_nhg_id={}, expected a new "
                    "3-way NHG".format(p, installed_reuse_nhg_id)
                )
            if first_id is None:
                first_id = nhg_id
            elif nhg_id != first_id:
                return (
                    "BGP {} on NHG {}, expected shared transient {} "
                    "(content-hash dedup miss)".format(p, nhg_id, first_id)
                )
        return None

    _, result = topotest.run_and_expect(
        check_withdraw_all_flushed, None, count=60, wait=2
    )
    assert result is None, (
        "post-withdraw-all flush validation failed: {}".format(result)
    )

    # Capture the new 3-way NHG id and verify its content.
    transient_3way_all_nhg_id, err = _get_route_installed_nhg_id(
        r1, prefixes[0], "bgp"
    )
    assert err is None, (
        "could not read transient 3-way NHG id after withdraw-all: {}"
        .format(err)
    )
    logger.info(
        "Step 10: transient 3-way NHG (all 10 BGP REs) = %s",
        transient_3way_all_nhg_id,
    )
    err = _check_nhg_nexthops(
        r1, transient_3way_all_nhg_id, shrink_nh_set
    )
    assert err is None, (
        "transient 3-way (all) NHG content mismatch: {}".format(err)
    )

    # Kernel: all 10 prefixes are bound to the transient 3-way NHG
    # (BGP is bestpath; SHARP is the loser even though it carries the
    # 4-way set on installed_reuse_nhg_id).
    def check_kernel_after_withdraw_all():
        return _check_kernel_state(
            r1, transient_3way_all_nhg_id, shrink_nh_set, prefixes
        )

    _, result = topotest.run_and_expect(
        check_kernel_after_withdraw_all, None, count=30, wait=1
    )
    assert result is None, (
        "kernel state after Step 10 (withdraw-all): {}".format(result)
    )

    # Step 11: Re-add ALL 10 statics on r2.  BGP advertisements bring
    # each prefix back to 4-way.  A tracker arms on the transient
    # 3-way NHG (matched grows to 10, expected_re=10) and flushes via
    # flush_if_full.  Phase 2 reworks the 3-way NHG in-place to 4-way
    # → hash_lookup finds installed_reuse_nhg_id (still in the content hash thanks
    # to Step 10's rehash) → mark_duplicate(transient_all, installed_reuse_nhg_id)
    # → consolidation migrates all 10 BGP REs back to installed_reuse_nhg_id.
    # Transient NHG goes deletion-pending or gone.
    logger.info(
        "Step 11: r2 re-adds ALL 10 statics; expect dup-consolidation "
        "to migrate all 10 BGP REs back to installed_reuse_nhg_id=%s",
        installed_reuse_nhg_id,
    )

    baseline_counters_11 = _get_tracker_global_counters(r1)
    assert baseline_counters_11 is not None, (
        "could not snapshot tracker counters before Step 11"
    )

    cmds = ["configure terminal"]
    for i in range(1, 11):
        cmds.append("ip route 45.1.1.{}/32 Null0".format(i))
    cmds.append("end")
    r2.vtysh_cmd("\n".join(cmds))

    def check_reexpand_all_consolidated():
        # New tracker (flush_if_full on the transient NHG, no timer
        # expiry).  matched=10 == orig_re=10, so trackerFullMatched
        # is bumped.  Same rationale as Step 10 for using counter
        # deltas + flushEvent instead of polling for the armed
        # tracker (flush_if_full runs synchronously inside the
        # vtysh_cmd batch).
        err = _check_tracker_counter_deltas(
            r1,
            baseline_counters_11,
            {
                "trackersAllocated": 1,
                "trackersFreed": 1,
                "trackerTimerExpired": 0,
                "trackerFullMatched": 1,
                "trackerFullTotal": 1,
            },
        )
        if err:
            return err
        # The latest flushEvent must describe THIS tracker (on the
        # transient 3-way NHG, all 10 BGP REs in matched).
        err = _check_tracker_latest_flush_event(
            r1,
            {
                "nhgId": transient_3way_all_nhg_id,
                "matched": 10,
                "unmatched": 0,
                "deleted": 0,
                "origReCount": 10,
            },
        )
        if err:
            return err
        # All 10 prefixes (BGP + SHARP) on installed_reuse_nhg_id.
        for p in prefixes:
            e = _check_route_protocol_uses_nhg(r1, p, "bgp", installed_reuse_nhg_id)
            if e:
                return e
            e = _check_route_protocol_uses_nhg(r1, p, "sharp", installed_reuse_nhg_id)
            if e:
                return e
        # installed_reuse_nhg_id content still 4-way; no trackers.
        err = _check_nhg_nexthops(r1, installed_reuse_nhg_id, peer_nhs)
        if err:
            return err
        err = _check_no_trackers(r1, installed_reuse_nhg_id)
        if err:
            return err
        # Per-prefix winner check.
        for p in prefixes:
            e = _check_route_multiprotocol_winner(
                r1,
                p,
                winner_protocol="bgp",
                nexthops_by_protocol={
                    "bgp": peer_nhs,
                    "sharp": peer_nhs,
                },
            )
            if e:
                return e
        # Kernel FIB.
        err = _check_kernel_state(r1, installed_reuse_nhg_id, peer_nhs, prefixes)
        if err:
            return err
        # The transient 3-way NHG (allocated in Step 10) lost its
        # consumers and must be deletion-pending or gone.
        err = _check_nhg_deletion_pending_or_gone(
            r1, transient_3way_all_nhg_id
        )
        if err:
            return "transient 3-way (all) NHG cleanup: " + err
        return None

    _, result = topotest.run_and_expect(
        check_reexpand_all_consolidated, None, count=60, wait=2
    )
    assert result is None, (
        "post-withdraw-all-and-re-add consolidation failed "
        ": {}".format(result)
    )


def test_nhg_tracker_wecmp_weight_change():
    """
    Verify the tracker reworks a zebra-owned ECMP NHG in place when only
    per-nexthop weights change (same NH set, same group shape).  After
    the rework, every route still references the SAME NHG id in both
    zebra and the kernel, and the NHG's per-NH weights reflect the new
    values.

    Steps:
      0. Scrub any leftover sharp routes for 47.1.1.1..10/32.
      1. sharp install 10 routes (47.1.1.1..10/32) with 4-way ECMP
         {10.0.1.2, 10.0.2.3, 10.0.3.4, 10.0.4.5} all at weight 100.
      2. Wait for convergence, capture initial_nhg_id, assert
         zebra-owned + zebra-side consistency.
      3. Verify kernel-side state matches (same nhid, same NH set).
      4. Snapshot tracker counters.
      5. Reissue the same 10 routes with the SAME NH set but new
         weights (50, 100, 100, 25).
      6. Assert tracker fired (trackersAllocated/Freed both += 1).
      7a. Assert NHG id is PRESERVED in zebra (the core assertion).
      7b. Assert NHG id is PRESERVED in the kernel.
      8. Assert zebra-side per-NH weights reflect the new values.
      9. Cleanup: remove sharp routes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    prefixes = ["47.1.1.{}/32".format(i) for i in range(1, 11)]
    peer_nhs = ["10.0.1.2", "10.0.2.3", "10.0.3.4", "10.0.4.5"]
    initial_weights = [100, 100, 100, 100]
    new_weights = [50, 100, 100, 25]

    # --- Step 0: scrub any leftover sharp routes for this prefix range
    logger.info(
        "Step 0: scrub leftover sharp routes for 47.1.1.1..10/32"
    )
    r1.vtysh_cmd("sharp remove routes 47.1.1.1 10")

    def check_sharp_clean():
        out = r1.vtysh_cmd("show ip route sharp json")
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return "sharp route json parse failed: {}".format(out[:200])
        for p in prefixes:
            if p in data:
                return "leftover sharp route {} still present".format(p)
        return None

    _, result = topotest.run_and_expect(
        check_sharp_clean, None, count=10, wait=1
    )
    assert result is None, (
        "leftover sharp routes not cleared: {}".format(result)
    )

    # --- Step 1: install with initial equal weights
    initial_nhs_str = ",".join(
        "{}:{}".format(nh, w) for nh, w in zip(peer_nhs, initial_weights)
    )
    logger.info(
        "Step 1: sharp install routes 47.1.1.1 nexthops %s 10",
        initial_nhs_str,
    )
    r1.vtysh_cmd(
        "sharp install routes 47.1.1.1 nexthops {} 10".format(
            initial_nhs_str
        )
    )

    # --- Step 2: wait for convergence, capture initial_nhg_id, verify
    #             zebra-side state (ownership + content)
    def check_initial_install():
        for p in prefixes:
            nhg_id, err = _get_route_installed_nhg_id(r1, p, "sharp")
            if err:
                return err
            if nhg_id is None or nhg_id <= 0:
                return "{} has no installed NHG id".format(p)
        return None

    _, result = topotest.run_and_expect(
        check_initial_install, None, count=30, wait=1
    )
    assert result is None, (
        "initial sharp install did not converge: {}".format(result)
    )

    initial_nhg_id, err = _get_route_installed_nhg_id(
        r1, prefixes[0], "sharp"
    )
    assert err is None, (
        "could not read initial NHG id: {}".format(err)
    )
    logger.info(
        "Step 2: initial NHG id = %s (zebra-owned)", initial_nhg_id
    )

    err = _check_routes_use_nhg(r1, prefixes, initial_nhg_id)
    assert err is None, (
        "initial routes not all on the same NHG id {}: {}".format(
            initial_nhg_id, err
        )
    )

    err = _check_nhg_nexthops(r1, initial_nhg_id, peer_nhs)
    assert err is None, (
        "initial NHG {} NH set mismatch: {}".format(initial_nhg_id, err)
    )

    # --- Step 3: kernel-side state matches
    def check_initial_kernel():
        e = _check_kernel_routes_use_nhid(r1, prefixes, initial_nhg_id)
        if e:
            return e
        e = _check_kernel_nhg_nexthops(r1, initial_nhg_id, peer_nhs)
        if e:
            return e
        return None

    _, result = topotest.run_and_expect(
        check_initial_kernel, None, count=20, wait=1
    )
    assert result is None, (
        "initial kernel state mismatch: {}".format(result)
    )
    logger.info(
        "Step 3: kernel agrees on NHG id %s and NH set %s",
        initial_nhg_id,
        peer_nhs,
    )

    # --- Step 4: snapshot tracker counters before weight change
    pre_change_counters = _get_tracker_global_counters(r1)
    assert pre_change_counters is not None, (
        "could not snapshot tracker counters"
    )
    logger.info(
        "Step 4: pre-change counters: allocated=%s freed=%s",
        pre_change_counters.get("trackersAllocated"),
        pre_change_counters.get("trackersFreed"),
    )

    # --- Step 5: reissue the same 10 prefixes with new weights
    new_nhs_str = ",".join(
        "{}:{}".format(nh, w) for nh, w in zip(peer_nhs, new_weights)
    )
    logger.info(
        "Step 5: re-issue with new weights: nexthops %s", new_nhs_str
    )
    r1.vtysh_cmd(
        "sharp install routes 47.1.1.1 nexthops {} 10".format(
            new_nhs_str
        )
    )

    # --- Step 6: tracker activity (saturation or timer expiry — both
    #             increment Allocated + Freed)
    def check_tracker_fired():
        cur = _get_tracker_global_counters(r1)
        if cur is None:
            return "could not snapshot tracker counters"
        alloc_delta = (
            cur.get("trackersAllocated", 0)
            - pre_change_counters.get("trackersAllocated", 0)
        )
        freed_delta = (
            cur.get("trackersFreed", 0)
            - pre_change_counters.get("trackersFreed", 0)
        )
        if alloc_delta < 1:
            return (
                "trackersAllocated did not increment "
                "(base={} cur={})".format(
                    pre_change_counters.get("trackersAllocated", 0),
                    cur.get("trackersAllocated", 0),
                )
            )
        if freed_delta < 1:
            return (
                "trackersFreed did not increment "
                "(base={} cur={})".format(
                    pre_change_counters.get("trackersFreed", 0),
                    cur.get("trackersFreed", 0),
                )
            )
        return None

    _, result = topotest.run_and_expect(
        check_tracker_fired, None, count=60, wait=2
    )
    assert result is None, (
        "tracker did not fire on weight-only change: {}".format(result)
    )
    logger.info("Step 6: tracker fired (allocated/freed counters incremented)")

    # --- Step 7a: NHG id preserved in zebra (core assertion)
    def check_nhg_id_preserved_zebra():
        for p in prefixes:
            nhg_id, err = _get_route_installed_nhg_id(r1, p, "sharp")
            if err:
                return err
            if nhg_id != initial_nhg_id:
                return "{} NHG id changed: {} -> {}".format(
                    p, initial_nhg_id, nhg_id
                )
        return None

    _, result = topotest.run_and_expect(
        check_nhg_id_preserved_zebra, None, count=20, wait=1
    )
    assert result is None, (
        "NHG id NOT preserved across weight change (zebra-side): {}"
        .format(result)
    )
    logger.info(
        "Step 7a: zebra NHG id %s preserved across weight change",
        initial_nhg_id,
    )

    # --- Step 7b: NHG id preserved in the kernel
    def check_nhg_id_preserved_kernel():
        e = _check_kernel_routes_use_nhid(r1, prefixes, initial_nhg_id)
        if e:
            return e
        e = _check_kernel_nhg_nexthops(r1, initial_nhg_id, peer_nhs)
        if e:
            return e
        return None

    _, result = topotest.run_and_expect(
        check_nhg_id_preserved_kernel, None, count=20, wait=1
    )
    assert result is None, (
        "NHG id NOT preserved across weight change (kernel-side): {}"
        .format(result)
    )
    logger.info(
        "Step 7b: kernel NHG id %s preserved across weight change",
        initial_nhg_id,
    )

    # --- Step 8: zebra-side per-NH weights reflect the new values.
    expected_scaled = _scale_weights_to_kernel(new_weights)
    expected_weights = dict(zip(peer_nhs, expected_scaled))

    def check_weights_updated():
        return _check_nhg_nexthop_weights(
            r1, initial_nhg_id, expected_weights
        )

    _, result = topotest.run_and_expect(
        check_weights_updated, None, count=20, wait=1
    )
    assert result is None, (
        "NHG {} per-NH weights not updated to {} (raw inputs {}): {}"
        .format(initial_nhg_id, expected_weights, new_weights, result)
    )
    logger.info(
        "Step 8: NHG %s per-NH weights updated to %s (raw inputs %s)",
        initial_nhg_id,
        expected_weights,
        new_weights,
    )

    # --- Step 9: cleanup
    logger.info("Step 9: cleanup sharp routes 47.1.1.1..10/32")
    r1.vtysh_cmd("sharp remove routes 47.1.1.1 10")
    _, result = topotest.run_and_expect(
        check_sharp_clean, None, count=20, wait=1
    )
    assert result is None, (
        "cleanup did not remove sharp routes: {}".format(result)
    )


def test_nhg_tracker_route_map():
    """
    Verify route-map / NHG interaction across four stages, including the
    `route_map_ok == false` branch of `nexthop_active_update` in the
    tracker-winner path.

    Stages:
      A. Configure RM denying NH3 (10.0.3.4) for R1, R2.  Install 10
         sharp routes with 3-way ECMP [NH1, NH2, NH3].  Per-NH ACTIVE
         comparison in `nhg_compare_nexthops` splits the routes:
           NHG_A (3-NH all ACTIVE)        -> R3..R10
           NHG_B (3-NH, NH3 inactive)     -> R1, R2

      B. Add a second RM clause denying NH2 (10.0.2.3) for R3, R4.
         RM update triggers rib_process (no rib_link, no tracker).
         R3, R4 split off into a fresh NHG_C (3-NH, NH2 inactive).

      C. Re-install R1, R2 with a 4-way ECMP set (adds NH4 = 10.0.4.5).
         rib_link sees an ECMP change vs NHG_B -> tracker fires on
         NHG_B.  For each winner, RM still denies NH3 ->
         `route_map_ok == false` -> the `if (!route_map_ok)` branch
         leaves TRACKER_REUSE set on NHG_B and the winners land on a
         fresh NHG_D (4-NH list, NH3 inactive).  NHG_B drops to
         refcnt=0 but goes to KEEP_AROUND zombie state (delete timer
         armed) -- NOT freed immediately.

      D. Remove the NH2 deny clause.  R3, R4 re-resolve via rib_process
         (no tracker).  `nhg_compare_nexthops` matches NHG_A directly
         -> R3, R4 migrate to NHG_A (8 REs total).  NHG_C goes to
         KEEP_AROUND zombie.  Both NHG_B and NHG_C remain pending
         deletion.

    Verifies, at each stage, both the zebra view (NHG ids, NH set,
    route bindings) and the kernel view (nhid, kernel NHG members),
    plus the global tracker counters (unchanged in A/B/D, alloc/freed
    each +1 in C).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    prefixes = ["47.1.1.{}/32".format(i) for i in range(1, 11)]
    nh1, nh2, nh3 = "10.0.1.2", "10.0.2.3", "10.0.3.4"
    initial_nhs = [nh1, nh2, nh3]                # 3-way ECMP
    nh4 = "10.0.4.5"                              # added in Stage C
    four_way_nhs = initial_nhs + [nh4]

    denied_nh_for_R12 = nh3                      # NH3 denied for R1, R2
    denied_nh_for_R34 = nh2                      # NH2 denied for R3, R4
    pfx_R12 = prefixes[0:2]                      # R1, R2
    pfx_R34 = prefixes[2:4]                      # R3, R4
    pfx_R5_R10 = prefixes[4:10]                  # R5..R10

    # ------------------------------------------------------------------
    # Test setup: long tracker timer (so flushes are batch-driven, not
    # timeout-driven), scrub any leftover sharp routes from prior tests.
    # ------------------------------------------------------------------
    step("Setup: tracker timer = 60s, scrub leftover sharp routes", reset=True)
    r1.vtysh_cmd("configure terminal\nzebra nexthop-group tracker 60\nend")
    r1.vtysh_cmd("sharp remove routes 47.1.1.1 10")

    def check_sharp_clean():
        out = r1.vtysh_cmd("show ip route sharp json")
        try:
            data = json.loads(out) if out.strip() else {}
        except json.JSONDecodeError:
            return "sharp route json parse failed: {}".format(out[:200])
        for p in prefixes:
            if p in data:
                return "leftover sharp route {} still present".format(p)
        return None

    _, result = topotest.run_and_expect(
        check_sharp_clean, None, count=20, wait=1
    )
    assert result is None, (
        "leftover sharp routes not cleared: {}".format(result)
    )

    baseline_counters = _get_tracker_global_counters(r1)
    assert baseline_counters is not None, (
        "could not snapshot baseline tracker counters"
    )

    # ==================================================================
    # Stage A — RM denies NH3 for R1,R2, then install 10x 3-way ECMP.
    # Expect 2 NHGs: NHG_A (R3..R10, all active) and NHG_B (R1,R2, NH3
    # inactive).  No tracker.
    # ==================================================================
    step("Stage A: configure RM (deny NH3 for R1,R2) and install 10x 3-way ECMP")
    r1.vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "ip prefix-list RM-PFX-NH3 seq 10 permit 47.1.1.1/32",
                "ip prefix-list RM-PFX-NH3 seq 20 permit 47.1.1.2/32",
                "ip prefix-list RM-NH-NH3 seq 10 permit {}/32".format(
                    denied_nh_for_R12
                ),
                "route-map RM-DROP deny 10",
                " match ip address prefix-list RM-PFX-NH3",
                " match ip next-hop prefix-list RM-NH-NH3",
                "route-map RM-DROP permit 99",
                "!",
                "ip protocol sharp route-map RM-DROP",
                "end",
            ]
        )
    )
    r1.vtysh_cmd(
        "sharp install routes 47.1.1.1 nexthops {} 10".format(
            ",".join(initial_nhs)
        )
    )

    # Wait for all 10 prefixes to be installed (regardless of which NHG
    # they land on) before sampling NHG ids.
    def check_all_10_installed():
        for p in prefixes:
            nhg_id, err = _get_route_installed_nhg_id(r1, p, "sharp")
            if err:
                return err
            if nhg_id is None or nhg_id <= 0:
                return "{} has no installed NHG id".format(p)
        return None

    _, result = topotest.run_and_expect(
        check_all_10_installed, None, count=30, wait=1
    )
    assert result is None, (
        "Stage A: initial install did not converge: {}".format(result)
    )

    # Capture NHG_A from one of the all-active prefixes and NHG_B from
    # one of the route-map-affected prefixes.
    nhg_A, err = _get_route_installed_nhg_id(r1, prefixes[2], "sharp")  # R3
    assert err is None, "Stage A: read NHG_A failed: {}".format(err)
    nhg_B, err = _get_route_installed_nhg_id(r1, prefixes[0], "sharp")  # R1
    assert err is None, "Stage A: read NHG_B failed: {}".format(err)
    assert nhg_A != nhg_B, (
        "Stage A: expected R3 and R1 on DIFFERENT NHGs (RM should have "
        "split them), but both are on NHG {}".format(nhg_A)
    )
    logger.info(
        "Stage A: captured NHG_A=%s (all active, R3..R10) NHG_B=%s "
        "(NH3 inactive, R1,R2)", nhg_A, nhg_B,
    )

    def check_stage_A():
        # zebra: route bindings
        err = _check_routes_use_nhg(r1, pfx_R5_R10 + pfx_R34, nhg_A)
        if err:
            return "Stage A: R3..R10 not on NHG_A: " + err
        err = _check_routes_use_nhg(r1, pfx_R12, nhg_B)
        if err:
            return "Stage A: R1,R2 not on NHG_B: " + err
        # zebra: NH set (top-level NHs are identical, only ACTIVE differs)
        err = _check_nhg_nexthops(r1, nhg_A, initial_nhs)
        if err:
            return "Stage A: NHG_A NH set: " + err
        err = _check_nhg_nexthops(r1, nhg_B, initial_nhs)
        if err:
            return "Stage A: NHG_B NH set: " + err
        # kernel: NHG_A has all 3 NHs; NHG_B has only the 2 active ones
        err = _check_kernel_state(
            r1, nhg_A, initial_nhs, pfx_R5_R10 + pfx_R34
        )
        if err:
            return "Stage A: kernel NHG_A: " + err
        err = _check_kernel_state(r1, nhg_B, [nh1, nh2], pfx_R12)
        if err:
            return "Stage A: kernel NHG_B: " + err
        # no tracker activity
        return _check_tracker_counters_unchanged(r1, baseline_counters)

    _, result = topotest.run_and_expect(check_stage_A, None, count=30, wait=1)
    assert result is None, "Stage A: end-state check failed: {}".format(result)
    logger.info("Stage A: PASS — 2 NHGs, no tracker activity")

    # ==================================================================
    # Stage B — add RM clause denying NH2 for R3,R4.  Expect R3,R4 to
    # split off into a new NHG_C (NH2 inactive).  No tracker.
    # ==================================================================
    step("Stage B: add RM clause denying NH2 for R3,R4 (no tracker expected)")
    r1.vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "ip prefix-list RM-PFX-NH2 seq 10 permit 47.1.1.3/32",
                "ip prefix-list RM-PFX-NH2 seq 20 permit 47.1.1.4/32",
                "ip prefix-list RM-NH-NH2 seq 10 permit {}/32".format(
                    denied_nh_for_R34
                ),
                "route-map RM-DROP deny 20",
                " match ip address prefix-list RM-PFX-NH2",
                " match ip next-hop prefix-list RM-NH-NH2",
                "end",
            ]
        )
    )

    # Wait for R3,R4 to migrate off NHG_A.
    def check_R34_moved():
        for p in pfx_R34:
            cur, err = _get_route_installed_nhg_id(r1, p, "sharp")
            if err:
                return err
            if cur == nhg_A or cur == nhg_B:
                return "{} still on NHG {}, expected a new NHG".format(p, cur)
            if cur is None or cur <= 0:
                return "{} has no installed NHG id".format(p)
        # Both R3 and R4 should share the same new NHG (NHG_C).
        c3, _ = _get_route_installed_nhg_id(r1, pfx_R34[0], "sharp")
        c4, _ = _get_route_installed_nhg_id(r1, pfx_R34[1], "sharp")
        if c3 != c4:
            return "R3 on NHG {} but R4 on NHG {}, expected same NHG_C".format(
                c3, c4
            )
        return None

    _, result = topotest.run_and_expect(check_R34_moved, None, count=30, wait=1)
    assert result is None, (
        "Stage B: R3,R4 did not migrate to a new NHG: {}".format(result)
    )

    nhg_C, _ = _get_route_installed_nhg_id(r1, pfx_R34[0], "sharp")
    logger.info(
        "Stage B: captured NHG_C=%s (NH2 inactive, R3,R4)", nhg_C
    )

    def check_stage_B():
        err = _check_routes_use_nhg(r1, pfx_R5_R10, nhg_A)
        if err:
            return "Stage B: R5..R10 not on NHG_A: " + err
        err = _check_routes_use_nhg(r1, pfx_R12, nhg_B)
        if err:
            return "Stage B: R1,R2 not on NHG_B: " + err
        err = _check_routes_use_nhg(r1, pfx_R34, nhg_C)
        if err:
            return "Stage B: R3,R4 not on NHG_C: " + err
        err = _check_nhg_nexthops(r1, nhg_C, initial_nhs)
        if err:
            return "Stage B: NHG_C NH set: " + err
        # kernel: NHG_C has only the 2 active NHs (NH2 filtered out)
        err = _check_kernel_state(r1, nhg_C, [nh1, nh3], pfx_R34)
        if err:
            return "Stage B: kernel NHG_C: " + err
        # NHG_A and NHG_B kernel state unchanged
        err = _check_kernel_state(r1, nhg_A, initial_nhs, pfx_R5_R10)
        if err:
            return "Stage B: kernel NHG_A: " + err
        err = _check_kernel_state(r1, nhg_B, [nh1, nh2], pfx_R12)
        if err:
            return "Stage B: kernel NHG_B: " + err
        # still no tracker activity since baseline
        return _check_tracker_counters_unchanged(r1, baseline_counters)

    _, result = topotest.run_and_expect(check_stage_B, None, count=30, wait=1)
    assert result is None, "Stage B: end-state check failed: {}".format(result)
    logger.info("Stage B: PASS — 3 NHGs, still no tracker activity")

    # ==================================================================
    # Stage C — re-install R1,R2 with 4-way ECMP (adds NH4 = 10.0.4.5).
    # This goes through rib_link's ECMP-change path -> tracker fires on
    # NHG_B.  For each winner, RM still denies NH3 ->
    # `route_map_ok == false` -> winners land on a fresh NHG_D (4-NH,
    # NH3 inactive).  NHG_B becomes KEEP_AROUND zombie.
    # ==================================================================
    step(
        "Stage C: re-install R1,R2 with 4-way ECMP (tracker on NHG_B "
        "should fire; route_map_ok=false path expected)"
    )
    r1.vtysh_cmd(
        "sharp install routes 47.1.1.1 nexthops {} 2".format(
            ",".join(four_way_nhs)
        )
    )

    # Wait for R1,R2 to migrate off NHG_B onto a new NHG_D.
    def check_R12_moved():
        for p in pfx_R12:
            cur, err = _get_route_installed_nhg_id(r1, p, "sharp")
            if err:
                return err
            if cur == nhg_B or cur == nhg_A or cur == nhg_C:
                return "{} still on NHG {}, expected a new NHG_D".format(
                    p, cur
                )
            if cur is None or cur <= 0:
                return "{} has no installed NHG id".format(p)
        d1, _ = _get_route_installed_nhg_id(r1, pfx_R12[0], "sharp")
        d2, _ = _get_route_installed_nhg_id(r1, pfx_R12[1], "sharp")
        if d1 != d2:
            return "R1 on NHG {} but R2 on NHG {}, expected same NHG_D".format(
                d1, d2
            )
        return None

    _, result = topotest.run_and_expect(check_R12_moved, None, count=60, wait=1)
    assert result is None, (
        "Stage C: R1,R2 did not migrate to a new NHG_D: {}".format(result)
    )

    nhg_D, _ = _get_route_installed_nhg_id(r1, pfx_R12[0], "sharp")
    logger.info(
        "Stage C: captured NHG_D=%s (4 NHs, NH3 inactive, R1,R2)", nhg_D,
    )

    def check_stage_C():
        # All three active NHGs and their route bindings
        err = _check_routes_use_nhg(r1, pfx_R5_R10, nhg_A)
        if err:
            return "Stage C: R5..R10 not on NHG_A: " + err
        err = _check_routes_use_nhg(r1, pfx_R34, nhg_C)
        if err:
            return "Stage C: R3,R4 not on NHG_C: " + err
        err = _check_routes_use_nhg(r1, pfx_R12, nhg_D)
        if err:
            return "Stage C: R1,R2 not on NHG_D: " + err
        # NHG_D has 4 NHs in zebra (NH3 inactive), 3 NHs in kernel.
        err = _check_nhg_nexthops(r1, nhg_D, four_way_nhs)
        if err:
            return "Stage C: NHG_D zebra NH set: " + err
        err = _check_kernel_state(r1, nhg_D, [nh1, nh2, nh4], pfx_R12)
        if err:
            return "Stage C: kernel NHG_D: " + err
        # NHG_A and NHG_C unchanged
        err = _check_kernel_state(r1, nhg_A, initial_nhs, pfx_R5_R10)
        if err:
            return "Stage C: kernel NHG_A: " + err
        err = _check_kernel_state(r1, nhg_C, [nh1, nh3], pfx_R34)
        if err:
            return "Stage C: kernel NHG_C: " + err
        # NHG_B is now refcnt=0 but should NOT be freed immediately
        # -- it should be in KEEP_AROUND (timeToDeletion non-empty)
        err = _check_nhg_deletion_pending_or_gone(r1, nhg_B)
        if err:
            return "Stage C: NHG_B zombie check: " + err
        # Tracker fired exactly once on NHG_B (alloc +1, freed +1).
        return _check_tracker_counter_deltas(
            r1,
            baseline_counters,
            {"trackersAllocated": 1, "trackersFreed": 1},
        )

    _, result = topotest.run_and_expect(check_stage_C, None, count=60, wait=1)
    assert result is None, "Stage C: end-state check failed: {}".format(result)
    logger.info(
        "Stage C: PASS — NHG_D=%s created via route_map_ok=false; "
        "NHG_B=%s is KEEP_AROUND zombie; tracker fired once",
        nhg_D, nhg_B,
    )

    # ==================================================================
    # Stage D — remove the NH2 deny clause.  R3,R4 re-resolve via
    # rib_process (no tracker), match NHG_A directly via
    # `nhg_compare_nexthops`, migrate to NHG_A (now 8 REs).  NHG_C
    # becomes a KEEP_AROUND zombie.
    # ==================================================================
    step(
        "Stage D: remove NH2 deny clause; R3,R4 should migrate back to "
        "NHG_A (no tracker); NHG_C goes to KEEP_AROUND zombie"
    )
    r1.vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "no route-map RM-DROP deny 20",
                "end",
            ]
        )
    )

    def check_stage_D():
        # R3,R4 now on NHG_A; R5..R10 still on NHG_A (8 REs total)
        err = _check_routes_use_nhg(r1, pfx_R34 + pfx_R5_R10, nhg_A)
        if err:
            return "Stage D: R3..R10 not all on NHG_A: " + err
        # R1,R2 still on NHG_D
        err = _check_routes_use_nhg(r1, pfx_R12, nhg_D)
        if err:
            return "Stage D: R1,R2 not on NHG_D: " + err
        # Kernel: NHG_A now serves R3..R10 (8 REs)
        err = _check_kernel_state(
            r1, nhg_A, initial_nhs, pfx_R34 + pfx_R5_R10
        )
        if err:
            return "Stage D: kernel NHG_A (8 REs): " + err
        err = _check_kernel_state(r1, nhg_D, [nh1, nh2, nh4], pfx_R12)
        if err:
            return "Stage D: kernel NHG_D: " + err
        # NHG_C is now refcnt=0 -- expect KEEP_AROUND zombie
        err = _check_nhg_deletion_pending_or_gone(r1, nhg_C)
        if err:
            return "Stage D: NHG_C zombie check: " + err
        # NHG_B still in KEEP_AROUND (delete timer hasn't fired yet)
        err = _check_nhg_deletion_pending_or_gone(r1, nhg_B)
        if err:
            return "Stage D: NHG_B still-zombie check: " + err
        # Stage D should not trigger any new tracker activity vs
        # the post-Stage-C state (which itself was alloc/freed +1).
        return _check_tracker_counter_deltas(
            r1,
            baseline_counters,
            {"trackersAllocated": 1, "trackersFreed": 1},
        )

    _, result = topotest.run_and_expect(check_stage_D, None, count=60, wait=1)
    assert result is None, "Stage D: end-state check failed: {}".format(result)
    logger.info(
        "Stage D: PASS — NHG_A has 8 REs (R3..R10); NHG_C=%s and NHG_B=%s "
        "both KEEP_AROUND zombies; no new tracker activity",
        nhg_C, nhg_B,
    )

    # ------------------------------------------------------------------
    # Cleanup: remove the sharp routes and the route-map + prefix-lists.
    # ------------------------------------------------------------------
    step("Cleanup: remove sharp routes and route-map config")
    r1.vtysh_cmd("sharp remove routes 47.1.1.1 10")
    r1.vtysh_cmd(
        "\n".join(
            [
                "configure terminal",
                "no ip protocol sharp route-map RM-DROP",
                "no route-map RM-DROP",
                "no ip prefix-list RM-PFX-NH3",
                "no ip prefix-list RM-PFX-NH2",
                "no ip prefix-list RM-NH-NH3",
                "no ip prefix-list RM-NH-NH2",
                "end",
            ]
        )
    )

    _, result = topotest.run_and_expect(
        check_sharp_clean, None, count=20, wait=1
    )
    assert result is None, (
        "Cleanup: sharp routes not removed: {}".format(result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
