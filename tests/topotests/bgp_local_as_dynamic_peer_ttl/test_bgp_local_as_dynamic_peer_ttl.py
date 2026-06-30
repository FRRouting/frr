#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Sudharsan Rajagopalan
#
# Topotest for bgpd TTL handling when 'local-as ... replace-as' makes a
# session behave like iBGP even though the bgp instance AS differs from
# remote-as.
#
# r3 talks to r1 over a two-hop path (via r2). r1 accepts the session with
# 'bgp listen range' and a peer-group that has matching remote-as/local-as.
# If r1 stamps TTL=1 on the dynamic peer socket the session never comes up.
#

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step, kill_router_daemons, start_router_daemons

pytestmark = [pytest.mark.bgpd]

R1_LO = "192.0.2.1"
R3_LO = "192.0.2.3"


def build_topo(tgen):
    """Build the three-router linear topology."""
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # r1 <-> r2
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])  # r1-eth0
    s1.add_link(tgen.gears["r2"])  # r2-eth0

    # r2 <-> r3
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r2"])  # r2-eth1
    s2.add_link(tgen.gears["r3"])  # r3-eth0


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()
    tgen.gears["r2"].cmd("sysctl -w net.ipv4.ip_forward=1")


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _r1_peer_ttl(addr=R3_LO):
    """
    Read peer->ttl (and the derived iBGP/eBGP sort) from r1 for any peer.

    bgpd emits one of two JSON fields depending on the iBGP/eBGP sort:
      - 'internalBgpNbrMaxHopsAway' when peer->sort == BGP_PEER_IBGP
      - 'externalBgpNbrMaxHopsAway' when peer->sort == BGP_PEER_EBGP
    Both hold the value of peer->ttl (or peer->gtsm_hops when GTSM is on).

    The pre-fix bug is observable in *both* ways:
      - The JSON field is 'externalBgpNbrMaxHopsAway' (wrong sort), AND
      - Its value is 1 (BGP_DEFAULT_TTL, the wrong default).
    After the fix an iBGP-via-local-as session reports
    'internalBgpNbrMaxHopsAway' with value 255.
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    raw = r1.vtysh_cmd("show bgp neighbors {} json".format(addr))
    try:
        data = json.loads(raw)
    except Exception:
        return {"json_parse_failed": raw[:200]}
    nbr = data.get(addr)
    if not nbr:
        return {"neighbor_absent": list(data.keys())}
    internal = nbr.get("internalBgpNbrMaxHopsAway")
    external = nbr.get("externalBgpNbrMaxHopsAway")
    sort = "iBGP" if internal is not None else "eBGP"
    ttl = internal if internal is not None else external
    return {"sort": sort, "ttl": ttl}


def _r1_dynamic_peer_ttl():
    """Back-compat wrapper: peer->ttl for the dynamic peer on r3."""
    return _r1_peer_ttl(R3_LO)


LOCAL_AS = "4271548441"  # r1's bgp AS (matches r1/bgpd.conf)


def _vtysh(cmds):
    """Run a block of config lines on r1 wrapped in configure terminal."""
    tgen = get_topogen()
    body = "\n".join(cmds)
    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp {}\n{}\nend\n".format(LOCAL_AS, body)
    )


def _expect_ttl(addr, sort, ttl, msg, count=30):
    """Wait until r1 reports (sort, ttl) for addr, else fail with msg + state."""

    def _check():
        d = _r1_peer_ttl(addr)
        return None if (d.get("sort") == sort and d.get("ttl") == ttl) else d

    _, res = topotest.run_and_expect(_check, None, count=count, wait=0.5)
    assert res is None, "{} Got: {} (expected {}/{}).".format(msg, res, sort, ttl)


def _r1_dynamic_session_state():
    """Read BGP session state on r1 toward the dynamic peer."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    raw = r1.vtysh_cmd("show bgp neighbors {} json".format(R3_LO))
    try:
        data = json.loads(raw)
    except Exception:
        return {"json_parse_failed": raw[:200]}
    nbr = data.get(R3_LO, {})
    return {"bgpState": nbr.get("bgpState")}


def test_bgp_listen_range_local_as_replace_as_ttl_in_memory():
    """
    Verify that the in-memory peer->ttl for the dynamic peer is MAXTTL
    (255), not the broken BGP_DEFAULT_TTL (1). This is the primary unit
    assertion against the bug -- it is satisfied by the fix in
    peer_create() / peer_group2peer_config_copy() and is observable via
    'show bgp neighbors ... json' as field 'internalBgpNbrMaxHopsAway'
    (or 'externalBgpNbrMaxHopsAway' on the buggy path).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for r1 to accept the dynamic neighbor {} from r3".format(R3_LO))

    def _peer_exists():
        out = json.loads(
            tgen.gears["r1"].vtysh_cmd(
                "show bgp neighbors {} json".format(R3_LO)
            )
        )
        return None if R3_LO in out else {"missing": R3_LO}

    _, res = topotest.run_and_expect(_peer_exists, None, count=60, wait=0.5)
    assert res is None, "r1 never created the dynamic peer for {}: {}".format(
        R3_LO, res
    )

    step("Verify r1 sorts the dynamic peer as iBGP and stamps peer->ttl=MAXTTL(255)")

    def _ttl_is_max():
        d = _r1_dynamic_peer_ttl()
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_ttl_is_max, None, count=30, wait=0.5)
    assert res is None, (
        "Dynamic peer was not classified as iBGP with TTL=255. "
        "Got: {}. This indicates the dynamic-peer + local-as replace-as "
        "TTL regression has reappeared (peer->sort was BGP_PEER_EBGP "
        "and peer->ttl was BGP_DEFAULT_TTL at peer_create time).".format(res)
    )


def test_bgp_listen_range_local_as_replace_as_session_established():
    """
    End-to-end check: r3's BGP session to r1, traversing r2, must
    reach Established. Before the fix, r1's outgoing TTL was 1 so
    r2 dropped the OPEN with ICMP time-exceeded and the session
    stuck in OpenSent / OpenConfirm.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify r3 <-> r1 dynamic BGP session is Established (2-hop path via r2)")

    def _session_up():
        d = _r1_dynamic_session_state()
        return None if d.get("bgpState") == "Established" else d

    _, res = topotest.run_and_expect(_session_up, None, count=120, wait=0.5)
    assert res is None, (
        "r1 <-> r3 session did not reach Established. State on r1: {}. "
        "This is the operational symptom of the TTL=1 bug -- r2 should "
        "be dropping r1's OPEN with ICMP time-exceeded.".format(res)
    )

    step("Cross-check from r3 side")
    out = json.loads(
        tgen.gears["r3"].vtysh_cmd("show bgp neighbors {} json".format(R1_LO))
    )
    state = out.get(R1_LO, {}).get("bgpState")
    assert state == "Established", (
        "r3 view of session to {} is {} (expected Established). "
        "Full output: {}".format(R1_LO, state, json.dumps(out, indent=2)[:1000])
    )


def test_bgp_listen_range_local_as_replace_as_route_exchange():
    """
    Confirm that prefixes can actually be exchanged: r1 must learn
    r3's loopback (192.0.2.3/32) via the iBGP-via-local-as session.
    This guards against a TTL value that is technically >1 but still
    too small to survive the path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _has_route():
        raw = tgen.gears["r1"].vtysh_cmd(
            "show bgp ipv4 unicast {}/32 json".format(R3_LO)
        )
        try:
            data = json.loads(raw)
        except Exception:
            return {"json_parse_failed": raw[:200]}
        paths = data.get("paths", [])
        if not paths:
            return {"no_paths": True}
        # iBGP-learnt route - aspath should be empty / "Local"
        return None

    _, res = topotest.run_and_expect(_has_route, None, count=60, wait=0.5)
    assert res is None, "r1 did not learn {}/32 from r3: {}".format(R3_LO, res)


def test_bgp_listen_range_local_as_replace_as_session_reestablish_after_flap():
    """
    Reconnect scenario.

    After the first session has established, simulate a session flap by
    killing bgpd on the initiator side (r3) and restarting it. r1 will
    still hold the previously-learnt dynamic peer object for r3.

    On reconnect r1 may reuse the existing dynamic peer object or create a
    fresh one depending on the bgp_accept() path. Either way the session
    must still come back with iBGP TTL and reach Established.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    step("Pre-flap: confirm session is already Established (set up by prior tests)")

    def _session_up():
        d = _r1_dynamic_session_state()
        return None if d.get("bgpState") == "Established" else d

    _, res = topotest.run_and_expect(_session_up, None, count=60, wait=0.5)
    assert res is None, "Session not Established before flap: {}".format(res)

    step("Kill bgpd on r3 to force a session flap")
    kill_router_daemons(tgen, "r3", ["bgpd"])

    def _session_down_on_r1():
        d = _r1_dynamic_session_state()
        return None if d.get("bgpState") != "Established" else d

    _, res = topotest.run_and_expect(_session_down_on_r1, None, count=60, wait=0.5)
    assert res is None, (
        "r1 view of dynamic peer never left Established after r3 bgpd kill: "
        "{}".format(res)
    )

    step("Restart bgpd on r3 and reload its configuration")
    start_router_daemons(tgen, "r3", ["bgpd"])
    r3.cmd("vtysh -f {}".format(os.path.join(CWD, "r3/frr.conf")))

    step("Verify the dynamic-peer session re-establishes (post-flap path)")
    _, res = topotest.run_and_expect(_session_up, None, count=120, wait=0.5)
    assert res is None, (
        "r3 <-> r1 session failed to re-Establish after flap. State on r1: "
        "{}. If TTL stayed at 1 the session would fail over the two-hop path.".format(res)
    )

    step("Verify TTL is still iBGP/255 on the re-created dynamic peer")

    def _ttl_still_max():
        d = _r1_dynamic_peer_ttl()
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_ttl_still_max, None, count=30, wait=0.5)
    assert res is None, (
        "Re-created dynamic peer was not sorted as iBGP with TTL=255 after "
        "flap. Got: {}. This indicates the reconnect path "
        "(peer_create_bind_dynamic_neighbor -> peer_create) regressed.".format(res)
    )


def test_bgp_nonpg_neighbor_local_as_replace_as_ttl():
    """
    Regular (non-peer-group) neighbor variant of the same bug.

    The dynamic-peer path is not the only consumer of the TTL-from-sort
    derivation: a plain 'neighbor <addr> remote-as X' + 'neighbor <addr>
    local-as X no-prepend replace-as' is also logically iBGP and must be
    stamped with peer->ttl = MAXTTL(255). This exercises peer_local_as_set()
    directly (not peer_group2peer_config_copy()), which previously called
    peer_sort() but never re-derived peer->ttl.

    A TEST-NET-1 address (192.0.2.7, RFC 5737) is used so the neighbor never
    forms a real session; only r1's in-memory peer->ttl is inspected.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure a regular (non-PG) neighbor with local-as replace-as")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.7 remote-as 65001\n"
        " neighbor 192.0.2.7 local-as 65001 no-prepend replace-as\n"
        " neighbor 192.0.2.7 timers connect 120\n"
        "end\n"
    )

    step("peer_local_as_set() must classify it iBGP and stamp TTL=255")

    def _nonpg_ttl_max():
        d = _r1_peer_ttl("192.0.2.7")
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_nonpg_ttl_max, None, count=30, wait=0.5)
    assert res is None, (
        "Non-peer-group neighbor with 'local-as replace-as' was not "
        "classified as iBGP with TTL=255. Got: {}. peer_local_as_set() "
        "is not re-deriving peer->ttl from the new sort.".format(res)
    )


def test_bgp_nonpg_neighbor_local_as_removal_reverts_ttl():
    """
    Removal half of the regular-neighbor case.

    Removing 'local-as ... replace-as' turns the session back into eBGP (its
    remote-as 65001 differs from the local bgp AS 4271548441), so peer->ttl
    must revert from MAXTTL(255) to the eBGP default (1). This exercises
    peer_local_as_unset(), which previously left a stale TTL=255 behind.

    Self-contained: configures its own neighbor + local-as so the coverage does
    not depend on pytest ordering (running standalone or with -k must work).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure the neighbor with local-as replace-as (iBGP-via-local-as)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.7 remote-as 65001\n"
        " neighbor 192.0.2.7 local-as 65001 no-prepend replace-as\n"
        " neighbor 192.0.2.7 timers connect 120\n"
        "end\n"
    )

    step("Sanity: neighbor 192.0.2.7 is currently iBGP/255")

    def _nonpg_ttl_max():
        d = _r1_peer_ttl("192.0.2.7")
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_nonpg_ttl_max, None, count=30, wait=0.5)
    assert res is None, "Precondition failed (expected iBGP/255): {}".format(res)

    step("Remove the local-as override")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.7 local-as\n"
        "end\n"
    )

    step("peer_local_as_unset() must revert the peer to eBGP/TTL=1")

    def _nonpg_ttl_reverted():
        d = _r1_peer_ttl("192.0.2.7")
        return None if (d.get("sort") == "eBGP" and d.get("ttl") == 1) else d

    _, res = topotest.run_and_expect(_nonpg_ttl_reverted, None, count=30, wait=0.5)
    assert res is None, (
        "After removing 'local-as replace-as' the neighbor still does not "
        "report eBGP/TTL=1. Got: {}. peer_local_as_unset() is not "
        "re-deriving peer->ttl, leaving a stale MAXTTL behind.".format(res)
    )

    step("Clean up the temporary neighbor")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.7\n"
        "end\n"
    )


def test_bgp_dynamic_peer_local_as_removal_reverts_ttl():
    """
    Remove local-as from the dynamic peer-group and check TTL falls back to 1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Pre-removal: dynamic peer {} is iBGP/255".format(R3_LO))

    def _dyn_ttl_max():
        d = _r1_peer_ttl(R3_LO)
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_dyn_ttl_max, None, count=60, wait=0.5)
    assert res is None, "Precondition failed (expected iBGP/255): {}".format(res)

    step("Remove local-as from the peer-group")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor PG_DYN local-as\n"
        "end\n"
    )

    step("Member TTL must revert to eBGP/1 via peer_local_as_unset() member loop")

    def _dyn_ttl_reverted():
        d = _r1_peer_ttl(R3_LO)
        return None if (d.get("sort") == "eBGP" and d.get("ttl") == 1) else d

    _, res = topotest.run_and_expect(_dyn_ttl_reverted, None, count=30, wait=0.5)
    assert res is None, (
        "After removing the peer-group local-as the dynamic member still "
        "does not report eBGP/TTL=1. Got: {}. The member loop in "
        "peer_local_as_unset() is not re-deriving peer->ttl.".format(res)
    )

    step("Re-apply local-as so the dynamic member is iBGP/255 again")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor PG_DYN local-as 65001 no-prepend replace-as\n"
        "end\n"
    )

    _, res = topotest.run_and_expect(_dyn_ttl_max, None, count=60, wait=0.5)
    assert res is None, (
        "After re-applying local-as the dynamic member did not return to "
        "iBGP/255 (peer_local_as_set() member loop). Got: {}".format(res)
    )


def test_bgp_ebgp_multihop_ttl_preserved_across_local_as_toggle():
    """
    A configured 'ebgp-multihop <hops>' must survive a local-as add/remove
    round-trip. The configured value is held in peer->cfg_ttl, so the effective
    peer->ttl tracks the sort: iBGP is always MAXTTL(255), eBGP restores cfg_ttl.

    Scenario (the AIReviewer-Bot Sev-3 concern, fixed via cfg_ttl):
      1. Configure an eBGP neighbor with 'ebgp-multihop 5' -> cfg_ttl=5, ttl=5.
      2. Add 'local-as <remote-as> no-prepend replace-as'. The peer is now
         iBGP, so peer->ttl becomes MAXTTL(255) (iBGP's only valid TTL), while
         cfg_ttl=5 is retained out of band.
      3. Remove the local-as override. The peer is eBGP again and peer->ttl
         must be restored from cfg_ttl to 5 (NOT BGP_DEFAULT_TTL=1, which would
         break a >1-hop eBGP session).

    A TEST-NET-1 address (192.0.2.8, RFC 5737) is used so no real session
    forms; only r1's in-memory peer->ttl is inspected.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Configure an eBGP neighbor with 'ebgp-multihop 5' (cfg_ttl=5, ttl=5)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.8 remote-as 65002\n"
        " neighbor 192.0.2.8 ebgp-multihop 5\n"
        " neighbor 192.0.2.8 timers connect 120\n"
        "end\n"
    )

    def _ttl_is(expected_sort, expected_ttl):
        d = _r1_peer_ttl("192.0.2.8")
        ok = d.get("sort") == expected_sort and d.get("ttl") == expected_ttl
        return None if ok else d

    step("Baseline: eBGP with ttl=5")
    _, res = topotest.run_and_expect(
        lambda: _ttl_is("eBGP", 5), None, count=30, wait=0.5
    )
    assert res is None, "ebgp-multihop 5 not applied (expected eBGP/5): {}".format(res)

    step("Add local-as making it iBGP; effective ttl becomes MAXTTL(255)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.8 local-as 65002 no-prepend replace-as\n"
        "end\n"
    )

    step("iBGP must report MAXTTL(255); cfg_ttl=5 is preserved out of band")
    _, res = topotest.run_and_expect(
        lambda: _ttl_is("iBGP", 255), None, count=30, wait=0.5
    )
    assert res is None, (
        "After adding local-as the peer was not iBGP/255. Got: {}. iBGP must "
        "use MAXTTL; the configured 5 is kept in cfg_ttl for later "
        "restoration.".format(res)
    )

    step("Remove local-as; peer is eBGP again and ttl must be restored to 5")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.8 local-as\n"
        "end\n"
    )

    _, res = topotest.run_and_expect(
        lambda: _ttl_is("eBGP", 5), None, count=30, wait=0.5
    )
    assert res is None, (
        "After removing local-as the eBGP multihop TTL was not restored to "
        "5 from cfg_ttl. Got: {}. A reset to BGP_DEFAULT_TTL(1) here would "
        "stop a multi-hop eBGP session from establishing.".format(res)
    )

    step("Clean up the temporary neighbor")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.8\n"
        "end\n"
    )


def test_bgp_local_as_on_group_does_not_pollute_template_ttl():
    """
    Applying 'local-as' to a peer-group must not write a *derived* iBGP
    default TTL into the group template (group->conf->ttl).

    peer_group2peer_config_copy() treats any non-default conf->ttl as an
    explicitly configured peer-group ebgp-multihop and copies it onto
    members. If 'neighbor PG local-as <remote-as> replace-as' (which makes
    the group template classify as iBGP) had stamped group->conf->ttl =
    MAXTTL, a member that is itself eBGP (e.g. it overrides local-as with a
    non-matching AS) would inherit 255 even though the group never
    configured multihop.

    Test: PG_TMPL has remote-as 65003 and gets a group-level local-as that
    makes the template look iBGP. A member then overrides local-as with a
    different AS so it stays eBGP. Its TTL must be the eBGP default (1), not
    a 255 leaked from the template.

    TEST-NET addresses (RFC 5737) are used; no real session is formed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Create PG_TMPL (remote-as 65003) and apply group-level local-as")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor PG_TMPL peer-group\n"
        " neighbor PG_TMPL remote-as 65003\n"
        " neighbor PG_TMPL local-as 65003 no-prepend replace-as\n"
        "end\n"
    )

    step("Add a member that overrides local-as with a non-matching AS (eBGP)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.9 peer-group PG_TMPL\n"
        " neighbor 192.0.2.9 local-as 65009 no-prepend replace-as\n"
        " neighbor 192.0.2.9 timers connect 120\n"
        "end\n"
    )

    step("Member must be eBGP/TTL=1; a 255 here means the template was polluted")

    def _member_ebgp_default():
        d = _r1_peer_ttl("192.0.2.9")
        return None if (d.get("sort") == "eBGP" and d.get("ttl") == 1) else d

    _, res = topotest.run_and_expect(_member_ebgp_default, None, count=30, wait=0.5)
    assert res is None, (
        "eBGP peer-group member inherited a non-default TTL. Got: {}. "
        "Applying 'local-as' to the group polluted group->conf->ttl with a "
        "derived iBGP default (MAXTTL), which was then copied onto the "
        "member by peer_group2peer_config_copy().".format(res)
    )

    step("Clean up the temporary member and peer-group")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.9\n"
        " no neighbor PG_TMPL\n"
        "end\n"
    )


def test_bgp_group_ebgp_multihop_inherited_when_member_leaves_ibgp():
    """
    A member leaving iBGP must inherit the peer-group's configured
    'ebgp-multihop', not reset to the eBGP default (AIReviewer-Bot Sev-3).

    Scenario: PG_MH has remote-as 65004. A member is first made iBGP via a
    member-level 'local-as 65004 replace-as', so it carries the implicit
    MAXTTL (255). 'ebgp-multihop 5' is then applied to the *group* -
    peer_ebgp_multihop_set() skips iBGP members, so the member's TTL stays
    255 while group->conf->ttl becomes 5. Removing the member's local-as
    turns it back to eBGP; the helper must inherit the group's ttl=5 (via
    peer->group->conf->ttl) rather than fall back to BGP_DEFAULT_TTL=1, so
    the multi-hop eBGP session can still establish.

    Ordering matters: the group ebgp-multihop must be applied *after* the
    member is iBGP, otherwise peer_group2peer_config_copy() would copy 5
    onto the still-eBGP member at bind time and the member would never be at
    the implicit 255 this scenario exercises.

    TEST-NET addresses (RFC 5737) are used; no real session is formed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Create PG_MH (remote-as 65004) and bind an iBGP member (local-as)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor PG_MH peer-group\n"
        " neighbor PG_MH remote-as 65004\n"
        " neighbor 192.0.2.10 peer-group PG_MH\n"
        " neighbor 192.0.2.10 local-as 65004 no-prepend replace-as\n"
        " neighbor 192.0.2.10 timers connect 120\n"
        "end\n"
    )

    step("Member is iBGP while local-as matches remote-as (TTL=255 implicit)")

    def _member_ibgp():
        d = _r1_peer_ttl("192.0.2.10")
        return None if (d.get("sort") == "iBGP" and d.get("ttl") == 255) else d

    _, res = topotest.run_and_expect(_member_ibgp, None, count=30, wait=0.5)
    assert res is None, "Member not iBGP/255 before group multihop: {}".format(res)

    step("Apply 'ebgp-multihop 5' to the group; the iBGP member is skipped")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor PG_MH ebgp-multihop 5\n"
        "end\n"
    )

    step("Member must still be iBGP/255 (group's 5 was not stamped on it)")
    _, res = topotest.run_and_expect(_member_ibgp, None, count=30, wait=0.5)
    assert res is None, (
        "iBGP member's TTL changed when 'ebgp-multihop 5' was applied to the "
        "group; peer_ebgp_multihop_set() must skip iBGP members. Got: "
        "{}".format(res)
    )

    step("Remove member local-as; member is eBGP and must inherit group ttl=5")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.10 local-as\n"
        "end\n"
    )

    def _member_inherits_group_ttl():
        d = _r1_peer_ttl("192.0.2.10")
        return None if (d.get("sort") == "eBGP" and d.get("ttl") == 5) else d

    _, res = topotest.run_and_expect(
        _member_inherits_group_ttl, None, count=30, wait=0.5
    )
    assert res is None, (
        "After removing the member's local-as the eBGP member did not "
        "inherit the peer-group's ebgp-multihop TTL (5). Got: {}. The helper "
        "must restore peer->group->conf->ttl when an active member leaves "
        "iBGP, not reset to BGP_DEFAULT_TTL(1).".format(res)
    )

    step("Clean up the temporary member and peer-group")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.10\n"
        " no neighbor PG_MH\n"
        "end\n"
    )


def test_bgp_ebgp_multihop_255_survives_local_as_toggle():
    """
    The headline ambiguity fix: an explicit 'ebgp-multihop 255' is numerically
    identical to the implicit iBGP MAXTTL, so without a separate store it was
    impossible to tell, after a local-as toggle, whether 255 was operator
    configured or just the iBGP default. With cfg_ttl the configured 255 is
    remembered, so removing local-as restores eBGP/255 instead of collapsing to
    the eBGP default (1).

    Steps (TEST-NET-1 192.0.2.11, no real session):
      1. eBGP neighbor + 'ebgp-multihop 255' -> cfg_ttl=255, eBGP/255.
      2. Add local-as -> iBGP/255.
      3. Remove local-as -> eBGP/255 (restored from cfg_ttl, NOT 1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("eBGP neighbor with 'ebgp-multihop 255' (cfg_ttl=255)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.11 remote-as 65011\n"
        " neighbor 192.0.2.11 ebgp-multihop 255\n"
        " neighbor 192.0.2.11 timers connect 120\n"
        "end\n"
    )

    def _ttl_is(expected_sort, expected_ttl):
        d = _r1_peer_ttl("192.0.2.11")
        ok = d.get("sort") == expected_sort and d.get("ttl") == expected_ttl
        return None if ok else d

    step("Baseline: eBGP/255")
    _, res = topotest.run_and_expect(
        lambda: _ttl_is("eBGP", 255), None, count=30, wait=0.5
    )
    assert res is None, "ebgp-multihop 255 not applied (expected eBGP/255): {}".format(
        res
    )

    step("Add local-as -> iBGP/255")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " neighbor 192.0.2.11 local-as 65011 no-prepend replace-as\n"
        "end\n"
    )
    _, res = topotest.run_and_expect(
        lambda: _ttl_is("iBGP", 255), None, count=30, wait=0.5
    )
    assert res is None, "Expected iBGP/255 after local-as: {}".format(res)

    step("Remove local-as -> eBGP/255 must be restored from cfg_ttl (not 1)")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.11 local-as\n"
        "end\n"
    )
    _, res = topotest.run_and_expect(
        lambda: _ttl_is("eBGP", 255), None, count=30, wait=0.5
    )
    assert res is None, (
        "Explicit 'ebgp-multihop 255' was lost across a local-as toggle. "
        "Got: {} (expected eBGP/255). cfg_ttl must disambiguate a configured "
        "255 from the implicit iBGP MAXTTL.".format(res)
    )

    step("Clean up")
    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 4271548441\n"
        " no neighbor 192.0.2.11\n"
        "end\n"
    )


def test_bgp_ebgp_multihop_ttl_preserved_across_remote_as_toggle():
    """
    The same cfg_ttl preservation must hold on the remote-as path
    (peer_as_change), not just local-as. Changing 'remote-as' so the peer
    flips eBGP<->iBGP must keep a configured ebgp-multihop (including 255).

    Steps (TEST-NET-1 192.0.2.12, no real session):
      1. eBGP neighbor (remote-as 65012) + 'ebgp-multihop 7' -> eBGP/7.
      2. Change remote-as to the local AS -> iBGP/255 (cfg_ttl=7 preserved).
      3. Change remote-as back to 65012 -> eBGP/7 restored.
      4. Repeat with 'ebgp-multihop 255' to cover the ambiguous boundary.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    local_as = "4271548441"

    def _ttl_is(expected_sort, expected_ttl):
        d = _r1_peer_ttl("192.0.2.12")
        ok = d.get("sort") == expected_sort and d.get("ttl") == expected_ttl
        return None if ok else d

    for hops in (7, 255):
        step("eBGP neighbor (remote-as 65012) with 'ebgp-multihop {}'".format(hops))
        r1.vtysh_cmd(
            "configure terminal\n"
            "router bgp {}\n"
            " neighbor 192.0.2.12 remote-as 65012\n"
            " neighbor 192.0.2.12 ebgp-multihop {}\n"
            " neighbor 192.0.2.12 timers connect 120\n"
            "end\n".format(local_as, hops)
        )
        _, res = topotest.run_and_expect(
            lambda: _ttl_is("eBGP", hops), None, count=30, wait=0.5
        )
        assert res is None, "Expected eBGP/{} baseline: {}".format(hops, res)

        step("remote-as -> local AS makes it iBGP/255 (cfg_ttl kept)")
        r1.vtysh_cmd(
            "configure terminal\n"
            "router bgp {}\n"
            " neighbor 192.0.2.12 remote-as {}\n"
            "end\n".format(local_as, local_as)
        )
        _, res = topotest.run_and_expect(
            lambda: _ttl_is("iBGP", 255), None, count=30, wait=0.5
        )
        assert res is None, "Expected iBGP/255 after remote-as change: {}".format(res)

        step("remote-as back to 65012 -> eBGP/{} restored via cfg_ttl".format(hops))
        r1.vtysh_cmd(
            "configure terminal\n"
            "router bgp {}\n"
            " neighbor 192.0.2.12 remote-as 65012\n"
            "end\n".format(local_as)
        )
        _, res = topotest.run_and_expect(
            lambda: _ttl_is("eBGP", hops), None, count=30, wait=0.5
        )
        assert res is None, (
            "ebgp-multihop {} was lost across a remote-as toggle. Got: {} "
            "(expected eBGP/{}). peer_as_change() must re-derive ttl via the "
            "shared helper and keep cfg_ttl.".format(hops, res, hops)
        )

        step("Clean up for next iteration")
        r1.vtysh_cmd(
            "configure terminal\n"
            "router bgp {}\n"
            " no neighbor 192.0.2.12\n"
            "end\n".format(local_as)
        )


# ---------------------------------------------------------------------------
# Full TTL matrix.
#
# The tests above target the specific regression and the AIReviewer-Bot
# concerns. The block below exhaustively walks the (peer-kind x base-sort x
# transition) matrix so every code path that derives peer->ttl is exercised:
#
#   peer kinds : regular (non-peer-group) neighbor, peer-group member
#   base sorts : plain iBGP (remote-as == local AS), plain eBGP
#   transitions: eBGP <-> iBGP via local-as override (add then remove)
#                eBGP <-> iBGP via remote-as change   (change then revert)
#   modifier   : an optional 'ebgp-multihop <hops>' (incl. 255) that must be
#                preserved (held in peer->cfg_ttl) across every transition
#
# Expected peer->ttl is always a pure function of the *current* sort:
#   iBGP -> 255 (MAXTTL, FRR has no per-iBGP TTL knob)
#   eBGP -> configured ebgp-multihop (own, else group's) else 1 (default)
#
# All neighbors use TEST-NET (RFC 5737) addresses so no real session forms;
# only r1's in-memory peer->ttl / sort is inspected.
# ---------------------------------------------------------------------------


def test_matrix_regular_ibgp_baseline():
    """Plain iBGP regular neighbor (remote-as == local AS) -> iBGP/255."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.20"
    step("Regular neighbor with remote-as == local AS is iBGP/255")
    _vtysh(
        [
            " neighbor {} remote-as {}".format(addr, LOCAL_AS),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "iBGP", 255, "Plain iBGP neighbor not iBGP/255.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_regular_ebgp_baseline():
    """Plain eBGP regular neighbor -> eBGP/1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.21"
    step("Regular neighbor with a different remote-as is eBGP/1")
    _vtysh(
        [
            " neighbor {} remote-as 65021".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "Plain eBGP neighbor not eBGP/1.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_regular_ebgp_local_as_roundtrip():
    """
    Regular eBGP neighbor: add 'local-as <remote-as> replace-as' -> iBGP/255,
    then remove it -> back to eBGP/1. Exercises peer_local_as_set/_unset on a
    non-peer-group peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.22"
    step("Baseline eBGP/1")
    _vtysh(
        [
            " neighbor {} remote-as 65022".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "Baseline not eBGP/1.")

    step("Add local-as override -> iBGP/255")
    _vtysh([" neighbor {} local-as 65022 no-prepend replace-as".format(addr)])
    _expect_ttl(addr, "iBGP", 255, "local-as override did not yield iBGP/255.")

    step("Remove local-as -> back to eBGP/1")
    _vtysh([" no neighbor {} local-as".format(addr)])
    _expect_ttl(addr, "eBGP", 1, "Removing local-as did not revert to eBGP/1.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_regular_remote_as_roundtrip():
    """
    Regular neighbor: flip eBGP<->iBGP by changing remote-as (no multihop).
    Exercises peer_as_change() on a non-peer-group peer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.23"
    step("Baseline eBGP/1")
    _vtysh(
        [
            " neighbor {} remote-as 65023".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "Baseline not eBGP/1.")

    step("remote-as -> local AS makes it iBGP/255")
    _vtysh([" neighbor {} remote-as {}".format(addr, LOCAL_AS)])
    _expect_ttl(addr, "iBGP", 255, "remote-as change to local AS not iBGP/255.")

    step("remote-as back to a different AS -> eBGP/1")
    _vtysh([" neighbor {} remote-as 65023".format(addr)])
    _expect_ttl(addr, "eBGP", 1, "remote-as revert did not yield eBGP/1.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_pg_member_ibgp_baseline():
    """Peer-group with remote-as == local AS: member is iBGP/255."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.24"
    step("iBGP peer-group + member -> iBGP/255")
    _vtysh(
        [
            " neighbor PG_IBGP peer-group",
            " neighbor PG_IBGP remote-as {}".format(LOCAL_AS),
            " neighbor {} peer-group PG_IBGP".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "iBGP", 255, "iBGP peer-group member not iBGP/255.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_IBGP"])


def test_matrix_pg_member_ebgp_baseline():
    """Peer-group with a different remote-as: member is eBGP/1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.25"
    step("eBGP peer-group + member -> eBGP/1")
    _vtysh(
        [
            " neighbor PG_EBGP peer-group",
            " neighbor PG_EBGP remote-as 65025",
            " neighbor {} peer-group PG_EBGP".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "eBGP peer-group member not eBGP/1.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_EBGP"])


def test_matrix_pg_group_local_as_roundtrip():
    """
    eBGP peer-group: apply 'local-as <remote-as> replace-as' on the *group*
    -> members become iBGP/255; remove it -> members revert to eBGP/1.
    Exercises the member loops in peer_local_as_set/_unset.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.26"
    step("Baseline: eBGP peer-group member eBGP/1")
    _vtysh(
        [
            " neighbor PG_LA peer-group",
            " neighbor PG_LA remote-as 65026",
            " neighbor {} peer-group PG_LA".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "Baseline member not eBGP/1.")

    step("Apply group local-as override -> member iBGP/255")
    _vtysh([" neighbor PG_LA local-as 65026 no-prepend replace-as"])
    _expect_ttl(addr, "iBGP", 255, "Group local-as did not make member iBGP/255.")

    step("Remove group local-as -> member back to eBGP/1")
    _vtysh([" no neighbor PG_LA local-as"])
    _expect_ttl(addr, "eBGP", 1, "Removing group local-as did not revert member.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_LA"])


def test_matrix_pg_group_remote_as_roundtrip():
    """
    Peer-group: flip members eBGP<->iBGP by changing the group remote-as.
    Exercises peer_group_remote_as() -> peer_as_change() member loop.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.27"
    step("Baseline: eBGP peer-group member eBGP/1")
    _vtysh(
        [
            " neighbor PG_RA peer-group",
            " neighbor PG_RA remote-as 65027",
            " neighbor {} peer-group PG_RA".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 1, "Baseline member not eBGP/1.")

    step("Group remote-as -> local AS makes members iBGP/255")
    _vtysh([" neighbor PG_RA remote-as {}".format(LOCAL_AS)])
    _expect_ttl(addr, "iBGP", 255, "Group remote-as change did not make member iBGP.")

    step("Group remote-as back to a different AS -> members eBGP/1")
    _vtysh([" neighbor PG_RA remote-as 65027"])
    _expect_ttl(addr, "eBGP", 1, "Group remote-as revert did not yield eBGP/1.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_RA"])


def test_matrix_pg_member_ebgp_multihop_local_as_roundtrip():
    """
    eBGP peer-group with 'ebgp-multihop <hops>': a member must show eBGP/hops,
    iBGP/255 while a group local-as override is active, and eBGP/hops again
    once removed. Run for hops=6 and the 255 boundary. Exercises group cfg_ttl
    inheritance through the local-as member loops.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.28"
    for hops in (6, 255):
        step(
            "eBGP peer-group + 'ebgp-multihop {}' -> member eBGP/{}".format(hops, hops)
        )
        _vtysh(
            [
                " neighbor PG_MH2 peer-group",
                " neighbor PG_MH2 remote-as 65028",
                " neighbor PG_MH2 ebgp-multihop {}".format(hops),
                " neighbor {} peer-group PG_MH2".format(addr),
                " neighbor {} timers connect 120".format(addr),
            ]
        )
        _expect_ttl(addr, "eBGP", hops, "Member did not inherit group multihop.")

        step("Group local-as override -> member iBGP/255 (cfg_ttl kept)")
        _vtysh([" neighbor PG_MH2 local-as 65028 no-prepend replace-as"])
        _expect_ttl(addr, "iBGP", 255, "Member not iBGP/255 under group local-as.")

        step("Remove group local-as -> member eBGP/{} restored".format(hops))
        _vtysh([" no neighbor PG_MH2 local-as"])
        _expect_ttl(
            addr,
            "eBGP",
            hops,
            "Member lost group ebgp-multihop {} across local-as toggle.".format(hops),
        )

        step("Clean up for next iteration")
        _vtysh([" no neighbor {}".format(addr), " no neighbor PG_MH2"])


def _r1_running_has(needle):
    """Return None if 'needle' appears in r1's running-config, else the config."""
    tgen = get_topogen()
    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    return None if needle in out else out


def test_matrix_ebgp_multihop_persists_in_running_config_while_ibgp():
    """
    Persistence: an explicit 'ebgp-multihop' must remain in the running-config
    even while a local-as override temporarily makes the peer iBGP, so a
    'write memory'/reload does not silently drop it (and later fall back to
    TTL 1 on returning to eBGP). The config writer serializes from
    peer->cfg_ttl, which is sort-independent.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.29"
    step("eBGP neighbor with 'ebgp-multihop 7'")
    _vtysh(
        [
            " neighbor {} remote-as 65029".format(addr),
            " neighbor {} ebgp-multihop 7".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 7, "Baseline not eBGP/7.")

    step("running-config emits 'ebgp-multihop 7' while eBGP")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 7".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "ebgp-multihop 7 missing from running-config (eBGP)."

    step("Add local-as -> iBGP/255, but running-config must STILL show multihop 7")
    _vtysh([" neighbor {} local-as 65029 no-prepend replace-as".format(addr)])
    _expect_ttl(addr, "iBGP", 255, "Peer not iBGP/255 after local-as.")

    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 7".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "ebgp-multihop 7 dropped from running-config while the peer is "
        "iBGP-via-local-as; a write/reload here would lose the configured "
        "multihop and the peer would fall back to TTL 1 when local-as is "
        "removed. The writer must serialize from peer->cfg_ttl."
    )

    step("Remove local-as -> eBGP/7 restored")
    _vtysh([" no neighbor {} local-as".format(addr)])
    _expect_ttl(addr, "eBGP", 7, "Did not restore eBGP/7 after local-as removal.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_no_ebgp_multihop_while_ibgp_clears_config():
    """
    Clearing an explicitly configured 'ebgp-multihop' must work even while a
    local-as override temporarily makes the peer iBGP. Otherwise the command is
    silently ignored, running-config keeps the old multihop line, and the peer
    returns to eBGP with the stale configured TTL instead of the default TTL 1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.43"
    step("eBGP neighbor with explicit ebgp-multihop 7")
    _vtysh(
        [
            " neighbor {} remote-as 65043".format(addr),
            " neighbor {} ebgp-multihop 7".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 7, "Baseline not eBGP/7.")

    step("local-as makes the peer iBGP/255 while cfg_ttl still stores 7")
    _vtysh([" neighbor {} local-as 65043 no-prepend replace-as".format(addr)])
    _expect_ttl(addr, "iBGP", 255, "Peer not iBGP/255 after local-as.")

    step("Clear ebgp-multihop while the peer is iBGP-sorted")
    _vtysh([" no neighbor {} ebgp-multihop".format(addr)])

    step("running-config must no longer contain ebgp-multihop for this peer")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor {} ebgp-multihop".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "'no ebgp-multihop' while iBGP did not clear cfg_ttl; running-config "
        "still contains the stale multihop line."
    )

    step("Remove local-as -> eBGP default TTL 1, not the stale configured 7")
    _vtysh([" no neighbor {} local-as".format(addr)])
    _expect_ttl(
        addr,
        "eBGP",
        1,
        "Cleared ebgp-multihop came back after local-as removal.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_ttl_security_does_not_become_ebgp_multihop():
    """
    ttl-security uses MAXTTL internally but must not be recorded as a
    configured 'ebgp-multihop'. Configure ttl-security on an eBGP peer, flip it
    to iBGP via local-as, remove ttl-security, then return to eBGP: the peer
    must come back at the eBGP default (1), not a spurious 255, and the
    running-config must never emit 'ebgp-multihop' for it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.30"
    step("eBGP neighbor with ttl-security hops 3 (no ebgp-multihop)")
    _vtysh(
        [
            " neighbor {} remote-as 65030".format(addr),
            " neighbor {} ttl-security hops 3".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("running-config must NOT contain ebgp-multihop for this peer")
    _, res = topotest.run_and_expect(
        lambda: (
            None
            if "neighbor {} ebgp-multihop".format(addr)
            not in get_topogen().gears["r1"].vtysh_cmd("show running-config")
            else "ebgp-multihop leaked"
        ),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "ttl-security was serialized as ebgp-multihop."

    step("local-as -> iBGP, remove ttl-security while iBGP, back to eBGP")
    _vtysh([" neighbor {} local-as 65030 no-prepend replace-as".format(addr)])
    _vtysh([" no neighbor {} ttl-security hops 3".format(addr)])
    _vtysh([" no neighbor {} local-as".format(addr)])

    step("Back to eBGP: must be the default TTL 1, not a leaked 255")
    _expect_ttl(
        addr,
        "eBGP",
        1,
        "ttl-security MAXTTL leaked into cfg_ttl and resurrected as eBGP/255.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_member_own_ebgp_multihop_survives_group_bind():
    """
    A neighbor configured with its own 'ebgp-multihop 4' that is then bound to
    a peer-group with NO group-level multihop must keep its own value (eBGP/4),
    not be reset to the default by peer_group2peer_config_copy().
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.31"
    step("Neighbor with its own 'ebgp-multihop 4'")
    _vtysh(
        [
            " neighbor {} remote-as 65031".format(addr),
            " neighbor {} ebgp-multihop 4".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 4, "Baseline not eBGP/4.")

    step("Create a group with no multihop and bind the neighbor to it")
    _vtysh(
        [
            " neighbor PG_NOMH peer-group",
            " neighbor PG_NOMH remote-as 65031",
            " neighbor {} peer-group PG_NOMH".format(addr),
        ]
    )

    step("Member must keep its own ebgp-multihop 4 (group has none)")
    _expect_ttl(
        addr,
        "eBGP",
        4,
        "Binding to a no-multihop group wiped the member's own ebgp-multihop.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_NOMH"])


def test_matrix_ebgp_multihop_noop_under_ttl_security_not_recorded():
    """
    If ttl-security is configured first, a subsequent bare 'ebgp-multihop'
    (which maps to MAXTTL) is a no-op for an already-MAXTTL peer and must NOT
    be recorded as configured multihop. Otherwise the running-config would emit
    BOTH 'ebgp-multihop' and 'ttl-security', and a reload would reject the
    ttl-security line as a conflict.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.32"
    step("eBGP neighbor with ttl-security hops 2, then a bare ebgp-multihop")
    _vtysh(
        [
            " neighbor {} remote-as 65032".format(addr),
            " neighbor {} ttl-security hops 2".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    # Bare 'ebgp-multihop' (-> MAXTTL) is a no-op while ttl-security is active.
    _vtysh([" neighbor {} ebgp-multihop".format(addr)])

    step("running-config must NOT contain ebgp-multihop for this peer")
    _, res = topotest.run_and_expect(
        lambda: (
            None
            if "neighbor {} ebgp-multihop".format(addr)
            not in get_topogen().gears["r1"].vtysh_cmd("show running-config")
            else "ebgp-multihop spuriously recorded"
        ),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "A bare ebgp-multihop no-op under ttl-security was recorded as "
        "configured multihop; running-config now emits a conflicting pair."
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def _r1_running_lacks(needle):
    """Return None if 'needle' is absent from r1's running-config, else config."""
    tgen = get_topogen()
    out = tgen.gears["r1"].vtysh_cmd("show running-config")
    return None if needle not in out else out


def test_matrix_ttl_security_preserved_across_local_as_toggle():
    """
    ttl-security (GTSM) keeps the effective TTL at MAXTTL while enabled. When a
    local-as override toggles the peer iBGP and back, peer_ttl_update() must NOT
    clobber that MAXTTL with the cfg_ttl/default (which would make a multihop
    GTSM peer look directly connected to NHT/BFD). The 'show' JSON masks
    peer->ttl with gtsm_hops while GTSM is on, so this verifies the observable
    invariants across the round-trip: the sort flips correctly, the GTSM hop
    count is retained, ttl-security stays in the running-config, and no spurious
    ebgp-multihop appears.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.33"
    step("eBGP neighbor with ttl-security hops 4")
    _vtysh(
        [
            " neighbor {} remote-as 65033".format(addr),
            " neighbor {} ttl-security hops 4".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("Baseline: eBGP reports the GTSM hop count (4)")
    _expect_ttl(addr, "eBGP", 4, "ttl-security baseline not eBGP/4 (gtsm hops).")

    step("Add local-as -> iBGP")
    _vtysh([" neighbor {} local-as 65033 no-prepend replace-as".format(addr)])
    _expect_ttl(addr, "iBGP", 4, "Not iBGP with gtsm hops 4 after local-as.")

    step("Remove local-as -> eBGP, GTSM hop count still 4 (TTL not clobbered)")
    _vtysh([" no neighbor {} local-as".format(addr)])
    _expect_ttl(
        addr,
        "eBGP",
        4,
        "ttl-security hop count lost after local-as round-trip (peer->ttl "
        "was clobbered away from MAXTTL).",
    )

    step("running-config still has 'ttl-security hops 4', no ebgp-multihop")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ttl-security hops 4".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "ttl-security hops 4 missing after local-as round-trip."
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor {} ebgp-multihop".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "ebgp-multihop spuriously present alongside ttl-security."

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_ttl_security_rejected_while_ebgp_multihop_set_under_local_as():
    """
    ebgp-multihop and ttl-security are mutually exclusive. Configuring
    ebgp-multihop and then a local-as override (peer temporarily iBGP) must not
    open a hole that lets ttl-security be accepted: the conflict check keys off
    cfg_ttl, so ttl-security is rejected and never written, even while iBGP.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.34"
    step("eBGP neighbor with ebgp-multihop 5, then local-as -> iBGP")
    _vtysh(
        [
            " neighbor {} remote-as 65034".format(addr),
            " neighbor {} ebgp-multihop 5".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 5, "Baseline not eBGP/5.")
    _vtysh([" neighbor {} local-as 65034 no-prepend replace-as".format(addr)])
    _expect_ttl(addr, "iBGP", 255, "Not iBGP/255 after local-as.")

    step("Attempt ttl-security while iBGP-via-local-as: must be rejected")
    _vtysh([" neighbor {} ttl-security hops 2".format(addr)])

    step("running-config must NOT contain ttl-security for this peer")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor {} ttl-security".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "ttl-security was accepted while ebgp-multihop is configured (cfg_ttl "
        "conflict check did not fire during the iBGP-via-local-as phase)."
    )

    step("ebgp-multihop is still present and intact")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 5".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "ebgp-multihop 5 lost."

    step("Remove local-as -> eBGP/5 (no mutually-exclusive leftovers)")
    _vtysh([" no neighbor {} local-as".format(addr)])
    _expect_ttl(addr, "eBGP", 5, "Did not restore eBGP/5.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr)])


def test_matrix_group_ttl_security_inherited_by_member():
    """
    A peer-group with 'ttl-security hops N' must propagate GTSM to its members
    so the member's effective TTL is derived as MAXTTL (peer_ttl_update() runs
    after gtsm_hops is copied in peer_group2peer_config_copy()). Otherwise an
    eBGP member would keep TTL 1 and be treated as directly connected. The
    'show' JSON masks peer->ttl with gtsm_hops while GTSM is on, so the member
    is asserted to report the inherited GTSM hop count.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.35"
    step("Create group with ttl-security hops 3, then bind an eBGP member")
    _vtysh(
        [
            " neighbor PG_GTSM peer-group",
            " neighbor PG_GTSM remote-as 65035",
            " neighbor PG_GTSM ttl-security hops 3",
            " neighbor {} peer-group PG_GTSM".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("Member inherits GTSM and reports eBGP with the group's hop count (3)")
    _expect_ttl(
        addr,
        "eBGP",
        3,
        "Group ttl-security not inherited by member (effective TTL likely left "
        "at 1 because gtsm_hops was copied after peer_ttl_update()).",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_GTSM"])


def test_matrix_no_ebgp_multihop_on_gtsm_member_is_config_clean():
    """
    'no ebgp-multihop' on a GTSM member must be a no-op for the multihop config:
    it must not record a spurious 'ebgp-multihop' line and must leave the member's
    inherited 'ttl-security' intact, so the running-config stays reloadable.

    The underlying peer->ttl preservation (keep MAXTTL while GTSM is enabled
    instead of resetting to BGP_DEFAULT_TTL) is enforced structurally by routing
    peer_ebgp_multihop_unset() through the shared peer_ttl_update() helper. That
    numeric value is NOT asserted here on purpose: for a GTSM peer the bgp
    neighbor 'maxHopsAway' JSON masks peer->ttl with gtsm_hops, so it cannot
    observe a peer->ttl regression. The operational consequence (BFD single-hop /
    NHT) is only observable on a real established session, which the dynamic
    2-hop r1<->r3 session tests already exercise for the non-GTSM path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.42"
    step("Create a ttl-security group and bind an eBGP member")
    _vtysh(
        [
            " neighbor PG_GTSM2 peer-group",
            " neighbor PG_GTSM2 remote-as 65042",
            " neighbor PG_GTSM2 ttl-security hops 5",
            " neighbor {} peer-group PG_GTSM2".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("Member inherits the group's GTSM hop count (5)")
    _expect_ttl(addr, "eBGP", 5, "member did not inherit group GTSM hops 5.")

    step("Issue 'no ebgp-multihop' on the GTSM member (no-op for multihop)")
    _vtysh([" no neighbor {} ebgp-multihop".format(addr)])

    step("No spurious ebgp-multihop line, and inherited ttl-security is intact")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor {} ebgp-multihop".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "GTSM member unexpectedly carries an ebgp-multihop line."
    _expect_ttl(
        addr,
        "eBGP",
        5,
        "GTSM was lost after 'no ebgp-multihop' on the member.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_GTSM2"])


def test_matrix_group_ebgp_multihop_rejected_when_member_has_ttl_security():
    """
    'neighbor PG ebgp-multihop' must be rejected when any member has
    ttl-security, even on the peer_ebgp_multihop_set() no-op paths (bare/MAXTTL
    form, or an iBGP-sorted group). Otherwise the group records cfg_ttl while a
    member keeps ttl-security, producing a mutually-exclusive running-config
    that a reload would reject.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.36"
    step("Group with an eBGP member that has ttl-security hops 2")
    _vtysh(
        [
            " neighbor PG_MIX peer-group",
            " neighbor PG_MIX remote-as 65036",
            " neighbor {} peer-group PG_MIX".format(addr),
            " neighbor {} ttl-security hops 2".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("Attempt 'neighbor PG_MIX ebgp-multihop' (bare/MAXTTL no-op path)")
    _vtysh([" neighbor PG_MIX ebgp-multihop"])

    step("Group must NOT have recorded ebgp-multihop (conflict with member GTSM)")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor PG_MIX ebgp-multihop"),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "Group ebgp-multihop was recorded while a member has ttl-security; "
        "running-config now has mutually exclusive lines."
    )

    step("Member ttl-security is intact")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ttl-security hops 2".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "member ttl-security hops 2 lost."

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_MIX"])


def test_matrix_ttl_security_rejected_for_member_inheriting_group_multihop():
    """
    A member that cleared its own 'ebgp-multihop' but still inherits multihop
    from the group (group has 'ebgp-multihop N', member cfg_ttl == 0) is still
    effectively multihop. 'ttl-security' must be rejected for it, otherwise the
    running-config ends up with mutually exclusive group multihop + member
    ttl-security that a reload rejects. Covers the inherited-multihop branch of
    the mutual-exclusion predicate.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.37"
    step("Group with ebgp-multihop 5; bind an eBGP member")
    _vtysh(
        [
            " neighbor PG_INH peer-group",
            " neighbor PG_INH remote-as 65037",
            " neighbor PG_INH ebgp-multihop 5",
            " neighbor {} peer-group PG_INH".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("Clear the member's own ebgp-multihop (it now inherits from the group)")
    _vtysh([" no neighbor {} ebgp-multihop".format(addr)])

    step("ttl-security on the member must be rejected (still multihop via group)")
    out = tgen.gears["r1"].vtysh_cmd(
        "configure terminal\nrouter bgp {}\n"
        " neighbor {} ttl-security hops 2\nend\n".format(LOCAL_AS, addr)
    )
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks(
            "neighbor {} ttl-security hops".format(addr)
        ),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "ttl-security was accepted on a member that inherits ebgp-multihop from "
        "its group; running-config now has mutually exclusive lines. cli_out={}".format(
            out
        )
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_INH"])


def test_matrix_group_clear_preserves_member_own_ebgp_multihop():
    """
    'no neighbor PG ebgp-multihop' must not wipe a member's own
    'ebgp-multihop' setting. peer_cfg_ttl_set() on a group only propagates a
    real group-level change and preserves member-specific cfg_ttl. Also verifies
    that a no-op clear on a group that never had multihop leaves members intact.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.38"
    step("Group (no multihop) with a member that has its own ebgp-multihop 7")
    _vtysh(
        [
            " neighbor PG_OWN peer-group",
            " neighbor PG_OWN remote-as 65038",
            " neighbor {} peer-group PG_OWN".format(addr),
            " neighbor {} ebgp-multihop 7".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )

    step("no-op 'no neighbor PG_OWN ebgp-multihop' must keep member's value")
    _vtysh([" no neighbor PG_OWN ebgp-multihop"])
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 7".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "member's own ebgp-multihop 7 was wiped by a group no-op clear."

    step("Set a real group-level value; member's own config AND effective ttl hold")
    _vtysh([" neighbor PG_OWN ebgp-multihop 4"])
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 7".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "member's own ebgp-multihop 7 was wiped by group set."
    # The legacy peer_ebgp_multihop_set() stamps members to the group TTL (4)
    # first; peer_cfg_ttl_set() must re-derive the member back to its own 7.
    _expect_ttl(
        addr,
        "eBGP",
        7,
        "member effective TTL was left at the group value (4) after a group set; "
        "peer_cfg_ttl_set() did not re-derive the preserved member.",
    )

    step("Clear the group-level value; member's own config AND effective ttl hold")
    _vtysh([" no neighbor PG_OWN ebgp-multihop"])
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 7".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "member's own ebgp-multihop 7 was wiped by group clear."
    # The legacy peer_ebgp_multihop_unset() stamps members to TTL 1 first;
    # peer_cfg_ttl_set() must re-derive the member back to its own 7.
    _expect_ttl(
        addr,
        "eBGP",
        7,
        "member effective TTL was left at 1 after a group clear; "
        "peer_cfg_ttl_set() did not re-derive the preserved member.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_OWN"])


def test_matrix_member_own_ebgp_multihop_equal_to_group_survives():
    """
    A member explicitly configured with the SAME hop count as its group still
    owns that config. Ownership is tracked with PEER_FLAG_EBGP_MULTIHOP, not by
    comparing cfg_ttl values, so changing or clearing the group must not wipe the
    member's own config or fall its effective TTL back to 1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.39"
    step("Group ebgp-multihop 5 and a member with its OWN ebgp-multihop 5")
    _vtysh(
        [
            " neighbor PG_EQ peer-group",
            " neighbor PG_EQ remote-as 65039",
            " neighbor PG_EQ ebgp-multihop 5",
            " neighbor {} peer-group PG_EQ".format(addr),
            " neighbor {} ebgp-multihop 5".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 5, "member with own ebgp-multihop 5 not at TTL 5.")

    step("Change the group value; member keeps its OWN value (5), not the group's")
    _vtysh([" neighbor PG_EQ ebgp-multihop 9"])
    _expect_ttl(
        addr,
        "eBGP",
        5,
        "member's own ebgp-multihop 5 was overwritten by group change to 9; "
        "ownership inferred from value equality instead of the flag.",
    )

    step("Clear the group value; member's own value (5) still holds, not TTL 1")
    _vtysh([" no neighbor PG_EQ ebgp-multihop"])
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 5".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "member's own ebgp-multihop 5 was wiped by group clear."
    _expect_ttl(
        addr,
        "eBGP",
        5,
        "member's effective TTL fell back to 1 after group clear; "
        "the same-value member was treated as inherited.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_EQ"])


def test_matrix_own_ebgp_multihop_survives_later_group_bind():
    """
    A peer configured with its OWN 'ebgp-multihop' BEFORE it joins a peer-group
    must keep that config after the bind. Ownership is recorded in flags_override
    (PEER_FLAG_EBGP_MULTIHOP), so peer_group2peer_config_copy() - which clears all
    non-overridden flags - preserves both the value and its serialization, and
    the effective TTL is re-derived rather than falling back to 1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.40"
    step("Configure neighbor with own ebgp-multihop 6 BEFORE any group bind")
    _vtysh(
        [
            " neighbor {} remote-as 65040".format(addr),
            " neighbor {} ebgp-multihop 6".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 6, "pre-bind own ebgp-multihop 6 not applied.")

    step("Create a group with NO multihop and bind the peer to it")
    _vtysh(
        [
            " neighbor PG_LATE peer-group",
            " neighbor PG_LATE remote-as 65040",
            " neighbor {} peer-group PG_LATE".format(addr),
        ]
    )

    step("Member's own ebgp-multihop 6 must survive the bind (config + TTL)")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 6".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "member's own ebgp-multihop 6 was dropped by the group bind; "
        "ownership not preserved in flags_override."
    )
    _expect_ttl(
        addr,
        "eBGP",
        6,
        "member's effective TTL fell back after group bind; "
        "pre-bind ownership was lost.",
    )

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_LATE"])


def test_matrix_own_ebgp_multihop_peer_bind_to_gtsm_group_rejected():
    """
    Binding a peer that owns 'ebgp-multihop' to a peer-group that has ttl-security
    (GTSM) must be REJECTED. ebgp-multihop and ttl-security are mutually exclusive,
    and silently preserving the member's multihop would yield a running-config that
    cannot be reloaded (on reload the bind inherits GTSM before the member multihop
    line is parsed, and the vty conflict check then rejects that line). Rejecting
    the bind in peer_group_bind() keeps the running-config reloadable.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    addr = "192.0.2.41"
    step("Configure neighbor with its OWN ebgp-multihop 4 before any group bind")
    _vtysh(
        [
            " neighbor {} remote-as 65041".format(addr),
            " neighbor {} ebgp-multihop 4".format(addr),
            " neighbor {} timers connect 120".format(addr),
        ]
    )
    _expect_ttl(addr, "eBGP", 4, "pre-bind own ebgp-multihop 4 not applied.")

    step("Create a GTSM group and attempt to bind the owner peer (must be rejected)")
    _vtysh(
        [
            " neighbor PG_GTSM peer-group",
            " neighbor PG_GTSM remote-as 65041",
            " neighbor PG_GTSM ttl-security hops 3",
            " neighbor {} peer-group PG_GTSM".format(addr),
        ]
    )

    step("Bind must be rejected: peer stays standalone, keeps its own multihop")
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks(
            "neighbor {} peer-group PG_GTSM".format(addr)
        ),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "peer was bound to a GTSM group despite owning ebgp-multihop; "
        "the conflicting bind should have been rejected."
    )
    _, res = topotest.run_and_expect(
        lambda: _r1_running_has("neighbor {} ebgp-multihop 4".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, "peer's own ebgp-multihop 4 was lost by the rejected bind."
    _, res = topotest.run_and_expect(
        lambda: _r1_running_lacks("neighbor {} ttl-security".format(addr)),
        None,
        count=10,
        wait=0.5,
    )
    assert res is None, (
        "peer wrongly carries ttl-security; the conflicting bind was not rejected."
    )
    _expect_ttl(addr, "eBGP", 4, "peer's effective TTL changed despite rejected bind.")

    step("Clean up")
    _vtysh([" no neighbor {}".format(addr), " no neighbor PG_GTSM"])


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
