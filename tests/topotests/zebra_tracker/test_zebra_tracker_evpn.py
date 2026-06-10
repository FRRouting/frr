#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_tracker_evpn.py
#
# Copyright (c) 2026 by
# Nvidia Corporation
#

"""
Nexthop group reuse across an underlay member change, under an EVPN overlay.

An uplink member is removed and re-added.  A route message carries
RTA_NH_ID and never the group's member list, so in either direction the
only thing the kernel needs is the group's new members: the group must keep
its id, every route on it must stay on it, and the route writes the
re-resolutions produce must be suppressed rather than sent.

Three tiers of route sit on the group:

  underlay   12 VTEP /32s directly on it.
  recursive  20 static routes via those /32s.  Their groups are recursive,
             so they are dependents of the underlay group and are walked
             when it changes; zebra_nhg_resolve() peels each down to that
             group before install, so all 20 carry its id.
  overlay    20 EVPN Type-5 routes on groups of their own.  Their nexthops
             are onlink on the L3VNI SVI, so those groups are not
             recursive, not dependents, and must not be touched.

Read counters from `show zebra dplane`, to measure what zebra pushed to the kernel

               +-----------------------+       +-----------------------+
               |         vtep1         |       |         vtep2         |
               |     lo 10.121.0.1     |       |     lo 10.121.0.2     |
               | Type-5 172.31.11.x/32 |       | Type-5 172.31.21.x/32 |  (vrf1)
               | Type-5 172.31.12.x/32 |       | Type-5 172.31.22.x/32 |  (vrf2)
               +-----------+-----------+       +-----------+-----------+
                           | .11                           | .12
                           +------ sw4   10.0.9.0/24 ------+
                           | .2                            | .3
             +-------------+-------------+   +-------------+-------------+
             |           leaf1           |   |           leaf2           |
             +-----+---------------+-----+   +-------------+-------------+
                   | .2            | .2                    | .2
                   | 10.0.1.0/24   | 10.0.2.0/24           | 10.0.3.0/24
                   | .1            | .1                    | .1
                   | dut-eth0      | dut-eth1              | dut-eth2  <-- FLAPPED
                   +---------------+---+-------------------+
                                       |
                            +----------+----------+
                            |         dut         |
                            +---------------------+

All routers are in AS 65001; dut's loopback is 10.10.10.1.  dut has two
L3VNIs: vrf1 = 4001 on vlan101, vrf2 = 4002 on vlan102, matched on both
VTEPs.  The leaves hold no VNIs -- they reflect EVPN between the VTEPs and
dut, and originate the 12 VTEP /32s (10.121.0.1-12, of which only .1 and .2
are real).  Each uplink carries one iBGP session, peered on the link
addresses so a link flap drops a session, with both families on it.  Two
uplinks land on leaf1 and only the flapped one on leaf2, so leaf1 keeps
carrying traffic throughout.
"""

import os
import re
import sys
import json
import pytest

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import required_linux_kernel_version, step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


ROUTERS = ["dut", "leaf1", "leaf2", "vtep1", "vtep2"]

# Routers whose L3VNI plumbing a setup.sh builds after FRR starts.
VTEP_ROUTERS = ["dut", "vtep1", "vtep2"]

FLAP_IF = "dut-eth2"

# The underlay group's members, before and during the flap.
UNDERLAY_NHS = ["10.0.1.2", "10.0.2.2", "10.0.3.2"]
SURVIVING_NHS = ["10.0.1.2", "10.0.2.2"]

# The remote VTEP /32s sharing the underlay group.  .1 and .2 are the real
# VTEPs; the rest only give the group a population.
UNDERLAY_POPULATION = ["10.121.0.{}/32".format(i) for i in range(1, 13)]
UNDERLAY_ROOT = "10.121.0.0/24"

# Each uplink is peered on its own link address, which is what makes a link
# flap drop a session.  Both families ride them.
UPLINK_PEERS = UNDERLAY_NHS

# {vrf: {VTEP IP: Type-5 prefixes it originates}}.  Each VTEP owns distinct
# prefixes, so every overlay group has one member.
OVERLAY_PREFIXES = {
    "vrf1": {
        "10.121.0.1": ["172.31.11.{}/32".format(i) for i in range(1, 6)],
        "10.121.0.2": ["172.31.21.{}/32".format(i) for i in range(1, 6)],
    },
    "vrf2": {
        "10.121.0.1": ["172.31.12.{}/32".format(i) for i in range(1, 6)],
        "10.121.0.2": ["172.31.22.{}/32".format(i) for i in range(1, 6)],
    },
}

# {gateway: prefixes resolving through it}.  Each gateway is a VTEP /32, so
# these groups resolve through the underlay group and are its dependents.
RECURSIVE_PREFIXES = {
    "10.121.0.{}".format(4 + tier): [
        "10.200.{}.{}/32".format(tier, i) for i in range(1, 6)
    ]
    for tier in range(1, 5)
}
ALL_RECURSIVE_PREFIXES = [p for ps in RECURSIVE_PREFIXES.values() for p in ps]
RECURSIVE_ROOT = "10.200.0.0/16"


def build_topo(tgen):
    for rname in ROUTERS:
        tgen.add_router(rname)

    dut = tgen.gears["dut"]
    leaf1 = tgen.gears["leaf1"]
    leaf2 = tgen.gears["leaf2"]

    # dut-eth0 <-> leaf1-eth0
    sw1 = tgen.add_switch("sw1")
    sw1.add_link(dut)
    sw1.add_link(leaf1)

    # dut-eth1 <-> leaf1-eth1.  Second member on the same leaf.
    sw2 = tgen.add_switch("sw2")
    sw2.add_link(dut)
    sw2.add_link(leaf1)

    # dut-eth2 <-> leaf2-eth0.  This is the member the test removes.
    sw3 = tgen.add_switch("sw3")
    sw3.add_link(dut)
    sw3.add_link(leaf2)

    # The core segment: both leaves and both remote VTEPs.
    sw4 = tgen.add_switch("sw4")
    sw4.add_link(leaf1)
    sw4.add_link(leaf2)
    sw4.add_link(tgen.gears["vtep1"])
    sw4.add_link(tgen.gears["vtep2"])


def setup_module(module):
    # VRF devices plus VXLAN need 4.19, the floor the other EVPN tests use.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met: {}".format(result))

    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        # Listed explicitly: load_frr_config() otherwise infers daemons by
        # grepping the config for each daemon's name, and a config whose only
        # staticd content is "ip route" lines never contains "static".
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()

    # L3VNI plumbing after FRR is up: zebra picks the VRF, bridge, VXLAN
    # device and SVI up as they appear and binds the VNI its config names.
    for rname in VTEP_ROUTERS:
        tgen.gears[rname].run("/bin/bash {}/{}/setup.sh".format(CWD, rname))


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


# ---------------------------------------------------------------------------
# State readers.  Two questions, asked of zebra and of the kernel: what
# group is a prefix installed on, and what does a group contain.
# ---------------------------------------------------------------------------


def _zebra_bindings(router, vrf, prefixes):
    """
    {prefix: installed NHG id} from `show ip route`, or (None, why).

    installedNexthopGroupId is the id the kernel was told, which for a
    recursive route is the resolved group and so differs from
    nexthopGroupId.  zebra omits it when the route was never programmed;
    that is an error here rather than a reason to fall back, since a
    RIB-pending id says nothing about what the kernel holds.
    """
    cmd = (
        "show ip route json"
        if vrf is None
        else "show ip route vrf {} json".format(vrf)
    )
    out = router.vtysh_cmd(cmd)
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return None, "`{}` did not return json".format(cmd)

    where = vrf or "default"
    bindings = {}
    for prefix in prefixes:
        entry = next(
            (
                e
                for e in data.get(prefix, [])
                if e.get("installed") and not e.get("queued")
            ),
            None,
        )
        if entry is None:
            return None, "zebra: {} is not installed in vrf {}".format(prefix, where)
        nhg_id = entry.get("installedNexthopGroupId")
        if nhg_id is None:
            return None, "zebra: {} in vrf {} has no installed group id".format(
                prefix, where
            )
        bindings[prefix] = nhg_id
    return bindings, None


def _kernel_bindings(router, prefixes, vrf=None, root=None):
    """
    {prefix: nhid} from one `ip route show`, or (None, why).

    Narrowed by `root` in the default table, since a bare
    `ip route show <prefix>` matches only an exact prefix.  A VRF table is
    small and listed whole, avoiding the two selectors combined.
    """
    selector = "vrf {}".format(vrf) if vrf else "root {}".format(root)
    cmd = "ip -j -4 route show {}".format(selector)
    out = router.cmd(cmd)
    try:
        data = json.loads(out) if out.strip() else []
    except (json.JSONDecodeError, ValueError):
        return None, "`{}` did not return json".format(cmd)

    # iproute2 prints a host route without its /32.
    seen = {}
    for entry in data:
        dst = entry.get("dst", "")
        seen[dst if "/" in dst else dst + "/32"] = entry.get("nhid")

    where = vrf or "default"
    bindings = {}
    for prefix in prefixes:
        if prefix not in seen:
            return None, "kernel: {} is not in the vrf {} fib".format(prefix, where)
        if seen[prefix] is None:
            return None, "kernel: {} carries no nhid".format(prefix)
        bindings[prefix] = seen[prefix]
    return bindings, None


def _zebra_nhg_members(router, nhg_id):
    """The gateways in zebra's copy of a group, or (None, why)."""
    cmd = "show nexthop-group rib {} json".format(nhg_id)
    out = router.vtysh_cmd(cmd)
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return None, "`{}` did not return json".format(cmd)
    nhe = data.get(str(nhg_id))
    if not nhe:
        return None, "zebra: NHG {} does not exist".format(nhg_id)
    return sorted(n["ip"] for n in nhe.get("nexthops", []) if n.get("ip")), None


def _kernel_nhg_members(router, nhid):
    """
    The gateways behind a kernel group, or (None, why).  Zebra builds every
    group it owns as NHA_GROUP, so members are ids needing a second lookup.
    """
    out = router.cmd("ip -j nexthop show id {}".format(nhid))
    try:
        data = json.loads(out) if out.strip() else []
    except (json.JSONDecodeError, ValueError):
        return None, "kernel: `ip nexthop show id {}` did not return json".format(nhid)
    if not data:
        return None, "kernel: NHG {} does not exist".format(nhid)

    entry = data[0]
    if not entry.get("group"):
        return ([entry["gateway"]] if entry.get("gateway") else []), None

    gateways = []
    for member in entry["group"]:
        member_id = member.get("id")
        out = router.cmd("ip -j nexthop show id {}".format(member_id))
        try:
            sub = json.loads(out) if out.strip() else []
        except (json.JSONDecodeError, ValueError):
            return None, "kernel: NHG {} member {} unreadable".format(nhid, member_id)
        if not sub:
            return None, "kernel: NHG {} member {} is missing".format(nhid, member_id)
        if sub[0].get("gateway"):
            gateways.append(sub[0]["gateway"])
    return sorted(gateways), None


def _overlay_bindings(router):
    """{(vrf, prefix): installed NHG id} over every Type-5 route."""
    result = {}
    for vrf, by_vtep in OVERLAY_PREFIXES.items():
        prefixes = [p for ps in by_vtep.values() for p in ps]
        bindings, err = _zebra_bindings(router, vrf, prefixes)
        if err:
            return None, err
        for prefix, nhg_id in bindings.items():
            result[(vrf, prefix)] = nhg_id
    return result, None


def _bgp_established(router):
    """All uplink sessions up in both families, or a string saying which."""
    out = router.vtysh_cmd("show bgp summary json")
    try:
        data = json.loads(out) if out.strip() else {}
    except json.JSONDecodeError:
        return "`show bgp summary json` did not return json"
    for af in ("ipv4Unicast", "l2VpnEvpn"):
        peers = (data.get(af) or {}).get("peers") or {}
        for peer in UPLINK_PEERS:
            state = (peers.get(peer) or {}).get("state")
            if state != "Established":
                return "{}: session with {} is {}".format(
                    af, peer, state or "not configured"
                )
    return None


# ---------------------------------------------------------------------------
# The end state, and the cost of getting there
# ---------------------------------------------------------------------------


def _end_state(router, nhg_id, members, overlay):
    """
    The whole claim in one predicate, returning None when it holds or a
    string naming the first thing that does not: group `nhg_id` holds
    exactly `members`, every underlay and recursive prefix is installed on
    it, and every Type-5 route is still on the id recorded in `overlay` --
    each checked in zebra and in the kernel.

    Both sides are needed.  Zebra's RIB is what zebra intends; only the
    kernel says what is forwarding.  The kernel alone will not do either:
    Linux prunes a group member itself when its device goes down, so the
    reduced group appears there within milliseconds, long before zebra has
    sent anything.

    `overlay` is None at bring-up, when there is nothing recorded yet; then
    zebra and the kernel need only agree with each other.
    """
    for side, read in (
        ("zebra", _zebra_nhg_members),
        ("kernel", _kernel_nhg_members),
    ):
        got, err = read(router, nhg_id)
        if err:
            return err
        if got != sorted(members):
            return "{}: NHG {} holds {}, expected {}".format(
                side, nhg_id, got, sorted(members)
            )

    # Both tiers carry the underlay group's id: zebra_nhg_resolve() peels a
    # recursive group down to its terminal depend before install.
    for root, prefixes in (
        (UNDERLAY_ROOT, UNDERLAY_POPULATION),
        (RECURSIVE_ROOT, ALL_RECURSIVE_PREFIXES),
    ):
        zebra, err = _zebra_bindings(router, None, prefixes)
        if err:
            return err
        kernel, err = _kernel_bindings(router, prefixes, root=root)
        if err:
            return err
        for prefix in prefixes:
            if zebra[prefix] != nhg_id:
                return "zebra: {} is on NHG {}, expected {}".format(
                    prefix, zebra[prefix], nhg_id
                )
            if kernel[prefix] != nhg_id:
                return "kernel: {} is on nhid {}, expected {}".format(
                    prefix, kernel[prefix], nhg_id
                )

    for vrf, by_vtep in OVERLAY_PREFIXES.items():
        prefixes = [p for ps in by_vtep.values() for p in ps]
        zebra, err = _zebra_bindings(router, vrf, prefixes)
        if err:
            return err
        kernel, err = _kernel_bindings(router, prefixes, vrf=vrf)
        if err:
            return err
        for prefix in prefixes:
            want = overlay[(vrf, prefix)] if overlay else zebra[prefix]
            if zebra[prefix] != want:
                return "zebra: overlay {} in {} moved to NHG {}, expected {}".format(
                    prefix, vrf, zebra[prefix], want
                )
            if kernel[prefix] != want:
                return "kernel: overlay {} in {} is on nhid {}, expected {}".format(
                    prefix, vrf, kernel[prefix], want
                )
    return None


def _settled(router, nhg_id, members, overlay):
    """
    A run_and_expect predicate: the end state holds and zebra has stopped
    submitting dataplane work, so the counters can be read right after.
    Without the second half the two flap windows bleed into each other --
    the end state is reached while bgpd is still reacting to the flap.
    """
    state = {"mark": None, "stable": 0}

    def check():
        err = _end_state(router, nhg_id, members, overlay)
        if err:
            state["stable"] = 0
            return err
        counters = _dplane_counters(router)
        mark = (counters["routes"], counters["nexthops"], counters["route_skips"])
        if mark != state["mark"]:
            state["mark"] = mark
            state["stable"] = 0
        else:
            state["stable"] += 1
        if state["stable"] < 2:
            return "state reached, dataplane still settling at {}".format(mark)
        return None

    return check


# dplane_show_helper(), zebra/zebra_dplane.c.
_DPLANE_FIELDS = (
    ("routes", re.compile(r"^\s*Route updates:\s+(\d+)")),
    ("route_errors", re.compile(r"^\s*Route update errors:\s+(\d+)")),
    ("nexthops", re.compile(r"^\s*Nexthop updates:\s+(\d+)")),
    ("nexthop_errors", re.compile(r"^\s*Nexthop update errors:\s+(\d+)")),
    ("route_skips", re.compile(r"^\s*Route updates skipped:\s+(\d+)")),
)

# Work not attributable to the population: the flapped link's own connected
# and local routes, and the singleton group for its nexthop.
ROUTE_WRITE_ALLOWANCE = 8
NEXTHOP_ALLOWANCE = 6


def _dplane_counters(router):
    """Zebra's dataplane totals, from `show zebra dplane`."""
    out = router.vtysh_cmd("show zebra dplane")
    counters = {name: 0 for name, _ in _DPLANE_FIELDS}
    for line in out.splitlines():
        for name, regex in _DPLANE_FIELDS:
            match = regex.match(line)
            if match:
                counters[name] = int(match.group(1))
                break
    return counters


def _dplane_delta(before, after):
    """What zebra submitted between two readings, and what it actually sent."""
    delta = {name: after[name] - before[name] for name, _ in _DPLANE_FIELDS}
    delta["route_writes"] = delta["routes"] - delta["route_skips"]
    return delta


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# Recorded by the bring-up test and required to survive both flaps.
BASELINE = {}


def test_initial_convergence():
    """
    Bring-up: the VTEP /32s and recursive routes land on one shared
    3-member group and the Type-5 routes on groups of their own, installed
    in the kernel and not merely present in zebra's RIB.  The ids recorded
    here are what the two flap tests require to survive unchanged.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    dut = tgen.gears["dut"]

    step("Uplink sessions reach Established in both families", reset=True)
    _, err = topotest.run_and_expect(
        lambda: _bgp_established(dut), None, count=60, wait=1
    )
    assert err is None, "underlay/EVPN sessions never came up: {}".format(err)

    step("Every route is installed, in zebra and in the kernel")

    def converged():
        bindings, err = _zebra_bindings(dut, None, UNDERLAY_POPULATION)
        if err:
            return err
        nhg_ids = set(bindings.values())
        if len(nhg_ids) != 1:
            return "the VTEP /32s are spread over groups {}, expected one".format(
                sorted(nhg_ids)
            )
        return _end_state(dut, nhg_ids.pop(), UNDERLAY_NHS, None)

    _, err = topotest.run_and_expect(converged, None, count=90, wait=1)
    assert err is None, "bring-up never converged: {}".format(err)

    bindings, err = _zebra_bindings(dut, None, UNDERLAY_POPULATION)
    assert err is None, err
    overlay, err = _overlay_bindings(dut)
    assert err is None, err

    BASELINE["nhg"] = bindings[UNDERLAY_POPULATION[0]]
    BASELINE["overlay"] = overlay

    # Or "the overlay was not re-programmed" says nothing.
    assert BASELINE["nhg"] not in set(overlay.values()), (
        "the Type-5 routes resolve through the underlay group {} itself, so "
        "an untouched overlay cannot be told from a changed underlay".format(
            BASELINE["nhg"]
        )
    )

    logger.info(
        "baseline: underlay NHG %s holds %s and carries %d VTEP /32s plus %d "
        "recursive routes; %d Type-5 routes sit on groups %s",
        BASELINE["nhg"],
        UNDERLAY_NHS,
        len(UNDERLAY_POPULATION),
        len(ALL_RECURSIVE_PREFIXES),
        len(overlay),
        sorted(set(overlay.values())),
    )


def _flap(config_line, expected_members, expect_skips):
    """
    Apply `config_line` to the flapped uplink, wait for the group to reach
    `expected_members` with its id and routes intact, then check the cost.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    if not BASELINE:
        pytest.skip("bring-up did not converge, so there is no baseline")

    dut = tgen.gears["dut"]
    nhg_id = BASELINE["nhg"]
    before = _dplane_counters(dut)

    step("{} {}".format(config_line, FLAP_IF))
    dut.vtysh_cmd(
        "configure terminal\ninterface {}\n{}\nend".format(FLAP_IF, config_line)
    )

    step(
        "Wait for NHG {} to hold {} member(s) with every route still on it, "
        "in zebra and in the kernel".format(nhg_id, len(expected_members))
    )
    _, err = topotest.run_and_expect(
        _settled(dut, nhg_id, expected_members, BASELINE["overlay"]),
        None,
        count=90,
        wait=1,
    )
    assert err is None, "never reached the expected end state: {}".format(err)

    delta = _dplane_delta(before, _dplane_counters(dut))
    logger.info(
        "%s %s: %d route submission(s), %d suppressed, %d reached the kernel; "
        "%d nexthop message(s); %d/%d dplane errors",
        config_line,
        FLAP_IF,
        delta["routes"],
        delta["route_skips"],
        delta["route_writes"],
        delta["nexthops"],
        delta["route_errors"],
        delta["nexthop_errors"],
    )

    assert delta["route_errors"] == 0 and delta["nexthop_errors"] == 0, (
        "the dataplane reported errors ({} route, {} nexthop), so a write "
        "that never happened cannot be told from one the kernel "
        "rejected".format(delta["route_errors"], delta["nexthop_errors"])
    )

    assert delta["route_writes"] <= ROUTE_WRITE_ALLOWANCE, (
        "{} route message(s) reached the kernel, at most {} were owed.  Every "
        "route kept its group id, so these carry an RTA_NH_ID the kernel "
        "already holds.  The usual cause is the skip gate in "
        "kernel_dplane_process_func() not matching, because the old and new "
        "group ids it compares are not drawn from the same resolution "
        "level.".format(delta["route_writes"], ROUTE_WRITE_ALLOWANCE)
    )

    assert delta["route_skips"] >= expect_skips, (
        "the skip gate suppressed {} route write(s), expected at least {}, "
        "one per recursive route: those are dependents of the group that "
        "changed, so each is re-submitted and must then be suppressed, its "
        "installed id never having moved.".format(
            delta["route_skips"], expect_skips
        )
    )

    assert delta["nexthops"] <= NEXTHOP_ALLOWANCE, (
        "{} nexthop message(s) were submitted, at most {} were owed.  Only "
        "the underlay group changed; anything more re-programs a group whose "
        "members the kernel already holds.".format(
            delta["nexthops"], NEXTHOP_ALLOWANCE
        )
    )


def test_underlay_member_removal():
    """
    Shut one of the three uplinks.  The group must keep its id and drop to
    two members, every route on it must stay on it in zebra and in the
    kernel, and the resulting route writes must be suppressed -- at least
    one per recursive route.
    """
    _flap("shutdown", SURVIVING_NHS, expect_skips=len(ALL_RECURSIVE_PREFIXES))


def test_underlay_member_readdition():
    """
    Put it back.  Same claim without a skip floor: the returning member's
    singleton is new work, and the recursive tier is not walked on this
    side, so there is nothing to suppress.
    """
    _flap("no shutdown", UNDERLAY_NHS, expect_skips=0)
