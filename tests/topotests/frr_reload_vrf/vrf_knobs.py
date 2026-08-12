#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# vrf_knobs.py
#
# Copyright (c) 2026 by Nvidia, Inc.
#
"""
Authoritative catalog of FRR per-VRF configuration "knobs" and helpers to
generate frr.conf fragments for them, at arbitrary scale.

Why this exists
---------------
tools/frr-reload.py applies configuration by diffing running-config against a
target file. VRF-context deletes are applied as a single "vtysh -f" batch
(instead of one "vtysh -c" per line) to avoid reload timeouts when hundreds of
VRFs are unset at once. To guard that path we need a test that exercises *every*
command that can live under "vrf NAME" - both individually and at scale - and
verifies that a frr-reload apply/rollback round-trip leaves the running-config
in the expected state without crashing a daemon.

Source of truth
---------------
The knob list below is derived directly from the "install_element(VRF_NODE, ...)"
call sites in the tree (verified, not guessed):

    zebra/zebra_cli.c      ip/ipv6 router-id, ip/ipv6 protocol route-map,
                           ip/ipv6 nht route-map, ip/ipv6 nht resolve-via-default,
                           vni
    staticd/static_vty.c   ip/ipv6 route (vrf forms)
    pimd/pim_cmd.c         ip pim rp, ssm/spt prefix-list, register-accept-list,
                           keep-alive-timer, ecmp[/rebalance], ssmpingd,
                           igmp watermark-warn, send-v6-secondary
    pimd/pim6_cmd.c        ipv6 pim rp, ssmpingd, mld watermark-warn

Exact command strings were taken from those files' DEFPY/DEFUN definitions and
the "vty_out()" running-config emitters in zebra_cli.c, so the "match" form used
by the tests is what actually appears in "show running-config".

Intentionally excluded (documented, not silently dropped):
  * "vrf netns NAME"      - namespace-backed VRFs; not vrf-lite, needs netns mode.
  * "rpki"                - opens a sub-node (RPKI config) rather than a leaf knob.
"""

import ipaddress

# ---------------------------------------------------------------------------
# Per-VRF deterministic address / id helpers
#
# Everything is derived from the 1-based VRF index so that N VRFs never collide,
# for N up to a few thousand.
# ---------------------------------------------------------------------------


def _octets(i):
    """Return (o2, o3) so that (o2, o3) is unique for i in 1..~64000."""
    return (i // 250) % 250, i % 250


def _c6(addr):
    """Canonical (RFC 5952) form of an IPv6 address, matching FRR's output.

    FRR renders IPv6 addresses via inet_ntop (RFC 5952: lowercase, longest
    zero-run compressed). Python's ipaddress uses the same rules, so feeding
    canonical strings both to the config and to the running-config assertions
    keeps them in lock-step with what "show running-config" prints.
    """
    return str(ipaddress.ip_address(addr))


def _c6n(prefix):
    """Canonical form of an IPv6 prefix (address/len)."""
    return str(ipaddress.ip_network(prefix, strict=False))


def vrf_name(i):
    return "vrf{}".format(i)


def vrf_table_id(i):
    # Linux VRF table ids; keep clear of the main tables (<1000).
    return 1000 + i


def vni_id(i):
    return 10000 + i


def rp4(i):
    o2, o3 = _octets(i)
    return "10.{}.{}.100".format(o2, o3)


def rp4_alt(i):
    o2, o3 = _octets(i)
    return "10.{}.{}.101".format(o2, o3)


def rp6(i):
    o2, o3 = _octets(i)
    return _c6("2001:db8:{:x}:{:x}::100".format(o2, o3))


def rp6_alt(i):
    # Distinct from rp6() so the group-based and prefix-list-based RP knobs do
    # not collide on the same RP address when applied to one VRF together (a
    # single RP address cannot carry both a static group and a prefix-list).
    o2, o3 = _octets(i)
    return _c6("2001:db8:{:x}:{:x}::101".format(o2, o3))


def router_id4(i):
    o2, o3 = _octets(i)
    return "10.255.{}.{}".format(o2, o3)


def router_id6(i):
    o2, o3 = _octets(i)
    return _c6("2001:db8:ffff:{:x}::{:x}".format(o2, o3))


def ssmpingd4(i):
    o2, o3 = _octets(i)
    return "10.{}.{}.250".format(o2, o3)


def ssmpingd6(i):
    o2, o3 = _octets(i)
    return _c6("2001:db8:{:x}:{:x}::250".format(o2, o3))


# Global (non-VRF) objects the knobs reference. They must exist in the target
# config or the daemon will reject the referencing command.
RMAP_PROTO = "RM-PROTO"
RMAP_NHT = "RM-NHT"
PLIST4_RP = "PL4-RP"
PLIST4_SSM = "PL4-SSM"
PLIST4_SPT = "PL4-SPT"
PLIST4_REG = "PL4-REG"
PLIST6_RP = "PL6-RP"
PLIST6_SPT = "PL6-SPT"


def global_prereqs():
    """Route-maps and prefix-lists referenced by the VRF knobs.

    Emitted once, outside any vrf stanza. These are *not* VRF knobs, so
    frr-reload will not batch-delete them; they simply have to exist.
    """
    return [
        "route-map {} permit 10".format(RMAP_PROTO),
        "exit",
        "route-map {} permit 10".format(RMAP_NHT),
        "exit",
        "ip prefix-list {} seq 5 permit 239.0.0.0/8 le 32".format(PLIST4_RP),
        "ip prefix-list {} seq 5 permit 232.0.0.0/8 le 32".format(PLIST4_SSM),
        "ip prefix-list {} seq 5 permit 238.0.0.0/8 le 32".format(PLIST4_SPT),
        "ip prefix-list {} seq 5 permit 10.0.0.0/8 le 32".format(PLIST4_REG),
        "ipv6 prefix-list {} seq 5 permit ff05::/16 le 128".format(PLIST6_RP),
        "ipv6 prefix-list {} seq 5 permit ff3e::/32 le 128".format(PLIST6_SPT),
    ]


# ---------------------------------------------------------------------------
# Knob catalog
#
# Each knob is a dict:
#   id       : short stable identifier (used to select/deselect in tests)
#   daemons  : set of daemons that must be running for the knob to be accepted
#   afi      : 4, 6 or None (informational)
#   lines(i) : callable -> list of config lines to place *inside* the vrf
#              stanza. These are the exact running-config forms, so the same
#              list is used both to build the target config and to assert the
#              knob is present in "show running-config".
#
# NOTE ordering: some knobs conflict if pointed at the same object (e.g. two
# "ip pim rp" statements for the same RP). Each knob uses distinct addresses /
# group ranges derived from the VRF index to avoid collisions when all knobs
# are enabled together on one VRF.
# ---------------------------------------------------------------------------


def _k(kid, daemons, afi, fn):
    return {"id": kid, "daemons": set(daemons), "afi": afi, "lines": fn}


ZEBRA_KNOBS = [
    _k("ip_router_id", ["zebra"], 4, lambda i: ["ip router-id {}".format(router_id4(i))]),
    _k("ipv6_router_id", ["zebra"], 6, lambda i: ["ipv6 router-id {}".format(router_id6(i))]),
    _k("ip_protocol_rmap", ["zebra"], 4,
       lambda i: ["ip protocol bgp route-map {}".format(RMAP_PROTO)]),
    _k("ipv6_protocol_rmap", ["zebra"], 6,
       lambda i: ["ipv6 protocol bgp route-map {}".format(RMAP_PROTO)]),
    _k("ip_nht_rmap", ["zebra"], 4,
       lambda i: ["ip nht bgp route-map {}".format(RMAP_NHT)]),
    _k("ipv6_nht_rmap", ["zebra"], 6,
       lambda i: ["ipv6 nht bgp route-map {}".format(RMAP_NHT)]),
    # NOTE: "ip/ipv6 nht resolve-via-default" is intentionally NOT in the
    # round-trip catalog. Its default is profile-dependent
    # (FRR_CFG_DEFAULT_BOOL ZEBRA_IP_NHT_RESOLVE_VIA_DEFAULT: on for
    # "traditional", off otherwise), so whether "ip nht resolve-via-default"
    # or "no ip nht resolve-via-default" appears in running-config flips with
    # the profile - it does not reliably round-trip as visible config (same
    # reason "ip pim send-v6-secondary" is omitted). The batch-delete path is
    # already exercised by the other zebra knobs.
    _k("vni", ["zebra"], None, lambda i: ["vni {}".format(vni_id(i))]),
]

STATIC_KNOBS = [
    _k("ip_route", ["staticd"], 4,
       lambda i: ["ip route {} blackhole".format(_static4(i, 0))]),
    _k("ipv6_route", ["staticd"], 6,
       lambda i: ["ipv6 route {} blackhole".format(_static6(i, 0))]),
]

PIM_KNOBS = [
    _k("ip_pim_rp_group", ["pimd"], 4,
       lambda i: ["ip pim rp {} 239.1.0.0/24".format(rp4(i))]),
    _k("ip_pim_rp_plist", ["pimd"], 4,
       lambda i: ["ip pim rp {} prefix-list {}".format(rp4_alt(i), PLIST4_RP)]),
    _k("ip_pim_ssm_plist", ["pimd"], 4,
       lambda i: ["ip pim ssm prefix-list {}".format(PLIST4_SSM)]),
    _k("ip_pim_spt", ["pimd"], 4,
       lambda i: ["ip pim spt-switchover infinity-and-beyond prefix-list {}".format(PLIST4_SPT)]),
    _k("ip_pim_reg_accept", ["pimd"], 4,
       lambda i: ["ip pim register-accept-list {}".format(PLIST4_REG)]),
    _k("ip_pim_kat", ["pimd"], 4, lambda i: ["ip pim keep-alive-timer 100"]),
    _k("ip_pim_rp_kat", ["pimd"], 4, lambda i: ["ip pim rp keep-alive-timer 120"]),
    # Only the plain "ip pim ecmp" knob is in the round-trip set. "ip pim ecmp
    # rebalance" is a *superset* that renders as a single line (pim_vty.c only
    # emits "ip pim ecmp rebalance" when rebalance is on, suppressing the plain
    # "ip pim ecmp" line). Removing it emits "no ip pim ecmp rebalance", which
    # clears only the rebalance sub-flag and leaves ecmp enabled - so a residual
    # "ip pim ecmp" reappears that frr-reload's single-pass delta cannot catch.
    # That is an inherent FRR CLI/frr-reload interaction, not a VRF batch-delete
    # issue, so the rebalance variant is cataloged in ECMP_REBALANCE_KNOBS below
    # but kept out of ALL_KNOBS. Plain "ip pim ecmp" round-trips cleanly.
    _k("ip_pim_ecmp", ["pimd"], 4, lambda i: ["ip pim ecmp"]),
    _k("ip_igmp_watermark", ["pimd"], 4, lambda i: ["ip igmp watermark-warn 1000"]),
    # Use the "any" source (0.0.0.0): a specific source must be a local address
    # or pimd cannot bind the ssmpingd socket and drops the config. "%pPA" of
    # the any-source renders as "0.0.0.0".
    _k("ip_ssmpingd", ["pimd"], 4, lambda i: ["ip ssmpingd 0.0.0.0"]),
]

# See the note on ip_pim_ecmp: this variant does not cleanly round-trip through
# a single frr-reload (removing it leaves a residual "ip pim ecmp"). Cataloged
# for completeness, excluded from ALL_KNOBS.
ECMP_REBALANCE_KNOBS = [
    _k("ip_pim_ecmp_rebalance", ["pimd"], 4, lambda i: ["ip pim ecmp rebalance"]),
]

# IPv6 PIM / MLD per-VRF knobs (pim6d).
PIM6_KNOBS = [
    _k("ipv6_pim_rp_group", ["pim6d"], 6,
       lambda i: ["ipv6 pim rp {} ff05::/16".format(rp6(i))]),
    _k("ipv6_pim_rp_plist", ["pim6d"], 6,
       lambda i: ["ipv6 pim rp {} prefix-list {}".format(rp6_alt(i), PLIST6_RP)]),
    _k("ipv6_mld_watermark", ["pim6d"], 6, lambda i: ["ipv6 mld watermark-warn 1000"]),
    _k("ipv6_ssmpingd", ["pim6d"], 6, lambda i: ["ipv6 ssmpingd ::"]),
]

ALL_KNOBS = ZEBRA_KNOBS + STATIC_KNOBS + PIM_KNOBS + PIM6_KNOBS


def _static4(i, k):
    o2, o3 = _octets(i)
    # 100 unique /32s per (vrf, k-block) via the last octet; callers that need
    # hundreds of routes iterate k and vary the third octet.
    return "198.{}.{}.{}/32".format(o2, o3, (k % 250) + 1)


def _static6(i, k):
    o2, o3 = _octets(i)
    return _c6n("2001:db8:a:{:x}:{:x}::{:x}/128".format(o2, o3, (k % 250) + 1))


# ---------------------------------------------------------------------------
# Config fragment builders
# ---------------------------------------------------------------------------


def daemons_for(knobs):
    """Union of daemons required by a selection of knobs (plus zebra/mgmtd)."""
    d = {"zebra", "mgmtd", "staticd"}
    for kn in knobs:
        d |= kn["daemons"]
    return d


def vrf_stanza(i, knobs):
    """Return the 'vrf NAME ... exit-vrf' block for VRF i using the given knobs."""
    lines = ["vrf {}".format(vrf_name(i))]
    for kn in knobs:
        for ln in kn["lines"](i):
            lines.append(" " + ln)
    lines.append("exit-vrf")
    lines.append("!")
    return lines


def vrf_stanza_scale_routes(i, routes_v4=0, routes_v6=0, knobs=None):
    """VRF block with 'routes_v4'/'routes_v6' blackhole static routes.

    Used by the scale variants to put hundreds of static routes under each VRF
    (blackhole routes need no reachable nexthop, so they exercise the reload
    delete path without any dataplane dependency).
    """
    lines = ["vrf {}".format(vrf_name(i))]
    if knobs:
        for kn in knobs:
            for ln in kn["lines"](i):
                lines.append(" " + ln)
    o2, _ = _octets(i)
    for k in range(routes_v4):
        lines.append(" ip route 198.{}.{}.{}/32 blackhole".format(o2, k % 250, (k // 250) + 1))
    for k in range(routes_v6):
        pfx = _c6n("2001:db8:a:{:x}:{:x}::{:x}/128".format(o2, k % 250, (k // 250) + 1))
        lines.append(" ipv6 route {} blackhole".format(pfx))
    lines.append("exit-vrf")
    lines.append("!")
    return lines


def expected_running_lines(i, knobs):
    """Lines (without leading indent) expected in 'show running-config' for VRF i.

    frr-reload / zebra render the knobs back exactly as fed in, so the target
    lines double as the assertion set.
    """
    return [ln for kn in knobs for ln in kn["lines"](i)]
