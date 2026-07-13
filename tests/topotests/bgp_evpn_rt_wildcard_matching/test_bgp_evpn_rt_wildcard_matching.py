#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_rt_wildcard_matching.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Robin Christ for partimus GmbH
#

"""
Test the EVPN route-target matching logic against all three route
target encodings and the wildcard local-admin keying rules:

- AS2-encoded route targets carry a 4-byte local admin; wildcard
  ("*:N") import route targets must match on the full 4 bytes, so an
  AS2 route target whose local admin only agrees in the low 16 bits
  (e.g. 65002:65637 vs "*:101") must NOT match.
- AS4- and IPv4-encoded route targets carry a 2-byte local admin;
  wildcard import route targets must match them on those 2 bytes.
- Fully-qualified import route targets must match on the exact
  encoded bytes (same encoding, same global admin).
- A route carrying multiple route targets (of different encodings) is
  imported if any one of them matches.

r1 (AS 65001, 2-byte) and r2 (AS 4200000001, 4-byte) peer via eBGP
and both carry L3VNI 101 (vrf-101) and L2VNI 201. r2 acts as the
route injector: its manual export route-target configuration controls
the exact encoding of the route targets that appear on the wire
(FRR AS2-encodes "A:B" for A <= 65535 - including 4-byte local
admins -, AS4-encodes it for A > 65535 and IP-encodes "A.B.C.D:N"),
while r1 is the device under test for the import matching.

r2's 4-byte AS also covers the auto route-target derivation edge
case: the auto route target is always AS2-encoded with the AS
truncated to its low 16 bits (4200000001 & 0xFFFF = 59905).
"""

from functools import partial
import os
import sys
import pytest
import platform

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

# 4200000001 & 0xFFFF - the AS2-truncated form of r2's AS used in its
# auto route targets.
R2_AS_TRUNCATED = 59905

R1_TYPE5_PREFIX = "[5]:[0]:[32]:[10.0.101.1]"
R2_TYPE5_PREFIX = "[5]:[0]:[32]:[10.0.101.2]"
R2_IMET_PREFIX = "[3]:[0]:[32]:[192.168.0.2]"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN route-target tests require kernel >= 4.18 (have "{}")'.format(
                krel
            )
        )
        return pytest.skip("Kernel too old for EVPN test")

    # L3VNI 101 (vrf-101 with SVI bridge-101) and L2VNI 201 on both
    # routers.
    cmds_vxlan = [
        "ip link add vrf-101 type vrf table 101",
        "ip link set dev vrf-101 up",
        "ip link add loop101 type dummy",
        "ip link set dev loop101 master vrf-101",
        "ip link set dev loop101 up",
        "ip link add bridge-101 up address 52:54:00:0{0}:01:65 type bridge stp_state 0",
        "ip link set bridge-101 master vrf-101",
        "ip link set dev bridge-101 up",
        "ip link add vxlan-101 type vxlan id 101 dstport 4789 dev r{0}-eth0 local 192.168.0.{0}",
        "ip link set dev vxlan-101 master bridge-101",
        "ip link set vxlan-101 up type bridge_slave learning off flood off mcast_flood off",
        "ip link add name bridge-201 up address 52:54:00:0{0}:00:c9 type bridge stp_state 0",
        "ip link add name vxlan-201 type vxlan id 201 dstport 4789 dev r{0}-eth0 local 192.168.0.{0}",
        "ip link set dev vxlan-201 master bridge-201",
        "ip link set vxlan-201 up type bridge_slave learning off flood off mcast_flood off",
    ]

    for rid in (1, 2):
        router = tgen.gears["r{}".format(rid)]
        for cmd in cmds_vxlan:
            formatted = cmd.format(rid)
            logger.info("cmd to r{}: {}".format(rid, formatted))
            output = router.cmd_raises(formatted)
            logger.info("result: " + output)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _find_prefix_entries(obj, prefix):
    """
    Recursively collect all dict values keyed by the given prefix.
    The EVPN route show output nests the prefixes under the route
    distinguishers, which are not predictable here (they derive from
    an instance counter); this walks the whole document instead.
    """
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == prefix and isinstance(value, dict):
                found.append(value)
            elif isinstance(value, (dict, list)):
                found.extend(_find_prefix_entries(value, prefix))
    elif isinstance(obj, list):
        for value in obj:
            found.extend(_find_prefix_entries(value, prefix))
    return found


def _extcomm_strings(obj):
    """
    Recursively collect all rendered extended community strings.
    """
    strings = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "extendedCommunity":
                if isinstance(value, dict):
                    strings.append(value.get("string", ""))
                elif isinstance(value, str):
                    strings.append(value)
            elif isinstance(value, (dict, list)):
                strings.extend(_extcomm_strings(value))
    elif isinstance(obj, list):
        for value in obj:
            strings.extend(_extcomm_strings(value))
    return strings


def _check_global_route_rt(router, prefix, rt):
    """
    Check that the given prefix is present in the router's global EVPN
    table and (some path of it) carries the given route target, in its
    rendered "RT:..." form. Used to make sure a route-target
    configuration change on the announcing router has propagated
    before asserting import (non-)matching on the receiving one.
    Returns None on success, an error string otherwise.
    """
    output = router.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
    entries = _find_prefix_entries(output, prefix)
    if not entries:
        return "{}: prefix {} not in global EVPN table".format(router.name, prefix)

    strings = []
    for entry in entries:
        strings.extend(_extcomm_strings(entry))
    if not any(rt in ecs for ecs in strings):
        return "{}: prefix {} does not carry {} (extended communities: {})".format(
            router.name, prefix, rt, strings
        )
    return None


def _check_vrf_route_present(router, prefix):
    expected = {"routes": {prefix: [{"valid": True}]}}
    return partial(
        topotest.router_json_cmp,
        router,
        "show bgp vrf vrf-101 ipv4 unicast json",
        expected,
    )


def _check_vrf_route_absent(router, prefix):
    """
    Check that the given prefix is not present in vrf-101. Returns None
    on success, an error string otherwise.
    """
    output = router.vtysh_cmd("show bgp vrf vrf-101 ipv4 unicast json", isjson=True)
    if prefix in (output.get("routes") or {}):
        return "{}: prefix {} still present in vrf-101".format(router.name, prefix)
    return None


def _check_vni_route_present(router, vni, prefix):
    expected = {prefix: {"prefix": prefix}}
    return partial(
        topotest.router_json_cmp,
        router,
        "show bgp l2vpn evpn route vni {} json".format(vni),
        expected,
    )


def _check_vni_route_absent(router, vni, prefix):
    """
    Check that the given prefix is not present in the VNI's table.
    Returns None on success, an error string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route vni {} json".format(vni), isjson=True
    )
    if prefix in output:
        return "{}: prefix {} still present in VNI {}".format(router.name, prefix, vni)
    return None


def _expect(test_func, msg):
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, msg


def test_bgp_convergence():
    """
    Assert that the BGP EVPN session comes up between r1 and r2.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, peer in [("r1", "192.168.0.2"), ("r2", "192.168.0.1")]:
        router = tgen.gears[rname]

        expected = {"peers": {peer: {"state": "Established"}}}
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp l2vpn evpn summary json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, '"{}" BGP session did not establish'.format(rname)


def test_auto_rt_4byte_as_truncation():
    """
    Assert that r2 (4-byte AS) derives its auto route targets with the
    AS truncated to 16 bits, AS2-encoded, and that the routes are still
    imported in both directions via the wildcard local-admin matching
    of the auto import route targets.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    for vni, vni_type in [(101, "L3"), (201, "L2")]:
        auto_export_rt = "{}:{}".format(R2_AS_TRUNCATED, vni)
        expected = {
            "vni": str(vni),
            "type": vni_type,
            "importRts": ["*:{}".format(vni)],
            "exportRts": [auto_export_rt],
        }
        test_func = partial(
            topotest.router_json_cmp,
            r2,
            "show bgp l2vpn evpn vni {} json".format(vni),
            expected,
        )
        _expect(test_func, "r2: truncated auto RT missing for VNI {}".format(vni))

    # The auto import RT must appear as a wildcard entry in r2's
    # VRF import RT table.
    expected = {"*:101": {"rt": "*:101"}}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vrf-import-rt json",
        expected,
    )
    _expect(test_func, "r2: wildcard auto import RT missing for vrf-101")

    # r2's type-5 route must carry the truncated, AS2-encoded auto RT
    # on the wire ...
    test_func = partial(
        _check_global_route_rt,
        r1,
        R2_TYPE5_PREFIX,
        "RT:{}:101".format(R2_AS_TRUNCATED),
    )
    _expect(test_func, "r1: r2's type-5 route does not carry the truncated auto RT")

    # ... and both routers must import each other's type-5 route via
    # the wildcard local-admin matching (the global admins differ).
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: r2's type-5 route not imported into vrf-101",
    )
    _expect(
        _check_vrf_route_present(r2, "10.0.101.1/32"),
        "r2: r1's type-5 route not imported into vrf-101",
    )


def test_as4_encoded_rt():
    """
    Assert that AS4-encoded route targets (global admin > 65535) are
    matched by wildcard import route targets on their 2-byte local
    admin and by fully-qualified import route targets on the exact
    encoded value.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Replace r2's auto export RT with a manual, AS4-encoded RT that
    # keeps the VNI as the local admin.
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  route-target export 4200000001:101
""")

    test_func = partial(
        _check_global_route_rt, r1, R2_TYPE5_PREFIX, "RT:4200000001:101"
    )
    _expect(test_func, "r1: r2's type-5 route does not carry the AS4-encoded RT")

    # r1's auto import RT (wildcard on local admin 101) must match the
    # AS4-encoded RT on its 2-byte local admin.
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route with AS4-encoded RT 4200000001:101 not imported",
    )

    # Move the local admin away from the VNI; r1 must stop importing.
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  route-target export 4200000001:999
  no route-target export 4200000001:101
""")

    test_func = partial(
        _check_global_route_rt, r1, R2_TYPE5_PREFIX, "RT:4200000001:999"
    )
    _expect(test_func, "r1: r2's type-5 route does not carry RT 4200000001:999")

    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(test_func, "r1: type-5 route still imported without a matching RT")

    # A fully-qualified import RT must match the AS4-encoded RT on the
    # exact encoded value.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  route-target import 4200000001:999
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: AS4-encoded RT not matched by the fully-qualified import RT",
    )

    # A wildcard import RT must match the AS4-encoded RT on its 2-byte
    # local admin.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import 4200000001:999
  route-target import *:999
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: AS4-encoded RT not matched by the wildcard import RT",
    )

    # Cleanup: back to auto RTs on both sides.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:999
""")
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  no route-target export 4200000001:999
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported after restoring the auto RTs",
    )


def test_ip_encoded_rt():
    """
    Assert that IPv4-encoded route targets are matched by wildcard
    import route targets on their 2-byte local admin and that
    fully-qualified import route target matching is exact (an import
    RT with the same local admin but a different IP must not match).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  route-target export 192.0.2.2:101
""")

    test_func = partial(_check_global_route_rt, r1, R2_TYPE5_PREFIX, "RT:192.0.2.2:101")
    _expect(test_func, "r1: r2's type-5 route does not carry the IP-encoded RT")

    # r1's auto import RT (wildcard on local admin 101) must match the
    # IP-encoded RT on its 2-byte local admin.
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route with IP-encoded RT 192.0.2.2:101 not imported",
    )

    # Disable the auto import RT; without any import RT the route must
    # no longer be imported (even though the local admin equals the
    # VNI).
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target import add-never
""")

    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(
        test_func, "r1: type-5 route still imported with the auto import RT disabled"
    )

    # A fully-qualified import RT must match the IP-encoded RT
    # exactly.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  route-target import 192.0.2.2:101
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: IP-encoded RT not matched by the fully-qualified import RT",
    )

    # An import RT with the same local admin but a different IP must
    # NOT match (fully-qualified matching is on the exact encoded
    # bytes and the wildcard matching is disabled here).
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import 192.0.2.2:101
  route-target import 192.0.2.9:101
""")

    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(
        test_func,
        "r1: IP-encoded RT 192.0.2.2:101 wrongly matched import RT 192.0.2.9:101",
    )

    # Cleanup: back to auto RTs on both sides.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import 192.0.2.9:101
  no auto-route-target import add-never
""")
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  no route-target export 192.0.2.2:101
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported after restoring the auto RTs",
    )


def test_wildcard_keying_as2_full_local_admin():
    """
    Assert that wildcard import route targets match AS2-encoded route
    targets on their full 4-byte local admin: an AS2-encoded RT whose
    local admin agrees with the wildcard only in the low 16 bits
    (65637 = 65536 + 101) must NOT be matched by "*:101" (r1's auto
    import RT), but must be matched by "*:65637".
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  route-target export 65002:65637
""")

    test_func = partial(_check_global_route_rt, r1, R2_TYPE5_PREFIX, "RT:65002:65637")
    _expect(test_func, "r1: r2's type-5 route does not carry RT 65002:65637")

    # 65637 & 0xFFFF == 101, but the AS2 local admin is 4 bytes wide;
    # r1's auto import RT (wildcard on local admin 101) must NOT match.
    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(
        test_func,
        "r1: AS2-encoded RT 65002:65637 wrongly matched the '*:101' auto import RT",
    )

    # A wildcard on the full 4-byte local admin must match.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  route-target import *:65637
""")

    expected = {"*:65637": {"rt": "*:65637"}}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn vrf-import-rt json",
        expected,
    )
    _expect(test_func, "r1: wildcard import RT *:65637 missing from vrf-import-rt")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: AS2-encoded RT 65002:65637 not matched by the '*:65637' import RT",
    )

    # Removing the wildcard again must uninstall the route.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:65637
""")

    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(test_func, "r1: type-5 route still imported after removing '*:65637'")

    # Cleanup: back to auto RTs.
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  no route-target export 65002:65637
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported after restoring the auto RTs",
    )


def test_multiple_rts_any_match():
    """
    Assert that a route carrying multiple route targets of different
    encodings is imported if any single one of them matches an import
    route target, and not imported if none does.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Attach one RT of each encoding, none with local admin 101 (so
    # r1's auto import RT does not interfere). Two AS4-encoded RTs
    # share the AS and differ only in the local admin; both must
    # survive (regression: the effective-RT dedup once compared AS4
    # local admins at the wrong offset and collapsed them).
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  route-target export 65002:999 192.0.2.2:888 4200000001:777 4200000001:778
""")

    for rt in [
        "RT:65002:999",
        "RT:192.0.2.2:888",
        "RT:4200000001:777",
        "RT:4200000001:778",
    ]:
        test_func = partial(_check_global_route_rt, r1, R2_TYPE5_PREFIX, rt)
        _expect(test_func, "r1: r2's type-5 route does not carry {}".format(rt))

    # Matching the AS4-encoded RT alone must be enough ...
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  route-target import *:777
""")
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not imported although '*:777' matches one of its RTs",
    )

    # ... as must matching the IP-encoded RT alone ...
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:777
  route-target import *:888
""")
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not imported although '*:888' matches one of its RTs",
    )

    # ... while a wildcard matching none of the RTs must not import.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:888
  route-target import *:666
""")
    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(test_func, "r1: type-5 route imported although none of its RTs match")

    # Cleanup: back to auto RTs on both sides.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:666
""")
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  no route-target export 65002:999 192.0.2.2:888 4200000001:777 4200000001:778
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported after restoring the auto RTs",
    )


def test_l2vni_rt_encoding():
    """
    Assert that the same encoding rules hold on the L2VNI (VNI import
    RT table) code path, which is separate from the VRF one: r2's IMET
    route for VNI 201 with an AS4-encoded RT must be imported via r1's
    auto (wildcard) import RT, while an AS2-encoded RT with a 4-byte
    local admin agreeing only in the low 16 bits (65737 = 65536 + 201)
    must not be, until a matching "*:65737" wildcard is configured.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Baseline: r2's IMET route is imported into r1's VNI 201 via the
    # auto RTs.
    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: r2's IMET route not imported into VNI 201 via the auto RTs",
    )

    # AS4-encoded export RT with the VNI as local admin: r1's auto
    # import RT must still match (2-byte local admin extraction).
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001
 address-family l2vpn evpn
  vni 201
   route-target export 4200000001:201
""")

    test_func = partial(_check_global_route_rt, r1, R2_IMET_PREFIX, "RT:4200000001:201")
    _expect(test_func, "r1: r2's IMET route does not carry the AS4-encoded RT")

    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: IMET route with AS4-encoded RT 4200000001:201 not imported",
    )

    # AS2-encoded RT with a 4-byte local admin whose low 16 bits equal
    # the VNI: must NOT match r1's auto import RT.
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001
 address-family l2vpn evpn
  vni 201
   no route-target export 4200000001:201
   route-target export 65002:65737
""")

    test_func = partial(_check_global_route_rt, r1, R2_IMET_PREFIX, "RT:65002:65737")
    _expect(test_func, "r1: r2's IMET route does not carry RT 65002:65737")

    test_func = partial(_check_vni_route_absent, r1, 201, R2_IMET_PREFIX)
    _expect(
        test_func,
        "r1: AS2-encoded RT 65002:65737 wrongly matched the '*:201' auto import RT",
    )

    # A wildcard on the full 4-byte local admin must match, and must
    # show up in the VNI import RT table.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   auto-route-target import add-always
   route-target import *:65737
""")

    expected = {"*:65737": {"rt": "*:65737", "vnis": [201]}}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn import-rt json",
        expected,
    )
    _expect(test_func, "r1: wildcard import RT *:65737 missing from import-rt")

    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: AS2-encoded RT 65002:65737 not matched by the '*:65737' import RT",
    )

    # Cleanup: back to auto RTs on both sides.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   no route-target import *:65737
   no auto-route-target import add-always
""")
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001
 address-family l2vpn evpn
  vni 201
   no route-target export 65002:65737
""")

    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: r2's IMET route not re-imported after restoring the auto RTs",
    )


def test_rfc8365_compatible_encoding():
    """
    "auto-route-target export rfc8365-compatible" sets the VXLAN
    encapsulation bit (0x10000000) in the local admin field of the
    exported auto route target; the matching per-direction import
    setting keys the auto import wildcard on the same encoded value.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Baseline: r2's L3VNI auto export RT is <as-truncated>:101 on the wire.
    _expect(
        partial(
            _check_global_route_rt,
            r1,
            R2_TYPE5_PREFIX,
            "RT:{}:101".format(R2_AS_TRUNCATED),
        ),
        "r1: r2's type-5 route does not carry the plain auto export RT",
    )

    # Enable RFC 8365 compatible encoding on r2's export direction; the
    # VXLAN bit (0x10000000) is OR'd into the local admin.
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target export rfc8365-compatible
""")

    rfc8365_local_admin = 0x10000000 + 101
    _expect(
        partial(
            _check_global_route_rt,
            r1,
            R2_TYPE5_PREFIX,
            "RT:{}:{}".format(R2_AS_TRUNCATED, rfc8365_local_admin),
        ),
        "r1: r2's type-5 route does not carry the RFC 8365 encoded auto export RT",
    )

    # r1's plain auto import RT (wildcard on local admin 101) no longer
    # matches the encoded local admin, so the route is unimported.
    _expect(
        partial(_check_vrf_route_absent, r1, "10.0.101.2/32"),
        "r1: type-5 route still imported despite the RFC 8365 encoded RT",
    )

    # Matching the encoding on r1's import direction restores the import.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target import rfc8365-compatible
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported with matching RFC 8365 import encoding",
    )

    # The per-direction setting round-trips in the running config.
    running_r2 = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target export rfc8365-compatible" in running_r2
    ), "r2: 'auto-route-target export rfc8365-compatible' not in running config"

    # Cleanup: back to the plain auto RTs on both sides.
    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no auto-route-target import rfc8365-compatible
""")
    r2.vtysh_cmd("""
configure terminal
router bgp 4200000001 vrf vrf-101
 address-family l2vpn evpn
  no auto-route-target export rfc8365-compatible
""")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: type-5 route not re-imported after clearing the RFC 8365 encoding",
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
