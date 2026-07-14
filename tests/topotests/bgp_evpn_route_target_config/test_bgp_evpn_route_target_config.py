#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_route_target_config.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 Robin Christ for partimus GmbH
#

"""
Test the EVPN route-target configuration features:

- implicit auto route targets for L3VNI VRFs and L2VNIs,
- "auto-route-target <import|export|both> <add-never|add-always>" on
  L3VNI VRFs and L2VNIs, including add-never with a retained manual
  wildcard and the "both" alias writing back split per-direction lines,
- manual wildcard import route targets ("*:N") on an L2VNI,
- manual route targets replacing the auto route target per direction
  (add-if-no-manual default), and the split/merge behavior of
  "route-target both <RT>" and its no-forms,
- canonical ordering of the effective import route-target list,
- cleanup of the wildcard auto import RT when the L3VNI is detached,
- the deprecated "route-target <dir> auto"/"autort rfc8365-compatible"
  aliases and the explicit "add-if-no-manual" round-trip.

Two routers (r1, AS 65001 and r2, AS 65002) peer via eBGP over a
back-to-back link. Both carry L3VNI 101 (vrf-101) and L2VNI 201;
r1 additionally carries L2VNI 202 with a gateway MAC-IP so that it
originates a type-2 route with the auto route target 65001:202.

Because the routers are in different ASes, all cross-router imports
rely on the local-admin-only (wildcard) matching of the auto route
targets.
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

# MAC/IP of the SVI of L2VNI 202 on r1, advertised as a gateway MAC-IP
# (type-2) route with the auto route target 65001:202. In the per-VNI
# table MAC-IP routes carrying an IP are keyed by the IP alone with the
# MAC zeroed (evpn_type2_prefix_vni_ip_copy()); only the global table
# keys them by MAC and IP.
GW_MAC = "52:54:00:01:00:ca"
GW_IP = "10.0.202.1"
GW_TYPE2_VNI_PREFIX = "[2]:[0]:[48]:[00:00:00:00:00:00]:[32]:[{}]".format(GW_IP)

# The IMET (type-3) routes the two routers originate for L2VNI 201.
R1_IMET_PREFIX = "[3]:[0]:[32]:[192.168.0.1]"
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

    # L2VNI 202 only exists on r1; its SVI has a fixed MAC and an IP
    # address so that r1 originates a gateway MAC-IP (type-2) route.
    cmds_vxlan_r1 = [
        "ip link add name bridge-202 up address {} type bridge stp_state 0".format(
            GW_MAC
        ),
        "ip addr add {}/24 dev bridge-202".format(GW_IP),
        "ip link add name vxlan-202 type vxlan id 202 dstport 4789 dev r1-eth0 local 192.168.0.1",
        "ip link set dev vxlan-202 master bridge-202",
        "ip link set vxlan-202 up type bridge_slave learning off flood off mcast_flood off",
    ]

    for rid in (1, 2):
        router = tgen.gears["r{}".format(rid)]
        for cmd in cmds_vxlan:
            formatted = cmd.format(rid)
            logger.info("cmd to r{}: {}".format(rid, formatted))
            output = router.cmd_raises(formatted)
            logger.info("result: " + output)

    for cmd in cmds_vxlan_r1:
        logger.info("cmd to r1: {}".format(cmd))
        output = tgen.gears["r1"].cmd_raises(cmd)
        logger.info("result: " + output)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_vni_rts(router, vni, vni_type, import_rts, export_rts):
    """
    Check that the given import/export RTs show up for the VNI. Returns
    a partial for run_and_expect.
    """
    expected = {
        "vni": str(vni),
        "type": vni_type,
        "importRts": import_rts,
        "exportRts": export_rts,
    }
    return partial(
        topotest.router_json_cmp,
        router,
        "show bgp l2vpn evpn vni {} json".format(vni),
        expected,
    )


def _check_vni_rt_absent(router, vni, field, rt):
    """
    Check that the given RT is absent from the VNI's import or export
    RTs ("importRts"/"exportRts"). Returns None on success, an error
    string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {} json".format(vni), isjson=True
    )
    if rt in (output.get(field) or []):
        return "{}: {} {} still present for VNI {}".format(router.name, field, rt, vni)
    return None


def _check_vni_rt_list(router, vni, field, expected):
    """
    Check that the VNI's import or export RTs ("importRts"/
    "exportRts") are exactly the expected list, in order. Returns None
    on success, an error string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {} json".format(vni), isjson=True
    )
    actual = output.get(field) or []
    if actual != expected:
        return "{}: VNI {} {} is {} (expected {})".format(
            router.name, vni, field, actual, expected
        )
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


def _check_vni_route_no_path_with_rt(router, vni, prefix, rt):
    """
    Check that no path of the given prefix in the VNI's table carries
    the given route target. Unlike _check_vni_route_absent() this
    tolerates the prefix staying present via other route targets: IMET
    prefixes are keyed by the originator IP alone, so IMET routes of
    several source VNIs of one router share a single prefix key.
    Returns None on success, an error string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route vni {} json".format(vni), isjson=True
    )
    for path_group in (output.get(prefix) or {}).get("paths", []):
        for path in path_group:
            ecom = (path.get("extendedCommunity") or {}).get("string", "")
            if "RT:" + rt in ecom.split():
                return "{}: prefix {} still has a path with RT {} in VNI {}".format(
                    router.name, prefix, rt, vni
                )
    return None


def _check_vni_route_has_path_with_rt(router, vni, prefix, rt):
    """
    Check that some path of the given prefix in the VNI's table carries
    the given route target (the positive counterpart of
    _check_vni_route_no_path_with_rt(), for prefix keys that stay
    present via other route targets). Returns None on success, an error
    string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route vni {} json".format(vni), isjson=True
    )
    for path_group in (output.get(prefix) or {}).get("paths", []):
        for path in path_group:
            ecom = (path.get("extendedCommunity") or {}).get("string", "")
            if "RT:" + rt in ecom.split():
                return None
    return "{}: prefix {} has no path with RT {} in VNI {}".format(
        router.name, prefix, rt, vni
    )


def _expect(test_func, msg):
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, msg


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


def test_auto_rt_baseline():
    """
    Assert that the implicit auto RTs are derived for the L3VNI and the
    L2VNI - the wildcard "*:VNI" on import, "AS:VNI" on export - and
    that routes are exchanged based on them (local-admin-only matching,
    as the two routers use different ASes).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, asn in [("r1", 65001), ("r2", 65002)]:
        router = tgen.gears[rname]

        for vni, vni_type in [(101, "L3"), (201, "L2")]:
            auto_import_rt = "*:{}".format(vni)
            auto_export_rt = "{}:{}".format(asn, vni)
            test_func = _check_vni_rts(
                router, vni, vni_type, [auto_import_rt], [auto_export_rt]
            )
            _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assert result is None, "{}: auto RT missing for VNI {}".format(rname, vni)

    # The type-5 route of the remote router must be imported into
    # vrf-101 (the auto import RT matches on the local admin - the VNI -
    # alone, regardless of the remote AS).
    for rname, remote_prefix in [("r1", "10.0.101.2/32"), ("r2", "10.0.101.1/32")]:
        router = tgen.gears[rname]
        test_func = _check_vrf_route_present(router, remote_prefix)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{}: type-5 route {} not imported into vrf-101".format(
            rname, remote_prefix
        )

    # The type-3 (IMET) route of r1's L2VNI 201 must be imported into
    # r2's L2VNI 201.
    expected = {"[3]:[0]:[32]:[192.168.0.1]": {}}
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show bgp l2vpn evpn route vni 201 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: type-3 route of r1 not imported into VNI 201"


def test_l3vni_import_auto_disable():
    """
    Disable the auto import RT on r2's L3VNI VRF and assert that the
    auto import RT disappears and remote type-5 routes are no longer
    imported; re-enable and assert that they come back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target import add-never
""")

    # The auto import RT must be gone ...
    test_func = partial(_check_vni_rt_absent, r2, 101, "importRts", "*:101")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    # ... the auto export RT must be unaffected ...
    expected = {"vni": "101", "exportRts": ["65002:101"]}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vni 101 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: auto export RT unexpectedly disappeared"

    # ... the remote type-5 route must no longer be imported ...
    test_func = partial(_check_vrf_route_absent, r2, "10.0.101.1/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    # ... and the configuration must be written out.
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target import add-never" in running
    ), "r2: 'auto-route-target import add-never' not in running config"

    # Re-enable the auto import RT; the type-5 route must come back.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  no auto-route-target import add-never
""")

    test_func = _check_vni_rts(r2, 101, "L3", ["*:101"], ["65002:101"])
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: auto import RT did not come back for VNI 101"

    test_func = _check_vrf_route_present(r2, "10.0.101.1/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: type-5 route not re-imported into vrf-101"


def test_l2vni_wildcard_import():
    """
    Configure a wildcard import RT for a different VNI (202, only used
    by r1) on r2's L2VNI 201 and assert that r1's type-2 route of VNI
    202 is imported into r2's VNI 201 although the routers are in
    different ASes ("*:202" matches "65001:202" on the local admin).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Keep the auto import RT (explicitly) next to the manual wildcard
    # RT so that VNI 201 routes are still imported.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   auto-route-target import add-always
   route-target import *:202
""")

    # The wildcard RT must show up in the import RTs of the VNI next to
    # the retained auto RT (both displayed as wildcards, like they
    # match) ...
    expected = {"vni": "201", "importRts": ["*:201", "*:202"]}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vni 201 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: wildcard/auto import RTs missing for VNI 201"

    # ... and in the import RT to VNI mapping.
    expected = {"*:202": {"rt": "*:202", "vnis": [201]}}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn import-rt json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: wildcard import RT missing from import-rt table"

    # r1's type-2 route of VNI 202 (RT 65001:202) must be imported into
    # r2's VNI 201 via the wildcard RT. Verify the gateway MAC via the
    # path attributes since the prefix key carries only the IP here.
    expected = {
        GW_TYPE2_VNI_PREFIX: {
            "prefix": GW_TYPE2_VNI_PREFIX,
            "paths": [[{"valid": True, "mac": GW_MAC}]],
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn route vni 201 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: type-2 route of r1's VNI 202 not imported into VNI 201"

    # The wildcard RT must be written out verbatim.
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "route-target import *:202" in running
    ), "r2: 'route-target import *:202' not in running config"


def test_l2vni_both_alias():
    """
    Configure "route-target both" on r2's L2VNI 201 and assert that it
    is active for both directions and written out as separate import
    and export lines ("both" is an alias, not a distinct config form).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   route-target both 65099:99
""")

    expected = {"vni": "201", "importRts": ["65099:99"], "exportRts": ["65099:99"]}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vni 201 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2: 'both' RT not active for both directions on VNI 201"

    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "route-target both 65099:99" not in running
    ), "r2: 'both' alias unexpectedly written back as a both line"
    assert (
        "route-target import 65099:99" in running
    ), "r2: 'route-target import 65099:99' not in running config"
    assert (
        "route-target export 65099:99" in running
    ), "r2: 'route-target export 65099:99' not in running config"


def test_l2vni_no_import_on_both_keeps_export():
    """
    Remove the import direction of the "route-target both 65099:99"
    configured on r2's VNI 201 in the previous test ("both" is an
    alias for import plus export) and assert that the export
    direction survives as a "route-target export" line; then remove
    that too and assert that the auto export RT comes back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   no route-target import 65099:99
""")

    # The RT must stay active for export only ...
    expected = {"vni": "201", "exportRts": ["65099:99"]}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vni 201 json",
        expected,
    )
    _expect(test_func, "r2: 65099:99 no longer active for export on VNI 201")

    test_func = partial(_check_vni_rt_absent, r2, 201, "importRts", "65099:99")
    _expect(test_func, "r2: 65099:99 still active for import on VNI 201")

    # ... and only the export line must remain in the configuration.
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "route-target export 65099:99" in running
    ), "r2: migrated 'route-target export 65099:99' not in running config"
    assert (
        "route-target both 65099:99" not in running
    ), "r2: 'route-target both 65099:99' still in running config"
    assert (
        "route-target import 65099:99" not in running
    ), "r2: unexpected 'route-target import 65099:99' in running config"

    # Removing the remaining export direction must restore the auto
    # export RT (65099:99 was the only configured export RT).
    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   no route-target export 65099:99
""")

    test_func = partial(_check_vni_rt_list, r2, 201, "exportRts", ["65002:201"])
    _expect(test_func, "r2: auto export RT not restored on VNI 201")


def test_l2vni_no_both_removes_split_import_export():
    """
    Configure the same RT as separate import and export lines on r1's
    VNI 201 and assert that a single "no route-target both" removes
    both of them.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   route-target import 65098:98
   route-target export 65098:98
""")

    # The RTs replace the auto RTs in both directions.
    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", ["65098:98"])
    _expect(test_func, "r1: import RT 65098:98 did not replace the auto import RT")
    test_func = partial(_check_vni_rt_list, r1, 201, "exportRts", ["65098:98"])
    _expect(test_func, "r1: export RT 65098:98 did not replace the auto export RT")

    running = r1.vtysh_cmd("show running-config", isjson=False)
    assert (
        "route-target import 65098:98" in running
        and "route-target export 65098:98" in running
    ), "r1: split import/export RT lines not in running config"
    assert (
        "route-target both 65098:98" not in running
    ), "r1: split import/export RTs unexpectedly merged into a 'both' line"

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   no route-target both 65098:98
""")

    # Both directions must be gone and the auto RTs restored.
    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", ["*:201"])
    _expect(test_func, "r1: auto import RT not restored after 'no route-target both'")
    test_func = partial(_check_vni_rt_list, r1, 201, "exportRts", ["65001:201"])
    _expect(test_func, "r1: auto export RT not restored after 'no route-target both'")

    running = r1.vtysh_cmd("show running-config", isjson=False)
    assert (
        "65098:98" not in running
    ), "r1: 65098:98 still in running config after 'no route-target both'"


def test_l2vni_manual_import_replaces_auto():
    """
    Configure a manual import RT on r1's VNI 201 and assert that it
    replaces the auto import RT entirely (so r2's IMET route, which
    only carries r2's auto RT, is unimported), and that removing it
    restores the auto import RT and re-imports the route.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Baseline: r2's IMET route is imported via the auto RTs.
    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: r2's IMET route not imported into VNI 201 via the auto RTs",
    )

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   route-target import 65530:1
""")

    # The manual import RT must be the only import RT; the export
    # side must keep its auto RT.
    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", ["65530:1"])
    _expect(test_func, "r1: manual import RT did not replace the auto import RT")

    test_func = partial(_check_vni_rt_list, r1, 201, "exportRts", ["65001:201"])
    _expect(test_func, "r1: auto export RT unexpectedly changed")

    # r2's IMET route (RT 65002:201) must no longer be imported.
    test_func = partial(_check_vni_route_absent, r1, 201, R2_IMET_PREFIX)
    _expect(test_func, "r1: r2's IMET route still imported without a matching RT")

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   no route-target import 65530:1
""")

    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", ["*:201"])
    _expect(test_func, "r1: auto import RT not restored on VNI 201")

    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: r2's IMET route not re-imported after restoring the auto RT",
    )


def test_l2vni_import_rt_ordering():
    """
    Configure import RTs of the different types in shuffled order on
    r1's VNI 201 and assert that the show output lists them in their
    canonical order: the wildcard RT (displayed as "*:N", like it
    matches) first, then the AS2-typed RTs numerically by AS and local
    admin, followed by the IP-typed RTs.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   route-target import 65100:10
   route-target import 192.0.2.1:7
   route-target import 65002:5
   route-target import *:300
   route-target import 65100:2
""")

    expected = ["*:300", "65002:5", "65100:2", "65100:10", "192.0.2.1:7"]
    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", expected)
    _expect(test_func, "r1: import RTs of VNI 201 not in canonical order")

    r1.vtysh_cmd("""
configure terminal
router bgp 65001
 address-family l2vpn evpn
  vni 201
   no route-target import 65100:10
   no route-target import 192.0.2.1:7
   no route-target import 65002:5
   no route-target import *:300
   no route-target import 65100:2
""")

    test_func = partial(_check_vni_rt_list, r1, 201, "importRts", ["*:201"])
    _expect(test_func, "r1: auto import RT not restored on VNI 201")


def test_l2vni_auto_disable():
    """
    Disable the auto import RT on r2's VNI 201 (which keeps its
    manual wildcard import RT "*:202" from the earlier test) and
    assert that only the wildcard remains and r1's IMET route is
    unimported; then do the same for the export direction and assert
    that r2's IMET route disappears from r1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Baseline: r1's IMET route is imported via r2's auto import RT
    # (assert on the path's RT: the prefix key alone stays present via
    # the wildcard import RT either way).
    _expect(
        partial(
            _check_vni_route_has_path_with_rt, r2, 201, R1_IMET_PREFIX, "65001:201"
        ),
        "r2: r1's IMET route not imported into VNI 201 via the auto RT",
    )

    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   auto-route-target import add-never
""")

    # Only the manual wildcard import RT remains.
    test_func = partial(_check_vni_rt_list, r2, 201, "importRts", ["*:202"])
    _expect(test_func, "r2: auto import RT not disabled on VNI 201")

    # r1's IMET route of VNI 201 (RT 65001:201, local admin 201) matches
    # neither the wildcard "*:202" nor anything else - it must be
    # unimported. The prefix key itself remains present: r1's IMET route
    # of VNI 202 shares it and stays imported via the wildcard.
    test_func = partial(
        _check_vni_route_no_path_with_rt, r2, 201, R1_IMET_PREFIX, "65001:201"
    )
    _expect(test_func, "r2: r1's IMET route still imported with the auto RT suppressed")

    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target import add-never" in running
    ), "r2: 'auto-route-target import add-never' not in running config of VNI 201"

    # Back to the explicitly configured auto import RT.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   auto-route-target import add-always
""")

    test_func = partial(_check_vni_rt_list, r2, 201, "importRts", ["*:201", "*:202"])
    _expect(test_func, "r2: auto import RT not re-enabled on VNI 201")

    _expect(
        partial(
            _check_vni_route_has_path_with_rt, r2, 201, R1_IMET_PREFIX, "65001:201"
        ),
        "r2: r1's IMET route not re-imported after re-enabling the auto RT",
    )

    # Now the export direction: r2 stops exporting VNI 201 routes, so
    # r1 must unimport r2's IMET route.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   auto-route-target export add-never
""")

    test_func = partial(_check_vni_rt_list, r2, 201, "exportRts", [])
    _expect(test_func, "r2: auto export RT not disabled on VNI 201")

    test_func = partial(_check_vni_route_absent, r1, 201, R2_IMET_PREFIX)
    _expect(test_func, "r1: r2's IMET route still imported with r2's export disabled")

    r2.vtysh_cmd("""
configure terminal
router bgp 65002
 address-family l2vpn evpn
  vni 201
   no auto-route-target export add-never
""")

    test_func = partial(_check_vni_rt_list, r2, 201, "exportRts", ["65002:201"])
    _expect(test_func, "r2: auto export RT not re-enabled on VNI 201")

    _expect(
        _check_vni_route_present(r1, 201, R2_IMET_PREFIX),
        "r1: r2's IMET route not re-imported after re-enabling r2's export",
    )


def test_l3vni_export_auto_disable():
    """
    Disable the auto export RT on r1's L3VNI VRF and assert that r2
    unimports r1's type-5 route while r1's import side is unaffected;
    re-enable and assert that the route comes back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target export add-never
""")

    test_func = partial(_check_vni_rt_absent, r1, 101, "exportRts", "65001:101")
    _expect(test_func, "r1: auto export RT not disabled on the L3VNI")

    # The import side of r1 must be unaffected ...
    expected = {"vni": "101", "importRts": ["*:101"]}
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp l2vpn evpn vni 101 json",
        expected,
    )
    _expect(test_func, "r1: auto import RT unexpectedly disappeared")

    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: r2's type-5 route unexpectedly unimported",
    )

    # ... but r2 must unimport r1's type-5 route.
    test_func = partial(_check_vrf_route_absent, r2, "10.0.101.1/32")
    _expect(test_func, "r2: r1's type-5 route still imported with r1's export disabled")

    r1.vtysh_cmd("""
configure terminal
router bgp 65001 vrf vrf-101
 address-family l2vpn evpn
  no auto-route-target export add-never
""")

    _expect(
        _check_vrf_route_present(r2, "10.0.101.1/32"),
        "r2: r1's type-5 route not re-imported after re-enabling r1's export",
    )


def test_l3vni_both_auto_disable_with_manual_wildcard():
    """
    Disable both auto RTs on r2's L3VNI VRF with a single
    "auto-route-target both add-never" ("both" is an alias for import
    plus export) and assert that route exchange stops in both
    directions; then add a manual wildcard import RT next to it and
    assert that only the import direction resumes.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target both add-never
""")

    test_func = partial(_check_vni_rt_absent, r2, 101, "importRts", "*:101")
    _expect(test_func, "r2: auto import RT not disabled on the L3VNI")
    test_func = partial(_check_vni_rt_absent, r2, 101, "exportRts", "65002:101")
    _expect(test_func, "r2: auto export RT not disabled on the L3VNI")

    test_func = partial(_check_vrf_route_absent, r2, "10.0.101.1/32")
    _expect(
        test_func, "r2: r1's type-5 route still imported with both auto RTs suppressed"
    )
    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(
        test_func, "r1: r2's type-5 route still imported with both auto RTs suppressed"
    )

    # The "both" alias configures the two per-direction settings.
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target import add-never" in running
        and "auto-route-target export add-never" in running
    ), "r2: per-direction add-never lines not in running config"
    assert (
        "auto-route-target both add-never" not in running
    ), "r2: 'both' alias unexpectedly written back as a both line"

    # A manual wildcard import RT next to the disabled auto RTs must
    # resume the import direction only.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  route-target import *:101
""")

    _expect(
        _check_vrf_route_present(r2, "10.0.101.1/32"),
        "r2: r1's type-5 route not imported via the manual wildcard RT",
    )
    test_func = partial(_check_vrf_route_absent, r1, "10.0.101.2/32")
    _expect(
        test_func, "r1: r2's type-5 route imported although r2's export is disabled"
    )

    # Cleanup: back to full auto in both directions.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  no route-target import *:101
  no auto-route-target both add-never
""")

    _expect(
        _check_vrf_route_present(r2, "10.0.101.1/32"),
        "r2: r1's type-5 route not re-imported after restoring the auto RTs",
    )
    _expect(
        _check_vrf_route_present(r1, "10.0.101.2/32"),
        "r1: r2's type-5 route not re-imported after restoring the auto RTs",
    )


def test_l3vni_removal_cleans_vrf_import_rt():
    """
    Detach the L3VNI from r2's VRF and assert that its auto import RT
    disappears from the VRF import RT table (it must not linger);
    re-attach and assert that it comes back.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Baseline: the auto import RT is present as a wildcard entry.
    expected = {"*:101": {"rt": "*:101"}}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vrf-import-rt json",
        expected,
    )
    _expect(test_func, "r2: wildcard auto import RT missing for vrf-101")

    r2.vtysh_cmd("""
configure terminal
vrf vrf-101
 no vni 101
""")

    # Neither the wildcard nor the fully-qualified form of the auto
    # import RT may linger in the VRF import RT table.
    expected = {"*:101": None, "65002:101": None}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vrf-import-rt json",
        expected,
    )
    _expect(test_func, "r2: auto import RT lingers after L3VNI removal")

    test_func = partial(_check_vrf_route_absent, r2, "10.0.101.1/32")
    _expect(test_func, "r2: r1's type-5 route still imported without an L3VNI")

    r2.vtysh_cmd("""
configure terminal
vrf vrf-101
 vni 101
""")

    expected = {"*:101": {"rt": "*:101"}}
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp l2vpn evpn vrf-import-rt json",
        expected,
    )
    _expect(test_func, "r2: wildcard auto import RT not restored for vrf-101")

    _expect(
        _check_vrf_route_present(r2, "10.0.101.1/32"),
        "r2: r1's type-5 route not re-imported after re-attaching the L3VNI",
    )


def test_deprecated_aliases_and_add_if_no_manual():
    """
    The deprecated "route-target <dir> auto" alias is still accepted,
    warns, and round-trips as "auto-route-target <dir> add-always"; the
    explicit default "add-if-no-manual" also round-trips in the running
    configuration.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # The deprecated alias is accepted but prints a deprecation hint ...
    out = r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  route-target import auto
""")
    assert (
        'is deprecated, use "auto-route-target import add-always"' in out
    ), "r2: deprecated 'route-target import auto' did not warn"

    # ... and it round-trips as the new syntax, not verbatim.
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target import add-always" in running
    ), "r2: deprecated alias not written back as 'auto-route-target import add-always'"
    assert (
        "route-target import auto\n" not in running
    ), "r2: deprecated 'route-target import auto' unexpectedly written back verbatim"

    # The explicit default add-if-no-manual round-trips too.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  auto-route-target export add-if-no-manual
""")
    running = r2.vtysh_cmd("show running-config", isjson=False)
    assert (
        "auto-route-target export add-if-no-manual" in running
    ), "r2: 'auto-route-target export add-if-no-manual' not in running config"

    # Cleanup: back to the implicit default in both directions.
    r2.vtysh_cmd("""
configure terminal
router bgp 65002 vrf vrf-101
 address-family l2vpn evpn
  no auto-route-target import add-always
  no auto-route-target export add-if-no-manual
""")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
