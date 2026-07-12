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
- "auto-route-target import add-never" on an L3VNI VRF,
- manual wildcard import route targets ("*:N") on an L2VNI,
- "route-target both <RT>" acting as an alias for import plus export.

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
        "vni": vni,
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


def _check_vni_import_rt_absent(router, vni, rt):
    """
    Check that the given RT is absent from the VNI's import RTs.
    Returns None on success, an error string otherwise.
    """
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn vni {} json".format(vni), isjson=True
    )
    if rt in (output.get("importRts") or []):
        return "{}: import RT {} still present for VNI {}".format(router.name, rt, vni)
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
    test_func = partial(_check_vni_import_rt_absent, r2, 101, "*:101")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    # ... the auto export RT must be unaffected ...
    expected = {"vni": 101, "exportRts": ["65002:101"]}
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
    expected = {"vni": 201, "importRts": ["*:201", "*:202"]}
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

    expected = {"vni": 201, "importRts": ["65099:99"], "exportRts": ["65099:99"]}
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


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
