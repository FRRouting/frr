#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 NVIDIA Corporation.
#

"""
Reproducer for stale EVPN type-5 re-export after inter-VRF leaking.

Topology:

                         EVPN Type-5
                    +-------------------+
                    |                   |
              +-----+-----+       +-----+-----+
              |    r1     |       |    r2     |
              | origin PE |       |  PE/VTEP  |
              +-----+-----+       +-----+-----+
                    |                   |
                    +---------+---------+
                              |
                         +----+----+
                         |   s1    |
                         +----+----+
                              |
                         +----+----+
                         |   r3    |
                         |  PE/VTEP|
                         +---------+

r1 injects 192.168.50.1/32 as a static route in VRF GREEN and exports it as an
EVPN type-5 route. r2 and r3 both import that EVPN route into GREEN, use
three-way leaking between GREEN, BLUE, and PURPLE, and re-export the leaked
paths as EVPN type-5 routes. This creates imported routes whose parents can be
other imported routes whose parent is the EVPN table, matching the customer
route chain.
After r1 withdraws the real origin, affected builds can keep stale leaked paths
alive through the mutual PE re-export.

The test withdraws the origin from r1 and fails if r2 or r3 retain stale leaked
or re-exported state, or if r1 relearns the withdrawn origin from EVPN.
Affected builds keep the PURPLE copy after GREEN is gone.
The r2/r3 tenant VRFs enable skip-evpn-imported, so fixed builds still
import and leak the original Type-5 route locally but do not re-export EVPN-origin
leaked paths back into EVPN.

The normal-leak test originates 192.168.60.1/32 in r2 BLUE and verifies the
route can still be leaked into r2 GREEN and exported to r1 GREEN as Type-5.
"""

import json
import os
import platform
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import (
    create_static_routes,
    create_vrf_cfg,
    kill_router_daemons,
    start_router_daemons,
)
from lib.common_check import iproute2_check_path_selection
from lib.bgp import create_router_bgp, verify_bgp_convergence_from_running_config
from lib.evpn import (
    evpn_type5_prefix_count,
    evpn_type5_route_distinguishers,
    evpn_verify_vrf_rib_route,
)
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PREFIX = "192.168.50.1/32"
NORMAL_LEAK_PREFIX = "192.168.60.1/32"
DIRECT_IMPORT_PREFIX = "192.168.70.1/32"
TOGGLE_PREFIX = "192.168.80.1/32"
RESTART_PREFIX = "192.168.90.1/32"
SESSION_CLEAR_PREFIX = "192.168.103.1/32"
L3VNI_PREFIX = "192.168.91.1/32"
SELECTIVE_EVPN_PREFIX = "192.168.92.1/32"
SELECTIVE_LOCAL_PREFIX = "192.168.93.1/32"
MIXED_PATH_PREFIX = "192.168.94.1/32"
VRF_IMPORT_PREFIX = "192.168.95.1/32"
SHARED_RD_PREFIX = "192.168.96.1/32"
L3_HOST_WITHDRAW_PREFIX = "192.168.97.1/32"
PRECONFIGURED_SKIP_PREFIX = "192.168.99.1/32"
MULTI_SOURCE_GREEN_PREFIX = "192.168.100.1/32"
MULTI_SOURCE_BLUE_PREFIX = "192.168.101.1/32"
INITIAL_IMPORT_PREFIX = "192.168.102.1/32"
PE_VRFS = ("GREEN", "BLUE", "PURPLE")
BLUE_L3VNI = 102
PURPLE_L3VNI = 103
# Fabric sessions live in the default instance; the tenant VRFs have no peers.
FABRIC_PEERS = {
    "r1": ("192.168.100.2", "192.168.100.3"),
    "r2": ("192.168.100.1", "192.168.100.3"),
    "r3": ("192.168.100.1", "192.168.100.2"),
}


def build_topo(tgen):
    "Build three routers connected through a shared test switch."

    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    for router in ("r1", "r2", "r3"):
        switch.add_link(tgen.gears[router])


def _configure_l3vni_interfaces(router, rname, vrf, vni, local_vtep):
    "Create the dummy, bridge, and VXLAN interfaces for one L3VNI."
    commands = [
        "ip link add loop{0} type dummy".format(vni),
        "ip link set dev loop{0} master {1}".format(vni, vrf),
        "ip link set dev loop{0} up".format(vni),
        "ip link add name br{0} up type bridge stp_state 0".format(vni),
        "ip link set dev br{0} master {1}".format(vni, vrf),
        "ip link set dev br{0} up".format(vni),
        (
            "ip link add name vxlan{0} type vxlan id {0} dstport 4789 "
            "dev {1}-eth0 local {2} nolearning"
        ).format(vni, rname, local_vtep),
        "ip link set dev vxlan{0} master br{0}".format(vni),
        (
            "ip link set dev vxlan{0} up type bridge_slave "
            "learning off flood off mcast_flood off"
        ).format(vni),
    ]
    for command in commands:
        logger.info("%s: %s", router.name, command)
        router.cmd_raises(command)


def setup_module(mod):
    "Create router VRFs and L3VNIs, load configs, and start the topology."

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(
            'EVPN type-5 VRF-leak test requires kernel >= 4.18, found "{}"'.format(krel)
        )

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    vrfs_by_router = {
        "r1": (("GREEN", 101, 101, "192.168.100.1"),),
        "r2": (
            ("GREEN", 101, 101, "192.168.100.2"),
            ("BLUE", 102, 102, "192.168.100.2"),
            ("PURPLE", 103, 103, "192.168.100.2"),
        ),
        "r3": (
            ("GREEN", 101, 101, "192.168.100.3"),
            ("BLUE", 102, 102, "192.168.100.3"),
            ("PURPLE", 103, 103, "192.168.100.3"),
        ),
    }
    for rname, vrfs in vrfs_by_router.items():
        result = create_vrf_cfg(
            tgen,
            None,
            {
                rname: {
                    "vrfs": [{"name": vrf, "id": table} for vrf, table, _, _ in vrfs]
                }
            },
        )
        assert result is True, result
        router = tgen.gears[rname]
        for vrf, _, vni, local_vtep in vrfs:
            _configure_l3vni_interfaces(router, rname, vrf, vni, local_vtep)

    for rname in ("r1", "r2", "r3"):
        router = tgen.gears[rname]
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    "Stop the topotest topology."

    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_route_present(router, vrf, prefix):
    "Return whether the VRF has a valid, non-removed path for the IPv4 prefix."
    output = json.loads(
        router.vtysh_cmd("show bgp vrf {0} ipv4 unicast {1} json".format(vrf, prefix))
        or "{}"
    )

    for path in output.get("paths", []):
        if path.get("valid") is not False and not path.get("removed", False):
            return True

    return False


def _bgp_valid_path_count(router, vrf, prefix):
    "Count valid, non-removed paths for an IPv4 prefix in a VRF."
    output = json.loads(
        router.vtysh_cmd("show bgp vrf {0} ipv4 unicast {1} json".format(vrf, prefix))
        or "{}"
    )
    return sum(
        path.get("valid") is not False and not path.get("removed", False)
        for path in output.get("paths", [])
    )


def _wait_bgp_valid_path_count_at_least(
    router, vrf, prefix, expected, count=60, wait=1
):
    "Wait until a VRF has at least the requested number of valid BGP paths."

    def _check_count():
        return _bgp_valid_path_count(router, vrf, prefix) >= expected

    _, result = topotest.run_and_expect(_check_count, True, count=count, wait=wait)
    assert result, "{0} {1} route {2} did not reach {3} valid paths\n{4}".format(
        router.name,
        vrf,
        prefix,
        expected,
        router.vtysh_cmd("show bgp vrf {0} ipv4 unicast {1}".format(vrf, prefix)),
    )


def _wait_bgp_route(router, vrf, prefix, expected, count=60, wait=1):
    "Wait for an IPv4 route to become present or absent in a VRF."

    def _check_route():
        return _bgp_route_present(router, vrf, prefix)

    _, result = topotest.run_and_expect(_check_route, expected, count=count, wait=wait)
    assert (
        result == expected
    ), "{0} {1} route {2} expected={3} last_seen={4}\n{5}".format(
        router.name,
        vrf,
        prefix,
        expected,
        result,
        router.vtysh_cmd("show bgp vrf {0} ipv4 unicast {1}".format(vrf, prefix)),
    )


def _configure_static_route(router, vrf, prefix, present):
    "Add or remove a Null0 static route through the shared route API."
    result = create_static_routes(
        get_topogen(),
        {
            router.name: {
                "static_routes": [
                    {
                        "network": prefix,
                        "interface": "Null0",
                        "vrf": vrf,
                        "delete": not present,
                    }
                ]
            }
        },
    )
    assert result is True, result


def _reload_frr_config(router, config_path):
    "Apply an FRR config file with frr-reload and report command failures."
    command = "/usr/lib/frr/frr-reload.py --reload {0}".format(config_path)
    result, output, error = router.net.cmd_status(command, warn=False)
    assert (
        result == 0
    ), "{0}: frr-reload failed for {1} (rc={2})\nstdout:\n{3}\nstderr:\n{4}".format(
        router.name, config_path, result, output, error
    )


def _configure_skip_evpn_imported(router, vrf, enabled):
    "Enable or disable IPv4 skip-evpn-imported in a VRF EVPN address family."
    command = "advertise ipv4 unicast skip-evpn-imported"
    if not enabled:
        command = "no {0}".format(command)

    output = router.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf {0}\n"
        "address-family l2vpn evpn\n"
        "{1}\n"
        "end\n".format(vrf, command)
    )
    assert "% Unknown" not in output and "% Invalid" not in output, output


def _configure_vrf_import(router, destination_vrf, source_vrf, present):
    "Add or remove an IPv4 unicast VRF import with the shared BGP API."
    import_vrf = {"vrf": source_vrf}
    if not present:
        import_vrf["delete"] = True

    result = create_router_bgp(
        get_topogen(),
        topo={"routers": {router.name: {}}},
        input_dict={
            router.name: {
                "bgp": [
                    {
                        "local_as": 65000,
                        "vrf": destination_vrf,
                        "address_family": {"ipv4": {"unicast": {"import": import_vrf}}},
                    }
                ]
            }
        },
    )
    assert result is True, result


def _configure_ipv6_skip_evpn_imported(router, vrf, enabled):
    "Enable or disable IPv6 skip-evpn-imported in a VRF EVPN address family."
    command = "advertise ipv6 unicast skip-evpn-imported"
    if not enabled:
        command = "no {0}".format(command)
    output = router.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf {0}\n"
        "address-family l2vpn evpn\n"
        "{1}\n"
        "end\n".format(vrf, command)
    )
    assert "% Unknown" not in output and "% Invalid" not in output, output


def _vrf_bgp_config(router, vrf):
    "Return the running BGP config section for one VRF."
    running_config = router.vtysh_cmd("show running-config bgpd")
    marker = "router bgp 65000 vrf {0}".format(vrf)
    assert marker in running_config, running_config
    config = running_config.split(marker, 1)[1]
    return config.split("\n!", 1)[0]


def _wait_evpn_type5_prefix_count(router, prefix, expected, count=60, wait=1):
    "Wait until the EVPN table has exactly the expected Type-5 path count."

    def _check_count():
        return evpn_type5_prefix_count(router, prefix)

    _, result = topotest.run_and_expect(_check_count, expected, count=count, wait=wait)
    assert (
        result == expected
    ), "{0} EVPN type-5 {1} count expected={2} last_seen={3}\n{4}".format(
        router.name,
        prefix,
        expected,
        result,
        router.vtysh_cmd("show bgp l2vpn evpn route type 5"),
    )


def _wait_evpn_type5_prefix_count_at_least(router, prefix, expected, count=60, wait=1):
    "Wait until the EVPN table has at least the expected Type-5 path count."

    def _check_count():
        return evpn_type5_prefix_count(router, prefix) >= expected

    _, result = topotest.run_and_expect(_check_count, True, count=count, wait=wait)
    assert (
        result is True
    ), "{0} EVPN type-5 {1} count expected at least {2}\n{3}".format(
        router.name,
        prefix,
        expected,
        router.vtysh_cmd("show bgp l2vpn evpn route type 5"),
    )


def _evpn_route_refresh_sent(router, peers):
    "Return the per-peer count of EVPN Route-Refresh messages sent."
    counts = {}
    for peer in peers:
        output = json.loads(
            router.vtysh_cmd("show bgp l2vpn evpn neighbor {0} json".format(peer))
            or "{}"
        )
        stats = output.get(peer, {}).get("messageStats", {})
        counts[peer] = stats.get("routeRefreshSent", 0)
    return counts


def _wait_evpn_route_refresh_sent(router, peers, before, count=60, wait=1):
    "Wait until a new Route-Refresh has been sent to each EVPN peer."

    def _refreshed():
        current = _evpn_route_refresh_sent(router, peers)
        return all(current[peer] > before[peer] for peer in peers)

    _, result = topotest.run_and_expect(_refreshed, True, count=count, wait=wait)
    assert (
        result is True
    ), "{0}: no EVPN Route-Refresh sent to {1}; before={2} after={3}".format(
        router.name,
        list(peers),
        before,
        _evpn_route_refresh_sent(router, peers),
    )


def _evpn_l3vni_rd(router, vni):
    "Return the Type-5 route distinguisher heading a VRF advertises under."
    output = json.loads(
        router.vtysh_cmd("show bgp l2vpn evpn vni {0} json".format(vni)) or "{}"
    )
    rd = output.get("rd")
    assert rd, "{0}: no RD reported for VNI {1}\n{2}".format(router.name, vni, output)
    return "Route Distinguisher: {0}".format(rd)


def _wait_evpn_type5_rds(router, prefix, present=(), absent=(), count=60, wait=1):
    "Wait until a prefix's Type-5 RDs include every present and no absent RD."
    seen = set()

    def _check_rds():
        seen.clear()
        seen.update(evpn_type5_route_distinguishers(router, prefix))
        return set(present) <= seen and not set(absent) & seen

    _, result = topotest.run_and_expect(_check_rds, True, count=count, wait=wait)
    assert (
        result is True
    ), "{0} {1}: expected RDs {2} present and {3} absent, actual={4}\n{5}".format(
        router.name,
        prefix,
        sorted(present),
        sorted(absent),
        sorted(seen),
        router.vtysh_cmd("show bgp l2vpn evpn route type 5"),
    )
    return set(seen)


def _dump_route_state(label, prefix, routers):
    "Log BGP VRF routes and EVPN Type-5 routes for the requested prefix."
    logger.info("=== %s: %s ===", label, prefix)

    for router, vrfs in routers:
        for vrf in vrfs:
            logger.info(
                "%s %s BGP %s:\n%s",
                router.name,
                vrf,
                prefix,
                router.vtysh_cmd(
                    "show bgp vrf {0} ipv4 unicast {1}".format(vrf, prefix)
                ),
            )
        logger.info(
            "%s EVPN type-5:\n%s",
            router.name,
            router.vtysh_cmd("show bgp l2vpn evpn route type 5"),
        )


def test_normal_vrf_leak_exports_with_suppress_imported_from_evpn():
    "Verify normal VRF-leaked routes still export while EVPN imports stay suppressed."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        logger.info("Inject a normal static route in r2 BLUE")
        _configure_static_route(r2, "BLUE", NORMAL_LEAK_PREFIX, True)

        logger.info("Verify r2 leaks the normal route from BLUE into GREEN")
        _wait_bgp_route(r2, "GREEN", NORMAL_LEAK_PREFIX, True)

        logger.info("Verify the leaked GREEN route is still exported as EVPN type-5")
        try:
            _wait_bgp_route(r1, "GREEN", NORMAL_LEAK_PREFIX, True)
        except AssertionError:
            _dump_route_state(
                "normal VRF-leaked route before withdraw failure",
                NORMAL_LEAK_PREFIX,
                ((r1, ("GREEN",)), (r2, PE_VRFS)),
            )
            raise

        logger.info("Dump normal VRF-leaked route before withdraw")
        _dump_route_state(
            "normal VRF-leaked route before withdraw",
            NORMAL_LEAK_PREFIX,
            ((r1, ("GREEN",)), (r2, PE_VRFS)),
        )
    finally:
        _configure_static_route(r2, "BLUE", NORMAL_LEAK_PREFIX, False)

    logger.info("Verify the normal leaked route is withdrawn cleanly")
    try:
        _wait_bgp_route(r1, "GREEN", NORMAL_LEAK_PREFIX, False)
        _wait_bgp_route(r2, "GREEN", NORMAL_LEAK_PREFIX, False)
    except AssertionError:
        _dump_route_state(
            "normal VRF-leaked route after withdraw failure",
            NORMAL_LEAK_PREFIX,
            ((r1, ("GREEN",)), (r2, PE_VRFS)),
        )
        raise

    logger.info("Dump normal VRF-leaked route after withdraw")
    _dump_route_state(
        "normal VRF-leaked route after withdraw",
        NORMAL_LEAK_PREFIX,
        ((r1, ("GREEN",)), (r2, PE_VRFS)),
    )


def test_direct_evpn_import_is_not_reexported_without_skip():
    "Verify the pre-existing direct EVPN-import suppression remains intact."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    try:
        logger.info("Disable skip-evpn-imported only in GREEN on both PEs")
        for router in (r2, r3):
            _configure_skip_evpn_imported(router, "GREEN", False)

        logger.info("Inject a new Type-5 origin in r1 GREEN")
        _configure_static_route(r1, "GREEN", DIRECT_IMPORT_PREFIX, True)

        logger.info("Verify both PEs directly import the r1 Type-5 route into GREEN")
        _wait_bgp_route(r2, "GREEN", DIRECT_IMPORT_PREFIX, True)
        _wait_bgp_route(r3, "GREEN", DIRECT_IMPORT_PREFIX, True)

        logger.info("Verify direct imports are not re-exported without the new option")
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, DIRECT_IMPORT_PREFIX, 1)
    finally:
        _configure_static_route(r1, "GREEN", DIRECT_IMPORT_PREFIX, False)
        for router in (r2, r3):
            _configure_skip_evpn_imported(router, "GREEN", True)


def test_skip_evpn_imported_survives_bgpd_restart():
    """Verify skip state and export suppression survive a bgpd restart."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    try:
        logger.info("Inject a route that is subject to skip-evpn-imported")
        _configure_static_route(r1, "GREEN", RESTART_PREFIX, True)

        logger.info("Verify the route is leaked into all tenant VRFs")
        _wait_bgp_route(r2, "GREEN", RESTART_PREFIX, True)
        _wait_bgp_route(r2, "BLUE", RESTART_PREFIX, True)
        _wait_bgp_route(r2, "PURPLE", RESTART_PREFIX, True)
        _wait_bgp_route(r3, "GREEN", RESTART_PREFIX, True)

        logger.info("Verify skip suppresses EVPN-derived re-export before restart")
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, RESTART_PREFIX, 1)

        logger.info("Restart bgpd on one PE")
        kill_router_daemons(tgen, "r2", ["bgpd"])
        start_result = start_router_daemons(tgen, "r2", ["bgpd"])
        assert not start_result, "r2 bgpd failed to start after restart:\n{0}".format(
            start_result
        )

        _reload_frr_config(r2, "/etc/frr/frr.conf")
        result = verify_bgp_convergence_from_running_config(tgen, dut="r2")
        assert result is True, "r2 BGP did not reconverge: {0}".format(result)

        logger.info("Verify leaked routes recover after bgpd restart")
        _wait_bgp_route(r2, "GREEN", RESTART_PREFIX, True)
        _wait_bgp_route(r2, "BLUE", RESTART_PREFIX, True)
        _wait_bgp_route(r2, "PURPLE", RESTART_PREFIX, True)

        logger.info("Verify skip remains enabled and re-export remains suppressed")
        running_config = r2.vtysh_cmd("show running-config bgpd")
        assert running_config.count("advertise ipv4 unicast skip-evpn-imported") == len(
            PE_VRFS
        ), (
            "r2: expected {0} IPv4 skip-evpn-imported configuration lines, "
            "actual={1}\n{2}".format(
                len(PE_VRFS),
                running_config.count("advertise ipv4 unicast skip-evpn-imported"),
                running_config,
            )
        )
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, RESTART_PREFIX, 1)
    finally:
        _configure_static_route(r1, "GREEN", RESTART_PREFIX, False)


def test_skip_evpn_imported_survives_bgp_session_clear():
    """Verify suppression and route state recover after a BGP session clear."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    try:
        logger.info("Originate an EVPN-derived route with suppression enabled")
        _configure_static_route(r1, "GREEN", SESSION_CLEAR_PREFIX, True)
        for router in (r2, r3):
            for vrf in ("GREEN", "BLUE", "PURPLE"):
                _wait_bgp_route(router, vrf, SESSION_CLEAR_PREFIX, True)
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, SESSION_CLEAR_PREFIX, 1)

        logger.info("Clear all BGP sessions on one PE")
        output = r2.vtysh_cmd("clear bgp *")
        assert "% Unknown" not in output and "% Invalid" not in output, output

        logger.info("Reload r2's existing unified configuration")
        _reload_frr_config(r2, "/etc/frr/frr.conf")
        result = verify_bgp_convergence_from_running_config(tgen, dut="r2")
        assert result is True, "r2 BGP did not reconverge: {0}".format(result)

        logger.info("Verify BGP routes reconverge after the session clear")
        for router in (r2, r3):
            for vrf in ("GREEN", "BLUE", "PURPLE"):
                _wait_bgp_route(router, vrf, SESSION_CLEAR_PREFIX, True)

        logger.info("Verify skip remains configured and no re-export is created")
        for vrf in ("GREEN", "BLUE", "PURPLE"):
            vrf_config = _vrf_bgp_config(r2, vrf)
            assert (
                "advertise ipv4 unicast skip-evpn-imported" in vrf_config
            ), "r2 {0}: expected IPv4 skip-evpn-imported enabled\n{1}".format(
                vrf, vrf_config
            )
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, SESSION_CLEAR_PREFIX, 1)
    finally:
        _configure_static_route(r1, "GREEN", SESSION_CLEAR_PREFIX, False)
        for router in (r2, r3):
            for vrf in ("GREEN", "BLUE", "PURPLE"):
                _configure_skip_evpn_imported(router, vrf, True)


def test_skip_evpn_imported_ipv6_is_independent_from_ipv4():
    """Verify IPv6 skip state does not change IPv4 skip state."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe_routers = (tgen.gears["r2"], tgen.gears["r3"])
    try:
        logger.info("Enable IPv6 skip-evpn-imported on BLUE")
        for router in pe_routers:
            _configure_ipv6_skip_evpn_imported(router, "BLUE", True)
            blue_config = _vrf_bgp_config(router, "BLUE")
            assert (
                "advertise ipv4 unicast skip-evpn-imported" in blue_config
            ), "{0} BLUE: expected IPV4 skip-evpn-imported enabled\n{1}".format(
                router.name, blue_config
            )
            assert (
                "advertise ipv6 unicast skip-evpn-imported" in blue_config
            ), "{0} BLUE: expected IPV6 skip-evpn-imported enabled\n{1}".format(
                router.name, blue_config
            )

        logger.info("Disable only IPv6 skip-evpn-imported")
        for router in pe_routers:
            _configure_ipv6_skip_evpn_imported(router, "BLUE", False)
            blue_config = _vrf_bgp_config(router, "BLUE")
            assert (
                "advertise ipv4 unicast skip-evpn-imported" in blue_config
            ), "{0} BLUE: expected IPV4 skip-evpn-imported enabled\n{1}".format(
                router.name, blue_config
            )
            assert (
                "advertise ipv6 unicast skip-evpn-imported" not in blue_config
            ), "{0} BLUE: expected IPV6 skip-evpn-imported disabled\n{1}".format(
                router.name, blue_config
            )

    finally:
        for router in pe_routers:
            _configure_ipv6_skip_evpn_imported(router, "BLUE", False)


def test_skip_evpn_imported_preserves_local_type5_export():
    """Verify skip does not change existing L3VNI control or route behavior."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    try:
        logger.info("Verify skip is rendered under the BLUE VRF EVPN AF")
        blue_config = _vrf_bgp_config(r2, "BLUE")
        assert (
            "advertise ipv4 unicast skip-evpn-imported" in blue_config
        ), "{0} BLUE: expected IPV4 skip-evpn-imported enabled\n{1}".format(
            r2.name, blue_config
        )

        logger.info("Verify BGP control-plane state is available before the route test")
        for router in (r1, r2, r3):
            summary = router.vtysh_cmd("show bgp summary")
            assert "% Unknown" not in summary and "% Invalid" not in summary, summary

            evpn_summary = json.loads(
                router.vtysh_cmd("show bgp l2vpn evpn summary json") or "{}"
            )
            # EVPN summary JSON exposes established peers through the
            # displayed-peer count; individual peer objects do not carry the
            # text-summary state field in all supported FRR versions.
            assert (
                evpn_summary.get("displayedPeers", 0) > 0
            ), "{0}: expected EVPN displayedPeers > 0, actual={1}\n{2}".format(
                router.name, evpn_summary.get("displayedPeers", 0), evpn_summary
            )

        for router in (r2, r3):
            vni_output = router.vtysh_cmd("show evpn vni 102")
            assert (
                "Type: L3" in vni_output and "BLUE" in vni_output
            ), "{0}: expected VNI 102 type L3 in BLUE\n{1}".format(
                router.name, vni_output
            )

        logger.info("Add a locally originated route in the BLUE L3VNI")
        _configure_static_route(r2, "BLUE", L3VNI_PREFIX, True)
        _wait_bgp_route(r2, "BLUE", L3VNI_PREFIX, True)

        logger.info("Verify the representative BLUE route is installed in Zebra RIB")
        expected_zebra_route = {
            L3VNI_PREFIX: [
                {
                    "protocol": "static",
                    "vrfName": "BLUE",
                    "selected": True,
                    "installed": True,
                }
            ]
        }
        _, result = topotest.run_and_expect(
            lambda: evpn_verify_vrf_rib_route(
                r2, "BLUE", L3VNI_PREFIX, expected_zebra_route
            ),
            None,
            count=30,
            wait=1,
        )
        assert result is None, "r2 BLUE {0}: expected route in Zebra RIB: {1}".format(
            L3VNI_PREFIX, result
        )

        logger.info("Verify the representative BLUE route is installed in kernel FIB")
        expected_kernel_route = [{"dst": L3VNI_PREFIX}]
        _, result = topotest.run_and_expect(
            lambda: iproute2_check_path_selection(
                r2,
                L3VNI_PREFIX,
                expected_kernel_route,
                vrf_name="BLUE",
            ),
            None,
            count=30,
            wait=1,
        )
        assert result is None, "r2 BLUE {0}: expected route in kernel FIB: {1}".format(
            L3VNI_PREFIX, result
        )

        logger.info("Verify a local L3VNI route remains exported with skip enabled")
        for router in (r1, r2, r3):
            # The local route can be exported through more than one valid
            # RD after local VRF leaking. Only require that export remains.
            _wait_evpn_type5_prefix_count_at_least(router, L3VNI_PREFIX, 1)
    finally:
        _configure_static_route(r2, "BLUE", L3VNI_PREFIX, False)


def test_skip_evpn_imported_scale_and_repeated_toggle():
    """Verify 1,000 Type-5 routes across two skip enable/disable cycles."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    prefixes = [
        "198.18.{0}.{1}/32".format(index // 256, index % 256)
        for index in range(1, 1001)
    ]
    prefix_addresses = [prefix.split("/", 1)[0] for prefix in prefixes]
    scale_deadline = time.monotonic() + 30 * 60

    def wait_for_counts(router, minimum, phase, exact=False):
        remaining = scale_deadline - time.monotonic()
        context = "{0}: {1}, expected {2} Type-5 copies per prefix ({3})".format(
            router.name, phase, minimum, "exact" if exact else "at least"
        )
        assert remaining > 0, "{0}: scale convergence budget expired".format(context)
        mismatches = {}

        def _check_counts():
            nonlocal mismatches
            output = router.vtysh_cmd("show bgp l2vpn evpn route type 5")
            counts = {}
            for address in re.findall(r"\[5\]:\[0\]:\[32\]:\[([^]]+)\]", output):
                counts[address] = counts.get(address, 0) + 1
            mismatches = {
                address: counts.get(address, 0)
                for address in prefix_addresses
                if (
                    counts.get(address, 0) != minimum
                    if exact
                    else counts.get(address, 0) < minimum
                )
            }
            return not mismatches

        retry_count = max(1, min(180, int(remaining // 2)))
        _, result = topotest.run_and_expect(
            _check_counts, True, count=retry_count, wait=2
        )
        assert (
            result
        ), "{0}: {1}/{2} prefixes mismatched; first 20 actual counts: {3}".format(
            context,
            len(mismatches),
            len(prefix_addresses),
            list(mismatches.items())[:20],
        )

    try:
        logger.info("Inject 1,000 Type-5 origins in r1 GREEN")
        result = create_static_routes(
            tgen,
            {
                r1.name: {
                    "static_routes": [
                        {
                            "network": prefixes,
                            "interface": "Null0",
                            "vrf": "GREEN",
                        }
                    ]
                }
            },
        )
        assert result is True, result

        logger.info("Verify all 1,000 prefixes are initially exported once")
        for router in (r1, r2, r3):
            wait_for_counts(router, 1, "initial advertisement", exact=True)

        for cycle in range(2):
            logger.info("Disable skip for scale cycle {0}".format(cycle + 1))
            for router in (r2, r3):
                _configure_skip_evpn_imported(router, "BLUE", False)
            wait_for_counts(r1, 2, "cycle {0}, skip disabled".format(cycle + 1))

            logger.info("Re-enable skip for scale cycle {0}".format(cycle + 1))
            for router in (r2, r3):
                _configure_skip_evpn_imported(router, "BLUE", True)
            wait_for_counts(
                r1, 1, "cycle {0}, skip enabled".format(cycle + 1), exact=True
            )
    finally:
        result = create_static_routes(
            tgen,
            {
                r1.name: {
                    "static_routes": [
                        {
                            "network": prefixes,
                            "interface": "Null0",
                            "vrf": "GREEN",
                            "delete": True,
                        }
                    ]
                }
            },
        )
        assert result is True, result
        for router in (r2, r3):
            _configure_skip_evpn_imported(router, "BLUE", True)


def test_skip_evpn_imported_survives_route_refresh():
    """Verify a BGP route refresh does not re-export a suppressed path."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    prefix = "192.168.94.1/32"

    try:
        logger.info("Establish an EVPN-originated leaked route with skip enabled")
        _configure_static_route(r1, "GREEN", prefix, True)
        for router, vrf in (
            (r2, "GREEN"),
            (r2, "BLUE"),
            (r3, "GREEN"),
            (r3, "BLUE"),
        ):
            _wait_bgp_route(router, vrf, prefix, True)
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, prefix, 1)

        logger.info("Reload r2's existing unified configuration before refresh")
        _reload_frr_config(r2, "/etc/frr/frr.conf")
        result = verify_bgp_convergence_from_running_config(tgen, dut="r2")
        assert result is True, "r2 BGP did not reconverge: {0}".format(result)

        # The tenant VRF instances have no neighbors of their own: the leaked
        # route arrives over the fabric sessions in the default EVPN instance,
        # so the refresh has to target those peers to reach the Type-5 path.
        logger.info("Trigger a soft inbound EVPN refresh on the fabric peers")
        for router in (r2, r3):
            peers = FABRIC_PEERS[router.name]
            before = _evpn_route_refresh_sent(router, peers)
            for peer in peers:
                output = router.vtysh_cmd(
                    "clear bgp l2vpn evpn {0} soft in".format(peer)
                )
                assert "% Unknown" not in output and "% Invalid" not in output, output
            _wait_evpn_route_refresh_sent(router, peers, before)

        logger.info("Verify refreshed routes remain installed in tenant VRFs")
        for router, vrf in (
            (r2, "GREEN"),
            (r2, "BLUE"),
            (r2, "PURPLE"),
            (r3, "GREEN"),
            (r3, "BLUE"),
            (r3, "PURPLE"),
        ):
            _wait_bgp_route(router, vrf, prefix, True)

        logger.info("Verify refresh did not create a local Type-5 re-export")
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, prefix, 1)
    finally:
        _configure_static_route(r1, "GREEN", prefix, False)
        for router in (r2, r3):
            _configure_skip_evpn_imported(router, "BLUE", True)


def test_skip_evpn_imported_preserves_default_route_export():
    """Verify a locally originated default remains eligible for Type-5 export."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    default_prefix = "0.0.0.0/0"

    try:
        logger.info("Install a local default route in r2 BLUE")
        _configure_static_route(r2, "BLUE", default_prefix, True)
        _wait_bgp_route(r2, "BLUE", default_prefix, True)

        logger.info("Verify skip does not suppress the locally originated default")
        expected = "[5]:[0]:[0]:[0.0.0.0]"
        for router in (tgen.gears["r1"], r2, tgen.gears["r3"]):

            def _default_exported(router=router):
                return expected in router.vtysh_cmd("show bgp l2vpn evpn route type 5")

            _, result = topotest.run_and_expect(
                _default_exported, True, count=60, wait=1
            )
            assert (
                result
            ), "{0} {1}: expected default Type-5 export present, actual absent\n{2}".format(
                router.name,
                default_prefix,
                router.vtysh_cmd("show bgp l2vpn evpn route type 5"),
            )
    finally:
        _configure_static_route(r2, "BLUE", default_prefix, False)


def test_skip_evpn_imported_prefix_move_between_vrfs():
    """Verify a moved prefix converges without retaining the old Type-5."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    prefix = "192.168.96.1/32"

    try:
        logger.info("Originate P in the initial PE r1 GREEN")
        _configure_static_route(r1, "GREEN", prefix, True)
        _wait_bgp_route(r2, "BLUE", prefix, True)
        _wait_bgp_route(r2, "PURPLE", prefix, True)
        old_rds = evpn_type5_route_distinguishers(r1, prefix)
        assert old_rds, r1.vtysh_cmd("show bgp l2vpn evpn route type 5")

        logger.info("Withdraw P from the old origin and verify old state is removed")
        _configure_static_route(r1, "GREEN", prefix, False)
        for router in (r1, r2, tgen.gears["r3"]):
            _wait_evpn_type5_prefix_count(router, prefix, 0)
        for router, vrf in (
            (r1, "GREEN"),
            (r2, "GREEN"),
            (r2, "BLUE"),
            (r2, "PURPLE"),
            (tgen.gears["r3"], "GREEN"),
            (tgen.gears["r3"], "BLUE"),
            (tgen.gears["r3"], "PURPLE"),
        ):
            _wait_bgp_route(router, vrf, prefix, False)

        logger.info("Originate P from the new PE r2 BLUE")
        _configure_static_route(r2, "BLUE", prefix, True)
        _wait_bgp_route(r2, "BLUE", prefix, True)
        _wait_evpn_type5_prefix_count_at_least(r2, prefix, 1)
        new_rds = evpn_type5_route_distinguishers(r2, prefix)
        assert new_rds, r2.vtysh_cmd("show bgp l2vpn evpn route type 5")

        logger.info("Verify VRF leaking converges to the new origin")
        for router, vrf in (
            (r2, "GREEN"),
            (r2, "PURPLE"),
            (tgen.gears["r3"], "GREEN"),
            (tgen.gears["r3"], "BLUE"),
            (tgen.gears["r3"], "PURPLE"),
            (r1, "GREEN"),
        ):
            _wait_bgp_route(router, vrf, prefix, True)

        logger.info("Verify the new Type-5 is present without the old origin")
        for router in (r1, r2, tgen.gears["r3"]):
            _wait_evpn_type5_prefix_count_at_least(router, prefix, 1)
            current_rds = evpn_type5_route_distinguishers(router, prefix)
            assert not set(old_rds).intersection(
                current_rds
            ), "{0} retained old Type-5 origin {1}: {2}".format(
                router.name, old_rds, current_rds
            )
    finally:
        _configure_static_route(r1, "GREEN", prefix, False)
        _configure_static_route(r2, "BLUE", prefix, False)


def test_skip_evpn_imported_coexists_with_route_map():
    """Verify route-map filtering and skip options can be changed independently."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    route_map = "evpn_skip_test_map"
    prefix_list = "evpn_skip_test_prefixes"
    allowed_prefix = "192.168.97.1/32"
    denied_prefix = "192.168.97.2/32"

    def configure_route_map(enabled):
        commands = ["configure terminal"]
        if enabled:
            commands.extend(
                [
                    "ip prefix-list {0} seq 10 permit {1}".format(
                        prefix_list, allowed_prefix
                    ),
                    "route-map {0} permit 10".format(route_map),
                    "match ip address prefix-list {0}".format(prefix_list),
                    "exit",
                ]
            )

        for vrf in PE_VRFS:
            if enabled:
                advertise = (
                    "advertise ipv4 unicast route-map {0} skip-evpn-imported".format(
                        route_map
                    )
                )
            else:
                advertise = "no advertise ipv4 unicast route-map {0}".format(route_map)
            commands.extend(
                [
                    "router bgp 65000 vrf {0}".format(vrf),
                    "address-family l2vpn evpn",
                    advertise,
                    "exit-address-family",
                    "exit",
                ]
            )

        if not enabled:
            commands.extend(
                [
                    "no route-map {0}".format(route_map),
                    "no ip prefix-list {0}".format(prefix_list),
                ]
            )
        commands.append("end")
        output = r2.vtysh_cmd("\n".join(commands))
        assert "% Unknown" not in output and "% Invalid" not in output, output

    try:
        logger.info("Inject an EVPN-derived route and local route-map test routes")
        _configure_static_route(r1, "GREEN", TOGGLE_PREFIX, True)
        _configure_static_route(r2, "BLUE", allowed_prefix, True)
        _configure_static_route(r2, "BLUE", denied_prefix, True)
        _wait_bgp_route(r2, "BLUE", allowed_prefix, True)
        _wait_bgp_route(r2, "BLUE", denied_prefix, True)

        logger.info("Attach a route-map to all r2 tenant VRFs")
        configure_route_map(True)
        blue_config = _vrf_bgp_config(r2, "BLUE")
        assert (
            "advertise ipv4 unicast route-map {0} skip-evpn-imported".format(route_map)
            in blue_config
        ), "r2 BLUE: expected route-map {0} and skip-evpn-imported\n{1}".format(
            route_map, blue_config
        )

        logger.info("Verify route-map filtering and EVPN ancestry suppression")
        _wait_evpn_type5_prefix_count_at_least(r1, allowed_prefix, 1)
        _wait_evpn_type5_prefix_count(r1, denied_prefix, 0)
        _wait_evpn_type5_prefix_count(r1, TOGGLE_PREFIX, 1)

        logger.info("Remove the route-map while keeping skip enabled")
        configure_route_map(False)
        blue_config = _vrf_bgp_config(r2, "BLUE")
        assert (
            "advertise ipv4 unicast skip-evpn-imported" in blue_config
        ), "{0} BLUE: expected IPV4 skip-evpn-imported enabled\n{1}".format(
            r2.name, blue_config
        )
        assert (
            "route-map {0}".format(route_map) not in blue_config
        ), "r2 BLUE: expected route-map {0} removed\n{1}".format(route_map, blue_config)
        _wait_evpn_type5_prefix_count_at_least(r1, denied_prefix, 1)

        logger.info("Reattach the route-map and remove only skip from BLUE")
        configure_route_map(True)
        _configure_skip_evpn_imported(r2, "BLUE", False)
        blue_config = _vrf_bgp_config(r2, "BLUE")
        assert (
            "advertise ipv4 unicast route-map {0}".format(route_map) in blue_config
        ), "r2 BLUE: expected IPv4 advertisement with route-map {0}\n{1}".format(
            route_map, blue_config
        )
        assert (
            "skip-evpn-imported" not in blue_config
        ), "{0} BLUE: expected skip-evpn-imported disabled\n{1}".format(
            r2.name, blue_config
        )
        _wait_evpn_type5_prefix_count(r1, denied_prefix, 0)
        _wait_evpn_type5_prefix_count(r1, TOGGLE_PREFIX, 1)

        logger.info("Remove the route-map and verify EVPN re-export resumes")
        configure_route_map(False)
        _wait_evpn_type5_prefix_count_at_least(r1, TOGGLE_PREFIX, 2)
    finally:
        _configure_static_route(r1, "GREEN", TOGGLE_PREFIX, False)
        _configure_static_route(r2, "BLUE", allowed_prefix, False)
        _configure_static_route(r2, "BLUE", denied_prefix, False)
        configure_route_map(False)
        for vrf in PE_VRFS:
            _configure_skip_evpn_imported(r2, vrf, True)


def test_no_skip_evpn_imported_reexports_and_reenabling_cleans_up():
    "Verify toggle transitions update configuration and Type-5 export eligibility."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    def check_running_config(enabled):
        marker = "advertise ipv4 unicast skip-evpn-imported"
        expected = len(PE_VRFS) if enabled else 0
        for router in pe_routers:
            running_config = router.vtysh_cmd("show running-config bgpd")
            actual = running_config.count(marker)
            assert actual == expected, (
                "{0} expected {1} skip-evpn-imported running-config lines, "
                "found {2}\n{3}".format(router.name, expected, actual, running_config)
            )
            for vrf in PE_VRFS:
                vrf_config = _vrf_bgp_config(router, vrf)
                assert vrf_config.count(marker) == int(
                    enabled
                ), "{0} {1}: unexpected skip-evpn-imported configuration\n{2}".format(
                    router.name, vrf, vrf_config
                )

    try:
        check_running_config(True)
        logger.info("Inject a Type-5 origin while skip-evpn-imported is enabled")
        _configure_static_route(r1, "GREEN", TOGGLE_PREFIX, True)

        logger.info("Verify the original Type-5 route is the only EVPN route")
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, TOGGLE_PREFIX, 1)

        logger.info("Remove skip-evpn-imported from all PE tenant VRFs")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, False)

        check_running_config(False)

        logger.info("Verify removing the option restores EVPN-origin re-export")
        _wait_evpn_type5_prefix_count_at_least(r1, TOGGLE_PREFIX, 2)

        logger.info("Re-enable skip-evpn-imported on all PE tenant VRFs")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)

        check_running_config(True)

        logger.info("Verify re-enabling the option withdraws re-exported copies")
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, TOGGLE_PREFIX, 1)
    finally:
        _configure_static_route(r1, "GREEN", TOGGLE_PREFIX, False)
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)


def test_skip_evpn_imported_withdrawal_is_vrf_scoped():
    """Withdraw one L3VNI copy without removing the other VRF copies."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Allow Type-5 exports for the shared-prefix baseline")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, False)

        # Identify the exact RDs each PE advertises the BLUE and PURPLE copies
        # under, so the remote checks below do not depend on a racy RD count.
        blue_rds = {_evpn_l3vni_rd(router, BLUE_L3VNI) for router in pe_routers}
        purple_rds = {_evpn_l3vni_rd(router, PURPLE_L3VNI) for router in pe_routers}

        logger.info("Originate one prefix and leak it into multiple L3VNIs")
        _configure_static_route(r1, "GREEN", SHARED_RD_PREFIX, True)
        for router in pe_routers:
            _wait_bgp_route(router, "GREEN", SHARED_RD_PREFIX, True)
            _wait_bgp_route(router, "BLUE", SHARED_RD_PREFIX, True)
            _wait_bgp_route(router, "PURPLE", SHARED_RD_PREFIX, True)

        # r1 receiving the exports is a convergence step of its own: the PEs
        # having installed the route locally does not mean r1 has them yet.
        before_rds = _wait_evpn_type5_rds(
            r1, SHARED_RD_PREFIX, present=blue_rds | purple_rds
        )

        logger.info("Remove all BLUE import paths for the shared prefix")
        for router in pe_routers:
            _configure_vrf_import(router, "BLUE", "GREEN", False)
            _configure_vrf_import(router, "BLUE", "PURPLE", False)

        logger.info("Verify withdrawal is scoped to BLUE's L3VNI")
        for router in pe_routers:
            _wait_bgp_route(router, "BLUE", SHARED_RD_PREFIX, False)
            _wait_bgp_route(router, "PURPLE", SHARED_RD_PREFIX, True)
        after_rds = _wait_evpn_type5_rds(
            r1, SHARED_RD_PREFIX, present=purple_rds, absent=blue_rds
        )
        logger.info(
            "r1 %s Type-5 RDs: before=%s after=%s",
            SHARED_RD_PREFIX,
            sorted(before_rds),
            sorted(after_rds),
        )
    finally:
        for router in pe_routers:
            _configure_vrf_import(router, "BLUE", "GREEN", True)
            _configure_vrf_import(router, "BLUE", "PURPLE", True)
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)
        _configure_static_route(r1, "GREEN", SHARED_RD_PREFIX, False)


def test_skip_evpn_imported_multiple_source_vrfs_to_purple():
    """Suppress EVPN-derived routes from multiple source VRFs in PURPLE."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Originate EVPN routes from separate GREEN and BLUE source VRFs")
        _configure_static_route(r1, "GREEN", MULTI_SOURCE_GREEN_PREFIX, True)
        _configure_static_route(r2, "BLUE", MULTI_SOURCE_BLUE_PREFIX, True)
        for router in pe_routers:
            _wait_bgp_route(router, "PURPLE", MULTI_SOURCE_GREEN_PREFIX, True)
            _wait_bgp_route(router, "PURPLE", MULTI_SOURCE_BLUE_PREFIX, True)

        logger.info("Verify local and local-leak Type-5 paths remain eligible")
        # Both origins are local to the fabric.  skip-evpn-imported must not
        # suppress the original paths or their legitimate local-VRF leaks.
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count_at_least(router, MULTI_SOURCE_GREEN_PREFIX, 1)
            _wait_evpn_type5_prefix_count_at_least(router, MULTI_SOURCE_BLUE_PREFIX, 3)
    finally:
        _configure_static_route(r1, "GREEN", MULTI_SOURCE_GREEN_PREFIX, False)
        _configure_static_route(r2, "BLUE", MULTI_SOURCE_BLUE_PREFIX, False)
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)


def test_skip_evpn_imported_suppresses_after_initial_vrf_import():
    """Suppress a route when a VRF import is added after route arrival."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Remove PURPLE imports from GREEN and BLUE before route arrival")
        for router in pe_routers:
            _configure_vrf_import(router, "PURPLE", "GREEN", False)
            _configure_vrf_import(router, "PURPLE", "BLUE", False)

        logger.info("Originate the route while PURPLE cannot import GREEN")
        _configure_static_route(r1, "GREEN", INITIAL_IMPORT_PREFIX, True)
        for router in pe_routers:
            _wait_bgp_route(router, "GREEN", INITIAL_IMPORT_PREFIX, True)
            _wait_bgp_route(router, "PURPLE", INITIAL_IMPORT_PREFIX, False)

        logger.info("Add the PURPLE import and verify first import is suppressed")
        for router in pe_routers:
            _configure_vrf_import(router, "PURPLE", "GREEN", True)
            _wait_bgp_route(router, "PURPLE", INITIAL_IMPORT_PREFIX, True)
        for router in (r1, r2, r3):
            _wait_evpn_type5_prefix_count(router, INITIAL_IMPORT_PREFIX, 1)
    finally:
        _configure_static_route(r1, "GREEN", INITIAL_IMPORT_PREFIX, False)
        for router in pe_routers:
            _configure_vrf_import(router, "PURPLE", "GREEN", True)
            _configure_vrf_import(router, "PURPLE", "BLUE", True)
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)


def test_skip_evpn_imported_selectively_withdraws_evpn_derived_paths():
    """Withdraw EVPN-derived Type-5 paths without removing local exports."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Temporarily allow all Type-5 exports for the baseline")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, False)

        logger.info("Create EVPN-derived and locally originated control routes")
        _configure_static_route(r1, "GREEN", SELECTIVE_EVPN_PREFIX, True)
        _configure_static_route(r2, "BLUE", SELECTIVE_LOCAL_PREFIX, True)
        _wait_bgp_route(r2, "BLUE", SELECTIVE_EVPN_PREFIX, True)
        _wait_bgp_route(r3, "BLUE", SELECTIVE_EVPN_PREFIX, True)
        _wait_evpn_type5_prefix_count_at_least(r1, SELECTIVE_EVPN_PREFIX, 2)
        _wait_evpn_type5_prefix_count_at_least(r1, SELECTIVE_LOCAL_PREFIX, 1)

        logger.info("Enable suppression on the tenant VRFs")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)

        logger.info("Verify only the EVPN-derived Type-5 copies are withdrawn")
        _wait_evpn_type5_prefix_count(r1, SELECTIVE_EVPN_PREFIX, 1)
        _wait_evpn_type5_prefix_count_at_least(r1, SELECTIVE_LOCAL_PREFIX, 1)
        _wait_bgp_route(r2, "BLUE", SELECTIVE_LOCAL_PREFIX, True)
    finally:
        _configure_static_route(r1, "GREEN", SELECTIVE_EVPN_PREFIX, False)
        _configure_static_route(r2, "BLUE", SELECTIVE_LOCAL_PREFIX, False)
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)


def test_skip_evpn_imported_cleans_up_after_vrf_import_removal():
    """Remove a VRF import and verify its stale Type-5 copy is withdrawn."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Allow BLUE Type-5 re-export for the cleanup baseline")
        for router in pe_routers:
            _configure_skip_evpn_imported(router, "BLUE", False)

        logger.info("Originate a route and leak it from GREEN into BLUE")
        _configure_static_route(r1, "GREEN", VRF_IMPORT_PREFIX, True)
        for router in pe_routers:
            _wait_bgp_route(router, "GREEN", VRF_IMPORT_PREFIX, True)
            _wait_bgp_route(router, "BLUE", VRF_IMPORT_PREFIX, True)
        _wait_evpn_type5_prefix_count_at_least(r1, VRF_IMPORT_PREFIX, 2)

        logger.info("Remove the GREEN import from BLUE on both PEs")
        for router in pe_routers:
            _configure_vrf_import(router, "BLUE", "GREEN", False)

        logger.info("Verify the leaked route and stale Type-5 copy are removed")
        for router in pe_routers:
            _wait_bgp_route(router, "BLUE", VRF_IMPORT_PREFIX, False)
        _wait_evpn_type5_prefix_count(r1, VRF_IMPORT_PREFIX, 1)
    finally:
        for router in pe_routers:
            _configure_vrf_import(router, "BLUE", "GREEN", True)
            _configure_skip_evpn_imported(router, "BLUE", True)
        _configure_static_route(r1, "GREEN", VRF_IMPORT_PREFIX, False)


def test_skip_evpn_imported_preserves_mixed_local_and_evpn_paths():
    """Keep a local path while withdrawing EVPN-derived paths for the prefix."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    pe_routers = (r2, r3)

    try:
        logger.info("Disable suppression to establish the mixed-path baseline")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, False)

        logger.info("Install the same prefix as an origin and a local BLUE route")
        _configure_static_route(r1, "GREEN", MIXED_PATH_PREFIX, True)
        _configure_static_route(r2, "BLUE", MIXED_PATH_PREFIX, True)
        _wait_bgp_valid_path_count_at_least(r2, "BLUE", MIXED_PATH_PREFIX, 2)
        _wait_evpn_type5_prefix_count_at_least(r1, MIXED_PATH_PREFIX, 2)
        before_rds = set(evpn_type5_route_distinguishers(r1, MIXED_PATH_PREFIX))
        assert (
            len(before_rds) >= 2
        ), "r1 {0}: expected at least 2 Type-5 RDs, actual={1}\n{2}".format(
            MIXED_PATH_PREFIX,
            before_rds,
            r1.vtysh_cmd("show bgp l2vpn evpn route type 5"),
        )

        # The RD r2 exports its local BLUE route under. Suppression must leave
        # this one advertised while the EVPN-derived copies are withdrawn.
        blue_rd = _evpn_l3vni_rd(r2, BLUE_L3VNI)
        assert (
            blue_rd in before_rds
        ), "r1 {0}: expected r2 BLUE export {1} in baseline {2}\n{3}".format(
            MIXED_PATH_PREFIX,
            blue_rd,
            sorted(before_rds),
            r1.vtysh_cmd("show bgp l2vpn evpn route type 5"),
        )

        logger.info("Suppress EVPN-derived paths while retaining the local path")
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)

        _wait_bgp_route(r2, "BLUE", MIXED_PATH_PREFIX, True)
        current_rds = set()

        def _type5_exports_reduced():
            nonlocal current_rds
            current_rds = set(evpn_type5_route_distinguishers(r1, MIXED_PATH_PREFIX))
            return current_rds < before_rds and blue_rd in current_rds

        topotest.run_and_expect(_type5_exports_reduced, True, count=60, wait=1)
        route_output = r2.vtysh_cmd(
            "show bgp vrf BLUE ipv4 unicast {0}".format(MIXED_PATH_PREFIX)
        )
        type5_output = r1.vtysh_cmd("show bgp l2vpn evpn route type 5")
        assert current_rds < before_rds, (
            "r1 {0}: expected Type-5 RDs to be a proper subset of baseline; "
            "before={1}, after={2}\n{3}".format(
                MIXED_PATH_PREFIX,
                sorted(before_rds),
                sorted(current_rds),
                type5_output,
            )
        )
        # Shrinking alone would also be satisfied by wrongly dropping r2's own
        # export, so require the RD carrying it to survive.
        assert (
            blue_rd in current_rds
        ), "r1 {0}: expected r2 BLUE export {1} to survive; after={2}\n{3}".format(
            MIXED_PATH_PREFIX,
            blue_rd,
            sorted(current_rds),
            type5_output,
        )
        assert (
            "weight 32768, valid" in route_output
        ), "r2 BLUE {0}: expected valid local path with weight 32768\n{1}".format(
            MIXED_PATH_PREFIX, route_output
        )
    finally:
        _configure_static_route(r1, "GREEN", MIXED_PATH_PREFIX, False)
        _configure_static_route(r2, "BLUE", MIXED_PATH_PREFIX, False)
        for router in pe_routers:
            for vrf in PE_VRFS:
                _configure_skip_evpn_imported(router, vrf, True)


def test_evpn_type5_vrf_leak_stale_after_origin_withdraw():
    """Verify three origin cycles leave no stale VRF or EVPN Type-5 routes."""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    try:
        for cycle in range(3):
            logger.info("Origin withdrawal/re-origination cycle {0}".format(cycle + 1))
            logger.info("Inject the static origin route in r1 GREEN")
            _configure_static_route(r1, "GREEN", PREFIX, True)

            try:
                logger.info("Verify both PEs import r1 EVPN-origin route into GREEN")
                _wait_bgp_route(r1, "GREEN", PREFIX, True)
                _wait_bgp_route(r2, "GREEN", PREFIX, True)
                _wait_bgp_route(r3, "GREEN", PREFIX, True)

                logger.info(
                    "Verify both PEs leak the EVPN-origin route into BLUE and PURPLE"
                )
                for router in (r2, r3):
                    _wait_bgp_route(router, "BLUE", PREFIX, True)
                    _wait_bgp_route(router, "PURPLE", PREFIX, True)
                for router in (r1, r2, r3):
                    _wait_evpn_type5_prefix_count(router, PREFIX, 1)
            except AssertionError:
                _dump_route_state(
                    "EVPN-origin route before withdraw failure",
                    PREFIX,
                    ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
                )
                raise

            if cycle == 0:
                logger.info("Reload r2's existing unified configuration")
                _reload_frr_config(r2, "/etc/frr/frr.conf")
                result = verify_bgp_convergence_from_running_config(tgen, dut="r2")
                assert result is True, "r2 BGP did not reconverge: {0}".format(result)
                for vrf in PE_VRFS:
                    _wait_bgp_route(r2, vrf, PREFIX, True)
                for router in (r1, r2, r3):
                    _wait_evpn_type5_prefix_count(router, PREFIX, 1)

            logger.info("Dump EVPN-origin route before withdraw")
            _dump_route_state(
                "EVPN-origin route before withdraw",
                PREFIX,
                ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
            )

            logger.info("Withdraw the origin prefix from r1 GREEN")
            _configure_static_route(r1, "GREEN", PREFIX, False)

            logger.info("Verify no stale leaked/re-exported copy remains on either PE")
            try:
                _wait_bgp_route(r1, "GREEN", PREFIX, False)
                for router in (r2, r3):
                    for vrf in PE_VRFS:
                        _wait_bgp_route(router, vrf, PREFIX, False)
                for router in (r1, r2, r3):
                    _wait_evpn_type5_prefix_count(router, PREFIX, 0)
            except AssertionError:
                _dump_route_state(
                    "EVPN-origin route after withdraw failure",
                    PREFIX,
                    ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
                )
                raise

            logger.info("Dump EVPN-origin route after withdraw")
            _dump_route_state(
                "EVPN-origin route after withdraw",
                PREFIX,
                ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
            )
    finally:
        _configure_static_route(r1, "GREEN", PREFIX, False)


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
