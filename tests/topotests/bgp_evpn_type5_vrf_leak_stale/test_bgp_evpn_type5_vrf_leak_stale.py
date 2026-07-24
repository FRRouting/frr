#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 NVIDIA Corporation.
#

"""
Reproducer for stale EVPN type-5 re-export after inter-VRF leaking.

Topology:

    r1 -----+
            |
    r2 -----+ s1
            |
    r3 -----+

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
The r2/r3 tenant VRFs enable suppress-imported-from-evpn, so fixed builds still
import and leak the original Type-5 route locally but do not re-export EVPN-origin
leaked paths back into EVPN.

The normal-leak test originates 192.168.60.1/32 in r2 BLUE and verifies the
route can still be leaked into r2 GREEN and exported to r1 GREEN as Type-5.
"""

import json
import os
import platform
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

PREFIX = "192.168.50.1/32"
NORMAL_LEAK_PREFIX = "192.168.60.1/32"
PE_VRFS = ("GREEN", "BLUE", "PURPLE")


def build_topo(tgen):
    "Build function"

    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    for router in ("r1", "r2", "r3"):
        switch.add_link(tgen.gears[router])


def _run_cmds(router, commands):
    for command in commands:
        logger.info("%s: %s", router.name, command)
        router.cmd_raises(command)


def _add_vrf_vni(router, rname, vrf, table, vni, local_vtep):
    _run_cmds(
        router,
        [
            "ip link add {0} type vrf table {1}".format(vrf, table),
            "ip link set dev {0} up".format(vrf),
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
        ],
    )


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.18") < 0:
        pytest.skip(
            'EVPN type-5 VRF-leak test requires kernel >= 4.18, found "{}"'.format(
                krel
            )
        )

    _add_vrf_vni(tgen.gears["r1"], "r1", "GREEN", 101, 101, "192.168.100.1")
    _add_vrf_vni(tgen.gears["r2"], "r2", "GREEN", 101, 101, "192.168.100.2")
    _add_vrf_vni(tgen.gears["r2"], "r2", "BLUE", 102, 102, "192.168.100.2")
    _add_vrf_vni(tgen.gears["r2"], "r2", "PURPLE", 103, 103, "192.168.100.2")
    _add_vrf_vni(tgen.gears["r3"], "r3", "GREEN", 101, 101, "192.168.100.3")
    _add_vrf_vni(tgen.gears["r3"], "r3", "BLUE", 102, 102, "192.168.100.3")
    _add_vrf_vni(tgen.gears["r3"], "r3", "PURPLE", 103, 103, "192.168.100.3")

    for rname in ("r1", "r2", "r3"):
        router = tgen.gears[rname]
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"

    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_route_present(router, vrf, prefix):
    output = json.loads(
        router.vtysh_cmd(
            "show bgp vrf {0} ipv4 unicast {1} json".format(vrf, prefix)
        )
        or "{}"
    )

    for path in output.get("paths", []):
        if path.get("valid") is not False:
            return True

    return False


def _wait_bgp_route(router, vrf, prefix, expected, count=60, wait=1):
    def _check_route():
        return _bgp_route_present(router, vrf, prefix)

    _, result = topotest.run_and_expect(
        _check_route, expected, count=count, wait=wait
    )
    assert result == expected, (
        "{0} {1} route {2} expected={3} last_seen={4}\n{5}".format(
            router.name,
            vrf,
            prefix,
            expected,
            result,
            router.vtysh_cmd(
                "show bgp vrf {0} ipv4 unicast {1}".format(vrf, prefix)
            ),
        )
    )


def _configure_static_route(router, vrf, prefix, present):
    command = "ip route {0} Null0".format(prefix)
    if not present:
        command = "no {0}".format(command)

    output = router.vtysh_cmd(
        "configure terminal\n"
        "vrf {0}\n"
        " {1}\n"
        "end\n".format(vrf, command)
    )
    assert "% Unknown" not in output and "% Invalid" not in output, output


def _configure_origin_route(present):
    _configure_static_route(get_topogen().gears["r1"], "GREEN", PREFIX, present)


def _configure_normal_leak_route(present):
    _configure_static_route(
        get_topogen().gears["r2"], "BLUE", NORMAL_LEAK_PREFIX, present
    )


def _withdraw_normal_leak_route():
    _configure_normal_leak_route(False)


def _add_normal_leak_route():
    _configure_normal_leak_route(True)


def _withdraw_origin_route():
    _configure_origin_route(False)


def _add_origin_route():
    _configure_origin_route(True)


def _dump_route_state(label, prefix, routers):
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


def _dump_prefix_state(label, routers):
    _dump_route_state(label, PREFIX, routers)


def test_normal_vrf_leak_exports_with_suppress_imported_from_evpn():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    try:
        step("Inject a normal static route in r2 BLUE")
        _add_normal_leak_route()

        step("Verify r2 leaks the normal route from BLUE into GREEN")
        _wait_bgp_route(r2, "GREEN", NORMAL_LEAK_PREFIX, True)

        step("Verify the leaked GREEN route is still exported as EVPN type-5")
        try:
            _wait_bgp_route(r1, "GREEN", NORMAL_LEAK_PREFIX, True)
        except AssertionError:
            _dump_route_state(
                "normal VRF-leaked route before withdraw failure",
                NORMAL_LEAK_PREFIX,
                ((r1, ("GREEN",)), (r2, PE_VRFS)),
            )
            raise

        step("Dump normal VRF-leaked route before withdraw")
        _dump_route_state(
            "normal VRF-leaked route before withdraw",
            NORMAL_LEAK_PREFIX,
            ((r1, ("GREEN",)), (r2, PE_VRFS)),
        )
    finally:
        _withdraw_normal_leak_route()

    step("Verify the normal leaked route is withdrawn cleanly")
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

    step("Dump normal VRF-leaked route after withdraw")
    _dump_route_state(
        "normal VRF-leaked route after withdraw",
        NORMAL_LEAK_PREFIX,
        ((r1, ("GREEN",)), (r2, PE_VRFS)),
    )


def test_evpn_type5_vrf_leak_stale_after_origin_withdraw():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    try:
        step("Inject the static origin route in r1 GREEN")
        _add_origin_route()

        try:
            step("Verify both PEs import r1 EVPN-origin route into GREEN")
            _wait_bgp_route(r2, "GREEN", PREFIX, True)
            _wait_bgp_route(r3, "GREEN", PREFIX, True)

            step("Verify both PEs leak the EVPN-origin route into BLUE and PURPLE")
            for router in (r2, r3):
                _wait_bgp_route(router, "BLUE", PREFIX, True)
                _wait_bgp_route(router, "PURPLE", PREFIX, True)
        except AssertionError:
            _dump_prefix_state(
                "EVPN-origin route before withdraw failure",
                ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
            )
            raise

        step("Dump EVPN-origin route before withdraw")
        _dump_prefix_state(
            "EVPN-origin route before withdraw",
            ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
        )

        step("Withdraw the origin prefix from r1 GREEN")
        _withdraw_origin_route()

        step("Verify no stale leaked/re-exported copy remains on either PE")
        try:
            _wait_bgp_route(r1, "GREEN", PREFIX, False)
            for router in (r2, r3):
                for vrf in PE_VRFS:
                    _wait_bgp_route(router, vrf, PREFIX, False)
        except AssertionError:
            _dump_prefix_state(
                "EVPN-origin route after withdraw failure",
                ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
            )
            raise

        step("Dump EVPN-origin route after withdraw")
        _dump_prefix_state(
            "EVPN-origin route after withdraw",
            ((r1, ("GREEN",)), (r2, PE_VRFS), (r3, PE_VRFS)),
        )
    finally:
        _withdraw_origin_route()


def test_memory_leak():
    "Run the memory leak test and report results."

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
