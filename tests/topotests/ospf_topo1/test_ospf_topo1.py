#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_topo1.py: Test the FRR OSPF routing daemon.
"""

import json
import os
import re
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospf6d, pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # Create a empty network for router 1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Create a empty network for router 2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 and 3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Create empty netowrk for router3
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])

    # Interconect router 3 and 4
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # Create a empty network for router 4
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    ospf6_config = "ospf6d.conf"

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF6, os.path.join(CWD, "{}/{}".format(rname, ospf6_config))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_wait_protocol_convergence():
    "Wait for OSPFv2/OSPFv3 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_ospfv2_neighbor_full(router, neighbor):
        "Wait until OSPFv2 convergence."
        logger.info("waiting OSPFv2 router '{}'".format(router))

        def run_command_and_expect():
            """
            Function that runs command and expect the following outcomes:
             * Full/DR
             * Full/DROther
             * Full/Backup
            """
            result = tgen.gears[router].vtysh_cmd(
                "show ip ospf neighbor json", isjson=True
            )
            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
                )
                is None
            ):
                return None

            if (
                topotest.json_cmp(
                    result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
                )
                is None
            ):
                return None

            return topotest.json_cmp(
                result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
            )

        _, result = topotest.run_and_expect(
            run_command_and_expect, None, count=130, wait=1
        )
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    def expect_ospfv3_neighbor_full(router, neighbor):
        "Wait until OSPFv3 convergence."
        logger.info("waiting OSPFv3 router '{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 neighbor json",
            {"neighbors": [{"neighborId": neighbor, "state": "Full"}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Wait for OSPFv2 convergence
    expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    expect_ospfv2_neighbor_full("r1", "10.0.255.3")
    expect_ospfv2_neighbor_full("r2", "10.0.255.1")
    expect_ospfv2_neighbor_full("r2", "10.0.255.3")
    expect_ospfv2_neighbor_full("r3", "10.0.255.1")
    expect_ospfv2_neighbor_full("r3", "10.0.255.2")
    expect_ospfv2_neighbor_full("r3", "10.0.255.4")
    expect_ospfv2_neighbor_full("r4", "10.0.255.3")

    # Wait for OSPFv3 convergence
    expect_ospfv3_neighbor_full("r1", "10.0.255.2")
    expect_ospfv3_neighbor_full("r1", "10.0.255.3")
    expect_ospfv3_neighbor_full("r2", "10.0.255.1")
    expect_ospfv3_neighbor_full("r2", "10.0.255.3")
    expect_ospfv3_neighbor_full("r3", "10.0.255.1")
    expect_ospfv3_neighbor_full("r3", "10.0.255.2")
    expect_ospfv3_neighbor_full("r3", "10.0.255.4")
    expect_ospfv3_neighbor_full("r4", "10.0.255.3")


def compare_show_ipv6_ospf6(rname, expected):
    """
    Calls 'show ipv6 ospf6 route' for router `rname` and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    current = tgen.gears[rname].vtysh_cmd("show ipv6 ospf6 route")

    # Remove the link addresses
    current = re.sub(r"fe80::[^ ]+", "fe80::xxxx:xxxx:xxxx:xxxx", current)
    expected = re.sub(r"fe80::[^ ]+", "fe80::xxxx:xxxx:xxxx:xxxx", expected)

    # Remove the time
    current = re.sub(r"\d+:\d{2}:\d{2}", "", current)
    expected = re.sub(r"\d+:\d{2}:\d{2}", "", expected)

    return topotest.difflines(
        topotest.normalize_text(current),
        topotest.normalize_text(expected),
        title1="Current output",
        title2="Expected output",
    )


def compare_ipv4_kernel_routes(router, expected):
    "Compare IPv4 kernel routes against expected routes."
    return topotest.json_cmp(topotest.ip4_route(router), expected)


def compare_ipv6_kernel_routes(router, expected):
    "Compare IPv6 kernel routes against expected routes."
    return topotest.json_cmp(topotest.ip6_route(router), expected)


def _as_list(value):
    if isinstance(value, list):
        return value
    return [value]


def _yang_operational_root(router):
    return json.loads(router.vtysh_cmd("show mgmt get-data /* datastore operational"))


def _yang_ospf_protocol(output, protocol_type, protocol_name):
    assert "ietf-routing:routing" in output, output
    protocols = output["ietf-routing:routing"]["control-plane-protocols"][
        "control-plane-protocol"
    ]
    for protocol in _as_list(protocols):
        if (
            protocol.get("type") == protocol_type
            and protocol.get("name") == protocol_name
        ):
            return protocol

    raise AssertionError(
        "missing {} control-plane-protocol named {}".format(
            protocol_type, protocol_name
        )
    )


def _yang_interface(output, ifname):
    assert "ietf-interfaces:interfaces" in output, output
    interfaces = output["ietf-interfaces:interfaces"]["interface"]
    for interface in _as_list(interfaces):
        if interface.get("name") == ifname:
            return interface

    raise AssertionError("missing ietf-interfaces interface {}".format(ifname))


def _yang_ospf_container(protocol):
    return protocol.get("ietf-ospf:ospf", protocol.get("ospf"))


def _yang_ospf_area(ospf, area_id):
    for area in _as_list(ospf["areas"]["area"]):
        if area.get("area-id") == area_id:
            return area

    raise AssertionError("missing OSPF area {}".format(area_id))


def _yang_ospf_interface(area, ifname):
    interfaces = area["interfaces"]["interface"]
    for interface in _as_list(interfaces):
        if interface.get("name") == ifname:
            return interface

    raise AssertionError("missing OSPF interface {}".format(ifname))


def _yang_ospf_neighbor(interface, router_id):
    neighbors = interface["neighbors"]["neighbor"]
    for neighbor in _as_list(neighbors):
        if neighbor.get("neighbor-router-id") == router_id:
            return neighbor

    raise AssertionError("missing OSPF neighbor {}".format(router_id))


def _yang_ospf_neighbor_state(router, protocol_type, expected_address_prefix):
    """Return None when the YANG operational tree shows a Full neighbor.

    Used by run_and_expect to poll until OSPF converges before the YANG
    operational test asserts adjacency state. Returns a diagnostic string
    while convergence is in progress.
    """
    try:
        output = _yang_operational_root(router)
        ospf = _yang_ospf_container(_yang_ospf_protocol(output, protocol_type, "default"))
        area = _yang_ospf_area(ospf, "0.0.0.0")
        interface = _yang_ospf_interface(area, "r1-eth1")
        neighbor = _yang_ospf_neighbor(interface, "10.0.255.2")
    except (AssertionError, KeyError):
        return "neighbor entry not yet visible"
    if neighbor.get("state") != "full":
        return "neighbor state is {}".format(neighbor.get("state"))
    if not neighbor.get("address", "").startswith(expected_address_prefix):
        return "neighbor address {} not in expected family".format(neighbor.get("address"))
    return None


def test_ospf_yang_operational_data():
    "Verify RFC 9129 OSPF operational data is exposed through YANG callbacks."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    backend_adapters = r1.vtysh_cmd("show mgmt backend-adapter all")
    assert "ospfd" in backend_adapters
    assert "ospf6d" in backend_adapters
    xpath_registry = r1.vtysh_cmd("show mgmt backend-yang-xpath-registry oper")
    assert (
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol"
        in xpath_registry
    )
    assert "/ietf-interfaces:interfaces/interface" in xpath_registry

    # Wait for OSPFv2 and OSPFv3 adjacencies to reach Full before asserting
    # operational state. ospf_topo1 fixture brings the topology up but does
    # not guarantee convergence by the time this test runs.
    for protocol_type, addr_prefix in (
        ("ietf-ospf:ospfv2", "10."),
        ("ietf-ospf:ospfv3", "fe80:"),
    ):
        test_func = partial(_yang_ospf_neighbor_state, r1, protocol_type, addr_prefix)
        _, diag = topotest.run_and_expect(test_func, None, count=160, wait=0.5)
        assert diag is None, "OSPF {} did not converge: {}".format(protocol_type, diag)

    output = _yang_operational_root(r1)
    _yang_interface(output, "r1-eth1")

    ospfv2 = _yang_ospf_container(
        _yang_ospf_protocol(output, "ietf-ospf:ospfv2", "default")
    )
    assert ospfv2["router-id"] == "10.0.255.1"
    assert isinstance(ospfv2["statistics"]["originate-new-lsa-count"], int)
    assert isinstance(ospfv2["statistics"]["rx-new-lsas-count"], int)
    area = _yang_ospf_area(ospfv2, "0.0.0.0")
    interface = _yang_ospf_interface(area, "r1-eth1")
    neighbor = _yang_ospf_neighbor(interface, "10.0.255.2")
    assert neighbor["state"] == "full"
    assert "address" in neighbor

    ospfv3 = _yang_ospf_container(
        _yang_ospf_protocol(output, "ietf-ospf:ospfv3", "default")
    )
    assert ospfv3["router-id"] == "10.0.255.1"
    assert isinstance(ospfv3["statistics"]["originate-new-lsa-count"], int)
    assert isinstance(ospfv3["statistics"]["rx-new-lsas-count"], int)
    area = _yang_ospf_area(ospfv3, "0.0.0.0")
    interface = _yang_ospf_interface(area, "r1-eth1")
    neighbor = _yang_ospf_neighbor(interface, "10.0.255.2")
    assert neighbor["state"] == "full"
    assert neighbor["address"].startswith("fe80:")


def _yang_explicit_router_id_xpath(protocol_type):
    return (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='" + protocol_type + "'][name='default']/"
        "ietf-ospf:ospf/explicit-router-id"
    )


def _mgmt_set_and_commit(router, xpath, value):
    """Run a single mgmt set-config + commit apply with explicit DS locks.

    `configure terminal file-lock` acquires both candidate and running locks
    on the mgmtd session; without the lock, `mgmt commit apply` fails with
    "source not locked by session-id".
    """
    router.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} {}\n"
        "mgmt commit apply".format(xpath, value)
    )


def _set_yang_router_id(router, protocol_type, daemon, running_line, new_value):
    """Set explicit-router-id via mgmtd, verify it lands, then restore.

    Exercises the config-write path end-to-end: candidate datastore set,
    commit apply, modify callback mutates FRR state, running-config reflects
    the change.
    """
    xpath = _yang_explicit_router_id_xpath(protocol_type)

    _mgmt_set_and_commit(router, xpath, new_value)

    running = router.vtysh_cmd("show running-config {}".format(daemon))
    assert "{} {}".format(running_line, new_value) in running, (
        "expected '{} {}' in running-config after YANG set, got:\n{}".format(
            running_line, new_value, running
        )
    )

    # Restore the original value through the same YANG path so subsequent
    # convergence-dependent tests in this module see the topology they expect.
    _mgmt_set_and_commit(router, xpath, "10.0.255.1")

    running = router.vtysh_cmd("show running-config {}".format(daemon))
    assert "{} 10.0.255.1".format(running_line) in running


def test_ospf_yang_router_id_config():
    "Verify RFC 9129 explicit-router-id is writable via mgmtd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    _set_yang_router_id(
        r1, "ietf-ospf:ospfv2", "ospfd", "ospf router-id", "10.0.255.21"
    )
    _set_yang_router_id(
        r1, "ietf-ospf:ospfv3", "ospf6d", "ospf6 router-id", "10.0.255.31"
    )


def _yang_area_xpath(protocol_type, area_id):
    return (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='"
        + protocol_type
        + "'][name='default']/ietf-ospf:ospf/areas/area[area-id='"
        + area_id
        + "']"
    )


def _set_yang_area_type(router, protocol_type, daemon, area_id, area_type,
                        expect_running_line):
    """Set areas/area[id=X]/area-type via mgmtd and verify it lands.

    area_type is one of "stub-area", "nssa-area", "normal-area" (the RFC 9129
    identityref values). expect_running_line is the substring to look for in
    `show running-config <daemon>` once the change has applied.
    """
    area_path = _yang_area_xpath(protocol_type, area_id)
    type_path = area_path + "/area-type"
    router.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} {}\n"
        "mgmt commit apply".format(type_path, area_type)
    )

    running = router.vtysh_cmd("show running-config {}".format(daemon))
    assert expect_running_line in running, (
        "expected '{}' in running-config after YANG area-type set to {}, got:\n{}".format(
            expect_running_line, area_type, running
        )
    )


def _delete_yang_area_type(router, protocol_type, daemon, area_id, absent_line):
    """Delete areas/area[id=X]/area-type and verify it returns to normal-area."""
    area_path = _yang_area_xpath(protocol_type, area_id)
    router.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}/area-type\n"
        "mgmt commit apply".format(area_path)
    )

    running = router.vtysh_cmd("show running-config {}".format(daemon))
    assert absent_line not in running, (
        "'{}' should be gone after YANG area-type delete, got:\n{}".format(
            absent_line, running
        )
    )

def _clear_yang_area(router, protocol_type, area_id):
    """Remove an area list entry via mgmtd."""
    area_path = _yang_area_xpath(protocol_type, area_id)
    router.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}\n"
        "mgmt commit apply".format(area_path)
    )


def test_ospf_yang_area_type_config():
    "Verify areas/area[area-id]/area-type is writable via mgmtd for both daemons."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: create a new stub area via YANG, verify it appears in
    # show running-config, then remove it.
    _set_yang_area_type(
        r1,
        "ietf-ospf:ospfv2",
        "ospfd",
        "0.0.0.42",
        "stub-area",
        "area 0.0.0.42 stub",
    )
    _delete_yang_area_type(
        r1, "ietf-ospf:ospfv2", "ospfd", "0.0.0.42", "area 0.0.0.42 stub"
    )
    _set_yang_area_type(
        r1,
        "ietf-ospf:ospfv2",
        "ospfd",
        "0.0.0.42",
        "stub-area",
        "area 0.0.0.42 stub",
    )
    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.42")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.42 stub" not in running, (
        "area 0.0.0.42 should be removed after YANG delete, running:\n" + running
    )

    # OSPFv3: same shape.
    _set_yang_area_type(
        r1,
        "ietf-ospf:ospfv3",
        "ospf6d",
        "0.0.0.42",
        "stub-area",
        "area 0.0.0.42 stub",
    )
    _delete_yang_area_type(
        r1, "ietf-ospf:ospfv3", "ospf6d", "0.0.0.42", "area 0.0.0.42 stub"
    )
    _set_yang_area_type(
        r1,
        "ietf-ospf:ospfv3",
        "ospf6d",
        "0.0.0.42",
        "stub-area",
        "area 0.0.0.42 stub",
    )
    _clear_yang_area(r1, "ietf-ospf:ospfv3", "0.0.0.42")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.42 stub" not in running, (
        "area 0.0.0.42 should be removed after YANG delete, running:\n" + running
    )

def test_ospf_yang_area_delete_clears_native_nssa_ranges():
    """Deleting a YANG NSSA area must also clear native NSSA range state."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    area_path = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.52")

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/area-type nssa-area\n"
        "mgmt commit apply".format(area_path)
    )
    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        "area 0.0.0.52 nssa range 10.52.0.0/16 cost 52"
    )

    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.52 nssa" in running, running
    assert "area 0.0.0.52 nssa range 10.52.0.0/16 cost 52" in running, (
        "expected native NSSA range before YANG area delete, got:\n" + running
    )

    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.52")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.52" not in running, (
        "area 0.0.0.52 and its NSSA range must be gone after delete, got:\n"
        + running
    )

def _set_yang_area_attrs(router, protocol_type, area_id, attrs):
    """Set multiple area attrs in one configure-and-commit block.

    `attrs` is a list of (sub_path, value) tuples; each becomes one
    `mgmt set-config` line, with all changes batched into a single
    commit apply. Uses `configure terminal file-lock` so the commit
    has the candidate+running DS locks it requires.
    """
    area_path = _yang_area_xpath(protocol_type, area_id)
    lines = ["configure terminal file-lock"]
    for sub_path, value in attrs:
        lines.append("mgmt set-config {}/{} {}".format(area_path, sub_path, value))
    lines.append("mgmt commit apply")
    router.vtysh_cmd("\n".join(lines))


def test_ospf_yang_area_summary_default_cost_config():
    "Verify areas/area[]/summary and /default-cost round-trip via mgmtd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: stub-area + summary=false + default-cost=42 should yield
    #   area 0.0.0.43 stub no-summary
    #   area 0.0.0.43 default-cost 42
    _set_yang_area_attrs(
        r1, "ietf-ospf:ospfv2", "0.0.0.43",
        [("area-type", "stub-area"), ("summary", "false"), ("default-cost", "42")],
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.43 stub no-summary" in running, (
        "expected 'area 0.0.0.43 stub no-summary' in running-config, got:\n" + running
    )
    assert "area 0.0.0.43 default-cost 42" in running, (
        "expected 'area 0.0.0.43 default-cost 42' in running-config, got:\n" + running
    )
    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.43")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.43" not in running, (
        "area 0.0.0.43 should be fully removed after YANG delete, running:\n" + running
    )

    # OSPFv3: summary only (FRR ospf6d has no per-area stub default-cost
    # surface, so the default-cost leaf is intentionally unimplemented on
    # the v3 side; see ospf6_nb_config.c for the rationale).
    _set_yang_area_attrs(
        r1, "ietf-ospf:ospfv3", "0.0.0.43",
        [("area-type", "stub-area"), ("summary", "false")],
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.43 stub no-summary" in running, (
        "expected 'area 0.0.0.43 stub no-summary' in running-config, got:\n" + running
    )
    _clear_yang_area(r1, "ietf-ospf:ospfv3", "0.0.0.43")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "0.0.0.43" not in running, (
        "area 0.0.0.43 should be fully removed after YANG delete, running:\n" + running
    )


def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for router, rnode in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 80 seconds.
        test_func = partial(
            topotest.router_output_cmp, rnode, "show ip ospf route", expected
        )
        result, diff = topotest.run_and_expect(test_func, "", count=160, wait=0.5)
        assert result, "OSPF did not converge on {}:\n{}".format(router, diff)


def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)

        def _routes_in_fib4():
            routes = topotest.ip4_route(router)
            expected = {
                "10.0.1.0/24": {},
                "10.0.2.0/24": {},
                "10.0.3.0/24": {},
                "10.0.10.0/24": {},
                "172.16.0.0/24": {},
                "172.16.1.0/24": {},
            }
            return topotest.json_cmp(routes, expected)

        _, result = topotest.run_and_expect(_routes_in_fib4, None, count=30, wait=1)

        assertmsg = 'OSPF IPv4 route mismatch in router "{}"'.format(router.name)
        assert result is None, assertmsg


def test_ospf6_convergence():
    "Test OSPF6 daemon convergence"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    ospf6route_file = "{}/ospf6route_ecmp.txt"
    for rnum in range(1, 5):
        router = "r{}".format(rnum)

        logger.info('Waiting for router "%s" IPv6 OSPF convergence', router)

        # Load expected results from the command
        reffile = os.path.join(CWD, ospf6route_file.format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=25, wait=3)
        if (not result) and (rnum == 1):
            # Didn't match the new ECMP version - try the old pre-ECMP format
            ospf6route_file = "{}/ospf6route.txt"

            # Load expected results from the command
            reffile = os.path.join(CWD, ospf6route_file.format(router))
            expected = open(reffile).read()

            test_func = partial(compare_show_ipv6_ospf6, router, expected)
            result, diff = topotest.run_and_expect(test_func, "", count=1, wait=3)
            if not result:
                # Didn't match the old version - switch back to new ECMP version
                # and fail
                ospf6route_file = "{}/ospf6route_ecmp.txt"

                # Load expected results from the command
                reffile = os.path.join(CWD, ospf6route_file.format(router))
                expected = open(reffile).read()

                test_func = partial(compare_show_ipv6_ospf6, router, expected)
                result, diff = topotest.run_and_expect(test_func, "", count=1, wait=3)

        assert result, "OSPF6 did not converge on {}:\n{}".format(router, diff)


def test_ospf6_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv6 kernel routes in "%s"', router.name)

        def _routes_in_fib6():
            routes = topotest.ip6_route(router)
            expected = {
                "2001:db8:1::/64": {},
                "2001:db8:2::/64": {},
                "2001:db8:3::/64": {},
                "2001:db8:100::/64": {},
                "2001:db8:200::/64": {},
                "2001:db8:300::/64": {},
            }
            logger.info("Routes:")
            logger.info(routes)
            logger.info(topotest.json_cmp(routes, expected))
            logger.info("ENd:")
            return topotest.json_cmp(routes, expected)

        _, result = topotest.run_and_expect(_routes_in_fib6, None, count=20, wait=1)

        assertmsg = 'OSPF IPv6 route mismatch in router "{}"'.format(router.name)
        assert result is None, assertmsg


def test_ospf_json():
    "Test 'show ip ospf json' output for coherency."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rnum in range(1, 5):
        router = tgen.gears["r{}".format(rnum)]
        logger.info(router.vtysh_cmd("show ip ospf database"))
        logger.info('Comparing router "%s" "show ip ospf json" output', router.name)
        expected = {
            "routerId": "10.0.255.{}".format(rnum),
            "tosRoutesOnly": True,
            "rfc2328Conform": True,
            "spfScheduleDelayMsecs": 0,
            "holdtimeMinMsecs": 50,
            "holdtimeMaxMsecs": 5000,
            "lsaMinIntervalMsecs": 5000,
            "lsaMinArrivalMsecs": 1000,
            "writeMultiplier": 20,
            "refreshTimerMsecs": 10000,
            "asbrRouter": "injectingExternalRoutingInformation",
            "attachedAreaCounter": 1,
            "areas": {},
        }
        # Area specific additional checks
        if router.name == "r1" or router.name == "r2" or router.name == "r3":
            expected["areas"]["0.0.0.0"] = {
                "areaIfActiveCounter": 2,
                "areaIfTotalCounter": 2,
                "authentication": "authenticationNone",
                "backbone": True,
                "lsaAsbrNumber": 1,
                "lsaNetworkNumber": 1,
                "lsaNssaNumber": 0,
                "lsaNumber": 7,
                "lsaOpaqueAreaNumber": 0,
                "lsaOpaqueLinkNumber": 0,
                "lsaRouterNumber": 3,
                "lsaSummaryNumber": 2,
                "nbrFullAdjacentCounter": 2,
            }
        if router.name == "r3" or router.name == "r4":
            expected["areas"]["0.0.0.1"] = {
                "areaIfActiveCounter": 1,
                "areaIfTotalCounter": 1,
                "authentication": "authenticationNone",
                "lsaAsbrNumber": 2,
                "lsaNetworkNumber": 1,
                "lsaNssaNumber": 0,
                "lsaNumber": 9,
                "lsaOpaqueAreaNumber": 0,
                "lsaOpaqueLinkNumber": 0,
                "lsaRouterNumber": 2,
                "lsaSummaryNumber": 4,
                "nbrFullAdjacentCounter": 1,
            }
            # r4 has more interfaces for area 0.0.0.1
            if router.name == "r4":
                expected["areas"]["0.0.0.1"].update(
                    {
                        "areaIfActiveCounter": 2,
                        "areaIfTotalCounter": 2,
                    }
                )

        # router 3 has an additional area
        if router.name == "r3":
            expected["attachedAreaCounter"] = 2

        output = router.vtysh_cmd("show ip ospf json", isjson=True)
        result = topotest.json_cmp(output, expected)
        assert result is None, '"{}" JSON output mismatches the expected result'.format(
            router.name
        )


def test_ospf_link_down():
    "Test OSPF convergence after a link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    # Simulate a network down event on router3 switch3 interface.
    router3 = tgen.gears["r3"]
    router3.peer_link_enable("r3-eth0", False)

    # Expect convergence on all routers
    for router, rnode in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence after link failure', router)
        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospfroute_down.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 80 seconds.
        test_func = partial(
            topotest.router_output_cmp, rnode, "show ip ospf route", expected
        )
        result, diff = topotest.run_and_expect(test_func, "", count=140, wait=0.5)
        assert result, "OSPF did not converge on {}:\n{}".format(router, diff)


def test_ospf_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info(
            'Checking OSPF IPv4 kernel routes in "%s" after link down', router.name
        )

        expected = {
            "10.0.1.0/24": {},
            "10.0.2.0/24": {},
            "10.0.3.0/24": {},
            "10.0.10.0/24": {},
            "172.16.0.0/24": {},
            "172.16.1.0/24": {},
        }
        if router.name == "r1" or router.name == "r2":
            expected.update(
                {
                    "10.0.10.0/24": None,
                    "172.16.0.0/24": None,
                    "172.16.1.0/24": None,
                }
            )
        elif router.name == "r3" or router.name == "r4":
            expected.update(
                {
                    "10.0.1.0/24": None,
                    "10.0.2.0/24": None,
                }
            )
        # Route '10.0.3.0' is no longer available for r4 since it is down.
        if router.name == "r4":
            expected.update(
                {
                    "10.0.3.0/24": None,
                }
            )
        assertmsg = 'OSPF IPv4 route mismatch in router "{}" after link down'.format(
            router.name
        )
        test_func = partial(compare_ipv4_kernel_routes, router, expected)
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, assertmsg


def test_ospf6_link_down():
    "Test OSPF6 daemon convergence after link goes down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rnum in range(1, 5):
        router = "r{}".format(rnum)

        logger.info(
            'Waiting for router "%s" IPv6 OSPF convergence after link down', router
        )

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospf6route_down.txt".format(router))
        expected = open(reffile).read()

        # Run test function until we get an result. Wait at most 60 seconds.
        test_func = partial(compare_show_ipv6_ospf6, router, expected)
        result, diff = topotest.run_and_expect(test_func, "", count=25, wait=3)
        assert result, "OSPF6 did not converge on {}:\n{}".format(router, diff)


def test_ospf6_link_down_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info(
            'Checking OSPF IPv6 kernel routes in "%s" after link down', router.name
        )

        expected = {
            "2001:db8:1::/64": {},
            "2001:db8:2::/64": {},
            "2001:db8:3::/64": {},
            "2001:db8:100::/64": {},
            "2001:db8:200::/64": {},
            "2001:db8:300::/64": {},
        }
        if router.name == "r1" or router.name == "r2":
            expected.update(
                {
                    "2001:db8:100::/64": None,
                    "2001:db8:200::/64": None,
                    "2001:db8:300::/64": None,
                }
            )
        elif router.name == "r3" or router.name == "r4":
            expected.update(
                {
                    "2001:db8:1::/64": None,
                    "2001:db8:2::/64": None,
                }
            )
        # Route '2001:db8:3::/64' is no longer available for r4 since it is down.
        if router.name == "r4":
            expected.update(
                {
                    "2001:db8:3::/64": None,
                }
            )
        assertmsg = 'OSPF IPv6 route mismatch in router "{}" after link down'.format(
            router.name
        )
        test_func = partial(compare_ipv6_kernel_routes, router, expected)
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
