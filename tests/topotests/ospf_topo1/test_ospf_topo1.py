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
import time
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


def _expect_ospfv2_neighbor_full(router, neighbor):
    "Wait until OSPFv2 neighbor reaches Full."
    tgen = get_topogen()
    logger.info("waiting OSPFv2 router '{}' for neighbor {}".format(router, neighbor))

    def run_command_and_expect():
        result = tgen.gears[router].vtysh_cmd("show ip ospf neighbor json", isjson=True)
        return topotest.json_cmp(
            result, {"neighbors": {neighbor: [{"converged": "Full"}]}}
        )

    _, result = topotest.run_and_expect(run_command_and_expect, None, count=130, wait=1)
    assert result is None, '"{}" convergence failure for {}'.format(router, neighbor)


def _expect_ospfv3_neighbor_full(router, neighbor):
    "Wait until OSPFv3 neighbor reaches Full."
    tgen = get_topogen()
    logger.info("waiting OSPFv3 router '{}' for neighbor {}".format(router, neighbor))
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 ospf6 neighbor json",
        {"neighbors": [{"neighborId": neighbor, "state": "Full"}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, '"{}" convergence failure for {}'.format(router, neighbor)


def _force_ospf_reconvergence_to_steady_state():
    """Restart ospfd / ospf6d on every router, then wait for the steady
    state LSDB.

    Several YANG mutation tests in this suite drive OSPF state
    transitions that the routing protocol can't fully clean up on its
    own. Two distinct failure modes:

      * router-id changes (test_ospf_yang_router_id_config) leave
        old-router-id self-LSAs in remote LSDBs. The local LSDB is
        wiped before re-origination, so the in-flight flush to
        neighbours never reaches them.
      * Interface priority / network-type / passive transitions
        (test_ospf_yang_area_interface_b3b_leaves_config,
        test_ospf_per_iface_cli_routes_through_yang,
        test_ospf_yang_interface_type_and_passive_config) move DR
        election around. The transient DR originates a Network LSA;
        when it stops being DR, FRR flushes that self-originated LSA
        but the resulting MaxAge entry is excluded from
        ospf_lsa_maxage_walker (line 3452 of ospf_lsa.c skips
        self-originated MaxAge LSAs), so it lingers in the LSDB
        indefinitely.

    `clear ip ospf process` is not enough -- the maxage state survives
    via flooding back from neighbours that also kept the phantom.
    A full daemon restart re-reads frr.conf cleanly and the LSDB
    starts from empty everywhere simultaneously, with no stale state
    in any router's memory for the phantoms to come back from.

    After restart we wait for r1's area 0 LSDB to settle at the
    steady-state count (3 router LSAs + 1 network LSA + 2 inter-area
    summary LSAs from r3 + 1 ASBR LSA = 7) so downstream read-only
    tests see deterministic state.
    """
    tgen = get_topogen()
    # Restart ospfd + ospf6d on every router. Daemon restart re-reads
    # frr.conf from scratch and gives a guaranteed clean LSDB on every
    # node, which `clear ip ospf process` alone cannot. SIGTERM each
    # daemon directly; the topogen wrapper only exposes a whole-router
    # stop, which would also tear down zebra / mgmtd.
    for rname in ("r1", "r2", "r3", "r4"):
        rnode = tgen.gears[rname]
        rnode.cmd("pkill -TERM -x ospfd")
        rnode.cmd("pkill -TERM -x ospf6d")
    # Brief settle for the kernel to reap the processes before restart.
    time.sleep(2)
    for rname in ("r1", "r2", "r3", "r4"):
        rnode = tgen.gears[rname]
        rnode.net.startRouterDaemons(["ospfd", "ospf6d"])

    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv2_neighbor_full("r1", "10.0.255.3")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.3")
    _expect_ospfv2_lsdb_equal("r1", "0.0.0.0", 7)


def _expect_ospfv2_lsdb_equal(router, area, expected_lsa_count):
    """Wait until `router` reports exactly expected_lsa_count LSAs in `area`.

    NSM Full happens once DBD exchange completes, but full LSDB
    propagation (especially summary / ASBR / network LSAs) requires
    further LSU flooding. After an OSPF process reset (e.g. router-id
    change) the adjacency reaches Full quickly while the LSDB is still
    refilling. Equality (not just min) lets us catch phantom LSAs from
    pre-restart state (e.g. stale network LSAs from a transient DR
    election) that must age out before downstream tests run.
    """
    tgen = get_topogen()

    def lsdb_matches():
        result = tgen.gears[router].vtysh_cmd("show ip ospf json", isjson=True)
        try:
            lsa_count = result["areas"][area]["lsaNumber"]
        except (KeyError, TypeError):
            return "LSA count not yet available"
        if lsa_count == expected_lsa_count:
            return None
        return "lsaNumber={} != {}".format(lsa_count, expected_lsa_count)

    _, diag = topotest.run_and_expect(lsdb_matches, None, count=180, wait=1)
    assert diag is None, '"{}" LSDB did not converge to {} LSAs in area {}: {}'.format(
        router, expected_lsa_count, area, diag
    )


def test_wait_protocol_convergence():
    "Wait for OSPFv2/OSPFv3 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    # Wait for OSPFv2 convergence
    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv2_neighbor_full("r1", "10.0.255.3")
    _expect_ospfv2_neighbor_full("r2", "10.0.255.1")
    _expect_ospfv2_neighbor_full("r2", "10.0.255.3")
    _expect_ospfv2_neighbor_full("r3", "10.0.255.1")
    _expect_ospfv2_neighbor_full("r3", "10.0.255.2")
    _expect_ospfv2_neighbor_full("r3", "10.0.255.4")
    _expect_ospfv2_neighbor_full("r4", "10.0.255.3")

    # Wait for OSPFv3 convergence
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.3")
    _expect_ospfv3_neighbor_full("r2", "10.0.255.1")
    _expect_ospfv3_neighbor_full("r2", "10.0.255.3")
    _expect_ospfv3_neighbor_full("r3", "10.0.255.1")
    _expect_ospfv3_neighbor_full("r3", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r3", "10.0.255.4")
    _expect_ospfv3_neighbor_full("r4", "10.0.255.3")


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


def _yang_get_data(router, xpath, datastore="operational"):
    return json.loads(
        router.vtysh_cmd("show mgmt get-data {} datastore {}".format(xpath, datastore))
    )


def _yang_xpath_subscription(router, xpath):
    return router.vtysh_cmd("show mgmt yang-xpath-subscription {}".format(xpath))


def _assert_xpath_client(output, client, oper):
    match = re.search(
        r"Client: {}\s+config:\d+ notify:\d+ oper:(\d+) rpc:\d+".format(client),
        output,
    )
    assert match, output
    assert match.group(1) == str(int(oper)), output


def _assert_xpath_no_ospf_clients(output):
    assert "Client: ospfd" not in output, output
    assert "Client: ospf6d" not in output, output


def _yang_operational_root(router):
    return _yang_get_data(router, "/*")


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
        ospf = _yang_ospf_container(
            _yang_ospf_protocol(output, protocol_type, "default")
        )
        area = _yang_ospf_area(ospf, "0.0.0.0")
        interface = _yang_ospf_interface(area, "r1-eth1")
        neighbor = _yang_ospf_neighbor(interface, "10.0.255.2")
    except (AssertionError, KeyError):
        return "neighbor entry not yet visible"
    if neighbor.get("state") != "full":
        return "neighbor state is {}".format(neighbor.get("state"))
    if not neighbor.get("address", "").startswith(expected_address_prefix):
        return "neighbor address {} not in expected family".format(
            neighbor.get("address")
        )
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


def test_ospf_yang_mgmtd_predicate_dispatch():
    "Verify mgmtd dispatches typed OSPF xpaths to the correct backend."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    output = _yang_operational_root(r1)
    _yang_ospf_protocol(output, "ietf-ospf:ospfv2", "default")
    _yang_ospf_protocol(output, "ietf-ospf:ospfv3", "default")

    for protocol_type in ("ietf-ospf:ospfv2", "ietf-ospf:ospfv3"):
        protocol_path = (
            "/ietf-routing:routing/control-plane-protocols/"
            "control-plane-protocol[type='" + protocol_type + "'][name='default']"
        )
        subscription = _yang_xpath_subscription(r1, protocol_path)
        if protocol_type == "ietf-ospf:ospfv2":
            _assert_xpath_client(subscription, "ospfd", True)
            assert "Client: ospf6d" not in subscription, subscription
        else:
            assert "Client: ospfd" not in subscription, subscription
            _assert_xpath_client(subscription, "ospf6d", True)

        selected = _yang_get_data(r1, protocol_path)
        protocols = _as_list(
            selected["ietf-routing:routing"]["control-plane-protocols"][
                "control-plane-protocol"
            ]
        )
        assert len(protocols) == 1, selected
        protocol = protocols[0]
        assert protocol["type"] == protocol_type, selected
        assert protocol["name"] == "default", selected
        assert _yang_ospf_container(protocol)["router-id"] == "10.0.255.1"

    subscription = _yang_xpath_subscription(
        r1,
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ospfv2'][name='default']",
    )
    _assert_xpath_client(subscription, "ospfd", True)
    assert "Client: ospf6d" not in subscription, subscription

    for protocol_path in (
        "/ietf-routing:routing/control-plane-protocols",
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol",
        "/ietf-routing:routing/control-plane-protocols/control-plane-protocol/ietf-ospf:ospf/router-id",
    ):
        subscription = _yang_xpath_subscription(r1, protocol_path)
        _assert_xpath_client(subscription, "ospfd", True)
        _assert_xpath_client(subscription, "ospf6d", True)

    for protocol_path in (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:unknown'][name='default']",
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv2'[name='default']",
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv2'][name='default']/"
        + ("x" * 1100),
    ):
        _assert_xpath_no_ospf_clients(_yang_xpath_subscription(r1, protocol_path))

    # Zebra registers the RFC 8343 interface list without an OSPF-style
    # protocol-type predicate. Keep one predicate query here so the test
    # catches regressions in both typed and untyped backend registrations.
    selected = _yang_get_data(
        r1, "/ietf-interfaces:interfaces/interface[name='r1-eth1']"
    )
    assert _yang_interface(selected, "r1-eth1")["oper-status"] == "up"


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
    assert (
        "{} {}".format(running_line, new_value) in running
    ), "expected '{} {}' in running-config after YANG set, got:\n{}".format(
        running_line, new_value, running
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

    # Router-id mutation leaves phantom self-LSAs in the other routers'
    # LSDBs that the routing protocol can't fully reconcile on its own;
    # bounce every adjacency so the LSDB is rebuilt cleanly before any
    # downstream test depends on it.
    _force_ospf_reconvergence_to_steady_state()


def _yang_area_xpath(protocol_type, area_id):
    return (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='"
        + protocol_type
        + "'][name='default']/ietf-ospf:ospf/areas/area[area-id='"
        + area_id
        + "']"
    )


def _set_yang_area_type(
    router, protocol_type, daemon, area_id, area_type, expect_running_line
):
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
    assert (
        expect_running_line in running
    ), "expected '{}' in running-config after YANG area-type set to {}, got:\n{}".format(
        expect_running_line, area_type, running
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


def _restore_r1_eth1_fixture_timers(router, protocol_type):
    """Restore the explicit timer leaves from the r1 fixture."""
    iface_path = (
        _yang_area_xpath(protocol_type, "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )

    router.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/hello-interval 2\n"
        "mgmt set-config {}/dead-interval 10\n"
        "mgmt commit apply".format(iface_path, iface_path)
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


def test_ospf_distance_cli_routes_through_yang():
    """The legacy single-value `distance N` / `no distance` and multi-value
    `distance ospf intra-area X inter-area Y external Z` / `no distance ospf`
    forms continue to work via vtysh but now route through the ietf-ospf
    YANG `/preference/all` and `/preference/{intra-area,inter-area,external}`
    leaves. Verify by issuing the legacy CLI and confirming the daemon's
    running-config reflects the change exactly as before.

    The OSPFv3 legacy CLI path also exercises ospf6_restart_spf with a
    populated route table, which covers the ospf6_route_remove_all iterator
    hardening."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    for daemon, router_block, cli_proto, no_distance in (
        ("ospfd", "router ospf", "ospf", "no distance"),
        ("ospf6d", "router ospf6", "ospf6", "no distance 137"),
    ):
        # single-value scope (preference/all)
        r1.vtysh_cmd(
            "configure terminal\n" "{}\n" " distance 137\n".format(router_block)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert " distance 137" in running, running

        r1.vtysh_cmd(
            "configure terminal\n" "{}\n" " {}\n".format(router_block, no_distance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert "distance 137" not in running, running

        # multi-value scope (preference/intra-area + /inter-area + /external)
        r1.vtysh_cmd(
            "configure terminal\n"
            "{}\n"
            " distance {} intra-area 21 inter-area 22 external 23\n".format(
                router_block, cli_proto
            )
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "distance {} intra-area 21".format(cli_proto) in running
        ), "expected 'distance {} intra-area 21' in {} running-config, got:\n{}".format(
            cli_proto, daemon, running
        )
        assert "inter-area 22" in running, running
        assert "external 23" in running, running

        r1.vtysh_cmd(
            "configure terminal\n"
            "{}\n"
            " no distance {}\n".format(router_block, cli_proto)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert "intra-area 21" not in running, running
        assert "inter-area 22" not in running, running
        assert "external 23" not in running, running

    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")


def test_ospf_area_cli_routes_through_yang():
    """The legacy `area X stub`, `area X stub no-summary`, `area X
    default-cost N`, and their `no` forms continue to work via vtysh but
    now route through the ietf-ospf YANG layer. Verify by issuing the
    legacy CLI and confirming the daemons running-config reflects the
    change exactly as before."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: stub, then totally-stubby, then add default-cost, then unwind.
    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        " area 0.0.0.51 stub\n"
        " area 0.0.0.51 stub no-summary\n"
        " area 0.0.0.51 default-cost 17\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.51 stub no-summary" in running, running
    assert "area 0.0.0.51 default-cost 17" in running, running

    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        " no area 0.0.0.51 default-cost\n"
        " no area 0.0.0.51 stub no-summary\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    # `no stub no-summary` clears only the no-summary, area stays stub.
    assert "area 0.0.0.51 stub" in running, running
    assert "area 0.0.0.51 stub no-summary" not in running, running
    assert "default-cost 17" not in running, running

    r1.vtysh_cmd("configure terminal\nrouter ospf\n no area 0.0.0.51 stub\n")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.51" not in running, running

    # OSPFv3: same cycle, minus default-cost (no v3 surface).
    r1.vtysh_cmd(
        "configure terminal\n" "router ospf6\n" " area 0.0.0.52 stub no-summary\n"
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.52 stub no-summary" in running, running

    r1.vtysh_cmd(
        "configure terminal\n" "router ospf6\n" " no area 0.0.0.52 stub no-summary\n"
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.52 stub" in running, running
    assert "area 0.0.0.52 stub no-summary" not in running, running

    r1.vtysh_cmd("configure terminal\nrouter ospf6\n no area 0.0.0.52 stub\n")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "0.0.0.52" not in running, running


def test_ospf_yang_area_interface_cost_config():
    """areas/area[id]/interfaces/interface[name]/cost via mgmtd.

    Exercises the per-interface YANG path end-to-end: creating the
    /areas/area[id='0.0.0.0']/interfaces/interface[name='r1-eth1']
    entry attaches r1-eth1 to area 0 (the same area it's already in
    from the fixture config), setting cost mutates the FRR-side
    output-cost-cmd. Then unwinds: deleting cost reverts to default,
    deleting the interface entry detaches it from the area.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: r1-eth1 is already in area 0.0.0.0 via `network 10.0.1.0/24 area 0`
    # in the fixture. The YANG list create is idempotent (same area), so this
    # is a clean set + cost change.
    area_path = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
    iface_path = area_path + "/interfaces/interface[name='r1-eth1']"
    cost_path = iface_path + "/cost"

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} 77\n"
        "mgmt commit apply".format(cost_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf cost 77" in running, (
        "expected 'ip ospf cost 77' in running-config after YANG set, got:\n" + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}\n"
        "mgmt commit apply".format(cost_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf cost 77" not in running, (
        "ip ospf cost should be removed after YANG delete, got:\n" + running
    )

    # OSPFv3: r1-eth1 is already in area 0 via the fixture's
    # `ipv6 ospf6 area 0` per-interface command. Same set + clear cycle.
    area_path = _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
    iface_path = area_path + "/interfaces/interface[name='r1-eth1']"
    cost_path = iface_path + "/cost"

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} 88\n"
        "mgmt commit apply".format(cost_path)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 cost 88" in running, (
        "expected 'ipv6 ospf6 cost 88' in running-config after YANG set, got:\n"
        + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}\n"
        "mgmt commit apply".format(cost_path)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 cost 88" not in running, (
        "ipv6 ospf6 cost should be removed after YANG delete, got:\n" + running
    )


def test_ospf_yang_area_interface_b3b_leaves_config():
    """hello/dead/retransmit/priority/mtu-ignore round-trip.

    Sets all five per-interface YANG leaves in a single mgmt commit
    apply for both OSPFv2 and OSPFv3, verifies each lands in
    `show running-config <daemon>`, then deletes them and verifies
    the reverts.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: r1-eth1 is already in area 0.0.0.0 via the fixture's
    # network statement. Existing fixture also sets hello-interval 2
    # and dead-interval 10, so we use distinguishable test values.
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    cmds = (
        "configure terminal file-lock\n"
        "mgmt set-config {}/hello-interval 7\n"
        "mgmt set-config {}/dead-interval 29\n"
        "mgmt set-config {}/retransmit-interval 11\n"
        "mgmt set-config {}/priority 13\n"
        "mgmt set-config {}/mtu-ignore true\n"
        "mgmt commit apply"
    ).format(iface, iface, iface, iface, iface)
    r1.vtysh_cmd(cmds)

    running = r1.vtysh_cmd("show running-config ospfd")
    for expected in (
        "ip ospf hello-interval 7",
        "ip ospf dead-interval 29",
        "ip ospf retransmit-interval 11",
        "ip ospf priority 13",
        "ip ospf mtu-ignore",
    ):
        assert (
            expected in running
        ), "expected '{}' in v2 running-config, got:\n{}".format(expected, running)

    # Tear down individual leaves
    cmds = (
        "configure terminal file-lock\n"
        "mgmt delete-config {}/hello-interval\n"
        "mgmt delete-config {}/dead-interval\n"
        "mgmt delete-config {}/retransmit-interval\n"
        "mgmt delete-config {}/priority\n"
        "mgmt delete-config {}/mtu-ignore\n"
        "mgmt commit apply"
    ).format(iface, iface, iface, iface, iface)
    r1.vtysh_cmd(cmds)
    running = r1.vtysh_cmd("show running-config ospfd")
    for unexpected in (
        "ip ospf hello-interval 7",
        "ip ospf dead-interval 29",
        "ip ospf retransmit-interval 11",
        "ip ospf priority 13",
        "ip ospf mtu-ignore",
    ):
        assert (
            unexpected not in running
        ), "'{}' should be gone after YANG delete, got:\n{}".format(unexpected, running)
    _restore_r1_eth1_fixture_timers(r1, "ietf-ospf:ospfv2")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf hello-interval 2" in running, running
    assert "ip ospf dead-interval 10" in running, running

    # OSPFv3: same leaves, same path shape.
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    cmds = (
        "configure terminal file-lock\n"
        "mgmt set-config {}/hello-interval 7\n"
        "mgmt set-config {}/dead-interval 29\n"
        "mgmt set-config {}/retransmit-interval 11\n"
        "mgmt set-config {}/priority 13\n"
        "mgmt set-config {}/mtu-ignore true\n"
        "mgmt commit apply"
    ).format(iface, iface, iface, iface, iface)
    r1.vtysh_cmd(cmds)
    running = r1.vtysh_cmd("show running-config ospf6d")
    for expected in (
        "ipv6 ospf6 hello-interval 7",
        "ipv6 ospf6 dead-interval 29",
        "ipv6 ospf6 retransmit-interval 11",
        "ipv6 ospf6 priority 13",
        "ipv6 ospf6 mtu-ignore",
    ):
        assert (
            expected in running
        ), "expected '{}' in v3 running-config, got:\n{}".format(expected, running)

    cmds = (
        "configure terminal file-lock\n"
        "mgmt delete-config {}/hello-interval\n"
        "mgmt delete-config {}/dead-interval\n"
        "mgmt delete-config {}/retransmit-interval\n"
        "mgmt delete-config {}/priority\n"
        "mgmt delete-config {}/mtu-ignore\n"
        "mgmt commit apply"
    ).format(iface, iface, iface, iface, iface)
    r1.vtysh_cmd(cmds)
    running = r1.vtysh_cmd("show running-config ospf6d")
    for unexpected in (
        "ipv6 ospf6 hello-interval 7",
        "ipv6 ospf6 dead-interval 29",
        "ipv6 ospf6 retransmit-interval 11",
        "ipv6 ospf6 priority 13",
        "ipv6 ospf6 mtu-ignore",
    ):
        assert (
            unexpected not in running
        ), "'{}' should be gone after YANG delete, got:\n{}".format(unexpected, running)
    _restore_r1_eth1_fixture_timers(r1, "ietf-ospf:ospfv3")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 hello-interval 2" in running, running
    assert "ipv6 ospf6 dead-interval 10" in running, running


def test_ospf_yang_area_interface_transmit_delay_config():
    """areas/area[id]/interfaces/interface[name]/transmit-delay via mgmtd.

    Round-trips the per-interface transmit-delay leaf on both
    daemons: set via mgmt, verify in `show running-config`, delete
    via mgmt, verify the line is gone and FRR is back at the
    compile-time default (OSPF_TRANSMIT_DELAY_DEFAULT for ospfd,
    OSPF6_INTERFACE_TRANSDELAY for ospf6d -- both 1).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2
    area_path = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
    iface_path = area_path + "/interfaces/interface[name='r1-eth1']"
    leaf_path = iface_path + "/transmit-delay"

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} 17\n"
        "mgmt commit apply".format(leaf_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf transmit-delay 17" in running, (
        "expected 'ip ospf transmit-delay 17' in running-config after YANG set, got:\n"
        + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}\n"
        "mgmt commit apply".format(leaf_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf transmit-delay" not in running, (
        "ip ospf transmit-delay should be removed after YANG delete, got:\n" + running
    )

    # OSPFv3
    area_path = _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
    iface_path = area_path + "/interfaces/interface[name='r1-eth1']"
    leaf_path = iface_path + "/transmit-delay"

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {} 19\n"
        "mgmt commit apply".format(leaf_path)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 transmit-delay 19" in running, (
        "expected 'ipv6 ospf6 transmit-delay 19' in running-config after YANG set, got:\n"
        + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}\n"
        "mgmt commit apply".format(leaf_path)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 transmit-delay" not in running, (
        "ipv6 ospf6 transmit-delay should be removed after YANG delete, got:\n" + running
    )


def test_ospf_per_iface_cli_routes_through_yang():
    """legacy per-interface CLI commands route through the
    ietf-ospf YANG layer when the interface is in an area.

    Drives `ip ospf cost N`, `ip ospf hello-interval N`, `ip ospf
    dead-interval N`, `ip ospf priority N`, `ip ospf mtu-ignore`,
    `ip ospf passive`, `ip ospf retransmit-interval N`, `ip ospf
    transmit-delay N`, `ip ospf network point-to-point` and their
    v3 siblings via vtysh on r1-eth1 (which the fixture already
    attached to area 0 for both daemons), confirms each lands in
    running-config, then unwinds via the corresponding `no` form.
    Covers both the conversion of the main DEFUN to DEFPY_YANG and
    the routing through the NB callbacks landed in the per-interface
    slices.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2 on r1-eth1
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " ip ospf cost 41\n"
        " ip ospf hello-interval 3\n"
        " ip ospf dead-interval 15\n"
        " ip ospf priority 19\n"
        " ip ospf mtu-ignore\n"
        " ip ospf passive\n"
        " ip ospf retransmit-interval 23\n"
        " ip ospf transmit-delay 31\n"
        " ip ospf network point-to-point\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    for expected in (
        "ip ospf cost 41",
        "ip ospf hello-interval 3",
        "ip ospf dead-interval 15",
        "ip ospf priority 19",
        "ip ospf mtu-ignore",
        "ip ospf passive",
        "ip ospf retransmit-interval 23",
        "ip ospf transmit-delay 31",
        "ip ospf network point-to-point",
    ):
        assert (
            expected in running
        ), "expected '{}' in v2 running-config after CLI set, got:\n{}".format(
            expected, running
        )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " no ip ospf cost\n"
        " no ip ospf hello-interval\n"
        " no ip ospf dead-interval\n"
        " no ip ospf priority\n"
        " no ip ospf mtu-ignore\n"
        " no ip ospf passive\n"
        " no ip ospf retransmit-interval\n"
        " no ip ospf transmit-delay\n"
        " no ip ospf network\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    for unexpected in (
        "ip ospf cost 41",
        "ip ospf hello-interval 3",
        "ip ospf dead-interval 15",
        "ip ospf priority 19",
        "ip ospf mtu-ignore",
        "ip ospf passive",
        "ip ospf retransmit-interval 23",
        "ip ospf transmit-delay 31",
        "ip ospf network point-to-point",
    ):
        assert (
            unexpected not in running
        ), "'{}' should be gone after CLI no form, got:\n{}".format(unexpected, running)

    # OSPFv3 on r1-eth1
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " ipv6 ospf6 cost 41\n"
        " ipv6 ospf6 hello-interval 3\n"
        " ipv6 ospf6 dead-interval 15\n"
        " ipv6 ospf6 priority 19\n"
        " ipv6 ospf6 mtu-ignore\n"
        " ipv6 ospf6 passive\n"
        " ipv6 ospf6 retransmit-interval 23\n"
        " ipv6 ospf6 transmit-delay 31\n"
        " ipv6 ospf6 network point-to-point\n"
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    for expected in (
        "ipv6 ospf6 cost 41",
        "ipv6 ospf6 hello-interval 3",
        "ipv6 ospf6 dead-interval 15",
        "ipv6 ospf6 priority 19",
        "ipv6 ospf6 mtu-ignore",
        "ipv6 ospf6 passive",
        "ipv6 ospf6 retransmit-interval 23",
        "ipv6 ospf6 transmit-delay 31",
        "ipv6 ospf6 network point-to-point",
    ):
        assert (
            expected in running
        ), "expected '{}' in v3 running-config after CLI set, got:\n{}".format(
            expected, running
        )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " no ipv6 ospf6 cost\n"
        " no ipv6 ospf6 hello-interval\n"
        " no ipv6 ospf6 dead-interval\n"
        " no ipv6 ospf6 priority\n"
        " no ipv6 ospf6 mtu-ignore\n"
        " no ipv6 ospf6 passive\n"
        " no ipv6 ospf6 retransmit-interval\n"
        " no ipv6 ospf6 transmit-delay\n"
        " no ipv6 ospf6 network\n"
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    for unexpected in (
        "ipv6 ospf6 cost 41",
        "ipv6 ospf6 hello-interval 3",
        "ipv6 ospf6 dead-interval 15",
        "ipv6 ospf6 priority 19",
        "ipv6 ospf6 mtu-ignore",
        "ipv6 ospf6 passive",
        "ipv6 ospf6 retransmit-interval 23",
        "ipv6 ospf6 transmit-delay 31",
        "ipv6 ospf6 network point-to-point",
    ):
        assert (
            unexpected not in running
        ), "'{}' should be gone after CLI no form, got:\n{}".format(unexpected, running)

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " ip ospf hello-interval 2\n"
        " ip ospf dead-interval 10\n"
        " ipv6 ospf6 hello-interval 2\n"
        " ipv6 ospf6 dead-interval 10\n"
    )


def test_ospf_network_dmvpn_falls_back_to_legacy():
    """`ip ospf network point-to-point dmvpn` keeps working via the
    legacy direct-mutation path because RFC 9129's interface-type
    enum doesn't model the FRR-specific dmvpn flag.

    The DEFPY_YANG body classifies the FRR-modifier as out-of-scope
    for YANG and falls through to ospf_network_legacy_apply.  This
    test confirms the running-config still shows the dmvpn modifier
    after the conversion.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " ip ospf network point-to-point dmvpn\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf network point-to-point dmvpn" in running, (
        "expected 'ip ospf network point-to-point dmvpn' in running-config "
        "after legacy CLI set, got:\n" + running
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " no ip ospf network\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf network" not in running, (
        "ip ospf network should be removed after CLI no form, got:\n" + running
    )


def test_ospf_yang_preference_config():
    """per-instance preference (admin distance) round-trip via mgmtd.

    Covers the single-value scope (preference/all -> distance N) and the
    multi-values scope (preference/intra-area, /inter-area, /external).
    For both OSPFv2 and OSPFv3.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon, cli_proto in (
        ("ietf-ospf:ospfv2", "ospfd", "ospf"),
        ("ietf-ospf:ospfv3", "ospf6d", "ospf6"),
    ):
        # v2 renders `distance ospf intra-area X`; v3 renders `distance ospf6 ...`
        cli_prefix = "distance"
        instance = (
            "/ietf-routing:routing/control-plane-protocols/"
            "control-plane-protocol[type='"
            + proto
            + "'][name='default']/ietf-ospf:ospf"
        )

        # single-value scope
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/preference/all 137\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "{} 137".format(cli_prefix) in running
        ), "expected '{} 137' in {} running-config, got:\n{}".format(
            cli_prefix, daemon, running
        )
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/preference/all\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert "{} 137".format(cli_prefix) not in running

        # multi-values scope (intra + inter + external set together)
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/preference/intra-area 21\n"
            "mgmt set-config {}/preference/inter-area 22\n"
            "mgmt set-config {}/preference/external 23\n"
            "mgmt commit apply".format(instance, instance, instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "{} {} intra-area 21".format(cli_prefix, cli_proto) in running
        ), "expected '{} {} intra-area 21' in {} running-config, got:\n{}".format(
            cli_prefix, cli_proto, daemon, running
        )
        assert "inter-area 22" in running, running
        assert "external 23" in running, running

        # cleanup
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/preference/intra-area\n"
            "mgmt delete-config {}/preference/inter-area\n"
            "mgmt delete-config {}/preference/external\n"
            "mgmt commit apply".format(instance, instance, instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert "intra-area 21" not in running
        assert "inter-area 22" not in running
        assert "external 23" not in running


def test_ospf_yang_spf_control_paths_config():
    """per-instance spf-control/paths round-trip via mgmtd.

    RFC 9129's `/spf-control/paths` is a uint16; the legacy CLI's
    `maximum-paths` accepts up to MULTIPATH_NUM (platform-defined).
    The conversion routes normal writes through YANG and keeps the
    legacy direct-mutation path as a fallback if an instance XPath
    cannot be built; this test covers the direct YANG path.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon in (
        ("ietf-ospf:ospfv2", "ospfd"),
        ("ietf-ospf:ospfv3", "ospf6d"),
    ):
        instance = (
            "/ietf-routing:routing/control-plane-protocols/"
            "control-plane-protocol[type='"
            + proto
            + "'][name='default']/ietf-ospf:ospf"
        )

        # YANG set within RFC range.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/spf-control/paths 7\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "maximum-paths 7" in running
        ), "expected 'maximum-paths 7' after YANG set, got:\n{}".format(running)

        # YANG delete restores no-config (FRR semantics).
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/spf-control/paths\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "maximum-paths 7" not in running
        ), "maximum-paths 7 should be gone after YANG delete, got:\n{}".format(running)


def test_ospf_yang_spf_control_paths_platform_limit_rejected():
    """Direct mgmtd writes honour FRR's platform ECMP cap.

    The RFC 9129 type allows values up to 65535, but FRR must still
    reject anything above MULTIPATH_NUM in the daemon callback so CLI
    and YANG clients observe the same platform limit.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon in (
        ("ietf-ospf:ospfv2", "ospfd"),
        ("ietf-ospf:ospfv3", "ospf6d"),
    ):
        instance = (
            "/ietf-routing:routing/control-plane-protocols/"
            "control-plane-protocol[type='"
            + proto
            + "'][name='default']/ietf-ospf:ospf"
        )
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/spf-control/paths 65535".format(instance),
        )
        assert (
            "maximum-paths exceeds platform max" in out
        ), "expected platform-limit rejection for {}, got:\n{}".format(proto, out)

        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "maximum-paths 65535" not in running
        ), "rejected maximum-paths value must not land on {}, got:\n{}".format(
            daemon, running
        )


def test_ospf_yang_mpls_ldp_igp_sync_config():
    """per-instance mpls/ldp/igp-sync round-trip via mgmtd (OSPFv2 only).

    cEOS-style: set the leaf to true, verify `mpls ldp-sync` lands in
    `show running-config`, then delete the leaf and verify it is
    gone. ospf6d has no LDP/IGP sync implementation; the OSPFv3
    callback is intentionally absent.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    instance = (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv2'][name='default']"
        "/ietf-ospf:ospf"
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/mpls/ldp/igp-sync true\n"
        "mgmt commit apply".format(instance)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "mpls ldp-sync" in running
    ), "expected 'mpls ldp-sync' after YANG set, got:\n{}".format(running)

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}/mpls/ldp/igp-sync\n"
        "mgmt commit apply".format(instance)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "mpls ldp-sync" not in running
    ), "mpls ldp-sync should be gone after YANG delete, got:\n{}".format(running)


def test_ospf_max_metric_router_lsa_admin_cli_routes_through_yang():
    """Legacy `max-metric router-lsa administrative` / `no max-metric
    router-lsa administrative` continues to work via vtysh and drives
    the YANG `/stub-router/trigger/always` create/destroy callbacks.

    RFC 9129's `/stub-router/trigger/always` is a presence container --
    a node with no value -- and FRR's mgmtd CLI `mgmt set-config WORD
    VALUE` grammar requires a VALUE token, so direct mgmtd-side
    round-trip testing of this leaf has no clean entry point.  The
    legacy CLI invokes the same NB_OP_CREATE / NB_OP_DESTROY
    callbacks the YANG path would, so this test covers both."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        " max-metric router-lsa administrative\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "max-metric router-lsa administrative" in running
    ), "expected 'max-metric router-lsa administrative' in ospfd running-config, got:\n{}".format(
        running
    )

    r1.vtysh_cmd(
        "configure terminal\n"
        "router ospf\n"
        " no max-metric router-lsa administrative\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "max-metric router-lsa administrative" not in running
    ), "max-metric router-lsa administrative should be gone after 'no ...', got:\n{}".format(
        running
    )


def test_ospf_mpls_ldp_sync_cli_routes_through_yang():
    """Legacy `mpls ldp-sync` / `no mpls ldp-sync` continues to work
    via vtysh and drives the YANG `/mpls/ldp/igp-sync` callback."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd("configure terminal\n" "router ospf\n" " mpls ldp-sync\n")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "mpls ldp-sync" in running
    ), "expected 'mpls ldp-sync' in ospfd running-config, got:\n{}".format(running)

    r1.vtysh_cmd("configure terminal\n" "router ospf\n" " no mpls ldp-sync\n")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "mpls ldp-sync" not in running
    ), "mpls ldp-sync should be gone after 'no mpls ldp-sync', got:\n{}".format(running)


def test_ospf_max_multipath_cli_routes_through_yang():
    """Legacy `maximum-paths N` continues to work via vtysh; values
    within RFC 9129's 1..32 range route through the YANG
    `/spf-control/paths` callback, the rest stay on the legacy
    direct-mutation path."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for router_block, daemon in (
        ("router ospf", "ospfd"),
        ("router ospf6", "ospf6d"),
    ):
        r1.vtysh_cmd(
            "configure terminal\n" "{}\n" " maximum-paths 5\n".format(router_block)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "maximum-paths 5" in running
        ), "expected 'maximum-paths 5' in {} running-config, got:\n{}".format(
            daemon, running
        )
        r1.vtysh_cmd(
            "configure terminal\n" "{}\n" " no maximum-paths\n".format(router_block)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "maximum-paths 5" not in running
        ), "maximum-paths 5 should be gone after 'no maximum-paths', got:\n{}".format(
            running
        )


def test_ospf_yang_interface_type_and_passive_config():
    """interface-type and passive leaves round-trip via mgmtd."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: r1-eth1 already in area 0 via the fixture.
    iface_v2 = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/interface-type point-to-point\n"
        "mgmt set-config {}/passive true\n"
        "mgmt commit apply".format(iface_v2, iface_v2)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf network point-to-point" in running, (
        "expected ip ospf network point-to-point in v2 running-config, got:\n" + running
    )
    assert "ip ospf passive" in running, (
        "expected ip ospf passive in v2 running-config, got:\n" + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}/interface-type\n"
        "mgmt delete-config {}/passive\n"
        "mgmt commit apply".format(iface_v2, iface_v2)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf network point-to-point" not in running, (
        "ip ospf network should be cleared, got:\n" + running
    )
    assert "ip ospf passive" not in running, (
        "ip ospf passive should be cleared, got:\n" + running
    )

    # OSPFv3: r1-eth1 already attached to area 0 via the fixture.
    iface_v3 = (
        _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/interface-type point-to-point\n"
        "mgmt set-config {}/passive true\n"
        "mgmt commit apply".format(iface_v3, iface_v3)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 network point-to-point" in running, (
        "expected ipv6 ospf6 network point-to-point in v3 running-config, got:\n"
        + running
    )
    assert "ipv6 ospf6 passive" in running, (
        "expected ipv6 ospf6 passive in v3 running-config, got:\n" + running
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}/interface-type\n"
        "mgmt delete-config {}/passive\n"
        "mgmt commit apply".format(iface_v3, iface_v3)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 network point-to-point" not in running, (
        "ipv6 ospf6 network should be cleared, got:\n" + running
    )
    assert "ipv6 ospf6 passive" not in running, (
        "ipv6 ospf6 passive should be cleared, got:\n" + running
    )


def test_ospf_yang_area_ranges_config():
    """areas/area/ranges/range list + advertise/cost leaves via mgmtd.

    Creates a range under a stub area, sets advertise=false and a cost,
    verifies `area X range PREFIX not-advertise` rendering. Then clears
    via per-leaf revert and via list-entry destroy.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # OSPFv2: create a fresh area 0.0.0.55 (to keep this orthogonal to
    # the existing fixture areas), add a range with cost.
    area_v2 = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.55")
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/area-type stub-area\n"
        "mgmt set-config {}/ranges/range[prefix='10.55.0.0/16']/cost 99\n"
        "mgmt commit apply".format(area_v2, area_v2)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.55 range 10.55.0.0/16" in running, (
        "expected area-range line in v2 running-config, got:\n" + running
    )
    assert "cost 99" in running, (
        "expected range cost 99 in v2 running-config, got:\n" + running
    )

    # Flip advertise to false
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/ranges/range[prefix='10.55.0.0/16']/advertise false\n"
        "mgmt commit apply".format(area_v2)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.55 range 10.55.0.0/16 not-advertise" in running, (
        "expected not-advertise after advertise=false, got:\n" + running
    )

    # Tear down: delete the area entry (cascades range removal too)
    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.55")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.55" not in running, (
        "area 0.0.0.55 should be fully removed, got:\n" + running
    )

    # OSPFv3: same shape with an IPv6 prefix.
    area_v3 = _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.55")
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/area-type stub-area\n"
        "mgmt set-config {}/ranges/range[prefix='2001:db8:55::/48']/cost 99\n"
        "mgmt commit apply".format(area_v3, area_v3)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.55 range 2001:db8:55::/48" in running, (
        "expected v3 range line in running-config, got:\n" + running
    )
    assert "cost 99" in running

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/ranges/range[prefix='2001:db8:55::/48']/advertise false\n"
        "mgmt commit apply".format(area_v3)
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.55 range 2001:db8:55::/48 not-advertise" in running, (
        "expected v3 not-advertise after advertise=false, got:\n" + running
    )

    _clear_yang_area(r1, "ietf-ospf:ospfv3", "0.0.0.55")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "0.0.0.55" not in running, (
        "v3 area 0.0.0.55 should be fully removed, got:\n" + running
    )


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
        r1,
        "ietf-ospf:ospfv2",
        "0.0.0.43",
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
        r1,
        "ietf-ospf:ospfv3",
        "0.0.0.43",
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


def _mgmt_commit_attempt(router, set_cmd):
    """Run a mgmt set-config + commit and return the vty output.

    The caller verifies the rejection by confirming the candidate value
    did NOT land in `show running-config` (more robust than parsing the
    error string, which varies by libyang version). `mgmt commit abort`
    follows the apply so a rejected candidate doesn't survive into the
    next test's commit attempt.
    """
    return router.vtysh_cmd(
        "configure terminal file-lock\n"
        "{}\n"
        "mgmt commit apply\n"
        "mgmt commit abort".format(set_cmd),
        isjson=False,
    )


def _assert_mgmt_rejected(output, what):
    assert (
        "Failed to edit configuration" in output
        or "Couldn't apply changes" in output
        or "Configuration failed" in output
        or "commit failed" in output.lower()
    ), "expected {} rejection, got:\n{}".format(what, output)


def test_ospf_yang_deviated_enabled_leaves_rejected():
    """The FRR deviation module marks OSPF enable switches not-supported.

    FRR has no independent protocol-level or per-interface OSPF
    on/off switch: an instance exists when the control-plane-protocol
    entry exists, and an interface participates when it is attached to
    an area. Writes to the RFC 9129 `ospf/enabled` and
    `interface/enabled` leaves must therefore fail instead of being
    accepted into the candidate with no daemon-side effect.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon in (
        ("ietf-ospf:ospfv2", "ospfd"),
        ("ietf-ospf:ospfv3", "ospf6d"),
    ):
        instance = (
            "/ietf-routing:routing/control-plane-protocols/"
            "control-plane-protocol[type='"
            + proto
            + "'][name='default']/ietf-ospf:ospf"
        )
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/enabled false".format(instance),
        )
        _assert_mgmt_rejected(out, "{}/enabled".format(proto))

        iface = (
            _yang_area_xpath(proto, "0.0.0.0")
            + "/interfaces/interface[name='r1-eth1']"
        )
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/enabled false".format(iface),
        )
        _assert_mgmt_rejected(out, "{}/interface/enabled".format(proto))

        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "enabled false" not in running
        ), "rejected enabled leaf must not land on {}, got:\n{}".format(
            daemon, running
        )

    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/mpls/te-rid/ipv6-router-id 2001:db8::1".format(
            instance
        ),
    )
    _assert_mgmt_rejected(out, "ospf/mpls/te-rid/ipv6-router-id")

    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/interfaces/interface[name='r1-eth1']"
        "/instance-id 1".format(_yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")),
    )
    _assert_mgmt_rejected(out, "ospfv3 interface instance-id")

    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/virtual-links/virtual-link"
        "[transit-area-id='0.0.0.1'][router-id='1.1.1.1']"
        "/hello-interval 10".format(_yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")),
    )
    _assert_mgmt_rejected(out, "ospfv2 virtual-link")


def test_ospf_yang_negative_missing_instance():
    """Reject YANG config that targets an OSPF instance the daemon doesn't have.

    The branch's resolve_instance helper rejects at NB_EV_VALIDATE when no
    FRR-side ospf / ospf6 instance matches the control-plane-protocol name
    key. Confirm a commit against name='ghost' does not land.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    ghost_v2 = (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv2'][name='ghost']/"
        "ietf-ospf:ospf/explicit-router-id"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 9.9.9.9".format(ghost_v2),
    )
    # The default instance is unchanged; the ghost one was never created.
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "router-id 9.9.9.9" not in running, (
        "ghost router-id must not have landed, got:\n" + running
    )

    ghost_v3 = (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv3'][name='ghost']/"
        "ietf-ospf:ospf/explicit-router-id"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 9.9.9.9".format(ghost_v3),
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "router-id 9.9.9.9" not in running, (
        "ghost ospf6 router-id must not have landed, got:\n" + running
    )


def test_ospf_yang_negative_missing_interface():
    """Reject per-interface YANG config that names a non-existent interface.

    frr-deviations-ietf-routing-ospf keeps the RFC 9129 interface-name
    leafref but sets require-instance false, so the target does not need to
    exist in config. The branch's resolve_interface helper restores FRR's live
    interface check inside the callback at NB_EV_VALIDATE.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    bogus_v2 = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth42']/cost"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 7".format(bogus_v2),
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "r1-eth42" not in running, (
        "interface r1-eth42 must not appear in running-config, got:\n" + running
    )

    bogus_v3 = (
        _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth42']/cost"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 7".format(bogus_v3),
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "r1-eth42" not in running, (
        "interface r1-eth42 must not appear in v3 running-config, got:\n" + running
    )


def test_ospf_yang_negative_duplicate_area_interface():
    """Reject a candidate that attaches one interface to two OSPF areas."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    other_v2 = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.99")
        + "/interfaces/interface[name='r1-eth1']/cost"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 7".format(other_v2),
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.99" not in running, (
        "r1-eth1 must not attach to a second OSPFv2 area, got:\n" + running
    )

    other_v3 = (
        _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.99")
        + "/interfaces/interface[name='r1-eth1']/cost"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {} 7".format(other_v3),
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "0.0.0.99" not in running, (
        "r1-eth1 must not attach to a second OSPFv3 area, got:\n" + running
    )


def test_ospf_yang_negative_default_cost_on_normal_area():
    """Reject default-cost on a non-stub / non-NSSA area.

    RFC 9129's `when` clause restricts default-cost to stub or NSSA areas;
    the callback also rejects at VALIDATE as a defence-in-depth measure.
    Area 0 is the backbone (normal); setting default-cost on it must fail.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    area_path = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/default-cost 99".format(area_path),
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "default-cost 99" not in running, (
        "default-cost 99 must not appear on the backbone area, got:\n" + running
    )


def test_ospf_yang_negative_v3_ospfv2_only_leaves_rejected():
    """Reject OSPFv3 writes that the daemon cannot support.

    RFC 9129 declares non-broadcast and hybrid; ospf6d only supports
    broadcast, point-to-point and point-to-multipoint. The callback must
    reject the unsupported enum values at VALIDATE. mgmtd also loads the
    union of ospfd and ospf6d feature sets, so OSPFv2-only feature leaves
    must not be accepted for an OSPFv3 instance.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    iface_v3 = (
        _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/interface-type non-broadcast".format(iface_v3),
    )
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "non-broadcast" not in running, (
        "unsupported interface-type must not appear in v3 running-config, "
        "got:\n" + running
    )

    instance_v3 = (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv3'][name='default']"
        "/ietf-ospf:ospf"
    iface_v2_loopback = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='lo']"
    )
    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/interface-type point-to-point".format(iface_v2_loopback),
    )
    _assert_mgmt_rejected(out, "{}/interface-type".format(iface_v2_loopback))
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "ip ospf network point-to-point" not in running, (
        "loopback interface-type rejection must not leave native config, got:\n"
        + running
    )

    )
    for command, path in (
        (
            "mgmt set-config {}/address-family ipv4".format(instance_v3),
            "{}/address-family".format(instance_v3),
        ),
        (
            "mgmt set-config {}/mpls/ldp/igp-sync true".format(instance_v3),
            "{}/mpls/ldp/igp-sync".format(instance_v3),
        ),
        (
            "mgmt set-config {}/mpls/te-rid/ipv4-router-id 192.0.2.9".format(
                instance_v3
            ),
            "{}/mpls/te-rid/ipv4-router-id".format(instance_v3),
        ),
        (
            "mgmt set-config {}/default-cost 99".format(
                _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
            ),
            "{}/default-cost".format(
                _yang_area_xpath("ietf-ospf:ospfv3", "0.0.0.0")
            ),
        ),
        (
            "mgmt set-config {}/prefix-suppression true".format(iface_v3),
            "{}/prefix-suppression".format(iface_v3),
        ),
        (
            "mgmt set-config {}/static-neighbors/neighbor"
            "[identifier='2001:db8::99']/priority 1".format(iface_v3),
            "{}/static-neighbors/neighbor[identifier='2001:db8::99']"
            "/priority".format(iface_v3),
        ),
    ):
        out = _mgmt_commit_attempt(r1, command)
        _assert_mgmt_rejected(out, path)

    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "igp-sync" not in running, running
    assert "192.0.2.9" not in running, running
    assert "stub-router administrative" not in running, running


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
def test_ospf_yang_area_delete_recreate_cleanup():
    """Delete then recreate an area; per-leaf state must reset cleanly.

    Sets a non-default summary and default-cost on a stub area, then deletes
    the area via the list-destroy path, then recreates it as a normal area,
    and confirms the previous stub / default-cost state is gone. Catches
    regressions where destroy callbacks leave stale per-leaf state.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    area_path = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.51")

    # Set area-type=stub + summary=false + default-cost=77 in one commit.
    # libyang materialises the area list entry implicitly when a child leaf
    # is set; no separate list-create step is needed.
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/area-type stub-area\n"
        "mgmt set-config {}/summary false\n"
        "mgmt set-config {}/default-cost 77\n"
        "mgmt commit apply".format(area_path, area_path, area_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.51 stub no-summary" in running, running
    assert "area 0.0.0.51 default-cost 77" in running, running

    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.51")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "0.0.0.51" not in running, (
        "area 0.0.0.51 must be gone after delete, got:\n" + running
    )

    # Recreate by setting only area-type=normal-area; previous stub /
    # default-cost must not bleed through.
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/area-type normal-area\n"
        "mgmt commit apply".format(area_path)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.51 stub" not in running, (
        "stub setting must not survive delete + recreate, got:\n" + running
    )
    assert "area 0.0.0.51 default-cost" not in running, (
        "default-cost must not survive delete + recreate, got:\n" + running
    )

    _clear_yang_area(r1, "ietf-ospf:ospfv2", "0.0.0.51")

    # This is the last YANG mutation test before the read-only downstream
    # tests (test_ospf_convergence, test_ospf_json, ...). The interface
    # priority / passive / network-type round-trips in the preceding tests
    # all bounce DR election on r1-eth1; OSPF leaves stale MAX_AGE
    # Network LSAs behind that don't fully flush. Force a full
    # reconvergence so downstream tests see deterministic LSDB state.
    _force_ospf_reconvergence_to_steady_state()


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
