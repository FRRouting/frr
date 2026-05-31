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


def _yang_get_running_config(router, xpath, with_defaults=False):
    defaults = " with-defaults all" if with_defaults else ""

    return json.loads(
        router.vtysh_cmd(
            "show mgmt get-data {} datastore running only-config exact{}".format(
                xpath, defaults
            )
        )
    )

def _yang_xpath_subscription(router, xpath):
    return router.vtysh_cmd("show mgmt yang-xpath-subscription {}".format(xpath))


def _ospf_interface_bfd_state(router, daemon, interface):
    if daemon == "ospfd":
        cmd = "show ip ospf interface {} json".format(interface)
        data = json.loads(router.vtysh_cmd(cmd))
        return data["interfaces"][interface]["peerBfdInfo"]

    cmd = "show ipv6 ospf6 interface {} json".format(interface)
    data = json.loads(router.vtysh_cmd(cmd))
    return data[interface]["peerBfdInfo"]


def _ospf_interface_timers(router, daemon, interface):
    if daemon == "ospfd":
        cmd = "show ip ospf interface {} json".format(interface)
        data = json.loads(router.vtysh_cmd(cmd))
        ifdata = data["interfaces"][interface]
        return ifdata["timerMsecs"] // 1000, ifdata["timerDeadSecs"]

    cmd = "show ipv6 ospf6 interface {} json".format(interface)
    data = json.loads(router.vtysh_cmd(cmd))
    ifdata = data[interface]
    return (
        ifdata["timerIntervalsConfigHello"],
        ifdata["timerIntervalsConfigDead"],
    )


def _assert_interface_default_leaves(router, iface):
    data = _yang_get_running_config(router, iface, with_defaults=True)
    text = json.dumps(data, sort_keys=True)

    for expected in (
        '"hello-interval": 10',
        '"dead-interval": 40',
        '"retransmit-interval": 5',
        '"priority": 1',
        '"mtu-ignore": false',
    ):
        assert expected in text, (
            "expected advertised FRR default {} under {}, got:\n{}"
        ).format(expected, iface, json.dumps(data, indent=2, sort_keys=True))


def _assert_interface_transmit_delay_default(router, iface):
    data = _yang_get_running_config(router, iface, with_defaults=True)
    text = json.dumps(data, sort_keys=True)

    assert '"transmit-delay": 1' in text, (
        "expected advertised FRR transmit-delay default under {}, got:\n{}"
    ).format(iface, json.dumps(data, indent=2, sort_keys=True))


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


def _yang_protocol_xpath(protocol_type, name):
    return (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='" + protocol_type + "'][name='" + name + "']"
    )


def _yang_named_explicit_router_id_xpath(protocol_type, name):
    return (
        _yang_protocol_xpath(protocol_type, name) + "/ietf-ospf:ospf/explicit-router-id"
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


def _mgmt_merge_json_and_commit(router, data):
    router.vtysh_cmd(
        "configure terminal\n"
        "mgmt edit merge / json lock commit {}".format(
            json.dumps(data, separators=(",", ":"))
        )
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

    r1.vtysh_cmd("configure terminal\nrouter ospf\n area 0.0.0.53 nssa\n")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.53 nssa" in running, running
    r1.vtysh_cmd("configure terminal\nrouter ospf\n no area 0.0.0.53 stub\n")
    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.53 nssa" in running, running
    r1.vtysh_cmd("configure terminal\nrouter ospf\n no area 0.0.0.53 nssa\n")

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
    _assert_interface_default_leaves(r1, iface)
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/hello-interval 6\n"
        "mgmt commit apply".format(iface)
    )
    hello, dead = _ospf_interface_timers(r1, "ospfd", "r1-eth1")
    assert (hello, dead) == (6, 24), (
        "expected dead-interval to re-derive after deleting the explicit "
        "dead leaf, got hello={} dead={}".format(hello, dead)
    )
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
    _assert_interface_default_leaves(r1, iface)
    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/hello-interval 6\n"
        "mgmt commit apply".format(iface)
    )
    hello, dead = _ospf_interface_timers(r1, "ospf6d", "r1-eth1")
    assert (hello, dead) == (6, 40), (
        "expected dead-interval to return to the FRR default after "
        "deleting the explicit dead leaf, got hello={} dead={}".format(
            hello, dead
        )
    )
    _restore_r1_eth1_fixture_timers(r1, "ietf-ospf:ospfv3")
    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "ipv6 ospf6 hello-interval 2" in running, running
    assert "ipv6 ospf6 dead-interval 10" in running, running


def test_ospf_yang_area_interface_transmit_delay_config():
    """areas/area[id]/interfaces/interface[name]/transmit-delay via mgmtd.

    Round-trips the per-interface transmit-delay leaf on both
    daemons: set via mgmt, verify in `show running-config`, delete
    via mgmt, verify the line is gone and FRR is back at the
    advertised FRR default of 1 second.
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
    _assert_interface_transmit_delay_default(r1, iface_path)

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
    _assert_interface_transmit_delay_default(r1, iface_path)


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


def test_ospf_yang_auto_cost_reference_bandwidth_config():
    """per-instance /auto-cost/reference-bandwidth round-trip via mgmtd
    on both daemons.  RFC 9129 wraps the leaf in a `when ../enabled
    = 'true'` constraint; the deviation file pins enabled to true so
    a bare reference-bandwidth set works without first toggling
    enabled.  Setting enabled=false is rejected at NB_EV_VALIDATE
    because FRR has no off-switch for auto-cost; a separate negative
    test exercises that path."""
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

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/auto-cost/reference-bandwidth 50000\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "auto-cost reference-bandwidth 50000" in running
        ), "expected 'auto-cost reference-bandwidth 50000' after YANG set, got:\n{}".format(
            running
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/auto-cost/reference-bandwidth\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "auto-cost reference-bandwidth 50000" not in running
        ), "'auto-cost reference-bandwidth 50000' should be gone after YANG delete, got:\n{}".format(
            running
        )


def test_ospf_yang_auto_cost_disable_rejected():
    """Setting /auto-cost/enabled=false is rejected at NB_EV_VALIDATE on
    both daemons -- FRR has no mechanism to honour an auto-cost
    off-switch; the validate callback returns NB_ERR_VALIDATION with
    the documented error message.

    Uses `_mgmt_commit_attempt` so the rejected candidate edit is
    aborted before returning, otherwise the bad `enabled=false` value
    survives in the candidate datastore and poisons every subsequent
    mgmt commit in the same test session.
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
            "mgmt set-config {}/auto-cost/enabled false".format(instance),
        )
        assert (
            "FRR auto-cost cannot be disabled" in out
        ), "expected validate-time rejection for {}, got:\n{}".format(proto, out)
        # And confirm nothing actually landed.
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "no auto-cost" not in running
        ), "rejected auto-cost disable must not appear in running-config, got:\n{}".format(
            running
        )


def test_ospf_auto_cost_cli_routes_through_yang():
    """Legacy `auto-cost reference-bandwidth N` / `no ...` on both
    daemons drives the YANG /auto-cost/reference-bandwidth callback."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for router_block, daemon in (
        ("router ospf", "ospfd"),
        ("router ospf6", "ospf6d"),
    ):
        r1.vtysh_cmd(
            "configure terminal\n"
            "{}\n"
            " auto-cost reference-bandwidth 25000\n".format(router_block)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "auto-cost reference-bandwidth 25000" in running
        ), "expected legacy CLI to land 25000 on {}, got:\n{}".format(daemon, running)

        r1.vtysh_cmd(
            "configure terminal\n"
            "{}\n"
            " no auto-cost reference-bandwidth\n".format(router_block)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "auto-cost reference-bandwidth 25000" not in running
        ), "'auto-cost reference-bandwidth 25000' should be gone after 'no', got:\n{}".format(
            running
        )


def test_ospf_yang_mpls_te_router_addr_config():
    """per-instance /mpls/te-rid/ipv4-router-id round-trip via mgmtd
    (OSPFv2 only -- ospf6d has no MPLS-TE module).

    MPLS-TE state is a process-wide global in FRR.  The running-config
    writer only emits `mpls-te router-address` once `mpls-te on` has
    been set, so the test enables MPLS-TE up front and tears it down at
    the end.  Cleanup is mandatory: the global `OspfMplsTE` would
    otherwise survive across tests and corrupt later assertions.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    instance = (
        "/ietf-routing:routing/control-plane-protocols/"
        "control-plane-protocol[type='ietf-ospf:ospfv2']"
        "[name='default']/ietf-ospf:ospf"
    )

    try:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " mpls-te on\n"
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/mpls/te-rid/ipv4-router-id 10.99.0.1\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "mpls-te router-address 10.99.0.1" in running
        ), "expected 'mpls-te router-address 10.99.0.1' after YANG set, got:\n{}".format(
            running
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/mpls/te-rid/ipv4-router-id\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "mpls-te router-address" not in running
        ), "'mpls-te router-address' should be gone after YANG delete, got:\n{}".format(
            running
        )
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " no mpls-te\n"
        )


def test_ospf_mpls_te_router_addr_cli_routes_through_yang():
    """Legacy `mpls-te router-address A.B.C.D` drives the YANG
    /mpls/te-rid/ipv4-router-id callback (OSPFv2 only).

    The legacy CLI never exposed a `no mpls-te router-address` form
    (operators clear the value by disabling MPLS-TE wholesale via
    `no mpls-te`).  We preserve that semantics; the targeted clear is
    only available through `mgmt delete-config` and is exercised by
    `test_ospf_yang_mpls_te_router_addr_config`.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    try:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " mpls-te on\n"
            " mpls-te router-address 10.99.0.2\n"
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "mpls-te router-address 10.99.0.2" in running
        ), "expected legacy CLI to land 10.99.0.2, got:\n{}".format(running)
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " no mpls-te\n"
        )


def test_ospf_yang_graceful_restart_config():
    """per-instance /graceful-restart/{enabled,restart-interval} round-trip
    via mgmtd on both daemons.

    RFC 9129 defaults restart-interval to 120s; FRR's compile-time
    defaults (`OSPF_DFLT_GRACE_INTERVAL` / `OSPF6_DFLT_GRACE_INTERVAL`)
    are also 120s, so no deviation is needed.  The two leaves are
    independent in the YANG model but the legacy CLI ties them
    together (`graceful-restart [grace-period N]`); both behaviours
    are exercised here.
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

        # Set enabled=true with a non-default restart-interval.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/graceful-restart/enabled true\n"
            "mgmt set-config {}/graceful-restart/restart-interval 240\n"
            "mgmt commit apply".format(instance, instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "graceful-restart grace-period 240" in running
        ), "expected 'graceful-restart grace-period 240' on {}, got:\n{}".format(
            daemon, running
        )

        # Drop the restart-interval alone -- enabled stays true,
        # period restores to the FRR default 120s.  The legacy
        # writer collapses that to bare `graceful-restart`.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/graceful-restart/restart-interval\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "graceful-restart\n" in running and "grace-period" not in running
        ), "expected bare 'graceful-restart' on {} after interval delete, got:\n{}".format(
            daemon, running
        )

        # And tear it all down.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/graceful-restart/enabled\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "graceful-restart" not in running
        ), "'graceful-restart' should be gone on {} after disable, got:\n{}".format(
            daemon, running
        )


def test_ospf_yang_graceful_restart_helper_config():
    """per-instance /graceful-restart/{helper-enabled,helper-strict-lsa-checking}
    round-trip via mgmtd on both daemons.

    FRR defaults strict-lsa-checking to true; the running-config
    writer only emits a line when the leaf is false, so the test
    asserts the line appears after a false write and disappears after
    delete.  Helper-enabled appears in running-config as
    `graceful-restart helper enable` on both daemons.
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

        # Enable helper + relax strict-lsa-checking.  v3's writer
        # emits `lsa-check-disable`; v2's emits the negated positive
        # form `no ... strict-lsa-checking` -- the assertion below
        # accepts either.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/graceful-restart/helper-enabled true\n"
            "mgmt set-config {}/graceful-restart/helper-strict-lsa-checking false\n"
            "mgmt commit apply".format(instance, instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "graceful-restart helper enable" in running
        ), "expected helper enable line on {}, got:\n{}".format(daemon, running)
        assert (
            "lsa-check-disable" in running
            or "no graceful-restart helper strict-lsa-checking" in running
        ), "expected relaxed strict-lsa-check on {}, got:\n{}".format(
            daemon, running
        )

        # Drop strict-lsa-checking alone -- helper stays on, strict
        # check restores to FRR's default true (line disappears).
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/graceful-restart/helper-strict-lsa-checking\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "lsa-check-disable" not in running
            and "no graceful-restart helper strict-lsa-checking" not in running
        ), "strict-lsa-check line should be gone after delete on {}, got:\n{}".format(
            daemon, running
        )

        # And tear down helper.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/graceful-restart/helper-enabled\n"
            "mgmt commit apply".format(instance)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            "graceful-restart helper enable" not in running
        ), "'graceful-restart helper enable' should be gone on {}, got:\n{}".format(
            daemon, running
        )


def test_ospf_graceful_restart_helper_cli_routes_through_yang():
    """Legacy helper CLI on both daemons drives the YANG callbacks.

    v3's `lsa-check-disable` CLI is inverted from v2's strict-lsa-
    checking form; the DEFPY_YANG shim flips the meaning before
    enqueueing.  Verified by toggling each daemon's relax form and
    confirming the line appears, then dropping it and confirming the
    line is gone.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for router_block, daemon, relax, relax_off in (
        ("router ospf", "ospfd",
         "no graceful-restart helper strict-lsa-checking",
         "graceful-restart helper strict-lsa-checking"),
        ("router ospf6", "ospf6d",
         "graceful-restart helper lsa-check-disable",
         "no graceful-restart helper lsa-check-disable"),
    ):
        try:
            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " graceful-restart helper enable\n"
                " {}\n".format(router_block, relax)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                "graceful-restart helper enable" in running
            ), "expected helper enable on {}, got:\n{}".format(daemon, running)
            assert (
                "lsa-check-disable" in running
                or "no graceful-restart helper strict-lsa-checking" in running
            ), "expected relaxed strict-lsa-check on {}, got:\n{}".format(
                daemon, running
            )

            # Restore strict-lsa-check default.
            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " {}\n".format(router_block, relax_off)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                "lsa-check-disable" not in running
                and "no graceful-restart helper strict-lsa-checking" not in running
            ), "strict-lsa-check should be back to default on {}, got:\n{}".format(
                daemon, running
            )
        finally:
            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " no graceful-restart helper enable\n".format(router_block)
            )


def test_ospf_graceful_restart_cli_routes_through_yang():
    """Legacy `graceful-restart [grace-period N]` / `no graceful-restart`
    on both daemons drive the YANG /graceful-restart callbacks."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for router_block, daemon in (
        ("router ospf", "ospfd"),
        ("router ospf6", "ospf6d"),
    ):
        try:
            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " graceful-restart grace-period 180\n".format(router_block)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                "graceful-restart grace-period 180" in running
            ), "expected legacy CLI to land GR period 180 on {}, got:\n{}".format(
                daemon, running
            )

            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " no graceful-restart\n".format(router_block)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                "graceful-restart" not in running
            ), "'graceful-restart' should be gone on {} after legacy 'no', got:\n{}".format(
                daemon, running
            )
        finally:
            r1.vtysh_cmd(
                "configure terminal\n"
                "{}\n"
                " no graceful-restart\n".format(router_block)
            )


def test_ospf_yang_prefix_suppression_config():
    """per-interface prefix-suppression round-trip via mgmtd (OSPFv2 only)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt set-config {}/prefix-suppression true\n"
        "mgmt commit apply".format(iface)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "ip ospf prefix-suppression" in running
    ), "expected 'ip ospf prefix-suppression' after YANG set, got:\n{}".format(running)

    r1.vtysh_cmd(
        "configure terminal file-lock\n"
        "mgmt delete-config {}/prefix-suppression\n"
        "mgmt commit apply".format(iface)
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "ip ospf prefix-suppression" not in running
    ), "'ip ospf prefix-suppression' should be gone after YANG delete, got:\n{}".format(
        running
    )


def test_ospf_yang_interface_bfd_config():
    """per-interface BFD round-trip via mgmtd on both daemons.

    Exercises the four leaves under .../interface/bfd: enabled (the
    presence-style on/off), local-multiplier, and the tx/rx interval
    pair.  The RFC unit is microseconds; FRR stores milliseconds and
    NB_EV_VALIDATE rejects non-multiple-of-1000 values, so the test
    writes whole-millisecond microsecond values (300000us = 300ms,
    400000us = 400ms).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon, expect_line in (
        ("ietf-ospf:ospfv2", "ospfd", "ip ospf bfd"),
        ("ietf-ospf:ospfv3", "ospf6d", "ipv6 ospf6 bfd"),
    ):
        iface = (
            _yang_area_xpath(proto, "0.0.0.0")
            + "/interfaces/interface[name='r1-eth1']"
        )

        # Enable BFD with non-default timers.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/bfd/enabled true\n"
            "mgmt set-config {}/bfd/local-multiplier 5\n"
            "mgmt set-config {}/bfd/desired-min-tx-interval 400000\n"
            "mgmt set-config {}/bfd/required-min-rx-interval 400000\n"
            "mgmt commit apply".format(iface, iface, iface, iface)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            expect_line in running
        ), "expected '{}' on {} after YANG set, got:\n{}".format(
            expect_line, daemon, running
        )
        bfd_data = _yang_get_running_config(r1, "{}/bfd".format(iface))
        bfd_text = json.dumps(bfd_data)
        assert "5" in bfd_text, (
            "same-transaction BFD multiplier was not retained for {}, got:\n{}"
        ).format(proto, json.dumps(bfd_data, indent=2))
        assert "400000" in bfd_text, (
            "same-transaction BFD intervals were not retained for {}, got:\n{}"
        ).format(proto, json.dumps(bfd_data, indent=2))

        # Disable BFD by deleting the explicit enabled leaf.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/bfd/enabled\n"
            "mgmt commit apply".format(iface)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            expect_line not in running
        ), "'{}' should be gone on {} after YANG delete, got:\n{}".format(
            expect_line, daemon, running
        )

        # Remove the explicit timer leaves, then enable BFD with no timer
        # values. The YANG deviations advertise FRR defaults in microseconds;
        # the daemon applies the same values in milliseconds.
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/bfd/local-multiplier\n"
            "mgmt delete-config {}/bfd/desired-min-tx-interval\n"
            "mgmt delete-config {}/bfd/required-min-rx-interval\n"
            "mgmt set-config {}/bfd/enabled true\n"
            "mgmt commit apply".format(iface, iface, iface, iface)
        )
        bfd_data = _yang_get_running_config(
            r1, "{}/bfd".format(iface), with_defaults=True
        )
        bfd_text = json.dumps(bfd_data)
        assert "300000" in bfd_text, (
            "YANG BFD defaults must track FRR 300ms timers for {}, got:\n{}"
        ).format(proto, json.dumps(bfd_data, indent=2))
        bfd_state = _ospf_interface_bfd_state(r1, daemon, "r1-eth1")
        assert bfd_state["rxMinInterval"] == 300, bfd_state
        assert bfd_state["txMinInterval"] == 300, bfd_state

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/bfd/enabled\n"
            "mgmt commit apply".format(iface)
        )


def test_ospf_yang_interface_bfd_interval_rejection():
    """NB_EV_VALIDATE rejects BFD interval values that are not whole
    milliseconds (multiple of 1000 us) or fall outside FRR's 50..60000
    ms grammar on both daemons.  The unsupported single-interval BFD
    form is also rejected by the FRR deviation module.  Uses
    `_mgmt_commit_attempt` so the rejected candidate is aborted and
    does not poison subsequent commits.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon, expect_line in (
        ("ietf-ospf:ospfv2", "ospfd", "ip ospf bfd"),
        ("ietf-ospf:ospfv3", "ospf6d", "ipv6 ospf6 bfd"),
    ):
        iface = (
            _yang_area_xpath(proto, "0.0.0.0")
            + "/interfaces/interface[name='r1-eth1']"
        )
        # Parameter leaves can be configured while BFD is disabled, but they
        # do not independently activate BFD.
        out = r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/bfd/local-multiplier 6\n"
            "mgmt commit apply".format(iface)
        )
        assert "commit failed" not in out.lower(), out
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert (
            expect_line not in running
        ), "'{}' should stay disabled after parameter-only YANG set, got:\n{}".format(
            expect_line, running
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/bfd/enabled true\n"
            "mgmt commit apply".format(iface)
        )
        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert expect_line in running, "BFD was not enabled for {}, got:\n{}".format(
            proto, running
        )
        bfd_data = _yang_get_running_config(r1, "{}/bfd".format(iface))
        assert "6" in json.dumps(bfd_data), (
            "staged BFD multiplier was not retained in running datastore "
            "for {}, got:\n{}".format(proto, json.dumps(bfd_data, indent=2))
        )
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}/bfd/enabled\n"
            "mgmt commit apply".format(iface)
        )

        # Not a multiple of 1000us.
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/bfd/enabled true\n"
            "mgmt set-config {}/bfd/desired-min-tx-interval 300500".format(
                iface, iface
            ),
        )
        assert (
            "Failed to edit configuration" in out
            or "Couldn't apply changes" in out
            or "Configuration failed" in out
            or "commit failed" in out
        ), "expected commit rejection on {}, got:\n{}".format(proto, out)
        # FRR exposes the tx/rx interval form only, not the single
        # min-interval case from ietf-bfd-types.
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/bfd/min-interval 300000".format(iface),
        )
        assert (
            "Failed to edit configuration" in out
            or "Couldn't apply changes" in out
        ), "expected single-interval rejection on {}, got:\n{}".format(proto, out)
        # Below 50ms.
        out = _mgmt_commit_attempt(
            r1,
            "mgmt set-config {}/bfd/enabled true\n"
            "mgmt set-config {}/bfd/required-min-rx-interval 1000".format(
                iface, iface
            ),
        )
        assert (
            "Failed to edit configuration" in out
            or "Couldn't apply changes" in out
            or "Configuration failed" in out
            or "commit failed" in out
        ), "expected commit rejection on {}, got:\n{}".format(proto, out)


def test_ospf_bfd_cli_routes_through_yang():
    """Legacy BFD CLI on both daemons drives the YANG callback when
    the interface is in an area. Also confirms legacy `no` removes the
    configured timers so a later bare enable uses FRR default timers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, cli, daemon, expect in (
        ("ietf-ospf:ospfv2", "ip ospf bfd", "ospfd", "ip ospf bfd"),
        (
            "ietf-ospf:ospfv3",
            "ipv6 ospf6 bfd",
            "ospf6d",
            "ipv6 ospf6 bfd",
        ),
    ):
        iface = (
            _yang_area_xpath(proto, "0.0.0.0")
            + "/interfaces/interface[name='r1-eth1']"
        )

        try:
            r1.vtysh_cmd(
                "configure terminal\n"
                "interface r1-eth1\n"
                " {}\n".format(cli)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                expect in running
            ), "expected '{}' on {} after CLI set, got:\n{}".format(
                expect, daemon, running
            )

            r1.vtysh_cmd(
                "configure terminal file-lock\n"
                "mgmt set-config {}/bfd/enabled true\n"
                "mgmt set-config {}/bfd/local-multiplier 5\n"
                "mgmt set-config {}/bfd/desired-min-tx-interval 400000\n"
                "mgmt set-config {}/bfd/required-min-rx-interval 400000\n"
                "mgmt commit apply".format(
                    iface,
                    iface,
                    iface,
                    iface,
                )
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert expect in running, running
            bfd_data = _yang_get_running_config(r1, "{}/bfd".format(iface))
            bfd_text = json.dumps(bfd_data)
            assert "5" in bfd_text and "400000" in bfd_text, (
                "expected non-default BFD values on {}, got:\n{}".format(
                    daemon, json.dumps(bfd_data, indent=2)
                )
            )

            r1.vtysh_cmd(
                "configure terminal\n"
                "interface r1-eth1\n"
                " no {}\n".format(cli)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                expect not in running
            ), "'{}' should be gone on {} after legacy 'no', got:\n{}".format(
                expect, daemon, running
            )

            r1.vtysh_cmd(
                "configure terminal\n" "interface r1-eth1\n" " {}\n".format(cli)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert expect in running, running
            bfd_state = _ospf_interface_bfd_state(r1, daemon, "r1-eth1")
            assert bfd_state["rxMinInterval"] == 300, bfd_state
            assert bfd_state["txMinInterval"] == 300, bfd_state
            assert (
                bfd_state.get("detectionMultiplier")
                or bfd_state.get("detectMultiplier")
            ) == 3, (
                "bare BFD enable must not retain stale timers on {}, got:\n{}".format(
                    daemon, json.dumps(bfd_state, indent=2)
                )
            )
        finally:
            r1.vtysh_cmd(
                "configure terminal\n"
                "interface r1-eth1\n"
                " no {}\n".format(cli)
            )

def test_ospf_yang_interface_static_neighbor_config():
    """per-interface /static-neighbors/neighbor round-trip via mgmtd
    (OSPFv2 only -- ospf6d has no NBMA neighbour surface).

    RFC 9129 keys the list per-(area, interface, identifier).  FRR's
    NBMA table is per-(instance, addr); area/interface labels are
    stored in the candidate but ignored on the FRR side.  Exercises
    create + priority + poll-interval + destroy, then verifies the
    `cost` leaf is rejected by the deviation module.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    nbr = iface + "/static-neighbors/neighbor[identifier='192.0.2.7']"

    try:
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/poll-interval 90\n"
            "mgmt set-config {}/priority 7\n"
            "mgmt commit apply".format(nbr, nbr)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "neighbor 192.0.2.7" in running
        ), "expected 'neighbor 192.0.2.7' after YANG set, got:\n{}".format(running)
        assert (
            "poll-interval 90" in running
        ), "expected static neighbour poll interval after YANG set, got:\n{}".format(
            running
        )
        assert (
            "priority 7" in running
        ), "expected static neighbour priority after YANG set, got:\n{}".format(
            running
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt delete-config {}\n"
            "mgmt commit apply".format(nbr)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "neighbor 192.0.2.7" not in running
        ), "'neighbor 192.0.2.7' should be gone after YANG delete, got:\n{}".format(
            running
        )
    finally:
        # Defensive cleanup in case the assert above tripped.
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " no neighbor 192.0.2.7\n"
        )

def test_ospf_yang_static_neighbor_duplicate_rejected():
    """The RFC keys static-neighbors per area/interface, but FRR's NBMA
    table is per instance and address.  Reject duplicate identifiers
    rather than letting two YANG entries collapse onto one daemon
    neighbour."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    area = _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
    nbr1 = (
        area
        + "/interfaces/interface[name='r1-eth1']"
        + "/static-neighbors/neighbor[identifier='192.0.2.9']"
    )
    nbr2 = (
        area
        + "/interfaces/interface[name='r1-eth2']"
        + "/static-neighbors/neighbor[identifier='192.0.2.9']"
    )

    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/poll-interval 90\n"
        "mgmt set-config {}/priority 7".format(nbr1, nbr2),
    )
    assert (
        "already configured in this OSPF instance" in out
        or "Couldn't apply changes" in out
        or "Configuration failed" in out
        or "commit failed" in out
    ), "expected duplicate static-neighbor rejection, got:\n{}".format(out)

def test_ospf_yang_static_neighbor_partial_leaves():
    """Static-neighbor optional leaves default to FRR's NBMA values.

    RFC 9129 does not provide defaults for poll-interval or priority.
    FRR deviates them to the daemon defaults so apply_finish can read a
    complete settled subtree even when the operator creates a neighbour
    with only one optional leaf.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    nbr = iface + "/static-neighbors/neighbor[identifier='192.0.2.10']"

    try:
        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/poll-interval 90\n"
            "mgmt commit apply".format(nbr)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "neighbor 192.0.2.10 poll-interval 90" in running
        ), "expected poll-only static neighbour, got:\n{}".format(running)
        assert (
            "neighbor 192.0.2.10 priority" not in running
        ), "default static neighbour priority should not be written, got:\n{}".format(
            running
        )

        r1.vtysh_cmd(
            "configure terminal file-lock\n"
            "mgmt set-config {}/priority 7\n"
            "mgmt delete-config {}/poll-interval\n"
            "mgmt commit apply".format(nbr, nbr)
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert (
            "neighbor 192.0.2.10 priority 7" in running
        ), "expected priority-only static neighbour, got:\n{}".format(running)
        assert (
            "neighbor 192.0.2.10 poll-interval" not in running
        ), "default static neighbour poll interval should not be written, got:\n{}".format(
            running
        )
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "router ospf\n"
            " no neighbor 192.0.2.10\n"
        )

def test_ospf_yang_interface_authentication_keychain_config():
    """per-interface /authentication/ospfv2-key-chain (OSPFv2) and
    /authentication/ospfv3-key-chain (OSPFv3) round-trip via mgmtd.

    Covers only the key-chain case of the RFC 9129 authentication
    container -- the explicit-key triplet and OSPFv3 IPsec SA forms
    map onto different FRR-side surfaces and are marked not-supported
    by the FRR deviation module.

    RFC 9129 types the key-chain leaves as a leafref into
    /key-chain:key-chains/key-chain/name, so libyang rejects writes
    against not-yet-existing keychains.  Create one via the CLI
    before driving the YANG round-trip.  The legacy CLI is more
    relaxed but matching the YANG semantics is the principled
    behaviour for this slice.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Set up a real keychain so the YANG leafref resolves.
    r1.vtysh_cmd(
        "configure terminal\n"
        "key chain kc-test\n"
        " key 1\n"
        "  key-string secret\n"
    )

    try:
        for proto, daemon, leaf, expect in (
            ("ietf-ospf:ospfv2", "ospfd", "ospfv2-key-chain",
             "ip ospf authentication key-chain"),
            ("ietf-ospf:ospfv3", "ospf6d", "ospfv3-key-chain",
             "ipv6 ospf6 authentication keychain"),
        ):
            iface = (
                _yang_area_xpath(proto, "0.0.0.0")
                + "/interfaces/interface[name='r1-eth1']"
            )
            path = "{}/authentication/{}".format(iface, leaf)

            r1.vtysh_cmd(
                "configure terminal file-lock\n"
                "mgmt set-config {} kc-test\n"
                "mgmt commit apply".format(path)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                "{} kc-test".format(expect) in running
            ), "expected '{} kc-test' on {} after YANG set, got:\n{}".format(
                expect, daemon, running
            )

            r1.vtysh_cmd(
                "configure terminal file-lock\n"
                "mgmt delete-config {}\n"
                "mgmt commit apply".format(path)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert (
                expect not in running
            ), "'{}' should be gone on {} after YANG delete, got:\n{}".format(
                expect, daemon, running
            )
    finally:
        # Defensive cleanup: tear down auth + the helper keychain.
        r1.vtysh_cmd(
            "configure terminal\n"
            "interface r1-eth1\n"
            " no ip ospf authentication\n"
            " no ipv6 ospf6 authentication keychain\n"
            "exit\n"
            "no key chain kc-test\n"
        )


def test_ospf_yang_authentication_unsupported_leaves_rejected():
    """Unsupported RFC authentication choices are rejected by deviation.

    Only the key-chain case is implemented through YANG. The explicit-key,
    OSPFv2 authentication trailer and OSPFv3 IPsec SA branches remain
    legacy-CLI-only, so mgmtd must reject YANG writes instead of accepting
    config with no daemon-side effect.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, leaf, value in (
        ("ietf-ospf:ospfv2", "ospfv2-key-id", "1"),
        ("ietf-ospf:ospfv2", "ospfv2-auth-trailer-rfc", "rfc7474"),
        ("ietf-ospf:ospfv3", "sa", "SA-1"),
        ("ietf-ospf:ospfv3", "ospfv3-sa-id", "1"),
    ):
        iface = _yang_area_xpath(proto, "0.0.0.0") + "/interfaces/interface[name='r1-eth1']"
        path = "{}/authentication/{}".format(iface, leaf)
        out = _mgmt_commit_attempt(r1, "mgmt set-config {} {}".format(path, value))
        _assert_mgmt_rejected(out, "unsupported authentication leaf {}".format(leaf))

def test_ospf_yang_static_neighbor_cost_rejected():
    """The /static-neighbors/neighbor/cost leaf is marked not-supported
    in the FRR deviations because FRR has no NBMA cost knob.  mgmtd
    must reject writes against it."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    iface = (
        _yang_area_xpath("ietf-ospf:ospfv2", "0.0.0.0")
        + "/interfaces/interface[name='r1-eth1']"
    )
    nbr = iface + "/static-neighbors/neighbor[identifier='192.0.2.8']"

    out = _mgmt_commit_attempt(
        r1,
        "mgmt set-config {}/cost 50".format(nbr),
    )
    assert (
        "Failed to edit configuration" in out
        or "Couldn't apply changes" in out
        or "Configuration failed" in out
        or "commit failed" in out
    ), "expected cost rejection, got:\n{}".format(out)


def test_ospf_prefix_suppression_cli_routes_through_yang():
    """Legacy `ip ospf prefix-suppression` / `no ip ospf prefix-suppression`
    on r1-eth1 (no per-address override) drives the YANG callback."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " ip ospf prefix-suppression\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "ip ospf prefix-suppression" in running
    ), "expected 'ip ospf prefix-suppression' after CLI set, got:\n{}".format(running)

    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        " no ip ospf prefix-suppression\n"
    )
    running = r1.vtysh_cmd("show running-config ospfd")
    assert (
        "ip ospf prefix-suppression" not in running
    ), "'ip ospf prefix-suppression' should be gone after 'no', got:\n{}".format(running)


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


def test_ospf_yang_atomic_instance_create():
    """Create an OSPF instance and child config in one YANG commit.

    The control-plane-protocol list entry is the RFC 9129 OSPF instance. A
    client may create that entry and set child leaves in the same transaction,
    so child callbacks must tolerate the missing daemon instance before APPLY
    and materialise it from the same list entry during APPLY if needed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    try:
        _mgmt_merge_json_and_commit(
            r1,
            {
                "ietf-routing:routing": {
                    "control-plane-protocols": {
                        "control-plane-protocol": [
                            {
                                "type": "ietf-ospf:ospfv2",
                                "name": "ghost",
                                "ietf-ospf:ospf": {
                                    "explicit-router-id": "9.9.9.9"
                                },
                            }
                        ]
                    }
                }
            },
        )
        running = r1.vtysh_cmd("show running-config ospfd")
        assert "router ospf vrf ghost" in running, running
        assert "ospf router-id 9.9.9.9" in running, running

        _mgmt_merge_json_and_commit(
            r1,
            {
                "ietf-routing:routing": {
                    "control-plane-protocols": {
                        "control-plane-protocol": [
                            {
                                "type": "ietf-ospf:ospfv3",
                                "name": "ghost",
                                "ietf-ospf:ospf": {
                                    "explicit-router-id": "9.9.9.9"
                                },
                            }
                        ]
                    }
                }
            },
        )
        running = r1.vtysh_cmd("show running-config ospf6d")
        assert "router ospf6 vrf ghost" in running, running
        assert "ospf6 router-id 9.9.9.9" in running, running
    finally:
        _mgmt_commit_attempt(
            r1,
            "mgmt delete-config {}\n"
            "mgmt delete-config {}".format(
                _yang_protocol_xpath("ietf-ospf:ospfv2", "ghost"),
                _yang_protocol_xpath("ietf-ospf:ospfv3", "ghost"),
            ),
        )
        r1.vtysh_cmd(
            "configure terminal\n"
            "no router ospf vrf ghost\n"
            "no router ospf6 vrf ghost\n"
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


def test_ospf_yang_atomic_area_interface_move():
    """Allow an interface area move staged in a single YANG commit."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, daemon, area_id, area_cmd in (
        ("ietf-ospf:ospfv2", "ospfd", "0.0.0.91", "ip ospf area"),
        ("ietf-ospf:ospfv3", "ospf6d", "0.0.0.92", "ipv6 ospf6 area"),
    ):
        old_iface = (
            _yang_area_xpath(proto, "0.0.0.0")
            + "/interfaces/interface[name='r1-eth1']"
        )
        new_iface = (
            _yang_area_xpath(proto, area_id)
            + "/interfaces/interface[name='r1-eth1']"
        )
        new_area = _yang_area_xpath(proto, area_id)

        try:
            r1.vtysh_cmd(
                "configure terminal file-lock\n"
                "mgmt delete-config {}\n"
                "mgmt set-config {}/cost 9\n"
                "mgmt commit apply".format(old_iface, new_iface)
            )
            running = r1.vtysh_cmd("show running-config {}".format(daemon))
            assert "{} {}".format(area_cmd, area_id) in running, running
            assert "cost 9" in running, running
        finally:
            r1.vtysh_cmd(
                "configure terminal file-lock\n"
                "mgmt delete-config {}\n"
                "mgmt set-config {}/hello-interval 2\n"
                "mgmt set-config {}/dead-interval 10\n"
                "mgmt commit apply".format(new_area, old_iface, old_iface)
            )


def test_ospf_yang_negative_duplicate_area_interface_new_instance():
    """Reject duplicate area bindings while creating the OSPF instance."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    for proto, name, daemon in (
        ("ietf-ospf:ospfv2", "dupareav2", "ospfd"),
        ("ietf-ospf:ospfv3", "dupareav3", "ospf6d"),
    ):
        out = _mgmt_merge_json_attempt(
            r1,
            {
                "ietf-routing:routing": {
                    "control-plane-protocols": {
                        "control-plane-protocol": [
                            {
                                "type": proto,
                                "name": name,
                                "ietf-ospf:ospf": {
                                    "areas": {
                                        "area": [
                                            {
                                                "area-id": "0.0.0.98",
                                                "interfaces": {
                                                    "interface": [
                                                        {"name": "r1-eth1", "cost": 7}
                                                    ]
                                                },
                                            },
                                            {
                                                "area-id": "0.0.0.99",
                                                "interfaces": {
                                                    "interface": [
                                                        {"name": "r1-eth1", "cost": 8}
                                                    ]
                                                },
                                            },
                                        ]
                                    }
                                },
                            }
                        ]
                    }
                }
            },
        )
        _assert_mgmt_rejected(out, "{} duplicate area interface".format(proto))
        r1.vtysh_cmd("configure terminal\nmgmt commit abort")

        running = r1.vtysh_cmd("show running-config {}".format(daemon))
        assert name not in running, (
            "duplicate area-interface commit must not create {}, got:\n{}".format(
                name, running
            )
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


def _send_ietf_ospf_rpc(router, rpc_xpath, input_json):
    """Issue a mgmt rpc and surface the daemon-side error if any.

    mgmtd reports backend errors as `% <message>` lines in the vty output.
    Catch any '%' or 'can\\'t' / 'error' / 'fail' / 'no backends' marker so
    a parse failure or unknown-xpath dispatch doesn't slip past the
    convergence checks (OSPF was already Full before the RPC, so a no-op
    RPC would otherwise look like a pass).
    """
    out = router.vtysh_cmd(
        "configure terminal\nmgmt rpc {} json {}".format(rpc_xpath, input_json)
    )
    lowered = out.lower()
    bad = ("% ", "can't", "error", "fail", "no backends", "invalid")
    for marker in bad:
        assert marker not in lowered, (
            "RPC {} on {} returned an error (matched '{}'):\n{}".format(
                rpc_xpath, router.name, marker, out
            )
        )
    return out


def test_ospf_yang_clear_neighbor_rpc():
    """RFC 9129 /ietf-ospf:clear-neighbor round-trip on both daemons.

    Both ospfd and ospf6d register the same RPC xpath; mgmtd fans the call
    out to each backend. The daemon that owns the named instance kills its
    neighbors, the other daemon returns silently. We verify the kill by
    waiting for OSPF to renegotiate back to Full.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Pre-state: r1 must already be Full with r2 on both daemons.
    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")

    # Whole-instance reset (no `interface` filter). The libyang RPC parser
    # expects the input leaves wrapped in the RPC name, namespace-qualified.
    _send_ietf_ospf_rpc(
        r1,
        "/ietf-ospf:clear-neighbor",
        '{"ietf-ospf:clear-neighbor":{"routing-protocol-name":"default"}}',
    )

    # The kill drives every neighbor to Down; OSPF must renegotiate.
    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")

    # Per-interface reset using the RFC's optional `interface` input. r1-eth1
    # is the interface r1 shares with r2 on both v2 and v3.
    _send_ietf_ospf_rpc(
        r1,
        "/ietf-ospf:clear-neighbor",
        '{"ietf-ospf:clear-neighbor":{"routing-protocol-name":"default","interface":"r1-eth1"}}',
    )

    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")


def test_ospf_yang_clear_database_rpc():
    """RFC 9129 /ietf-ospf:clear-database round-trip on both daemons.

    Maps to `ospf_process_reset` / `ospf6_process_reset`. Flushes self-
    originated LSAs, drops all adjacencies, rebuilds. Verify by waiting
    for r1 to come back Full with r2 on both daemons.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")

    _send_ietf_ospf_rpc(
        r1,
        "/ietf-ospf:clear-database",
        '{"ietf-ospf:clear-database":{"routing-protocol-name":"default"}}',
    )

    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")
    _expect_ospfv3_neighbor_full("r1", "10.0.255.2")


def test_ospf_yang_rpc_unknown_instance_silent():
    """RPC against an instance name no daemon owns must return silently.

    Mirrors the non-owner case: both daemons' handlers look up the named
    instance and, if not found, return NB_OK. mgmtd surfaces the combined
    success. No error to the caller, no state change on r1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    _expect_ospfv2_neighbor_full("r1", "10.0.255.2")

    _send_ietf_ospf_rpc(
        r1,
        "/ietf-ospf:clear-neighbor",
        '{"ietf-ospf:clear-neighbor":{"routing-protocol-name":"does-not-exist"}}',
    )

    # r1's v2 neighbor must still be Full -- the RPC did not touch it.
    out = r1.vtysh_cmd("show ip ospf neighbor json", isjson=True)
    nbr = out.get("neighbors", {}).get("10.0.255.2", [])
    assert nbr and nbr[0].get("converged") == "Full", (
        "neighbor was disturbed by an RPC against an unknown instance:\n{}".format(out)
    )


def test_ospf_yang_clear_neighbor_rpc_unknown_interface():
    """clear-neighbor with `interface` for an interface that exists on the
    box but isn't in the OSPF instance must surface ospf-interface-not-found.

    r1 has lo (loopback) configured as an interface but it isn't bound into
    the OSPFv2 area, so ospfd's lookup returns NULL and the handler returns
    # returning NB_ERR_NOT_FOUND surfaces an error in the vty output -- which
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # lo is not in any OSPF area on r1; ospfd_ietf_lookup_oi returns NULL
    # for it. ospf6d may also error on the same input. Either backend
    # returning NB_ERR_RESOURCE surfaces an error in the vty output -- which
    # is exactly what we want to verify.
    out = r1.vtysh_cmd(
        "configure terminal\nmgmt rpc /ietf-ospf:clear-neighbor json "
        '{"ietf-ospf:clear-neighbor":{"routing-protocol-name":"default","interface":"lo"}}'
    )
    assert "ospf-interface-not-found" in out.lower() or "error" in out.lower(), (
        "expected error for unknown interface, got:\n{}".format(out)
    )

    # The clear-database RPC above flushed and re-originated r1's LSAs.
    # Adjacencies come back Full quickly but the rest of the area takes
    # longer to re-learn the flushed LSAs. Downstream read-only tests
    # (test_ospf_json, test_ospf_kernel_route) compare full LSDB snapshots
    # against a stable expected baseline, so force a clean reconvergence
    # before handing off to them.
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
