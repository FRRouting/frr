#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_vxlan.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_evpn_vxlan.py: Test VXLAN EVPN MAC a route signalling over BGP.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.evpn import (
    evpn_check_vni_macs_present,
    evpn_mac_learn_test,
    evpn_mac_test_local_remote,
    evpn_show_vni_json_elide_ifindex,
    evpn_check_bgp_imet,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn, pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.
    #
    #
    # Create routers
    tgen.add_router("P1")
    tgen.add_router("PE1")
    tgen.add_router("PE2")
    tgen.add_router("host1")
    tgen.add_router("host2")

    # Host1-PE1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["host1"])
    switch.add_link(tgen.gears["PE1"])

    # PE1-P1
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["PE1"])
    switch.add_link(tgen.gears["P1"])

    # P1-PE2
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["P1"])
    switch.add_link(tgen.gears["PE2"])

    # PE2-host2
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["PE2"])
    switch.add_link(tgen.gears["host2"])


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    p1 = tgen.gears["P1"]

    # set up PE bridges with the EVPN member interfaces facing the CE hosts
    pe1.run("ip link add name br101 type bridge stp_state 0")
    pe1.run("ip addr add 10.10.1.1/24 dev br101")
    pe1.run("ip link set dev br101 up")
    pe1.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan101 master br101")
    pe1.run("ip link set up dev vxlan101")
    pe1.run("ip link set dev PE1-eth0 master br101")

    pe2.run("ip link add name br101 type bridge stp_state 0")
    pe2.run("ip addr add 10.10.1.3/24 dev br101")
    pe2.run("ip link set dev br101 up")
    pe2.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan101 master br101")
    pe2.run("ip link set up dev vxlan101")
    pe2.run("ip link set dev PE2-eth1 master br101")
    p1.run("sysctl -w net.ipv4.ip_forward=1")

    # Setup L3 VNI 999 with VLAN interface for testing fix 3ad2a782e6
    # PE1
    pe1.run("ip link add vrf-blue type vrf table 1000")
    pe1.run("ip link set vrf-blue up")
    pe1.run("ip link add name br999 type bridge stp_state 0 vlan_filtering 1")
    pe1.run("ip link set dev br999 up")
    pe1.run(
        "ip link add vxlan999 type vxlan id 999 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan999 master br999")
    pe1.run("ip link set up dev vxlan999")
    # Set VLAN 999 as access VLAN on the bridge
    pe1.run("bridge vlan add vid 999 dev br999 self")
    pe1.run("bridge vlan del vid 1 dev vxlan999")
    pe1.run("bridge vlan add vid 999 dev vxlan999 pvid untagged")
    pe1.run("ip link add link br999 name vlan999 type vlan id 999")
    pe1.run("ip link set dev vlan999 master vrf-blue")
    pe1.run("ip addr add 10.99.99.1/24 dev vlan999")
    pe1.run("ip link set dev vlan999 up")

    # PE2
    pe2.run("ip link add vrf-blue type vrf table 1000")
    pe2.run("ip link set vrf-blue up")
    pe2.run("ip link add name br999 type bridge stp_state 0 vlan_filtering 1")
    pe2.run("ip link set dev br999 up")
    pe2.run(
        "ip link add vxlan999 type vxlan id 999 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan999 master br999")
    pe2.run("ip link set up dev vxlan999")
    # Set VLAN 999 as access VLAN on the bridge
    pe2.run("bridge vlan add vid 999 dev br999 self")
    pe2.run("bridge vlan del vid 1 dev vxlan999")
    pe2.run("bridge vlan add vid 999 dev vxlan999 pvid untagged")
    pe2.run("ip link add link br999 name vlan999 type vlan id 999")
    pe2.run("ip link set dev vlan999 master vrf-blue")
    pe2.run("ip addr add 10.99.99.3/24 dev vlan999")
    pe2.run("ip link set dev vlan999 up")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_pe1_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    json_file = "{}/{}/evpn.vni.json".format(CWD, pe1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(evpn_show_vni_json_elide_ifindex, pe1, 101, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe1.name)

    # Let's ensure that the hosts have actually tried talking to
    # each other.  Otherwise under certain startup conditions
    # they may not actually do any l2 arp'ing and as such
    # the bridges won't know about the hosts on their networks
    host1 = tgen.gears["host1"]
    host1.run("ping -c 1 10.10.1.56")
    host2 = tgen.gears["host2"]
    host2.run("ping -c 1 10.10.1.55")

    test_func = partial(
        evpn_check_vni_macs_present,
        tgen,
        pe1,
        101,
        (("host1", "host1-eth0"), ("host2", "host2-eth0")),
    )

    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result:
        logger.warning("%s", result)
        assert None, '"{}" missing expected MACs'.format(pe1.name)


def test_pe2_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe2 = tgen.gears["PE2"]
    json_file = "{}/{}/evpn.vni.json".format(CWD, pe2.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(evpn_show_vni_json_elide_ifindex, pe2, 101, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe2.name)
    assert result is None, assertmsg

    test_func = partial(
        evpn_check_vni_macs_present,
        tgen,
        pe2,
        101,
        (("host1", "host1-eth0"), ("host2", "host2-eth0")),
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result:
        logger.warning("%s", result)
        assert None, '"{}" missing expected MACs'.format(pe2.name)


def test_learning_pe1():
    "test MAC learning on PE1"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    pe1 = tgen.gears["PE1"]
    evpn_mac_learn_test(host1, pe1)


def test_learning_pe2():
    "test MAC learning on PE2"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host2 = tgen.gears["host2"]
    pe2 = tgen.gears["PE2"]
    evpn_mac_learn_test(host2, pe2)


def test_local_remote_mac_pe1():
    "Test MAC transfer PE1 local and PE2 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    evpn_mac_test_local_remote(pe1, pe2)


def test_local_remote_mac_pe2():
    "Test MAC transfer PE2 local and PE1 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    evpn_mac_test_local_remote(pe2, pe1)

    # Memory leak test template


def ip_learn_test(tgen, host, local, remote, ip_addr):
    "check the host IP gets learned by the VNI"
    host_output = host.vtysh_cmd("show interface {}-eth0".format(host.name))
    int_lines = host_output.splitlines()
    for line in int_lines:
        line_items = line.split(": ")
        if "HWaddr" in line_items[0]:
            mac = line_items[1]
            break
    print(host_output)

    # check we have a local association between the MAC and IP
    def check_local_ip_learned():
        local_output = local.vtysh_cmd("show evpn mac vni 101 mac {} json".format(mac))
        print(local_output)
        local_output_json = json.loads(local_output)
        mac_type = local_output_json[mac]["type"]

        if local_output_json[mac]["neighbors"] == "none":
            return False

        learned_ip = local_output_json[mac]["neighbors"]["active"][0]

        if mac_type == "local" and learned_ip == ip_addr:
            return True
        return False

    _, result = topotest.run_and_expect(check_local_ip_learned, True, count=30, wait=1)
    assertmsg = "Failed to learn local IP address on host {}".format(host.name)
    assert result, assertmsg

    # now lets check the remote
    def check_remote_ip_learned():
        remote_output = remote.vtysh_cmd(
            "show evpn mac vni 101 mac {} json".format(mac)
        )
        print(remote_output)
        remote_output_json = json.loads(remote_output)
        type = remote_output_json[mac]["type"]
        if not remote_output_json[mac]["neighbors"] == "none":
            # due to a kernel quirk, learned IPs can be inactive
            if (
                remote_output_json[mac]["neighbors"]["active"]
                or remote_output_json[mac]["neighbors"]["inactive"]
            ):
                # Store the data for later use
                check_remote_ip_learned.remote_output_json = remote_output_json
                check_remote_ip_learned.type = type
                return True
        return False

    _, result = topotest.run_and_expect(check_remote_ip_learned, True, count=30, wait=1)
    assertmsg = "{} remote learned mac no address: {} ".format(host.name, mac)

    assert result, assertmsg

    # Get the data from the successful check
    remote_output_json = check_remote_ip_learned.remote_output_json
    type = check_remote_ip_learned.type

    if remote_output_json[mac]["neighbors"]["active"]:
        learned_ip = remote_output_json[mac]["neighbors"]["active"][0]
    else:
        learned_ip = remote_output_json[mac]["neighbors"]["inactive"][0]
    assertmsg = "remote learned mac wrong type: {} ".format(type)
    assert type == "remote", assertmsg

    assertmsg = "remote learned address mismatch with configured address host: {} learned: {}".format(
        ip_addr, learned_ip
    )
    assert ip_addr == learned_ip, assertmsg


def _ip_neigh_has_entry(router, dev, ip_addr, require_extern=True):
    output = router.cmd("ip neigh show dev {}".format(dev))
    for line in output.splitlines():
        parts = line.split()
        if not parts:
            continue
        if parts[0] == ip_addr:
            if require_extern and "extern_learn" not in line:
                return False
            return True
    return False


def _ip_neigh_missing(router, dev, ip_addr):
    output = router.cmd("ip neigh show dev {}".format(dev))
    for line in output.splitlines():
        parts = line.split()
        if parts and parts[0] == ip_addr:
            return False
    return True


def test_ip_pe1_learn():
    "run the IP learn test for PE1"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    # pe2.vtysh_cmd("debug zebra vxlan")
    # pe2.vtysh_cmd("debug zebra kernel")
    # lets populate that arp cache
    host1.run("ping -c1 10.10.1.1")
    ip_learn_test(tgen, host1, pe1, pe2, "10.10.1.55")
    # tgen.mininet_cli()


def test_ip_pe2_learn():
    "run the IP learn test for PE2"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host2 = tgen.gears["host2"]
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    # pe1.vtysh_cmd("debug zebra vxlan")
    # pe1.vtysh_cmd("debug zebra kernel")
    # lets populate that arp cache
    host2.run("ping -c1 10.10.1.3")
    ip_learn_test(tgen, host2, pe2, pe1, "10.10.1.56")
    # tgen.mininet_cli()


def test_bgp_evpn_route_vni():
    "Test show bgp l2vpn evpn route vni command"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    host1 = tgen.gears["host1"]

    mac = host1.run(
        "ip link show host1-eth0 | grep link/ether | awk '{print $2}'"
    ).strip()
    ip = "10.10.1.55"

    output = pe1.vtysh_cmd("show bgp l2vpn evpn route vni 101")

    logger.info(
        "Testing 'show bgp l2vpn evpn route vni 101 mac {} ip {} json' on PE1".format(
            mac, ip
        )
    )
    mac_output = pe1.vtysh_cmd(
        "show bgp l2vpn evpn route vni 101 mac {} ip {} json".format(mac, ip),
        isjson=True,
    )

    prefix = mac_output.get("prefix")
    assert prefix in output, "PE1: Prefix {} not found in full VNI output".format(
        prefix
    )

    # Check that RD is displayed for each route
    output = pe1.vtysh_cmd("show bgp l2vpn evpn route")
    lines = output.split("\n")
    route_count = 0
    routes_with_rd = 0

    for line in lines:
        # Route lines start with status codes (* > etc) and contain EVPN prefix [type]:...
        if line.strip().startswith("*") and "[" in line and "]:" in line:
            route_count += 1
            if " RD " in line:
                routes_with_rd += 1
            else:
                logger.warning("PE1: Route without RD: {}".format(line.strip()))

    logger.info(
        "PE1: Found {} routes, {} with RD displayed".format(route_count, routes_with_rd)
    )
    assert (
        routes_with_rd == route_count
    ), "PE1: Not all routes have RD displayed ({}/{})".format(
        routes_with_rd, route_count
    )

    logger.info("PE1: Test passed")


def test_bgp_evpn_route_brief_json():
    """
    Test 'show bgp l2vpn evpn route brief json':
    - Produces valid JSON with RD-keyed prefix list (minimal loc-rib).
    - 'brief' without 'json' is rejected with a clear error.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    # 1) brief without json must fail with clear message
    out_no_json = pe1.vtysh_cmd("show bgp l2vpn evpn route brief", isjson=False)
    if "% Unknown command" in out_no_json or "invalid" in out_no_json.lower():
        pytest.skip("'brief' option not available in this build")
    assert (
        "brief" in out_no_json.lower()
        and "requires" in out_no_json.lower()
        and "json" in out_no_json.lower()
    ), f"PE1: 'brief' without 'json' should report that brief requires json, got: {out_no_json[:300]}"

    # 2) brief json: valid JSON, RD-keyed structure, no path detail
    out = pe1.vtysh_cmd("show bgp l2vpn evpn route brief json", isjson=True)
    if out is None:
        # Command might not exist or returned non-JSON
        raw = pe1.vtysh_cmd("show bgp l2vpn evpn route brief json", isjson=False)
        if "% Unknown command" in raw or "invalid" in raw.lower():
            pytest.skip("'brief json' not available in this build")
        pytest.fail("Expected valid JSON from 'show bgp l2vpn evpn route brief json'")
    assert isinstance(out, dict), "brief json output should be a JSON object"

    # Top-level keys are RDs; values are prefix-keyed objects (brief = no paths)
    for key, val in out.items():
        if key in ("numPrefix", "numPaths"):
            continue
        assert isinstance(
            val, dict
        ), f"PE1: RD entry '{key}' in brief json should be a dict, got {type(val)}"

    logger.info("PE1: show bgp l2vpn evpn route brief [json] tests passed")


def test_bgp_evpn_neighbor_routes_json_brief():
    """
    Test 'show bgp l2vpn evpn neighbors <peer> routes [json [brief]]' on PE1.

    PE1 peers with PE2 (10.30.30.30) for EVPN; we assert full JSON includes
    table-level keys and per-prefix paths, and brief JSON omits those in favor
    of pathCount / flags only.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    peer = "10.30.30.30"

    probe = pe1.vtysh_cmd(
        "show bgp l2vpn evpn neighbors {} routes json brief".format(peer),
        isjson=False,
    )
    if "% Unknown command" in probe or "Unknown command:" in probe:
        pytest.skip("neighbor routes json brief not in this build")

    def _full_neighbor_json_ready():
        j = pe1.vtysh_cmd(
            "show bgp l2vpn evpn neighbors {} routes json".format(peer), isjson=True
        )
        if not j or not isinstance(j, dict):
            return False
        if j.get("bgpLocalRouterId") != "10.10.10.10":
            return False
        if "numPrefix" not in j or "totalPrefix" not in j:
            return False
        if "localAS" not in j:
            return False
        meta = {
            "numPrefix",
            "totalPrefix",
            "bgpTableVersion",
            "bgpLocalRouterId",
            "defaultLocPrf",
            "localAS",
        }
        rd_objs = {k: v for k, v in j.items() if k not in meta and isinstance(v, dict)}
        if not rd_objs:
            return False
        rd = next(iter(rd_objs.values()))
        if "numPrefixes" not in rd:
            return False
        for k, v in rd.items():
            if k in ("rd", "numPrefixes"):
                continue
            if isinstance(v, dict) and "paths" in v:
                return True
        return False

    ok, _ = topotest.run_and_expect(_full_neighbor_json_ready, True, count=20, wait=3)
    assert ok, "PE1: neighbor routes full JSON did not converge"

    text = pe1.vtysh_cmd(
        "show bgp l2vpn evpn neighbors {} routes".format(peer), isjson=False
    )
    assert "Route Distinguisher" in text
    assert "Displayed" in text and "total prefixes" in text

    full = pe1.vtysh_cmd(
        "show bgp l2vpn evpn neighbors {} routes json".format(peer), isjson=True
    )
    assert isinstance(full, dict)
    assert full.get("bgpLocalRouterId") == "10.10.10.10"

    brief = pe1.vtysh_cmd(
        "show bgp l2vpn evpn neighbors {} routes json brief".format(peer),
        isjson=True,
    )
    assert isinstance(brief, dict)
    for k in ("bgpTableVersion", "bgpLocalRouterId", "numPrefix", "totalPrefix"):
        assert k not in brief, "PE1: brief json should omit top-level key {}".format(k)

    meta = {
        "numPrefix",
        "totalPrefix",
        "bgpTableVersion",
        "bgpLocalRouterId",
        "defaultLocPrf",
        "localAS",
    }
    rd_keys = [x for x in brief if x not in meta and isinstance(brief[x], dict)]
    assert rd_keys, "PE1: brief json should contain at least one RD object"
    rd = brief[rd_keys[0]]
    assert "numPrefixes" in rd
    saw_nlri = False
    for k, v in rd.items():
        if k in ("rd", "numPrefixes"):
            continue
        if not isinstance(v, dict):
            continue
        saw_nlri = True
        assert "paths" not in v, "PE1: brief must omit paths for NLRI {}".format(k)
        assert "pathCount" in v, "PE1: brief expects pathCount for NLRI {}".format(k)
        assert "flags" in v, "PE1: brief expects flags for NLRI {}".format(k)
    assert saw_nlri, "PE1: brief json RD should contain at least one NLRI entry"

    logger.info("PE1: neighbor routes json / json brief tests passed")


def test_evpn_l2vni_vlan_bridge_json():
    """
    Test L2 VNI JSON output includes vlan and bridge fields

    This verifies the fix where L2 VNI JSON output was missing
    "vlan" and "bridge" fields.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    # Check PE1 L2 VNI 101
    output = pe1.vtysh_cmd("show evpn vni 101 json", isjson=True)
    if output:
        assertmsg = "L2 VNI 101 (PE1): 'vlan' field should be present in JSON"
        assert "vlan" in output, assertmsg

        assertmsg = "L2 VNI 101 (PE1): 'bridge' field should be present in JSON"
        assert "bridge" in output, assertmsg

    # Check PE2 L2 VNI 101
    output = pe2.vtysh_cmd("show evpn vni 101 json", isjson=True)
    if output:
        assertmsg = "L2 VNI 101 (PE2): 'vlan' field should be present in JSON"
        assert "vlan" in output, assertmsg

        assertmsg = "L2 VNI 101 (PE2): 'bridge' field should be present in JSON"
        assert "bridge" in output, assertmsg


def test_evpn_vni_summary_output():
    """
    Test EVPN VNI summary output includes VLAN and BRIDGE columns

    This verifies that 'show evpn vni' summary output displays
    VLAN and BRIDGE information in both text and JSON formats.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    # Test text output has VLAN and BRIDGE columns
    output = pe1.vtysh_cmd("show evpn vni", isjson=False)
    if output and "VNI" in output:
        assertmsg = "'show evpn vni' should have VLAN column in header"
        assert "VLAN" in output, assertmsg

        assertmsg = "'show evpn vni' should have BRIDGE column in header"
        assert "BRIDGE" in output, assertmsg

    # Test JSON output has vlan and bridge fields
    output = pe1.vtysh_cmd("show evpn vni json", isjson=True)
    if output:
        for vni_key, vni_data in output.items():
            if isinstance(vni_data, dict) and "type" in vni_data:
                assertmsg = "VNI {} JSON should have 'vlan' field".format(vni_key)
                assert "vlan" in vni_data, assertmsg

                assertmsg = "VNI {} JSON should have 'bridge' field".format(vni_key)
                assert "bridge" in vni_data, assertmsg
                break


def test_evpn_l3vni_vlan_bridge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    # Check PE1 L3 VNI 999 - TEXT output
    output = pe1.vtysh_cmd("show evpn vni 999", isjson=False)
    if output:
        assertmsg = "L3 VNI 999 (PE1): text output should contain 'Vlan: 999'"
        assert "Vlan: 999" in output, assertmsg

        assertmsg = "L3 VNI 999 (PE1): text output should contain 'Bridge: br999'"
        assert "Bridge: br999" in output, assertmsg

        assertmsg = "L3 VNI 999 (PE1): text output should contain 'Type: L3'"
        assert "Type: L3" in output, assertmsg

    # Check PE2 L3 VNI 999 - TEXT output
    output = pe2.vtysh_cmd("show evpn vni 999", isjson=False)
    if output:
        assertmsg = "L3 VNI 999 (PE2): text output should contain 'Vlan: 999'"
        assert "Vlan: 999" in output, assertmsg

        assertmsg = "L3 VNI 999 (PE2): text output should contain 'Bridge: br999'"
        assert "Bridge: br999" in output, assertmsg

        assertmsg = "L3 VNI 999 (PE2): text output should contain 'Type: L3'"
        assert "Type: L3" in output, assertmsg


def show_interface_vxlan101_json(pe, expected):
    output_json = pe.vtysh_cmd("show interface vxlan101 json", isjson=True)
    return topotest.json_cmp(output_json, expected)


def test_tvd_vxlan_interface_json():
    "Verify TVD vxlan101 JSON output on PE1 contains vxlanId with single VNI entry"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    json_file = "{}/{}/show_intf_vxlan101.json".format(CWD, pe1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(show_interface_vxlan101_json, pe1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    output_json = pe1.vtysh_cmd("show interface vxlan101 json", isjson=True)
    logger.info(
        "PE1 show interface vxlan101 json:\n%s", json.dumps(output_json, indent=2)
    )

    assertmsg = '"{}" show interface vxlan101 json output mismatch'.format(pe1.name)
    assert result is None, assertmsg


def test_tvd_vxlan_interface_vty():
    "Verify TVD vxlan101 VTY output on PE1 shows VTEP IP and VNI info"

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    output = pe1.vtysh_cmd("show interface vxlan101")
    logger.info("PE1 show interface vxlan101:\n%s", output)

    expected_strings = [
        "VTEP IP: 10.10.10.10",
        "VxLAN Id 101",
        "Master interface: br101",
    ]

    for s in expected_strings:
        assert (
            s in output
        ), '"{}" show interface vxlan101 missing "{}"\nFull output:\n{}'.format(
            pe1.name, s, output
        )


def _evpn_l2vni_svi_setup(router, vni, vtep, addr):
    router.run(
        "ip link add name br{} type bridge stp_state 0 vlan_filtering 1".format(vni)
    )
    router.run("ip link set dev br{} up".format(vni))
    router.run("bridge vlan add vid {} dev br{} self".format(vni, vni))
    router.run(
        "ip link add vxlan{} type vxlan id {} dstport 4789 local {} nolearning".format(
            vni, vni, vtep
        )
    )
    router.run("ip link set dev vxlan{} master br{}".format(vni, vni))
    router.run("bridge vlan del vid 1 dev vxlan{}".format(vni))
    router.run("bridge vlan add vid {} dev vxlan{} pvid untagged".format(vni, vni))
    router.run("ip link set up dev vxlan{}".format(vni))
    router.run(
        "ip link add link br{} name vlan{} type vlan id {} protocol 802.1q".format(
            vni, vni, vni
        )
    )
    router.run("ip addr add {} dev vlan{}".format(addr, vni))
    router.run("ip link set dev vlan{} up".format(vni))


def _wait_for_existing_l2vni(router, vni, vxlan_if, svi_if):
    expected = {
        "vni": vni,
        "type": "L2",
        "vxlanInterface": vxlan_if,
        "sviInterface": svi_if,
    }

    test_func = partial(evpn_show_vni_json_elide_ifindex, router, vni, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" VNI {} did not converge before repro: {}'.format(
        router.name, vni, result
    )
    assert result is None, assertmsg


def _evpn_l2vni_svi_cleanup(router, vni):
    router.run("ip link del vlan{} 2>/dev/null || true".format(vni))
    router.run("ip link del vxlan{} 2>/dev/null || true".format(vni))
    router.run("ip link del br{} 2>/dev/null || true".format(vni))


def _check_vni_svi(router, vni, svi_name):
    output = router.vtysh_cmd("show evpn vni {} json".format(vni), isjson=True)
    if not output:
        return "VNI {} missing".format(vni)

    if output.get("sviInterface") != svi_name:
        return "VNI {} SVI mismatch: {}".format(vni, json.dumps(output, indent=4))

    return None


def _evpn_l2vni_vlan_flip(router, vni, vlan):
    other_vlan = 202 if vlan == vni else vni
    router.run(
        "bridge vlan del vid {} dev vxlan{} 2>/dev/null || true".format(
            other_vlan, vni
        )
    )
    router.run("bridge vlan add vid {} dev vxlan{} pvid untagged".format(vlan, vni))


def _evpn_l2vni_remap_away_then_delete_svi(router, vni):
    _evpn_l2vni_vlan_flip(router, vni, 202)
    router.vtysh_cmd("show evpn vni {} json".format(vni), isjson=True)
    router.run("ip link del vlan{} 2>/dev/null || true".format(vni))
    _evpn_l2vni_vlan_flip(router, vni, vni)
    router.vtysh_cmd("show evpn vni {} json".format(vni), isjson=True)


def test_evpn_l2vni_svi_delete_after_vlan_remap_issue_21794():
    """
    Delete an L2 VNI SVI after remapping the VXLAN away from its VLAN.

    This targets stale zevpn->svi_if references. The SVI-down lookup no longer
    maps back to the VNI once the VXLAN access VLAN is changed, so a later VNI
    update can expose a stale zevpn->svi_if pointer.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    vni = 201
    svi_name = "vlan{}".format(vni)

    _wait_for_existing_l2vni(pe1, 101, "vxlan101", "br101")
    _evpn_l2vni_svi_cleanup(pe1, vni)
    try:
        _evpn_l2vni_svi_setup(pe1, vni, "10.10.10.10", "10.201.0.1/24")

        test_func = partial(_check_vni_svi, pe1, vni, svi_name)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = '"{}" VNI {} did not bind to {}'.format(pe1.name, vni, svi_name)
        assert result is None, assertmsg

        _evpn_l2vni_remap_away_then_delete_svi(pe1, vni)

        status = pe1.check_router_running()
        assertmsg = "Router {} has issues after SVI delete: {}".format(
            pe1.name, status
        )
        assert not status, assertmsg
    finally:
        _evpn_l2vni_svi_cleanup(pe1, vni)


def test_imet():
    """
    Verify PMSI tunnel attribute info
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut_name = "PE1"
    dut = tgen.gears[dut_name]
    rd = "10.30.30.30:2"
    prefix = "[3]:[0]:[32]:[10.30.30.30]"
    pmsi_label = 101
    pmsi_id = "10.30.30.30"
    # Check Imet from PE2 to PE1
    test_fn = partial(evpn_check_bgp_imet, dut, rd, prefix, pmsi_label, pmsi_id)
    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = f"{dut_name} IMET not present/incorrect, result:{result}"
    assert result is None, assertmsg

    # Check Imet from PE1 to PE2
    dut_name = "PE2"
    dut = tgen.gears[dut_name]
    rd = "10.10.10.10:2"
    prefix = "[3]:[0]:[32]:[10.10.10.10]"
    pmsi_label = 101
    pmsi_id = "10.10.10.10"
    test_fn = partial(evpn_check_bgp_imet, dut, rd, prefix, pmsi_label, pmsi_id)
    _, result = topotest.run_and_expect(test_fn, None, count=10, wait=3)
    assertmsg = f"{dut_name} IMET not present/incorrect, result:{result}"
    assert result is None, assertmsg


def test_remote_neigh_uninstall_on_vxlan_down():
    "Ensure remote neighs are removed when VxLAN if is down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    pe1 = tgen.gears["PE1"]

    # Trigger ARP/neighbor learning for the remote host
    host1.run("ping -c1 10.10.1.56")

    test_func = partial(_ip_neigh_has_entry, pe1, "br101", "10.10.1.56", True)
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assertmsg = "PE1 missing extern_learn neighbor 10.10.1.56 on br101"
    assert result, assertmsg

    # Remove VxLAN device to trigger L2VNI cleanup
    pe1.run("ip link del vxlan101")

    test_func = partial(_ip_neigh_missing, pe1, "br101", "10.10.1.56")
    _, result = topotest.run_and_expect(test_func, True, count=20, wait=3)
    assertmsg = "PE1 still has neighbor 10.10.1.56 after VxLAN down"
    assert result, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
