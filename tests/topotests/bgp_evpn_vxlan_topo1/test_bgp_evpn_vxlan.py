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
from lib.evpn import evpn_show_vni_json_elide_ifindex, evpn_check_vni_macs_present
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


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


def mac_learn_test(host, local):
    "check the host MAC gets learned by the VNI"

    host_output = host.vtysh_cmd("show interface {}-eth0".format(host.name))
    int_lines = host_output.splitlines()
    for line in int_lines:
        line_items = line.split(": ")
        if "HWaddr" in line_items[0]:
            mac = line_items[1]
            break

    mac_output = local.vtysh_cmd("show evpn mac vni 101 mac {} json".format(mac))
    mac_output_json = json.loads(mac_output)
    assertmsg = "Local MAC output does not match interface mac {}".format(mac)
    assert mac_output_json[mac]["type"] == "local", assertmsg


def mac_test_local_remote(local, remote):
    "test MAC transfer between local and remote"

    local_output = local.vtysh_cmd("show evpn mac vni all json")
    remote_output = remote.vtysh_cmd("show evpn mac vni all json")
    local_output_vni = local.vtysh_cmd("show evpn vni detail json")
    local_output_json = json.loads(local_output)
    remote_output_json = json.loads(remote_output)
    local_output_vni_json = json.loads(local_output_vni)

    for vni in local_output_json:
        mac_list = local_output_json[vni]["macs"]
        for mac in mac_list:
            if mac_list[mac]["type"] == "local" and mac_list[mac]["intf"] != "br101":
                assertmsg = "JSON output mismatches local: {} remote: {}".format(
                    local_output_vni_json[0]["vtepIp"],
                    remote_output_json[vni]["macs"][mac]["remoteVtep"],
                )
                assert (
                    remote_output_json[vni]["macs"][mac]["remoteVtep"]
                    == local_output_vni_json[0]["vtepIp"]
                ), assertmsg


def test_learning_pe1():
    "test MAC learning on PE1"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    pe1 = tgen.gears["PE1"]
    mac_learn_test(host1, pe1)


def test_learning_pe2():
    "test MAC learning on PE2"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host2 = tgen.gears["host2"]
    pe2 = tgen.gears["PE2"]
    mac_learn_test(host2, pe2)


def test_local_remote_mac_pe1():
    "Test MAC transfer PE1 local and PE2 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    mac_test_local_remote(pe1, pe2)


def test_local_remote_mac_pe2():
    "Test MAC transfer PE2 local and PE1 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    mac_test_local_remote(pe2, pe1)

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


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
