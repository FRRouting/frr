#!/usr/bin/env python

#
# test_bgp_evpn_vxlan_svd.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 NVIDIA Corporation
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_bgp_evpn_vxlan.py: Test VXLAN EVPN MAC and route signalling over BGP
using Single Vxlan Device Configurtion
"""

import os
import sys
import json
from functools import partial
from time import sleep
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

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


def setup_pe_router(tgen, pe_name, tunnel_local_ip, svi_ip, intf):
    pe = tgen.gears[pe_name]

    # configure vlan aware bridge
    pe.run("ip link add name bridge type bridge stp_state 0")
    pe.run("ip link set dev bridge type bridge vlan_filtering 1")
    pe.run("bridge vlan add vid 1 dev bridge self")
    if pe_name == "PE1":
        pe.run("ip link set dev bridge address 44:00:00:ff:ff:01")
    if pe_name == "PE2":
        pe.run("ip link set dev bridge address 44:20:00:ff:ff:01")
    pe.run("ip link set dev bridge up")

    # setup svi
    pe.run("ip link add link bridge name vlan1 type vlan id 1 protocol 802.1q")
    pe.run("ip link set dev vlan1 up")
    pe.run("ip addr add {0} dev vlan1".format(svi_ip))
    pe.run("/sbin/sysctl net.ipv4.conf.vlan1.arp_accept=1")

    # setup single vxlan device
    pe.run(
        "ip link add dev vxlan0 type vxlan dstport 4789 local {0} nolearning external".format(
            tunnel_local_ip
        )
    )
    pe.run("ip link set dev vxlan0 master bridge")
    pe.run("bridge link set dev vxlan0 vlan_tunnel on")
    pe.run("bridge link set dev vxlan0 neigh_suppress on")
    pe.run("bridge link set dev vxlan0 learning off")
    pe.run("bridge vlan add dev vxlan0 vid 1")
    pe.run("bridge vlan add dev vxlan0 vid 1 tunnel_info id 101")
    pe.run("ip link set up dev vxlan0")

    # VRF creation
    pe.run("ip link add vrf-purple type vrf table 1003")
    pe.run("ip link set dev vrf-purple up")
    if pe_name == "PE1":
        pe.run("ip link add vrf-blue type vrf table 1002")
        pe.run("ip link set dev vrf-blue up")
        pe.run("ip addr add 27.2.0.85/32 dev vrf-blue")
        pe.run("ip addr add 27.3.0.85/32 dev vrf-purple")
    if pe_name == "PE2":
        pe.run("ip link add vrf-blue type vrf table 2400")
        pe.run("ip link set dev vrf-blue up")

    # setup PE interface
    pe.run("ip link set dev {0}-{1} master bridge".format(pe_name, intf))
    pe.run("bridge vlan del vid 1 dev {0}-{1}".format(pe_name, intf))
    pe.run("bridge vlan del vid 1 untagged pvid dev {0}-{1}".format(pe_name, intf))
    pe.run("bridge vlan add vid 1 dev {0}-{1}".format(pe_name, intf))
    pe.run("bridge vlan add vid 1 pvid untagged dev {0}-{1}".format(pe_name, intf))

    # L3VNI 100
    pe.run("ip link add vrf-red type vrf table 1400")
    pe.run("ip link add link bridge name vlan100 type vlan id 100 protocol 802.1q")
    pe.run("ip link set dev vlan100 master vrf-blue")
    pe.run("ip link set dev vlan100 up")
    pe.run("bridge vlan add vid 100 dev bridge self")
    pe.run("bridge vlan add dev vxlan0 vid 100")
    pe.run("bridge vlan add dev vxlan0 vid 100 tunnel_info id 100")

    # L3VNI 4000
    pe.run("ip link add link bridge name vlan400 type vlan id 400 protocol 802.1q")
    pe.run("ip link set dev vlan400 master vrf-purple")
    pe.run("ip link set dev vlan400 up")
    pe.run("bridge vlan add vid 400 dev bridge self")
    pe.run("bridge vlan add dev vxlan0 vid 400")
    pe.run("bridge vlan add dev vxlan0 vid 400 tunnel_info id 4000")

    # add a vrf for testing DVNI
    if pe_name == "PE2":
        pe.run("ip link add link bridge name vlan300 type vlan id 300 protocol 802.1q")
        pe.run("ip link set dev vlan300 master vrf-blue")
        pe.run("ip link set dev vlan300 up")
        pe.run("bridge vlan add vid 300 dev bridge self")
        pe.run("bridge vlan add dev vxlan0 vid 300")
        pe.run("bridge vlan add dev vxlan0 vid 300 tunnel_info id 300")


def setup_p_router(tgen, p_name):
    p1 = tgen.gears[p_name]
    p1.run("sysctl -w net.ipv4.ip_forward=1")


def setup_module(mod):
    "Sets up the pytest environment"

    result = required_linux_kernel_version("5.7")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 5.7")

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)

    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    setup_pe_router(tgen, "PE1", "10.10.10.10", "10.10.1.1/24", "eth0")
    setup_pe_router(tgen, "PE2", "10.30.30.30", "10.10.1.3/24", "eth1")
    setup_p_router(tgen, "P1")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
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

    # tgen.mininet_cli()
    # This function tears down the whole topology.
    tgen.stop_topology()


def show_vni_json_elide_ifindex(pe, vni, expected):
    output_json = pe.vtysh_cmd("show evpn vni {} json".format(vni), isjson=True)

    if "ifindex" in output_json:
        output_json.pop("ifindex")

    return topotest.json_cmp(output_json, expected)


def show_bgp_l2vpn_evpn_route_type_prefix_json(pe, expected):
    output_json = pe.vtysh_cmd(
        "show bgp l2vpn evpn route type prefix json", isjson=True
    )

    return topotest.json_cmp(output_json, expected)


def check_vni_macs_present(tgen, router, vni, maclist):
    result = router.vtysh_cmd("show evpn mac vni {} json".format(vni), isjson=True)
    for rname, ifname in maclist:
        m = tgen.net.macs[(rname, ifname)]
        if m not in result["macs"]:
            return "MAC ({}) for interface {} on {} missing on {} from {}".format(
                m, ifname, rname, router.name, json.dumps(result, indent=4)
            )
    return None


def check_flood_entry_present(pe, vni, vtep):
    if not topotest.iproute2_is_fdb_get_capable():
        return None

    output = pe.run(
        "bridge fdb get 00:00:00:00:00:00 dev vxlan0 vni {} self".format(vni)
    )

    if str(vtep) not in output:
        return output

    return None


def test_pe1_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    json_file = "{}/{}/evpn.vni.json".format(CWD, pe1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(show_vni_json_elide_ifindex, pe1, 101, expected)
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
        check_vni_macs_present,
        tgen,
        pe1,
        101,
        (("host1", "host1-eth0"), ("host2", "host2-eth0")),
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result:
        logger.warning("%s", result)
        assert None, '"{}" missing expected MACs'.format(pe1.name)

    vtep = "10.30.30.30"
    test_func = partial(check_flood_entry_present, pe1, 101, vtep)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" Flood FDB Entry for VTEP {} not found'.format(pe1.name, vtep)
    assert result is None, assertmsg


def test_pe2_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe2 = tgen.gears["PE2"]
    json_file = "{}/{}/evpn.vni.json".format(CWD, pe2.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(show_vni_json_elide_ifindex, pe2, 101, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe2.name)
    assert result is None, assertmsg

    test_func = partial(
        check_vni_macs_present,
        tgen,
        pe2,
        101,
        (("host1", "host1-eth0"), ("host2", "host2-eth0")),
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result:
        logger.warning("%s", result)
        assert None, '"{}" missing expected MACs'.format(pe2.name)

    vtep = "10.10.10.10"
    test_func = partial(check_flood_entry_present, pe2, 101, vtep)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" Flood FDB Entry for VTEP {} not found'.format(pe2.name, vtep)
    assert result is None, assertmsg


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

    # breakpoint()
    for vni in local_output_json:
        if vni not in remote_output_json:
            continue

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


def ip_learn_test(tgen, host, local, remote, ip_addr):
    "check the host IP gets learned by the VNI"
    host_output = host.vtysh_cmd("show interface {}-eth0".format(host.name))
    int_lines = host_output.splitlines()
    for line in int_lines:
        line_items = line.split(": ")
        if "HWaddr" in line_items[0]:
            mac = line_items[1]
            break
    # print(host_output)

    # check we have a local association between the MAC and IP
    local_output = local.vtysh_cmd("show evpn mac vni 101 mac {} json".format(mac))
    # print(local_output)
    local_output_json = json.loads(local_output)
    mac_type = local_output_json[mac]["type"]
    assertmsg = "Failed to learn local IP address on host {}".format(host.name)
    assert local_output_json[mac]["neighbors"] != "none", assertmsg
    learned_ip = local_output_json[mac]["neighbors"]["active"][0]

    assertmsg = "local learned mac wrong type: {} ".format(mac_type)
    assert mac_type == "local", assertmsg

    assertmsg = (
        "learned address mismatch with configured address host: {} learned: {}".format(
            ip_addr, learned_ip
        )
    )
    assert ip_addr == learned_ip, assertmsg

    # now lets check the remote
    count = 0
    converged = False
    while count < 30:
        remote_output = remote.vtysh_cmd(
            "show evpn mac vni 101 mac {} json".format(mac)
        )
        # print(remote_output)
        remote_output_json = json.loads(remote_output)
        type = remote_output_json[mac]["type"]
        if not remote_output_json[mac]["neighbors"] == "none":
            # due to a kernel quirk, learned IPs can be inactive
            if (
                remote_output_json[mac]["neighbors"]["active"]
                or remote_output_json[mac]["neighbors"]["inactive"]
            ):
                converged = True
                break
        count += 1
        sleep(1)

    # print("tries: {}".format(count))
    assertmsg = "{} remote learned mac no address: {} ".format(host.name, mac)
    # some debug for this failure
    if not converged == True:
        log_output = remote.run("cat zebra.log")
        # print(log_output)

    assert converged == True, assertmsg
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


def show_dvni_route(pe, vni, prefix, vrf):
    output = pe.vtysh_cmd("show ip route vrf {} {}".format(vrf, prefix))

    if str(vni) not in output:
        return output

    output = pe.run("ip route show vrf {} {}".format(vrf, prefix))

    if str(vni) not in output:
        return output

    return None


def test_dvni():
    "test Downstream VNI works as expected importing into PE1"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]

    prefix = "4.4.4.1/32"
    test_func = partial(show_dvni_route, pe1, 300, prefix, "vrf-red")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = '"{}" DVNI route {} not found'.format(pe1.name, prefix)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pe_advertise_aggr_evpn_route():
    "BGP advertise aggregated Type-5 prefix route"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP EVPN route contains non-aggregate prefixes")
    pe1 = tgen.gears["PE1"]
    json_file = "{}/{}/bgp.evpn.route.prefix.before.json".format(CWD, pe1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(show_bgp_l2vpn_evpn_route_type_prefix_json, pe1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe1.name)
    assert result is None, assertmsg

    logger.info("Configure BGP aggregate-address summary-only under ipv4-unicast")
    pe1.cmd(
        'vtysh -c "config t" -c "router bgp 65000 vrf vrf-purple" '
        + ' -c "address-family ipv4 unicast" '
        + ' -c "aggregate-address 10.27.0.0/16 summary-only" '
    )

    logger.info("Checking BGP EVPN route contains aggregated prefix")
    pe1 = tgen.gears["PE1"]
    json_file = "{}/{}/bgp.evpn.route.prefix.after.json".format(CWD, pe1.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(show_bgp_l2vpn_evpn_route_type_prefix_json, pe1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=45, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe1.name)
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
