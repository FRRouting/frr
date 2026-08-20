#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_vxlan.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
#

"""
test_bgp_evpn_vxlan.py:
Test VXLAN EVPN MAC signalling over BGP.

This test is the basis the Integrated Routing and Bridging (IRB) tests.
"""

import os
import sys
import json
from functools import partial
import pytest
import time

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.checkping import check_ping
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]

VRF_OVERLAY = None
IRB_TEST = False
L3VNI = None

HOST_VNI = {
    "h1": 101,
    "h2": 101,
    "h3": 101,
    "h4": 102,
    "h5": 102,
    "h6": 102,
}

VNI_HOST = {
    str(v): {h for h, vv in HOST_VNI.items() if vv == v} for v in set(HOST_VNI.values())
}

HOST_PE = {
    "h1": "pe1",
    "h2": "pe2",
    "h3": "pe3",
    "h4": "pe1",
    "h5": "pe2",
    "h6": "pe3",
}

PE_HOST = {
    str(v): {h for h, vv in HOST_PE.items() if vv == v} for v in set(HOST_PE.values())
}


HOST_IP = {
    host: f'192.168.{vni}.10{HOST_PE[host].replace("pe", "")}'
    for host, vni in HOST_VNI.items()
}


def connect_routers(tgen, left, right):
    for rname in [left, right]:
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

    switch = tgen.add_switch("s-{}-{}".format(left, right))
    switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
    switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))


def build_topo(tgen):
    "Build function"

    # This function only purpose is to define allocation and relationship
    # between routers, switches and hosts.

    connect_routers(tgen, "p1", "pe1")
    connect_routers(tgen, "p1", "pe2")
    connect_routers(tgen, "p1", "pe3")
    connect_routers(tgen, "pe1", "h1")
    connect_routers(tgen, "pe2", "h2")
    connect_routers(tgen, "pe3", "h3")
    connect_routers(tgen, "pe1", "h4")
    connect_routers(tgen, "pe2", "h5")
    connect_routers(tgen, "pe3", "h6")
    connect_routers(tgen, "pe3", "h1")
    connect_routers(tgen, "pe2", "h1a")
    connect_routers(tgen, "pe2", "h1b")


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    router_list = tgen.routers()

    global VRF_OVERLAY, IRB_TEST, L3VNI

    if "irb" in mod.__name__:
        VRF_OVERLAY = "vrf-red"
        IRB_TEST = True
    else:
        VRF_OVERLAY = None
        IRB_TEST = False

    L3VNI = "300" if "irb_sym" in mod.__name__ else None

    # previous tests may have changed the global variables
    # set the correct values.
    global HOST_PE, PE_HOST, VNI_HOST, HOST_VNI, HOST_IP
    # restore global variables
    HOST_PE.pop("h1a", None)
    HOST_PE.pop("h1b", None)
    HOST_PE["h1"] = "pe1"
    PE_HOST["pe3"].discard("h1")
    PE_HOST["pe2"].discard("h1a")
    PE_HOST["pe2"].discard("h1b")
    PE_HOST["pe1"].add("h1")
    VNI_HOST["101"].discard("h1a")
    VNI_HOST["101"].discard("h1b")
    VNI_HOST["101"].add("h1")
    HOST_VNI.pop("h1a", None)
    HOST_VNI.pop("h1b", None)
    HOST_VNI["h1"] = 101
    HOST_IP["h1"] = "192.168.101.101"
    HOST_IP["h3"] = "192.168.101.103"
    HOST_IP.pop("h1a", None)
    HOST_IP.pop("h1b", None)

    tgen.gears["h1"].cmd(
        """
ip link set eth-pe1 down
ip link set eth-pe1 address 00:00:00:00:01:01
ip link set eth-pe1 up
"""
    )
    tgen.net.macs[("h1", "eth-pe1")] = "00:00:00:00:01:01"

    for rname, pe in router_list.items():
        if not rname.startswith("pe"):
            continue

        if VRF_OVERLAY:
            pe.cmd(
                f"""
ip link add {VRF_OVERLAY} type vrf table 300
ip link set {VRF_OVERLAY} up
"""
            )

        log_path = os.path.join(tgen.logdir, rname, "l2vpn-neighd.log")
        pe.run(f"nohup /usr/sbin/l2vpn-neighd -v </dev/null >{log_path} 2>&1 &")

        i = int(rname.replace("pe", ""))

        for host in PE_HOST.get(rname):
            # set up pe bridges with the EVPN member interfaces facing the hosts
            vni = HOST_VNI.get(host)
            pe.cmd(f"ip link add name br{vni} type bridge stp_state 0")
            if VRF_OVERLAY:
                pe.cmd(f"ip link set br{vni} master {VRF_OVERLAY}")
            if L3VNI:
                pe.cmd(
                    f"""
ip link add name br{L3VNI} type bridge stp_state 0
ip link set br{L3VNI} master {VRF_OVERLAY}
ip link set br{L3VNI} up
ip link add vxlan{L3VNI} type vxlan id {L3VNI} dstport 4789 dev eth-p1 local 10.0.0.{i} nolearning
ip link set vxlan{L3VNI} address 00:00:00:00:00:0{i}
ip link set vxlan{L3VNI} master br{L3VNI}
ip link set vxlan{L3VNI} up
"""
                )
            pe.cmd(
                f"""
ip addr add 192.168.{vni}.{i}/24 dev br{vni}
ip link set dev br{vni} up
ip link add vxlan{vni} type vxlan id {vni} dstport 4789 dev eth-p1 local 10.0.0.{i} nolearning
ip link set dev vxlan{vni} master br{vni}
bridge link set dev vxlan{vni} neigh_suppress on
bridge link set dev vxlan{vni} learning off
ip link set up dev vxlan{vni}
ip link set dev eth-{host} master br{vni}
"""
            )

    tgen.gears["pe3"].cmd("ip link set dev eth-h1 master br101")
    tgen.gears["pe2"].cmd("ip link set dev eth-h1a master br101")
    tgen.gears["pe2"].cmd("ip link set dev eth-h1b master br101")

    tgen.gears["p1"].run("sysctl -w net.ipv4.ip_forward=1")

    # For all registered routers, load the zebra configuration file
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if rname.startswith("h"):
            continue
        router.load_config(
            TopoRouter.RD_OSPF, os.path.join(CWD, "{}/ospfd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()

    # wait for l2vpn-neighd to start
    time.sleep(5)

    # Set host default gateway route and arp_accept
    for hname, host in router_list.items():
        if hname not in HOST_PE:
            continue
        pename = HOST_PE.get(hname)
        i = pename.replace("pe", "")
        vni = HOST_VNI.get(hname)
        if IRB_TEST:
            host.run(f"ip route add default via 192.168.{vni}.{i}")
        # Send gratuitous ARP
        host.run(f"arping -c 1 -U -I eth-{pename} {HOST_IP[hname]}")

        host.run(f"sysctl -w net.ipv4.conf.eth-{pename}.arp_accept=1")

    if L3VNI:
        for rname, pe in router_list.items():
            if not rname.startswith("pe"):
                continue
            pe.vtysh_cmd(
                f"""
configure terminal
 vrf {VRF_OVERLAY}
  vni {L3VNI}
"""
            )


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # kill all l2vpn-neighd instances
    tgen.net.cmd_nostatus("pkill -f l2vpn-neighd")

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_bgp_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        if not rname.startswith("pe"):
            continue

        result = verify_bgp_convergence_from_running_config(tgen, dut=rname)
        assert result is True, f"{rname}: BGP is not converging. {result}"


def check_vni_macs_present(tgen, router, vni, maclist):
    result = router.vtysh_cmd("show evpn mac vni {} json".format(vni), isjson=True)
    for rname, ifname in maclist:
        m = tgen.net.macs[(rname, ifname)]
        if m not in result["macs"]:
            return "MAC ({}) for interface {} on {} missing on {} from {}".format(
                m, ifname, rname, router.name, json.dumps(result, indent=4)
            )
    return None


def _check_pe_converge_evpn(tgen, router):
    rname = router.name

    logger.info(f"Check {rname} EVPN convergence")

    json_file = "{}/{}/evpn.vni.json".format(CWD, rname)
    expected = json.loads(open(json_file).read())
    if VRF_OVERLAY:
        for vni in expected:
            vni.update(tenantVrf=VRF_OVERLAY)

    test_func = partial(
        topotest.router_json_cmp, router, "show evpn vni detail json", expected
    )
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success, f"{rname} JSON output mismatches {result}"

    if L3VNI:
        expected = json.loads(open(f"{CWD}/{rname}/evpn.l3vni.json").read())
        test_func = partial(
            topotest.router_json_cmp, router, f"show evpn vni {L3VNI} json", expected
        )
        success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, f"{rname} JSON output mismatches {result}"

    for vni, hosts in VNI_HOST.items():
        maclist = set()
        for hname in hosts:
            maclist.add((hname, f"eth-{HOST_PE.get(hname)}"))

        test_func = partial(
            check_vni_macs_present,
            tgen,
            router,
            vni,
            maclist,
        )

        success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert success, f"{rname} missing expected MACs {result}"


def check_pe_converge_evpn(tgen):
    "Wait for protocol convergence"

    # Let's ensure that the hosts have actually tried talking to
    # each other.  Otherwise under certain startup conditions
    # they may not actually do any l2 arp'ing and as such
    # the bridges won't know about the hosts on their networks
    for host, vni in HOST_VNI.items():
        for h, ip in HOST_IP.items():
            if host == h:
                continue
            if not IRB_TEST and f"192.168.{vni}." not in ip:
                # only test inter-subnet routing in IRB tests
                continue
            check_ping(host, ip, True, 30, 1)

    for rname, router in tgen.routers().items():
        if not rname.startswith("pe"):
            continue
        _check_pe_converge_evpn(tgen, router)


def test_pe_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_pe_converge_evpn(tgen)


def mac_learn_test(host, local):
    "check the host MAC gets learned by the VNI"

    host_output = host.vtysh_cmd(f"show interface eth-{local.name}")
    int_lines = host_output.splitlines()
    for line in int_lines:
        line_items = line.split(": ")
        if "HWaddr" in line_items[0]:
            mac = line_items[1]
            break

    vni = HOST_VNI.get(host.name)
    mac_output = local.vtysh_cmd(f"show evpn mac vni {vni} mac {mac} json")
    mac_output_json = json.loads(mac_output)
    assertmsg = "Local MAC output does not match interface mac {}".format(mac)
    assert mac_output_json[mac]["type"] == "local", assertmsg


def test_learning_pe():
    "test MAC learning on pe"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, pe in tgen.routers().items():
        if not rname.startswith("pe"):
            continue

        logger.info(f"Check MAC learning on {rname}")

        for hname in PE_HOST.get(rname):
            host = tgen.gears[hname]
            mac_learn_test(host, pe)


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
            if mac_list[mac]["type"] != "local":
                continue
            if mac_list[mac]["intf"].startswith("br"):
                continue
            assertmsg = "JSON output mismatches local: {} remote: {}".format(
                local_output_vni_json[0]["vtepIp"],
                remote_output_json[vni]["macs"][mac]["remoteVtep"],
            )
            assert (
                remote_output_json[vni]["macs"][mac]["remoteVtep"]
                == local_output_vni_json[0]["vtepIp"]
            ), assertmsg


def test_local_remote_mac_pe():
    "Test MAC transfer PE local and PE remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe_list = {n: r for n, r in tgen.routers().items() if n.startswith("pe")}

    for rname, pe in pe_list.items():
        for remote_rname, remote_pe in pe_list.items():
            if rname == remote_rname:
                continue
            logger.info(f"Check MAC transfer local {rname} remote {remote_rname}")

            mac_test_local_remote(pe, remote_pe)


def ip_learn_test(tgen, host, local, remote, ip_addr):
    "check the host IP gets learned by the VNI"
    host_output = host.vtysh_cmd(f"show interface eth-{local.name}")
    int_lines = host_output.splitlines()
    for line in int_lines:
        line_items = line.split(": ")
        if "HWaddr" in line_items[0]:
            mac = line_items[1]
            break

    vni = HOST_VNI.get(host.name)
    # check we have a local association between the MAC and IP

    def check_local_ip_learned():
        local_output = local.vtysh_cmd(f"show evpn mac vni {vni} mac {mac} json")
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
        remote_output = remote.vtysh_cmd(f"show evpn mac vni {vni} mac {mac} json")
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


def test_ip_pe_learn():
    "run the IP learn test for pe"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe_list = {n: r for n, r in tgen.routers().items() if n.startswith("pe")}
    host_list = {n: r for n, r in tgen.routers().items() if n.startswith("h")}

    for hname, host in host_list.items():
        if hname not in HOST_PE:
            continue
        pename = HOST_PE.get(hname)
        i = pename.replace("pe", "")
        vni = HOST_VNI.get(hname)

        # lets populate that arp cache
        host.run(f"ping -c1 192.168.{vni}.{i}")
        local_pe = tgen.gears[pename]
        for rname, remote_pe in pe_list.items():
            if rname == pename:
                continue
            ip_learn_test(tgen, host, local_pe, remote_pe, HOST_IP[hname])


def iptables_filter_vni(router, interface, vni, set=True):
    a = "A" if set else "D"
    iface_arg = f"-i {interface} " if interface else ""

    router.cmd(
        f"""
iptables -{a} PREROUTING -t raw -p udp --dport 4789 -m u32 --u32 '0>>22&0x3c@11&0xffffff={vni}' {iface_arg} -j DROP
"""
    )


def test_routing_asymmetric_vni():
    """
    Check that inter-subnet is taking the correct VxLAN.
    Check ping h1 (192.168.101.101 - VNI 101) to h6 (192.168.102.103 - VNI 102)
    ICMP request must go through VxLAN to pe3 VNI 102
    ICMP reply must go through VxLAN to pe1 VNI 101

    Use iptables filtering.
    ping from h1 to h3 and h6 to h4 take are in the subnet within the same VNI. They
    confirm iptables filtering is working properly.
    """

    if not IRB_TEST or L3VNI:
        pytest.skip("Only for IRB asymmetric tests")

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    p1 = tgen.gears["p1"]

    check_ping("h1", "192.168.101.103", True, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", True, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, "eth-pe1", 101, set=True)
    iptables_filter_vni(p1, "eth-pe3", 102, set=True)

    check_ping("h1", "192.168.101.103", False, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", False, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, "eth-pe3", 101, set=True)
    iptables_filter_vni(p1, "eth-pe2", 102, set=True)

    check_ping("h1", "192.168.102.103", False, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, "eth-pe1", 101, set=False)
    iptables_filter_vni(p1, "eth-pe3", 102, set=False)
    iptables_filter_vni(p1, "eth-pe3", 101, set=False)
    iptables_filter_vni(p1, "eth-pe2", 102, set=False)

    check_ping("h1", "192.168.101.103", True, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", True, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet


def test_routing_symmetric_vni():
    """
    Check that inter-subnet is taking the correct VxLAN.
    Check ping h1 (192.168.101.101 - VNI 101) to h6 (192.168.102.103 - VNI 102)
    ICMP request must go through VxLAN to pe3 VNI 300 (L3VNI)
    ICMP reply must go through VxLAN to pe1 VNI 300 (L3VNI)

    Use iptables filtering.
    ping from h1 to h3 and h6 to h4 take are in the subnet within the same VNI. They
    confirm iptables filtering is working properly.
    """

    if not IRB_TEST or not L3VNI:
        pytest.skip("Only for IRB symmetric tests")

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    p1 = tgen.gears["p1"]

    check_ping("h1", "192.168.101.103", True, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", True, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, None, 101, set=True)
    iptables_filter_vni(p1, None, 102, set=True)

    check_ping("h1", "192.168.101.103", False, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", False, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, None, L3VNI, set=True)

    check_ping("h1", "192.168.102.103", False, 30, 1)  # ping h6 inter-subnet

    iptables_filter_vni(p1, None, 101, set=False)
    iptables_filter_vni(p1, None, 102, set=False)
    iptables_filter_vni(p1, None, L3VNI, set=False)

    check_ping("h1", "192.168.101.103", True, 30, 1)  # ping h3
    check_ping("h6", "192.168.102.101", True, 30, 1)  # ping h4
    check_ping("h1", "192.168.102.103", True, 30, 1)  # ping h6 inter-subnet


def test_unique_svi():
    """
    Currently, each PE assigns a different Switch Virtual Interface (SVI) IP
    address. Hosts use the SVI IP of their directly connected PE as their
    default gateway.

    To enable consistent gateway behavior across all PEs, configure identical
    SVI IP addresses per VNI. This allows all hosts to use the same default
    gateway, regardless of which PE they are connected to.

    Check that hosts can still ping each other with this configuration.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe_list = {n: r for n, r in tgen.routers().items() if n.startswith("pe")}
    host_list = {n: r for n, r in tgen.routers().items() if n.startswith("h")}

    for pename, pe in pe_list.items():
        pe.vtysh_cmd(
            f"""
configure terminal
router bgp 65000
 address-family l2vpn evpn
  no advertise-svi-ip
"""
        )

        if pename == "pe1":
            # no change
            continue

        for hname in PE_HOST.get(pename):
            vni = HOST_VNI.get(hname)

            # set up pe bridges with the EVPN member interfaces facing the hosts
            i = pename.replace("pe", "")
            pe.cmd(
                f"""
    ip addr del 192.168.{vni}.{i}/24 dev br{vni}
    ip addr add 192.168.{vni}.1/24 dev br{vni}
    """
            )

            # update host gateway and ARP
            if IRB_TEST:
                tgen.gears[hname].run(f"ip route change default via 192.168.{vni}.1")
            tgen.gears[hname].run(f"ip neigh del 192.168.{vni}.1 dev eth-{pename}")
            check_ping(pename, HOST_IP[hname], True, 30, 1, source_addr=f"br{vni}")

    check_pe_converge_evpn(tgen)


def test_move_host():
    """
    Check that with we can move host h1 from pe1 to pe3.
    MAC/IP 192.168.101.101/00:00:00:00:01:01 moves from pe1 to pe3
    The connectivity must be still operational.

    Since we cannot move a host, we simulate it by:
    - shutting down h1 interface to pe1
    - connecting h1 to pe3
    - reusing h1 eth-pe1 MAC/IP for h1 eth-pe3
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h1"].cmd(
        f"""
ip link set eth-pe1 down
ip link set eth-pe1 address 00:00:00:00:01:ff
ip address del dev eth-pe1 192.168.101.101/24
"""
    )
    tgen.net.macs[("h1", "eth-pe1")] = "00:00:00:00:01:ff"

    tgen.gears["h1"].cmd(
        f"""
ip link set eth-pe3 down
ip link set eth-pe3 address 00:00:00:00:01:01
ip link set eth-pe3 up

ip address add dev eth-pe3 192.168.101.101/24
"""
    )

    if IRB_TEST:
        tgen.gears["h1"].cmd("ip route add default via 192.168.101.1")

    tgen.net.macs[("h1", "eth-pe3")] = "00:00:00:00:01:01"

    tgen.gears["h1"].cmd(f"arping -c 1 -U -I eth-pe3 192.168.101.101")

    tgen.gears["h1"].cmd("sysctl -w net.ipv4.conf.eth-pe3.arp_accept=1")

    global HOST_PE, PE_HOST
    HOST_PE["h1"] = "pe3"
    PE_HOST["pe1"].discard("h1")
    PE_HOST["pe3"].add("h1")

    check_pe_converge_evpn(tgen)


def test_revert_move_host():
    """
    Revert previous step.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h1"].cmd(
        f"""
ip link set eth-pe3 down
ip link set eth-pe3 address 00:00:00:00:01:fe
ip address del dev eth-pe3 192.168.101.101/24
"""
    )
    tgen.net.macs[("h1", "eth-pe3")] = "00:00:00:00:01:fe"

    tgen.gears["h1"].cmd(
        f"""
ip link set eth-pe1 up
ip link set eth-pe1 address 00:00:00:00:01:01

ip address add dev eth-pe1 192.168.101.101/24
"""
    )

    if IRB_TEST:
        tgen.gears["h1"].cmd("ip route add default via 192.168.101.1")

    tgen.net.macs[("h1", "eth-pe1")] = "00:00:00:00:01:01"

    tgen.gears["h1"].cmd(f"arping -c 1 -U -I eth-pe1 192.168.101.101")

    global HOST_PE, PE_HOST
    HOST_PE["h1"] = "pe1"
    PE_HOST["pe3"].discard("h1")
    PE_HOST["pe1"].add("h1")

    check_pe_converge_evpn(tgen)


def test_move_ip():
    """
    Check that with we can move ip 192.168.101.101 from h1 to h1a
    The connectivity must be still operational.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h1"].cmd("ip link set dev eth-pe1 down")

    tgen.gears["h1a"].cmd("ip address add dev eth-pe2 192.168.101.101/24")
    if IRB_TEST:
        tgen.gears["h1a"].cmd("ip route add default via 192.168.101.1")
    tgen.gears["h1a"].cmd("sysctl -w net.ipv4.conf.eth-pe2.arp_accept=1")

    tgen.gears["h1a"].cmd(f"arping -c 1 -U -I eth-pe2 192.168.101.101")

    global HOST_PE, PE_HOST, VNI_HOST, HOST_VNI, HOST_IP
    HOST_PE.pop("h1")
    HOST_PE["h1a"] = "pe2"
    PE_HOST["pe1"].discard("h1")
    PE_HOST["pe2"].add("h1a")
    VNI_HOST["101"].discard("h1")
    VNI_HOST["101"].add("h1a")
    HOST_VNI.pop("h1")
    HOST_VNI["h1a"] = 101
    HOST_IP.pop("h1")
    HOST_IP["h1a"] = "192.168.101.101"

    check_pe_converge_evpn(tgen)


def test_move_ip_same_pe():
    """
    Check that with we can move ip 192.168.101.101 from h1a to h1b
    The connectivity must be still operational.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h1a"].cmd("ip link set dev eth-pe2 down")

    tgen.gears["h1b"].cmd("ip address add dev eth-pe2 192.168.101.101/24")
    if IRB_TEST:
        tgen.gears["h1b"].cmd("ip route add default via 192.168.101.1")

    tgen.gears["h1b"].cmd("sysctl -w net.ipv4.conf.eth-pe2.arp_accept=1")

    tgen.gears["h1b"].cmd(f"arping -c 1 -U -I eth-pe2 192.168.101.101")

    global HOST_PE, PE_HOST, VNI_HOST, HOST_VNI, HOST_IP
    HOST_PE.pop("h1a")
    HOST_PE["h1b"] = "pe2"
    PE_HOST["pe2"].discard("h1a")
    PE_HOST["pe2"].add("h1b")
    VNI_HOST["101"].discard("h1a")
    VNI_HOST["101"].add("h1b")
    HOST_VNI.pop("h1a")
    HOST_VNI["h1b"] = 101
    HOST_IP.pop("h1a")
    HOST_IP["h1b"] = "192.168.101.101"

    check_pe_converge_evpn(tgen)


def test_change_ip():
    """
    Check that h1b can change its IP address.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h1b"].cmd("ip address del dev eth-pe2 192.168.101.101/24")
    tgen.gears["h1b"].cmd("ip address add dev eth-pe2 192.168.101.104/24")
    if IRB_TEST:
        tgen.gears["h1b"].cmd("ip route add default via 192.168.101.1")

    tgen.gears["h1b"].cmd(f"arping -c 1 -U -I eth-pe2 192.168.101.104")

    global HOST_IP

    HOST_IP["h1b"] = "192.168.101.104"

    check_pe_converge_evpn(tgen)


def test_change_to_previous_ip():
    """
    Check that h1b can change its IP address.
    """

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["h3"].cmd("ip address del dev eth-pe3 192.168.101.103/24")
    tgen.gears["h3"].cmd("ip address add dev eth-pe3 192.168.101.101/24")
    if IRB_TEST:
        tgen.gears["h3"].cmd("ip route add default via 192.168.101.1")

    tgen.gears["h3"].cmd(f"arping -c 1 -U -I eth-pe3 192.168.101.101")

    global HOST_IP

    HOST_IP["h3"] = "192.168.101.101"

    check_pe_converge_evpn(tgen)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
