#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_bgp_evpn_vxlan_macvrf_soo.py
#
# May 10 2023, Trey Aspelund <taspelund@nvidia.com>
#
# Copyright (C) 2023 NVIDIA Corporation
#
# Test MAC-VRF Site-of-Origin feature.
# Ensure:
# - routes received with SoO are installed w/o "mac-vrf soo" config
# - invalid "mac-vrf soo" config is rejected
# - valid "mac-vrf soo" config is applied to local VNIs
# - valid "mac-vrf soo" is set for locally originated type-2/3 routes
# - routes received with SoO are unimported/uninstalled from L2VNI/zebra
# - routes received with SoO are unimported/uninstalled from L3VNI/RIB
# - routes received with SoO are still present in global EVPN loc-rib
#

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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"

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
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    p1 = tgen.gears["P1"]
    host1 = tgen.gears["host1"]
    host2 = tgen.gears["host2"]

    # Setup PEs with:
    # - vrf: VRF-A
    # - l3vni 404: vxlan404 / br404
    # - l2vni 101: vxlan101 / br101

    ## Setup VRF
    # pe1
    pe1.run("ip link add VRF-A type vrf table 4000")
    pe1.run("ip link set VRF-A up")
    # pe2
    pe2.run("ip link add VRF-A type vrf table 4000")
    pe2.run("ip link set VRF-A up")

    ## Setup L3VNI bridge/vxlan
    # pe1
    pe1.run("ip link add name br404 type bridge stp_state 0")
    pe1.run("ip link set dev br404 addr aa:bb:cc:00:11:ff")
    pe1.run("ip link set dev br404 master VRF-A addrgenmode none")
    pe1.run("ip link set dev br404 up")
    pe1.run(
        "ip link add vxlan404 type vxlan id 404 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan404 master br404 addrgenmode none")
    pe1.run("ip link set dev vxlan404 type bridge_slave neigh_suppress on learning off")
    pe1.run("ip link set dev vxlan404 up")
    # pe2
    pe2.run("ip link add name br404 type bridge stp_state 0")
    pe2.run("ip link set dev br404 addr aa:bb:cc:00:22:ff")
    pe2.run("ip link set dev br404 master VRF-A addrgenmode none")
    pe2.run("ip link set dev br404 up")
    pe2.run(
        "ip link add vxlan404 type vxlan id 404 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan404 master br404 addrgenmode none")
    pe2.run("ip link set dev vxlan404 type bridge_slave neigh_suppress on learning off")
    pe2.run("ip link set dev vxlan404 up")

    ## Setup L2VNI bridge/vxlan + L2 PE/CE link
    # pe1
    pe1.run("ip link add name br101 type bridge stp_state 0")
    pe1.run("ip addr add 10.10.1.1/24 dev br101")
    pe1.run("ip link set dev br101 addr aa:bb:cc:00:11:aa")
    pe1.run("ip link set dev br101 master VRF-A")
    pe1.run("ip link set dev br101 up")
    pe1.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan101 master br101")
    pe1.run("ip link set dev vxlan101 type bridge_slave neigh_suppress on learning off")
    pe1.run("ip link set dev vxlan101 up")
    pe1.run("ip link set dev PE1-eth0 master br101")
    pe1.run("ip link set dev PE1-eth0 up")
    # pe2
    pe2.run("ip link add name br101 type bridge stp_state 0")
    pe2.run("ip addr add 10.10.1.3/24 dev br101")
    pe2.run("ip link set dev br101 addr aa:bb:cc:00:22:ff")
    pe2.run("ip link set dev br101 master VRF-A")
    pe2.run("ip link set dev br101 up")
    pe2.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan101 master br101")
    pe2.run("ip link set dev vxlan101 type bridge_slave neigh_suppress on learning off")
    pe2.run("ip link set dev vxlan101 up")
    pe2.run("ip link set dev PE2-eth1 master br101")
    pe2.run("ip link set dev PE2-eth1 up")

    ## Enable IPv4 Routing
    p1.run("sysctl -w net.ipv4.ip_forward=1")
    pe1.run("sysctl -w net.ipv4.ip_forward=1")
    pe2.run("sysctl -w net.ipv4.ip_forward=1")

    ## tell hosts to send GARP upon IPv4 addr assignment
    host1.run("sysctl -w net.ipv4.conf.host1-eth0.arp_announce=1")
    host2.run("sysctl -w net.ipv4.conf.host2-eth0.arp_announce=1")

    ## Load FRR config on all nodes and start topo
    router_list = tgen.routers()
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
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def show_vni_json_elide_ifindex(pe, vni, expected):
    output_json = pe.vtysh_cmd("show evpn vni {} json".format(vni), isjson=True)
    if "ifindex" in output_json:
        output_json.pop("ifindex")

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
    local_output = local.vtysh_cmd("show evpn mac vni 101 mac {} json".format(mac))
    print(local_output)
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
        print(remote_output)
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

    print("tries: {}".format(count))
    assertmsg = "{} remote learned mac no address: {} ".format(host.name, mac)
    # some debug for this failure
    if not converged == True:
        log_output = remote.run("cat zebra.log")
        print(log_output)

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


def is_installed(json_paths, soo):
    """
    check if any path has been selected as best.
    optionally check for matching SoO on bestpath.
    """
    best = False
    soo_present = False
    for path in json_paths:
        path = path[0]
        # sometimes "bestpath" is a bool, other times it's a dict
        # either way, the key isn't present when the bool is false...
        # so we may as well just check for the key's existence
        best = "bestpath" in path
        path_keys = path.keys()
        if best:
            if soo:
                soo_present = soo in path["extendedCommunity"]["string"]
            break
    return (best and soo_present) if soo else best


def change_soo(pe, soo, vni):
    soo_cmd_str = "mac-vrf soo "
    if soo:
        soo_cmd_str += soo
    else:
        soo_cmd_str = "no " + soo_cmd_str
    pe.vtysh_cmd(
        """
        configure terminal
        router bgp 65000
        address-family l2vpn evpn
         {}
        """.format(
            soo_cmd_str
        )
    )
    bgp_l2vni = get_bgp_l2vni_fields(pe, vni)
    l2vni_soo = bgp_l2vni[2]
    return l2vni_soo == soo


def get_evpn_rt_json_str(vni, rd, oip=None, mac=None, ip=None):
    "convert evpn route fields into a route string + global/l2vni cli syntax"
    # type-3
    if oip:
        rt_str = "[3]:[0]:[32]:[{}]".format(oip)
        global_rt_cmd = "show bgp l2vpn evpn route rd {} type 3 json".format(rd)
        l2vni_rt_cmd = "show bgp vni {} type 3 vtep {} json".format(vni, oip)
    # type-2
    else:
        rt_str = "[2]:[0]:[48]:[{}]".format(mac)
        global_rt_cmd = "show bgp l2vpn evpn route rd {} type 2".format(rd)
        l2vni_rt_cmd = "show bgp vni {} type 2 mac {}".format(vni, mac)
        if ip:
            ip_len = 128 if ":" in ip else 32
            rt_str += ":[{}]:[{}]".format(ip_len, ip)
            l2vni_rt_cmd = "show bgp vni {} type 2 ip {}".format(vni, ip)
        global_rt_cmd += " json"
        l2vni_rt_cmd += " json"
    return [rt_str, global_rt_cmd, l2vni_rt_cmd]


def get_evpn_rt_json(pe, vni, rd, oip=None, mac=None, ip=None):
    "get json global/l2vni json blobs for the corresponding evpn route"
    rt = get_evpn_rt_json_str(vni, rd, oip, mac, ip)
    rt_str = rt.pop(0)
    global_rt_cmd = rt.pop(0)
    l2vni_rt_cmd = rt.pop(0)
    logger.info(
        "collecting global/l2vni evpn routes for pfx {} on {}".format(rt_str, pe.name)
    )
    global_rt_json = pe.vtysh_cmd(global_rt_cmd, isjson=True)
    logger.info("global evpn route for pfx {} on {}".format(rt_str, pe.name))
    logger.info(global_rt_json)
    l2vni_rt_json = pe.vtysh_cmd(l2vni_rt_cmd, isjson=True)
    logger.info("l2vni evpn route for pfx {} on {}".format(rt_str, pe.name))
    logger.info(l2vni_rt_json)
    return [rt_str, global_rt_json, l2vni_rt_json]


def get_bgp_l2vni_fields(pe, vni):
    bgp_vni_output = pe.vtysh_cmd(
        "show bgp l2vpn evpn vni {} json".format(vni), isjson=True
    )
    rd = bgp_vni_output["rd"]
    oip = bgp_vni_output["originatorIp"]
    soo = bgp_vni_output["siteOfOrigin"]
    return [rd, oip, soo]


def rt_test(pe, vni, rd, oip, mac, ip, soo):
    """
    Check installation status of a given route.
    @pe = router where bgp routes are collected from
    @vni = l2vni
    @rd = rd of the route
    @oip = originator-ip, set only for type-3 route
    @mac = nlri mac, set only for type-2
    @ip = nlri ip, optionally set for type-2
    @soo = MAC-VRF SoO string, set if SoO needs to be
      on the rt to be considered installed.
    """
    rt = get_evpn_rt_json(pe, vni, rd, oip, mac, ip)
    rt_str = rt.pop(0)
    rt_global_json = rt.pop(0)
    rt_l2vni_json = rt.pop(0)

    if (
        not rt_global_json
        or rd not in rt_global_json
        or rt_str not in rt_global_json[rd]
    ):
        global_installed = False
    else:
        global_json_paths = rt_global_json[rd][rt_str]["paths"]
        global_installed = is_installed(global_json_paths, soo)
    if not rt_l2vni_json:
        l2vni_installed = False
    else:
        if not oip:
            # json for RT2s in l2vni don't key by route string
            l2vni_json_paths = rt_l2vni_json["paths"]
            l2vni_installed = is_installed(l2vni_json_paths, soo)
        elif rt_str in rt_l2vni_json and "paths" in rt_l2vni_json[rt_str]:
            l2vni_json_paths = rt_l2vni_json[rt_str]["paths"]
            l2vni_installed = is_installed(l2vni_json_paths, soo)
        else:
            l2vni_installed = False
    return [global_installed, l2vni_installed]


def test_macvrf_soo():
    "Test MAC-VRF Site-of-Origin on pe1"
    l2vni = 101
    l3vni = 404
    soo = "65000:0"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host1 = tgen.gears["host1"]
    host2 = tgen.gears["host2"]
    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]

    # Collect pe2 RD/Originator-IP
    pe2_bgp_vni = get_bgp_l2vni_fields(pe2, l2vni)
    pe2_rd = pe2_bgp_vni[0]
    pe2_oip = pe2_bgp_vni[1]
    # Collect local addrs
    h2_mac = host2.run("ip -br link show host2-eth0").split()[2]
    h2_ip = host2.run("ip -4 -br addr show host2-eth0").split()[2].split("/")[0]
    pe2_mac = pe2.run("ip -br link show br101").split()[2]
    pe2_ip = pe2.run("ip -4 -br addr show br101").split()[2].split("/")[0]
    # Route fields
    pe2_svi_parms = [l2vni, pe2_rd, None, pe2_mac, pe2_ip]
    pe2_imet_parms = [l2vni, pe2_rd, pe2_oip, None, None]
    host2_mac_parms = [l2vni, pe2_rd, None, h2_mac, None]
    host2_neigh_parms = [l2vni, pe2_rd, None, h2_mac, h2_ip]
    # Route strings
    pe2_svi_rt_str, _, _ = get_evpn_rt_json_str(*pe2_svi_parms)
    pe2_imet_rt_str, _, _ = get_evpn_rt_json_str(*pe2_imet_parms)
    host2_mac_rt_str, _, _ = get_evpn_rt_json_str(*host2_mac_parms)
    host2_neigh_rt_str, _, _ = get_evpn_rt_json_str(*host2_neigh_parms)

    ## trigger mac/arp learn
    host1.run("ping -c1 10.10.1.1")
    host2.run("ping -c1 10.10.1.3")

    step("Test pe2/host2 routes are installed on pe1 (global/l2vni)")

    # expected state:
    # - global table: present w/o soo
    # - l2vni table: present w/o soo
    assertmsg = "{} missing on {} in {}{} evpn table(s)"
    global_parms = [pe2.name, "global", ""]
    l2vni_parms = [pe2.name, "l2vni", l2vni]
    # pe2's type-2 for l2vni 101 svi mac/ip
    test_f = partial(rt_test, pe2, *pe2_svi_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_svi_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_svi_rt_str, *l2vni_parms)
    # pe2's type-3 for l2vni 101
    test_f = partial(rt_test, pe2, *pe2_imet_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_imet_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_imet_rt_str, *l2vni_parms)
    # mac-only type-2 for host2
    test_f = partial(rt_test, pe1, *host2_mac_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_mac_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_mac_rt_str, *l2vni_parms)
    # mac+ip type-2 for host2
    test_f = partial(rt_test, pe1, *host2_neigh_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_neigh_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_neigh_rt_str, *l2vni_parms)

    step("Add valid SoO config to pe2")
    test_f = partial(change_soo, pe2, soo, l2vni)
    _, res = topotest.run_and_expect(test_f, True, count=10, wait=1)
    assertmsg = "soo '{}' not properly applied on {}".format(soo, pe2.name)
    assert res == True, assertmsg

    step("Test valid config applied to L2VNI on pe2")
    ## expected state:
    ## - global table: present w/ soo
    ## - l2vni table: present w/ soo
    assertmsg = "{} not originated with soo {} by {} in {}{} evpn table(s)"
    global_parms = [soo, pe2.name, "global", ""]
    l2vni_parms = [soo, pe2.name, "l2vni", l2vni]
    # type-2 for l2vni 101 svi mac/ip
    test_f = partial(rt_test, pe2, *pe2_svi_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_svi_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_svi_rt_str, *l2vni_parms)
    # type-3 for l2vni 101
    test_f = partial(rt_test, pe2, *pe2_imet_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_imet_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_imet_rt_str, *l2vni_parms)

    step("Test invalid SoO config on pe2")
    test_f = partial(change_soo, pe2, "1:1:1", l2vni)
    _, res = topotest.run_and_expect(test_f, False, count=10, wait=1)
    assertmsg = "soo '1:1:1' should not have been allowed on {}".format(pe2.name)
    assert res == False, assertmsg

    step("Test valid SoO applied to host2 routes (mac-only + mac/ip) on pe2")

    ## expected state:
    ## - global table: present w/ soo
    ## - l2vni table: present w/ soo
    assertmsg = "{} not originated with soo {} by {} in {}{} evpn table(s)"
    global_parms = [soo, pe1.name, "global", ""]
    l2vni_parms = [soo, pe1.name, "l2vni", l2vni]
    # mac-only type-2 for host2
    test_f = partial(rt_test, pe2, *host2_mac_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_mac_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_mac_rt_str, *l2vni_parms)
    # mac+ip type-2 for host2
    test_f = partial(rt_test, pe2, *host2_neigh_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_neigh_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_neigh_rt_str, *l2vni_parms)

    step("Add valid SoO to pe1")
    test_f = partial(change_soo, pe1, soo, l2vni)
    _, res = topotest.run_and_expect(test_f, True, count=10, wait=1)
    assertmsg = "soo '{}' not properly applied on {}".format(soo, pe1.name)
    assert res == True, assertmsg

    step("Test pe2's routes are filtered from l2vni on pe1.")
    ## expected state:
    ## - global table: present w/ soo
    ## - l2vni table: not present
    global_assertmsg = "{} with soo {} from {} missing from global evpn table"
    l2vni_assertmsg = "{} with soo {} from {} not filtered from {}{} evpn table"
    global_parms = [soo, pe1.name, "global", ""]
    l2vni_parms = [soo, pe1.name, "l2vni", l2vni]
    # pe2's svi route
    test_f = partial(rt_test, pe1, *pe2_svi_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, False], count=30, wait=1)
    assert res[0] == True, global_assertmsg.format(pe2_svi_rt_str, *global_parms)
    assert res[1] == False, l2vni_assertmsg.format(pe2_svi_rt_str, *l2vni_parms)
    # pe2's imet route
    test_f = partial(rt_test, pe1, *pe2_imet_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, False], count=30, wait=1)
    assert res[0] == True, global_assertmsg.format(pe2_imet_rt_str, *global_parms)
    assert res[1] == False, l2vni_assertmsg.format(pe2_imet_rt_str, *l2vni_parms)
    # mac-only type-2 for host2
    test_f = partial(rt_test, pe1, *host2_mac_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, False], count=30, wait=1)
    assert res[0] == True, global_assertmsg.format(host2_mac_rt_str, *global_parms)
    assert res[1] == False, l2vni_assertmsg.format(host2_mac_rt_str, *l2vni_parms)
    # mac+ip type-2 for host2
    test_f = partial(rt_test, pe1, *host2_neigh_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, False], count=30, wait=1)
    assert res[0] == True, global_assertmsg.format(host2_neigh_rt_str, *global_parms)
    assert res[1] == False, l2vni_assertmsg.format(host2_neigh_rt_str, *l2vni_parms)

    step("Remove SoO from pe1")
    test_f = partial(change_soo, pe1, "", l2vni)
    _, res = topotest.run_and_expect(test_f, True, count=10, wait=1)
    assertmsg = "soo '{}' not properly removed from {}".format(soo, pe1.name)
    assert res == True, assertmsg

    step("Test pe2/host2 routes are installed on pe1 (global/l2vni)")
    ## expected state:
    ## - global table: present w/ soo
    ## - l2vni table: present w/ soo
    assertmsg = "{} with soo {} missing on {} in {}{} evpn table"
    global_parms = [soo, pe1.name, "global", ""]
    l2vni_parms = [soo, pe1.name, "l2vni", l2vni]
    # pe2's type-2 for l2vni 101 svi mac/ip
    test_f = partial(rt_test, pe1, *pe2_svi_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_svi_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_svi_rt_str, *l2vni_parms)
    # pe2's type-3 for l2vni 101
    test_f = partial(rt_test, pe1, *pe2_imet_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_imet_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_imet_rt_str, *l2vni_parms)
    # mac-only type-2 for host2
    test_f = partial(rt_test, pe1, *host2_mac_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_mac_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_mac_rt_str, *l2vni_parms)
    # mac+ip type-2 for host2
    test_f = partial(rt_test, pe1, *host2_neigh_parms, soo)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_neigh_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_neigh_rt_str, *l2vni_parms)

    step("Remove SoO from pe2")
    test_f = partial(change_soo, pe2, "", l2vni)
    _, res = topotest.run_and_expect(test_f, True, count=10, wait=1)
    assertmsg = "soo '{}' not properly removed from {}".format(soo, pe2.name)
    assert res == True, assertmsg

    step("Test pe2's 'self' routes are installed on pe1 (global/l2vni)")
    ## expected state:
    ## - global table: present w/o soo
    ## - l2vni table: present w/o soo
    assertmsg = "{} missing on {} in {}{} evpn table(s)"
    global_parms = [pe1.name, "global", ""]
    l2vni_parms = [pe1.name, "l2vni", l2vni]
    # pe2's type-2 for l2vni 101 svi mac/ip
    test_f = partial(rt_test, pe1, *pe2_svi_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_svi_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_svi_rt_str, *l2vni_parms)
    # pe2's type-3 for l2vni 101
    test_f = partial(rt_test, pe1, *pe2_imet_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(pe2_imet_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(pe2_imet_rt_str, *l2vni_parms)
    # mac-only type-2 for host2
    test_f = partial(rt_test, pe1, *host2_mac_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_mac_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_mac_rt_str, *l2vni_parms)
    # mac+ip type-2 for host2
    test_f = partial(rt_test, pe1, *host2_neigh_parms, None)
    _, res = topotest.run_and_expect(test_f, [True, True], count=30, wait=1)
    assert res[0] == True, assertmsg.format(host2_neigh_rt_str, *global_parms)
    assert res[1] == True, assertmsg.format(host2_neigh_rt_str, *l2vni_parms)

    # tgen.mininet_cli()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
