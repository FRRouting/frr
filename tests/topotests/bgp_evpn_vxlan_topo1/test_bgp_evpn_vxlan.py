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
from lib.bgp import verify_bgp_convergence_from_running_config
from lib.checkping import check_ping
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd]


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
    connect_routers(tgen, "pe1", "h1")
    connect_routers(tgen, "pe2", "h2")


def setup_module(mod):
    "Sets up the pytest environment"
    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, pe in router_list.items():
        if not rname.startswith("pe"):
            continue

        i = rname.replace("pe", "")

        # set up pe bridges with the EVPN member interfaces facing the hosts
        pe.cmd(
            f"""
ip link add name br101 type bridge stp_state 0
ip addr add 192.168.101.{i}/24 dev br101
ip link set dev br101 up
ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.0.0.{i} nolearning
ip link set dev vxlan101 master br101
ip link set up dev vxlan101
ip link set dev eth-h{i} master br101
"""
        )

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


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

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


def _test_pe_converge_evpn(tgen, router):
    rname = router.name

    logger.info(f"Check {rname} EVPN convergence")

    json_file = "{}/{}/evpn.vni.json".format(CWD, rname)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, router, "show evpn vni 101 json", expected
    )
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success, f"{rname} JSON output mismatches {result}"

    maclist = set()
    for hname in tgen.routers():
        if not rname.startswith("h"):
            continue
        i = hname.replace("h", "")
        maclist.add((hname, f"eth-pe{i}"))

    test_func = partial(
        check_vni_macs_present,
        tgen,
        router,
        101,
        maclist,
    )

    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert success, f"{rname} missing expected MACs {result}"


def test_pe_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host_list = [rname for rname in tgen.routers() if rname.startswith("h")]

    # Let's ensure that the hosts have actually tried talking to
    # each other.  Otherwise under certain startup conditions
    # they may not actually do any l2 arp'ing and as such
    # the bridges won't know about the hosts on their networks
    for host in host_list:
        for i in range(1, len(host_list) + 1):
            check_ping(host, f"192.168.101.10{i}", True, 30, 1)

    for rname, router in tgen.routers().items():
        if not rname.startswith("pe"):
            continue
        _test_pe_converge_evpn(tgen, router)


def mac_learn_test(host, local):
    "check the host MAC gets learned by the VNI"

    host_id = host.name.replace("h", "")
    host_output = host.vtysh_cmd("show interface eth-pe{}".format(host_id))
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

        i = rname.replace("pe", "")
        host = tgen.gears[f"h{i}"]
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
            if mac_list[mac]["type"] == "local" and mac_list[mac]["intf"] != "br101":
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
    host_id = host.name.replace("h", "")
    host_output = host.vtysh_cmd("show interface eth-pe{}".format(host_id))
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


def test_ip_pe_learn():
    "run the IP learn test for pe"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe_list = {n: r for n, r in tgen.routers().items() if n.startswith("pe")}
    host_list = {n: r for n, r in tgen.routers().items() if n.startswith("h")}

    for hname, host in host_list.items():
        i = hname.replace("h", "")

        # lets populate that arp cache
        host.run(f"ping -c1 192.168.101.{i}")
        local_pe = tgen.gears[f"pe{i}"]
        for rname, remote_pe in pe_list.items():
            if rname == f"pe{i}":
                continue
            ip_learn_test(tgen, host, local_pe, remote_pe, f"192.168.101.10{i}")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
