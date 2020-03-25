#!/usr/bin/env python

#
# test_bgp_evpn_vxlan.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by Volta Networks
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo


class TemplateTopo(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

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
    tgen = Topogen(TemplateTopo, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    tgen.start_topology()

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    p1 = tgen.gears["P1"]

    # set up PE bridges with the EVPN member interfaces facing the CE hosts
    pe1.run("ip link add name br101 type bridge stp_state 0")
    pe1.run("ip link set dev br101 up")
    pe1.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.10.10.10 nolearning"
    )
    pe1.run("ip link set dev vxlan101 master br101")
    pe1.run("ip link set up dev vxlan101")
    pe1.run("ip link set dev PE1-eth0 master br101")

    pe2.run("ip link add name br101 type bridge stp_state 0")
    pe2.run("ip link set dev br101 up")
    pe2.run(
        "ip link add vxlan101 type vxlan id 101 dstport 4789 local 10.30.30.30 nolearning"
    )
    pe2.run("ip link set dev vxlan101 master br101")
    pe2.run("ip link set up dev vxlan101")
    pe2.run("ip link set dev PE2-eth1 master br101")
    p1.run("sysctl -w net.ipv4.ip_forward=1")

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    for rname, router in router_list.iteritems():
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

    test_func = partial(
        topotest.router_json_cmp, pe1, "show evpn vni 101 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=125, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe1.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def test_pe2_converge_evpn():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe2 = tgen.gears["PE2"]
    json_file = "{}/{}/evpn.vni.json".format(CWD, pe2.name)
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, pe2, "show evpn vni 101 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=125, wait=1)
    assertmsg = '"{}" JSON output mismatches'.format(pe2.name)
    assert result is None, assertmsg
    # tgen.mininet_cli()


def mac_learn_test(host, local):
    "check the host MAC gets learned by the VNI"

    host_output = host.vtysh_cmd("show interface {}-eth0".format(host.name))
    int_lines = host_output.splitlines()
    line_items = int_lines[7].split(": ")
    mac = line_items[1]
    mac_output = local.vtysh_cmd("show evpn mac vni 101 mac {} json".format(mac))
    mac_output_json = json.loads(mac_output)
    assertmsg = "Local MAC output does not match interface mac {}".format(mac)
    assert mac_output_json[mac]["type"] == "local"


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
    " Test MAC transfer PE1 local and PE2 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    mac_test_local_remote(pe1, pe2)


def test_local_remote_mac_pe2():
    " Test MAC transfer PE2 local and PE1 remote"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pe1 = tgen.gears["PE1"]
    pe2 = tgen.gears["PE2"]
    mac_test_local_remote(pe2, pe1)

    # Memory leak test template


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
