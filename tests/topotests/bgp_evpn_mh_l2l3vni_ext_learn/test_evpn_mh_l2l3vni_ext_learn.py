#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_evpn_mh_l2l3vni_ext_learn.py
#
# Copyright (c) 2025 by
# Cisco Systems, Inc.
# Patrice Brissette
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
test_evpn_mh_l2l3vni_ext_learn.py: Testing EVPN multihoming with L3VNI

"""

import os
import sys
import subprocess
from functools import partial
import time

import pytest
import json
import platform
from functools import partial

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen

# bgp_evpn library
from lib import bgp_evpn

#####################################################
##
##   Network Topology Definition
##
## See topology picture at evpn-mh-topo-tests.pdf
#####################################################


def build_topo(tgen):
    """
    EVPN Multihoming Topology -
    1. Two level CLOS
    2. Two spine switches - spine1, spine2
    3. Two racks with Top-of-Rack switches per rack - tormx1, tormx2
    4. Dual attached hosts per-rack - hostd12, hostd21, hostd22
    5. Single attached host - hostd11 to torm11
    6. hostd22 is in a different subnet then hostd1x and hostd21
    7. L2VNI with L3VNI setup on each leaf with SVI as IP gateway
    8. hostd33 is a orphan on torm11
    """

    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("torm11")
    tgen.add_router("torm12")
    tgen.add_router("torm21")
    tgen.add_router("torm22")
    tgen.add_router("hostd11")
    tgen.add_router("hostd12")
    tgen.add_router("hostd21")
    tgen.add_router("hostd22")
    tgen.add_router("hostd33")

    # On main router
    # First switch is for a dummy interface (for local network)

    ##################### spine1 ########################
    # spine1-eth0 is connected to torm11-eth0
    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm11"])

    # spine1-eth1 is connected to torm12-eth0
    switch = tgen.add_switch("sw2")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm12"])

    # spine1-eth2 is connected to torm21-eth0
    switch = tgen.add_switch("sw3")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm21"])

    # spine1-eth3 is connected to torm22-eth0
    switch = tgen.add_switch("sw4")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torm22"])

    ##################### spine2 ########################
    # spine2-eth0 is connected to torm11-eth1
    switch = tgen.add_switch("sw5")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm11"])

    # spine2-eth1 is connected to torm12-eth1
    switch = tgen.add_switch("sw6")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm12"])

    # spine2-eth2 is connected to torm21-eth1
    switch = tgen.add_switch("sw7")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm21"])

    # spine2-eth3 is connected to torm22-eth1
    switch = tgen.add_switch("sw8")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torm22"])

    ##################### torm11 ########################
    # torm11-eth2 is connected to hostd11-eth0
    switch = tgen.add_switch("sw9")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd11"])

    # torm11-eth3 is connected to hostd12-eth0
    switch = tgen.add_switch("sw10")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd12"])

    # torm11-eth4 is connected to hostd33-eth0
    # Its an orphan on torm11
    switch = tgen.add_switch("sw11")
    switch.add_link(tgen.gears["torm11"])
    switch.add_link(tgen.gears["hostd33"])

    ##################### torm12 ########################
    # keeping the hostd11 single-homed
    # torm12-eth2 is connected to hostd11-eth1
    # switch = tgen.add_switch("sw11")
    # switch.add_link(tgen.gears["torm12"])
    # switch.add_link(tgen.gears["hostd11"])

    # torm12-eth3 is connected to hostd12-eth1
    switch = tgen.add_switch("sw12")
    switch.add_link(tgen.gears["torm12"])
    switch.add_link(tgen.gears["hostd12"])

    ##################### torm21 ########################
    # torm21-eth2 is connected to hostd21-eth0
    switch = tgen.add_switch("sw13")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd21"])

    # torm21-eth3 is connected to hostd22-eth0
    switch = tgen.add_switch("sw14")
    switch.add_link(tgen.gears["torm21"])
    switch.add_link(tgen.gears["hostd22"])

    ##################### torm22 ########################
    # torm22-eth2 is connected to hostd21-eth1
    switch = tgen.add_switch("sw15")
    switch.add_link(tgen.gears["torm22"])
    switch.add_link(tgen.gears["hostd21"])

    # torm22-eth3 is connected to hostd22-eth1
    switch = tgen.add_switch("sw16")
    switch.add_link(tgen.gears["torm22"])
    switch.add_link(tgen.gears["hostd22"])


#####################################################
##
##   Tests starting
##
#####################################################

tor_ips = {
    "torm11": "192.168.100.15",
    "torm12": "192.168.100.16",
    "torm21": "192.168.100.17",
    "torm22": "192.168.100.18",
}
tor_mac_macs = {
    "torm11": "aa:bb:cc:00:00:11",
    "torm12": "aa:bb:cc:00:00:12",
    "torm21": "aa:bb:cc:00:00:21",
    "torm22": "aa:bb:cc:00:00:22",
}

svi_ips = {
    "torm11": "45.0.0.2",
    "torm12": "45.0.0.3",
    "torm21": "45.0.0.4",
    "torm22": "45.0.0.5",
}
svi2_ips = {
    "torm11": "20.0.0.2",
    "torm12": "20.0.0.3",
    "torm21": "20.0.0.4",
    "torm22": "20.0.0.5",
}

tor_ips_rack_1 = {"torm11": "192.168.100.15", "torm12": "192.168.100.16"}

tor_ips_rack_2 = {"torm21": "192.168.100.17", "torm22": "192.168.100.18"}

host_es_map = {
    "hostd12": "03:44:38:39:ff:ff:01:00:00:02",
    "hostd21": "03:44:38:39:ff:ff:02:00:00:01",
    "hostd22": "03:44:38:39:ff:ff:02:00:00:02",
}

host_vni_map = {
    "hostd12": 1000,
    "hostd21": 1000,
    "hostd22": 2000,
}


def config_tor(tor_name, tor, tor_ip, svi_pip, svi2_pip):
    """
    Create the bond/vxlan-bridge on the TOR which acts as VTEP and EPN-PE
    """

    # create l3vni along with l3vni bridge
    bgp_evpn.config_l3vni(tor_name, tor, tor_ip, tor_mac_macs)

    # create l2vni, bridge and associated SVI
    bgp_evpn.config_l2vni(tor_name, tor, svi_pip, tor_ip)
    if "torm2" in tor_name:
        bgp_evpn.config_l2vni(tor_name, tor, svi2_pip, tor_ip, vni=2000, vid=2000)

    # create hostbonds and add them to the bridge
    if "torm1" in tor_name:
        sys_mac = "44:38:39:ff:ff:01"
    else:
        sys_mac = "44:38:39:ff:ff:02"

    # torm11 has 3 connections on the same subnet: hostbond1, hostbond2 & hostbond3
    if "torm11" in tor_name:
        bond_member = tor_name + "-eth2"
        bgp_evpn.config_bond(tor, "hostbond1", [bond_member], sys_mac, "br1000")
        bond_member = tor_name + "-eth3"
        bgp_evpn.config_bond(tor, "hostbond2", [bond_member], sys_mac, "br1000")
        bond_member = tor_name + "-eth4"
        bgp_evpn.config_bond(tor, "hostbond3", [bond_member], sys_mac, "br1000")
    # torm12 has only 1 connection with hostbond2
    elif "torm12" in tor_name:
        bond_member = tor_name + "-eth2"
        bgp_evpn.config_bond(tor, "hostbond2", [bond_member], sys_mac, "br1000")
    # torm2x has 2 connections but on different subnets
    else:
        bond_member = tor_name + "-eth2"
        bgp_evpn.config_bond(tor, "hostbond1", [bond_member], sys_mac, "br1000")
        bond_member = tor_name + "-eth3"
        bgp_evpn.config_bond(tor, "hostbond2", [bond_member], sys_mac, "br2000")


def config_tors(tgen, tors):
    for tor_name in tors:
        tor = tgen.gears[tor_name]
        config_tor(
            tor_name,
            tor,
            tor_ips.get(tor_name),
            svi_ips.get(tor_name),
            svi2_ips.get(tor_name),
        )


def compute_host_ip_mac(host_name):
    host_id = host_name.split("hostd")[1]
    if host_name == "hostd22":
        host_ip = "20.0.0." + host_id + "/24"
    else:
        host_ip = "45.0.0." + host_id + "/24"
    host_mac = "00:00:00:00:00:" + host_id
    return host_ip, host_mac


def config_hosts(tgen, hosts):
    for host_name in hosts:
        host = tgen.gears[host_name]
        host_ip, host_mac = compute_host_ip_mac(host_name)
        bgp_evpn.config_host(host_name, host, host_ip, host_mac)


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    krel = platform.release()
    if topotest.version_cmp(krel, "4.19") < 0:
        tgen.errors = "kernel 4.19 needed for multihoming tests"
        pytest.skip(tgen.errors)

    tors = []
    tors.append("torm11")
    tors.append("torm12")
    tors.append("torm21")
    tors.append("torm22")
    config_tors(tgen, tors)

    hosts = []
    hosts.append("hostd11")
    hosts.append("hostd12")
    hosts.append("hostd21")
    hosts.append("hostd22")
    hosts.append("hostd33")
    config_hosts(tgen, hosts)

    # tgen.mininet_cli()
    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, " --kernel-mac-ext-learn"),
                (TopoRouter.RD_BGP, None),
            ],
        )
    tgen.start_router()
    # tgen.mininet_cli()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_evpn_es():
    """
    One ES is setup on torm1x
    Two ES are setup on torm2x. This test checks if -
    1. ES peer has been added to the local ES (via Type-1/EAD route)
    2. The remote ESs are setup with the right list of PEs (via Type-1)
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    dut_name = "torm11"
    local_vteps = set([v for k, v in tor_ips_rack_1.items() if k != dut_name])
    remote_vteps = set([v for _, v in tor_ips_rack_2.items()])

    dut = tgen.gears[dut_name]
    test_fn = partial(
        bgp_evpn.check_es, dut, host_es_map, host_vni_map, local_vteps, remote_vteps
    )
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)

    assertmsg = '"{}" ES content incorrect'.format(dut_name)
    assert result is None, assertmsg


def test_evpn_df():
    """
    1. Check the DF role on all the PEs on rack-1.
    2. Increase the DF preference on the non-DF and check if it becomes
       the DF winner.
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # We will run the tests on just one ES
    esi = host_es_map.get("hostd12")
    intf = "hostbond2"

    tors = []
    tors.append(tgen.gears["torm11"])
    tors.append(tgen.gears["torm12"])
    df_node = "torm11"

    # check roles on rack-1
    for tor in tors:
        role = "DF" if tor.name == df_node else "nonDF"
        test_fn = partial(bgp_evpn.check_df_role, tor, esi, role)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" DF role incorrect'.format(tor.name)
        assert result is None, assertmsg

    # change df preference on the nonDF to make it the df
    torm12 = tgen.gears["torm12"]
    torm12.vtysh_cmd("conf\ninterface %s\nevpn mh es-df-pref %d" % (intf, 60000))
    df_node = "torm12"

    # re-check roles on rack-1; we should have a new winner
    for tor in tors:
        role = "DF" if tor.name == df_node else "nonDF"
        test_fn = partial(bgp_evpn.check_df_role, tor, esi, role)
        _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
        assertmsg = '"{}" DF role incorrect'.format(tor.name)
        assert result is None, assertmsg


def test_mac_extern_learn_basic():
    """
    Test adding a MAC using bridge fdb command with extern_learn option on torm11
    and verify it appears in both TORs with correct flags
    Precondition: bridge fdb, protocol support is needed for this test
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup for torm11
    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    mac = "00:00:00:00:00:88"
    dev = "hostbond2"
    vlan = 1000
    vni = 1000

    # Precondition check on support of 'bridge fdb' with protocol field
    result = bgp_evpn.check_bridge_fdb_proto_supported(dut)
    if result != None:
        pytest.skip(result)

    # wait for protodown rc to clear after startup
    test_fn = partial(bgp_evpn.check_protodown_rc, dut, None)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=3)
    assertmsg = '"{}" protodown rc incorrect'.format(dut_name)
    assert result is None, assertmsg

    # Also get reference to torm12 for cross-checking
    dut2_name = "torm12"
    dut2 = tgen.gears[dut2_name]
    dev2 = "hostbond2"

    # Add MAC using bridge fdb command on torm11
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Check if MAC exists in torm11 kernel bridge FDB with proto hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Bridge FDB check failed for MAC {mac} on device {dev} vlan {vlan} with protocol hw"
    assert result is None, assertmsg

    # Check if MAC exists in torm11's EVPN MAC table as local entry with peer-proxy flag (X)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "X", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"EVPN MAC check failed for MAC {mac} on VNI {vni} with peer-proxy flag as local entry"
    assert result is None, assertmsg

    # Check if MAC has been synced to torm12's kernel bridge FDB with proto zebra
    test_fn = partial(
        bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="zebra"
    )
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Bridge FDB check failed for MAC {mac} on torm12 device {dev2} vlan {vlan} with protocol zebra"
    assert result is None, assertmsg

    # Check if MAC exists in torm12's EVPN MAC table as local entry with peer-active and local-inactive flags (PI)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "PI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"EVPN MAC check failed for MAC {mac} on torm12 VNI {vni} with peer-active and local-inactive flags"
    assert result is None, assertmsg

    # Test MAC removal from torm11
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")

    # Get the MAC holdtime from zebra and wait for that duration
    holdtime = bgp_evpn.get_mac_holdtime(dut)
    # Let the hold timer expire
    time.sleep(holdtime)

    # Verify MAC is removed from torm11's kernel bridge FDB
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Bridge FDB still contains MAC {mac} on device {dev} vlan {vlan} after deletion"
    assert result is None, assertmsg

    # Verify MAC is removed from torm11's EVPN MAC table
    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"EVPN MAC table still contains MAC {mac} on VNI {vni} after deletion"
    assert result is None, assertmsg

    # Verify MAC is also removed from torm12's kernel bridge FDB
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = (
        f"Bridge FDB on torm12 still contains MAC {mac} after deletion from torm11"
    )
    assert result is None, assertmsg

    # Verify MAC is also removed from torm12's EVPN MAC table
    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut2, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"EVPN MAC table on torm12 still contains MAC {mac} after deletion from torm11"
    )
    assert result is None, assertmsg


def test_mac_extern_learn_both_tors():
    """
    Test adding the same MAC on both torm11 and torm12 with extern_learn
    and verify both have it with peer-active flag
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup for torm11
    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    mac = "00:00:00:00:00:99"
    dev = "hostbond2"
    vlan = 1000
    vni = 1000

    # Precondition check on support of 'bridge fdb' with protocol field
    result = bgp_evpn.check_bridge_fdb_proto_supported(dut)
    if result != None:
        pytest.skip(result)

    # Also get reference to torm12
    dut2_name = "torm12"
    dut2 = tgen.gears[dut2_name]
    dev2 = "hostbond2"

    # Add MAC using bridge fdb command on torm11
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Add same MAC using bridge fdb command on torm12
    dut2.run(
        f"bridge fdb add {mac} dev {dev2} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Check if MAC exists in torm11 kernel bridge FDB with proto hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Bridge FDB check failed for MAC {mac} on torm11 device {dev} vlan {vlan} with protocol hw"
    assert result is None, assertmsg

    # Check if MAC exists in torm12 kernel bridge FDB with proto hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Bridge FDB check failed for MAC {mac} on torm12 device {dev2} vlan {vlan} with protocol hw"
    assert result is None, assertmsg

    # Check if MAC exists in torm11's EVPN MAC table as local entry with peer-active flag (P)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"EVPN MAC check failed for MAC {mac} on torm11 VNI {vni} with peer-active flag as local entry"
    assert result is None, assertmsg

    # Check if MAC exists in torm12's EVPN MAC table as local entry with peer-active flag (P)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"EVPN MAC check failed for MAC {mac} on torm12 VNI {vni} with peer-active flag as local entry"
    assert result is None, assertmsg

    # Clean up: remove MACs from both torm11 and torm12
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")
    dut2.run(f"bridge fdb del {mac} dev {dev2} vlan {vlan} master")

    # Wait for MAC removal (using holdtime from first device)
    holdtime = bgp_evpn.get_mac_holdtime(dut)
    time.sleep(holdtime)

    # Verify MAC is removed from both TORs
    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"EVPN MAC table still contains MAC {mac} on torm11 VNI {vni} after deletion"
    )
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut2, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"EVPN MAC table still contains MAC {mac} on torm12 VNI {vni} after deletion"
    )
    assert result is None, assertmsg


def test_mac_extern_learn_delete_readd():
    """
    Test MAC flag transitions when deleting from one TOR and quickly readding before hold timer expires
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup for torm11
    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    mac = "00:00:00:00:00:77"
    dev = "hostbond2"
    vlan = 1000
    vni = 1000

    # Precondition check on support of 'bridge fdb' with protocol field
    result = bgp_evpn.check_bridge_fdb_proto_supported(dut)
    if result != None:
        pytest.skip(result)

    # Also get reference to torm12
    dut2_name = "torm12"
    dut2 = tgen.gears[dut2_name]
    dev2 = "hostbond2"

    # Add MAC using bridge fdb command on both torm11 and torm12
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )
    dut2.run(
        f"bridge fdb add {mac} dev {dev2} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Verify initial state: proto=hw on both sides, both show peer-active flag
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Initial check: Bridge FDB failed for MAC {mac} on torm11 device {dev} with proto hw"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Initial check: Bridge FDB failed for MAC {mac} on torm12 device {dev2} with proto hw"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"Initial check: EVPN MAC failed for MAC {mac} on torm11 with peer-active flag"
    )
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"Initial check: EVPN MAC failed for MAC {mac} on torm12 with peer-active flag"
    )
    assert result is None, assertmsg

    # Delete MAC on torm11 only
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")

    # Sync in progress, don't wait for hold timer
    # Check protocol has changed on torm11 (hw → zebra)
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="zebra")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"After torm11 deletion: Bridge FDB failed for MAC {mac} on torm11 - expected proto zebra"
    assert result is None, assertmsg

    # Verify torm12 still shows proto=hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"After torm11 deletion: Bridge FDB failed for MAC {mac} on torm12 - should stay proto hw"
    assert result is None, assertmsg

    # Check flags on torm11: local, peer-active, local-inactive
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "PI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"After torm11 deletion: EVPN MAC failed for MAC {mac} on torm11 - expected PI flags"
    assert result is None, assertmsg

    # Check flags on torm12: local, peer-active, peer-proxy
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "PX", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"After torm11 deletion: EVPN MAC failed for MAC {mac} on torm12 - expected PX flags"
    assert result is None, assertmsg

    # Re-add MAC on torm11 before hold timer expires
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Sync in progress
    # Verify restored state: proto=hw on both sides, both show peer-active flag
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"After re-add: Bridge FDB failed for MAC {mac} on torm11 device {dev} with proto hw"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"After re-add: Bridge FDB failed for MAC {mac} on torm12 device {dev2} with proto hw"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"After re-add: EVPN MAC failed for MAC {mac} on torm11 with peer-active flag"
    )
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"After re-add: EVPN MAC failed for MAC {mac} on torm12 with peer-active flag"
    )
    assert result is None, assertmsg

    # Final cleanup - remove MAC from both TORs
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")
    dut2.run(f"bridge fdb del {mac} dev {dev2} vlan {vlan} master")

    # Wait for holdtime to expire
    holdtime = bgp_evpn.get_mac_holdtime(dut)
    time.sleep(holdtime)

    # Verify MAC is fully removed from both TORs
    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Final cleanup: MAC {mac} still exists in torm11 EVPN table"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut2, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Final cleanup: MAC {mac} still exists in torm12 EVPN table"
    assert result is None, assertmsg


def test_mac_extern_learn_transition():
    """
    Test MAC transition between TORs:
    1. Add MAC on torm11, verify flags
    2. Delete MAC from torm11, verify flags change
    3. Add MAC on torm12, verify flags change again
    4. Re-add MAC on torm11, verify flags return to both active
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup for torm11
    dut_name = "torm11"
    dut = tgen.gears[dut_name]
    mac = "00:00:00:00:00:55"
    dev = "hostbond2"
    vlan = 1000
    vni = 1000

    # Precondition check on support of 'bridge fdb' with protocol field
    result = bgp_evpn.check_bridge_fdb_proto_supported(dut)
    if result != None:
        pytest.skip(result)

    # Also get reference to torm12
    dut2_name = "torm12"
    dut2 = tgen.gears[dut2_name]
    dev2 = "hostbond2"

    # Step 1: Add MAC on torm11 only
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Check if MAC exists in torm11 kernel bridge FDB with proto hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Step 1: Bridge FDB check failed for MAC {mac} on torm11 device {dev} with protocol hw"
    assert result is None, assertmsg

    # Check if MAC exists in torm11's EVPN MAC table as local entry with peer-proxy flag (X)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "X", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = (
        f"Step 1: EVPN MAC check failed for MAC {mac} on torm11 with peer-proxy flag"
    )
    assert result is None, assertmsg

    # Check if MAC has been synced to torm12's kernel bridge FDB with proto zebra
    test_fn = partial(
        bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="zebra"
    )
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = (
        f"Step 1: Bridge FDB check failed for MAC {mac} on torm12 with protocol zebra"
    )
    assert result is None, assertmsg

    # Check if MAC exists in torm12 with peer-active and local-inactive flags (PI)
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "PI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 1: EVPN MAC check failed for MAC {mac} on torm12 with peer-active and local-inactive flags"
    assert result is None, assertmsg

    # Step 2: Delete MAC from torm11
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")

    # Sync to happen, don't wait for hold timer
    # Verify MAC is removed from torm11's bridge FDB, but would be added back
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="zebra")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Step 2: Bridge FDB check failed for MAC {mac} on torm11 - MAC should be present"
    assert result is None, assertmsg

    # Check torm12 has proto zebra
    test_fn = partial(
        bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="zebra"
    )
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Step 2: Bridge FDB check failed for MAC {mac} on torm12 - expected proto zebra"
    assert result is None, assertmsg

    # Check flags on torm11: local, peer-proxy, local-inactive
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "XI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 2: EVPN MAC check failed for MAC {mac} on torm11 - expected peer-proxy and local-inactive flags"
    assert result is None, assertmsg

    # Check flags on torm12: local, peer-active, local-inactive
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "PI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 2: EVPN MAC check failed for MAC {mac} on torm12 - expected peer-active and local-inactive flags"
    assert result is None, assertmsg

    # Step 3: Add MAC on torm12
    dut2.run(
        f"bridge fdb add {mac} dev {dev2} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Check torm12 now has proto hw
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = (
        f"Step 3: Bridge FDB check failed for MAC {mac} on torm12 - expected proto hw"
    )
    assert result is None, assertmsg

    # Check flags on torm12: local with peer-proxy
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "X", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 3: EVPN MAC check failed for MAC {mac} on torm12 - expected peer-proxy flag"
    assert result is None, assertmsg

    # Check torm11 still has proto zebra
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="zebra")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = f"Step 3: Bridge FDB check failed for MAC {mac} on torm11 - should still have proto zebra"
    assert result is None, assertmsg

    # Check flags on torm11: local, peer-active, local-inactive
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "PI", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 3: EVPN MAC check failed for MAC {mac} on torm11 - expected peer-active and local-inactive flags"
    assert result is None, assertmsg

    # Step 4: Re-add MAC on torm11
    dut.run(
        f"bridge fdb add {mac} dev {dev} vlan {vlan} master dynamic extern_learn proto hw"
    )

    # Verify proto=hw on torm11
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut, mac, dev, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = (
        f"Step 4: Bridge FDB check failed for MAC {mac} on torm11 - expected proto hw"
    )
    assert result is None, assertmsg

    # Verify proto=hw on torm12
    test_fn = partial(bgp_evpn.check_mac_in_bridge, dut2, mac, dev2, vlan, proto="hw")
    _, result = topotest.run_and_expect(test_fn, None, count=15, wait=1)
    assertmsg = (
        f"Step 4: Bridge FDB check failed for MAC {mac} on torm12 - expected proto hw"
    )
    assert result is None, assertmsg

    # Check flags on torm11: local with peer-active
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 4: EVPN MAC check failed for MAC {mac} on torm11 - expected peer-active flag"
    assert result is None, assertmsg

    # Check flags on torm12: local with peer-active
    test_fn = partial(bgp_evpn.check_mac_flag_in_evpn, dut2, vni, mac, "P", "local")
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Step 4: EVPN MAC check failed for MAC {mac} on torm12 - expected peer-active flag"
    assert result is None, assertmsg

    # Final cleanup - remove MAC from both TORs
    dut.run(f"bridge fdb del {mac} dev {dev} vlan {vlan} master")
    dut2.run(f"bridge fdb del {mac} dev {dev2} vlan {vlan} master")

    # Wait for holdtime to expire
    holdtime = bgp_evpn.get_mac_holdtime(dut)
    time.sleep(holdtime)

    # Verify MAC is fully removed from both TORs
    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Final cleanup: MAC {mac} still exists in torm11 EVPN table"
    assert result is None, assertmsg

    test_fn = partial(bgp_evpn.check_mac_exists_in_evpn, dut2, vni, mac, expect=False)
    _, result = topotest.run_and_expect(test_fn, None, count=20, wait=1)
    assertmsg = f"Final cleanup: MAC {mac} still exists in torm12 EVPN table"
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
