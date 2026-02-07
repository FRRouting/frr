#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_ead_evi_routes.py
#
# Copyright (c) 2024 by
# Nvidia, Inc.
# Rajasekar Raja
#

"""
Test BGP EVPN EAD-EVI route generation with disable-ead-evi-tx knob
"""

import os
import sys
import json
import time
from functools import partial

import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    """
    Simple topology with 2 TORs and 1 spine for EVPN multihoming
    - Both TORs have same ES configured
    - Each TOR has 3 VNIs (1001, 1002, 1003)
    - This generates EAD-EVI routes that can be tested
    """
    
    tgen.add_router("tor1")
    tgen.add_router("tor2")
    tgen.add_router("spine")
    
    # Connect TORs to spine
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["tor1"])
    switch.add_link(tgen.gears["spine"])
    
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["tor2"])
    switch.add_link(tgen.gears["spine"])


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()
    
    # Configure VxLAN and ES on TORs
    for tor_name in ["tor1", "tor2"]:
        tor = tgen.gears[tor_name]
        tor_ip = "1.1.1.1" if tor_name == "tor1" else "2.2.2.2"
        
        # Create VLAN-aware bridge
        tor.run("ip link add dev bridge type bridge stp_state 0")
        tor.run("ip link set dev bridge type bridge vlan_filtering 1")
        tor.run("ip link set dev bridge type bridge mcast_snooping 0")
        tor.run("ip link set dev bridge up")
        tor.run("/sbin/bridge vlan add vid 1001 dev bridge self")
        tor.run("/sbin/bridge vlan add vid 1002 dev bridge self")
        tor.run("/sbin/bridge vlan add vid 1003 dev bridge self")
        
        # Create bond interface for ES
        tor.run("ip link add dev hostbond1 type bond mode 802.3ad")
        tor.run("ip link set dev hostbond1 type bond ad_actor_system 44:38:39:ff:ff:01")
        tor.run("ip link set dev hostbond1 up")
        
        # Add bond to bridge with VLANs
        tor.run("ip link set dev hostbond1 master bridge")
        tor.run("/sbin/bridge vlan del vid 1 dev hostbond1")
        tor.run("/sbin/bridge vlan add vid 1001 dev hostbond1")
        tor.run("/sbin/bridge vlan add vid 1002 dev hostbond1")
        tor.run("/sbin/bridge vlan add vid 1003 dev hostbond1")
        
        # Create VxLAN interfaces for 3 VNIs
        for vni in [1001, 1002, 1003]:
            tor.run(f"ip link add dev vx-{vni} type vxlan id {vni} dstport 4789 local {tor_ip} nolearning")
            tor.run(f"ip link set dev vx-{vni} up")
            tor.run(f"ip link set dev vx-{vni} master bridge")
            tor.run(f"/sbin/bridge link set dev vx-{vni} neigh_suppress on")
            tor.run(f"/sbin/bridge link set dev vx-{vni} learning off")
            tor.run(f"/sbin/bridge vlan del vid 1 dev vx-{vni}")
            tor.run(f"/sbin/bridge vlan add vid {vni} dev vx-{vni}")
            tor.run(f"/sbin/bridge vlan add vid {vni} untagged pvid dev vx-{vni}")
    
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))
    
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def count_ead_routes_by_type(router):
    """
    Count EAD-ES and EAD-EVI routes
    EAD-ES: [1]:[4294967295]:... (eth-tag = MAX_ET)
    EAD-EVI: [1]:[0]:... or other non-MAX eth-tags
    
    Note: In the output we're looking at lines like:
    *>  [1]:[0]:[ESI]:[128]:[IP]:[Frag] - EAD-EVI
    *>  [1]:[4294967295]:[ESI]:[128]:[IP]:[Frag] - EAD-ES
    """
    output = router.vtysh_cmd("show bgp l2vpn evpn route type ead")
    
    ead_es_count = 0
    ead_evi_count = 0
    
    for line in output.splitlines():
        if "*>" in line and "[1]:[" in line:
            # Extract the eth-tag which is the second field after [1]:
            try:
                idx = line.find("[1]:[")
                if idx >= 0:
                    rest = line[idx+5:]
                    eth_tag_str = rest.split("]")[0]
                    eth_tag = int(eth_tag_str)
                    
                    if eth_tag == 4294967295:
                        ead_es_count += 1
                    else:
                        ead_evi_count += 1
            except:
                pass
    
    return ead_es_count, ead_evi_count


def test_evpn_ead_evi_routes_initial():
    """
    Verify EAD routes are generated with multiple VNIs
    """
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    router = tgen.gears["tor1"]
    
    def check_bgp_summary():
        output = router.vtysh_cmd("show bgp summary json")
        try:
            data = json.loads(output)
            if "ipv4Unicast" in data:
                peers = data["ipv4Unicast"]["peers"]
                for peer in peers.values():
                    if peer.get("state") != "Established":
                        return False
                return True
        except:
            return False
        return False
    
    test_fn = partial(check_bgp_summary)
    _, result = topotest.run_and_expect(lambda: check_bgp_summary(), True, count=20, wait=3)
    
    ead_es, ead_evi = count_ead_routes_by_type(router)
    assertmsg = "No EAD-EVI routes found, VNI/ES-EVI may not be configured properly. ES: {}, EVI: {}".format(
        ead_es, ead_evi)
    assert ead_evi > 0, assertmsg


def test_evpn_disable_ead_evi_tx():
    """
    Test disable-ead-evi-tx knob
    
    Expected behavior:
    - Initial: EAD-EVI routes present (3 routes for 3 VNIs)
    - After disable-ead-evi-tx: EAD-EVI routes withdrawn (count = 0)
    - After no disable-ead-evi-tx: EAD-EVI routes restored
    
    Note: EAD-ES routes may not be present since bond has no members
    """
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    router = tgen.gears["tor1"]
    
    initial_es, initial_evi = count_ead_routes_by_type(router)
    if initial_evi == 0:
        pytest.skip("No EAD-EVI routes, cannot test disable-ead-evi-tx")
    
    router.vtysh_cmd("conf\nrouter bgp 65000\naddress-family l2vpn evpn\ndisable-ead-evi-tx")
    
    def check_ead_evi_withdrawn():
        _, ead_evi = count_ead_routes_by_type(router)
        return ead_evi == 0
    
    test_fn = partial(check_ead_evi_withdrawn)
    _, result = topotest.run_and_expect(test_fn, True, count=20, wait=3)
    disabled_es, disabled_evi = count_ead_routes_by_type(router)
    assertmsg = "EAD-EVI routes not withdrawn: had {}, still have {}".format(initial_evi, disabled_evi)
    assert disabled_evi == 0, assertmsg
    
    router.vtysh_cmd("conf\nrouter bgp 65000\naddress-family l2vpn evpn\nno disable-ead-evi-tx")
    def check_ead_evi_restored():
        _, ead_evi = count_ead_routes_by_type(router)
        return ead_evi == initial_evi
    
    test_fn = partial(check_ead_evi_restored)
    _, result = topotest.run_and_expect(test_fn, True, count=20, wait=3)
    final_es, final_evi = count_ead_routes_by_type(router)
    assertmsg = "EAD-EVI routes not restored: expected {}, got {}".format(initial_evi, final_evi)
    assert final_evi == initial_evi, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
