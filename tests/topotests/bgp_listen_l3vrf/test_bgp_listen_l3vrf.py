#!/usr/bin/env python

#
# test_bgp_listen_l3vrf.py
#
# Copyright 2025 6WIND S.A.
#

"""
 test_bgp_listen_l3vrf.py:
 Check that the FRR BGP daemon on r1 open and close BGP port for
 non VRF instances accordingly to needs


+---+----+          +---+----+
|        |          |        +
|  r1    +----------+  r3    +
|        |          |        +
+++-+----+          +--------+


"""

import os
import sys
import json
from functools import partial
import pytest
import functools
import time
import re

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.common_check import ip_check_path_selection, iproute2_check_path_selection
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


from lib.bgp import (
    verify_bgp_convergence_from_running_config,
)

# Required to instantiate the topology builder class.


def check_port_179_open():
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    output = r1.cmd("ss -tuplen | grep 179 ")
    logger.info(output)
    return re.search("r1-cust", output)


def build_topo(tgen):
    "Build function"

    # Create 7 PE routers.
    tgen.add_router("r1")
    tgen.add_router("r3")

    # switch
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/zebra.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r1.net.del_iface("r1-eth1.100")
    r1.net.del_iface("r1-loop1")
    tgen.stop_topology()


def check_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    bgp_convergence = verify_bgp_convergence_from_running_config(tgen)

    assertmsg = "BGP didn't converge"
    assert bgp_convergence is True, assertmsg


def test_add_l3vrf():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bgp_convergence()

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]
    logger.info("test r1-cust before and after l3vrf add")

    step("create r1-cust l3vrf with iproute 2")
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust when r1-cust is not created"
    assert res is None, assertmsg

    # create l3vrf
    r1.cmd("ip link add r1-cust type vrf table 10")
    r1.cmd("ip link set dev r1-cust up")

    r1.cmd("ip link add link r1-eth1 dev r1-eth1.100 type vlan id 100")
    r1.cmd("ip link set dev r1-eth1.100 up")
    r1.cmd("ip link set  dev r1-eth1.100 master r1-cust")

    r1.cmd("ip link add r1-loop1 type dummy")
    r1.cmd("ip link set dev r1-loop1 up")
    r1.cmd("ip link set  dev r1-loop1 master r1-cust")

    r3.cmd("ip link add link r3-eth1 dev r3-eth1.100 type vlan id 100")
    r3.cmd("ip link set dev r3-eth1.100 up")

    r3.vtysh_cmd(
        """
        configure terminal
        interface r3-eth1.100
         ip address 172.31.0.3/24
        ip route 192.0.102.1/32 172.31.0.1
        """
    )

    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port open on l3vrf when l3vrf address not set"
    assert res is None, assertmsg

    step("setting r1-cust up")
    r1.vtysh_cmd(
        """
        configure terminal
         interface r1-loop1 vrf r1-cust
          ip  address 192.0.102.1/32
         interface r1-eth1.100 vrf r1-cust
          ip address 172.31.0.1/24
        ip route 192.0.2.3/32 172.31.0.3 vrf r1-cust
        """
    )

    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust when r1-cust is set up"
    assert res is None, assertmsg

    step("setting bgp on r1-cust")

    r3.vtysh_cmd(
        """
        configure terminal
         router bgp 64500 view one
           neighbor 192.0.102.1 peer-group rlisten
        """
    )
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
          bgp router-id 192.0.102.1
          no bgp ebgp-requires-policy
          no bgp network import-check
        """
    )

    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust when neighbor or listen not set"
    assert res is None, assertmsg

    step("add a neighbor on r1-cust BGP")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
         neighbor 192.0.2.3 remote-as 64500
        """
    )

    check_bgp_convergence()

    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust not listening when a neighbor is set"
    assert res is not None, assertmsg

    step("remove the neighbor from r1-cust")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
         no neighbor 192.0.2.3 remote-as 64600
        """
    )
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust listening when neighbor is removed"
    assert res is None, assertmsg

    step("add a neighbor on r1-cust BGP twice")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
         neighbor 192.0.2.4 remote-as 64600
        """
    )
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust not listening when a neighbor is set twice"
    assert res is not None, assertmsg

    step("remove the neighbor from r1-cust twice")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
         no neighbor 192.0.2.4 remote-as 64600
        """
    )
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust listening when neighbor is removed twice"
    assert res is None, assertmsg

    step("add a listen range  ot r1-cust")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
          neighbor rlisten peer-group
          neighbor rlisten remote-as 64500
          bgp listen range 192.0.2.0/24 peer-group rlisten
        """
    )
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust not listening when a listen range is set "
    assert res is not None, assertmsg

    set("remove the listen range  ot r1-cust")

    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 64600 vrf r1-cust
          no bgp listen range 192.0.2.0/24 peer-group rlisten
        """
    )
    _, res = topotest.run_and_expect(check_port_179_open, None, count=30, wait=1)
    assertmsg = "BGP port related to r1-cust listening when listen range is removed"
    assert res is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
