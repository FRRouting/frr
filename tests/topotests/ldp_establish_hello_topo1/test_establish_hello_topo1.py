#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_establish_hello_topo1.py
#
# Copyright (c) 2025 by VyOS Networks
# Andrii Melnychenko (a.melnychenko@vyos.io)
#

r"""
test_establish_hello_topo1.py: Simple FRR LDP Test

                            +-------------+
                            |     r1      |
                            |   1.1.1.1   |
                            +-------------+
                              |
                              | .1 r1-eth0
                              |
+---------+                 ~~~~~~~~~~~~~
|   r2    |  .2 r2-eth0   ~~     sw0     ~~
| 2.2.2.2 | ------------- ~~ 10.0.1.0/24 ~~
+---------+                 ~~~~~~~~~~~~~
                              |
                              | .3 r3-eth0
                              |
                            +-------------+
                            |     r3      |
                            |   3.3.3.3   |
                            +-------------+

"""

import os
import re
import sys
import pytest
from time import sleep

from lib.topogen import Topogen, get_topogen

fatal_error = ""

pytestmark = [pytest.mark.ldpd]

def build_topo(tgen):
    # Setup Routers
    for router in ["r1", "r2", "r3"]:
        tgen.add_router(router)

    # Switch
    switch = tgen.add_switch("sw0")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

def setup_module(module):

    thisDir = os.path.dirname(os.path.realpath(__file__))
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    net = tgen.net

    # Starting Routers
    for router in ["r1", "r2", "r3"]:
        net[router].loadConf("zebra", "%s/%s/zebra.conf" % (thisDir, router))
        net[router].loadConf("ldpd", "%s/%s/ldpd.conf" % (thisDir, router))
        tgen.gears[router].start()

    # For debugging after starting FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(module):

    tgen = get_topogen()
    tgen.stop_topology()


def test_default_behaviour():
    
    global fatal_error

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    tgen = get_topogen()

    # Setup counters
    tgen.gears["r3"].run("""
            iptables -t filter -A INPUT -s 10.0.1.1 -p udp --dport 646 -j ACCEPT
            iptables -t filter -A INPUT -s 10.0.1.2 -p udp --dport 646 -j ACCEPT
            iptables -t filter -A OUTPUT -s 10.0.1.3 -p udp --dport 646 -j ACCEPT
            """)

    # Setup the LDP service
    for router in ["r3", "r2", "r1"]:
        tgen.gears[router].vtysh_multicmd([
                            "configure terminal",
                            "mpls ldp",
                            "address-family ipv4",
                            f"interface {router}-eth0",
                            "end"])

    sleep(7)

    # Get values from counters
    output = tgen.gears["r3"].run("iptables -t filter -L -v -n")

    # Disable the LDP service
    for router in ["r3", "r2", "r1"]:
        tgen.gears[router].vtysh_multicmd([
                            "configure terminal",
                            "mpls ldp",
                            "address-family ipv4",
                            f"no interface {router}-eth0",
                            "end"])

    # Remove counter
    tgen.gears["r3"].run("iptables -t filter -F")

    pattern = r"\n\s+(\d+)"
    matches = re.findall(pattern, output)

    # Each router should send at least 2 packets of LDP hello,
    # one at the start and one after the "interval"(default 5 sec)
    # So, router 10.0.1.1(1.1.1.1) should send only 2 packets
    # Router 10.0.1.2(2.2.2.2) sent 2 packets plus 2 packets for each attempt to connect to the 1.1.1.1 - in total 4
    # Router 10.0.1.3(3.3.3.3) sent 2 packets plus 2 packets to the 1.1.1.1 and 4 packets to the 2.2.2.2 - in total 8
    assert matches == ['2', '4', '8'], "Wrong count of the LDP hello messages"


def test_disable_establish_hello():
    
    global fatal_error

    # Skip if previous fatal error condition is raised
    if fatal_error != "":
        pytest.skip(fatal_error)

    tgen = get_topogen()

    # Setup counters
    tgen.gears["r3"].run("""
            iptables -t filter -A INPUT -s 10.0.1.1 -p udp --dport 646 -j ACCEPT
            iptables -t filter -A INPUT -s 10.0.1.2 -p udp --dport 646 -j ACCEPT
            iptables -t filter -A OUTPUT -s 10.0.1.3 -p udp --dport 646 -j ACCEPT
            """)

    # Setup the LDP service with disable-establish-hello option
    for router in ["r3", "r2", "r1"]:
        tgen.gears[router].vtysh_multicmd([
                            "configure terminal",
                            "mpls ldp",
                            "address-family ipv4",
                            f"interface {router}-eth0",
                            "disable-establish-hello",
                            "end"])

    sleep(7)

    # Get values from counters
    output = tgen.gears["r3"].run("iptables -t filter -L -v -n")

    # Disable the LDP service
    for router in ["r3", "r2", "r1"]:
        tgen.gears[router].vtysh_multicmd([
                            "configure terminal",
                            "mpls ldp",
                            "address-family ipv4",
                            f"no interface {router}-eth0",
                            "end"])

    # Remove counter
    tgen.gears["r3"].run("iptables -t filter -F")

    pattern = r"\n\s+(\d+)"
    matches = re.findall(pattern, output)

    # With disabled sending LDP hello message on attempt to establish TCP connection
    # Each router should only send 2 packets, at start and after 5 seconds(default interval)
    assert matches == ['2', '2', '2'], "Wrong count of the LDP hello messages"

if __name__ == "__main__":

    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
