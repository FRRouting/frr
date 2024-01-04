#!/usr/bin/env python

#
# test_bgp_flowspec_vrfleak_topo.py
# Part of NetDEF Topology Tests
#
# Copyright 2018 6WIND S.A.
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
test_bgp_flowspec_vrfleak_topo.py: Test BGP topology with Flowspec EBGP peering with vrf route leak


                 +----+----+          +------+------+
                 |   r2    |          |    peer1    |
                 |attacker |          | BGP peer 1  |
                 | 1.1.1.2 |          |192.168.0.161|
                 |         |          |             |
                 +----+----+          +------+------+
                      | .2  r1-eth0          |
                      |                      |
                      |     ~~~~~~~~~        |
                      +---~~    s1   ~~------+
                          ~~         ~~
                            ~~~~~~~~~
                                | 10.0.1.1 r1-eth0
                                | 1.1.1.1  r1-eth0
           vrf r1-cust1+--------+--------+
   ~~~~~~~~~~~~ r1-eth2|    r1           |r1-eth4  ~~~~~~~~~~~
  ~    s3     ~--------|BGP 192.168.0.162|--------~    s5     ~
  ~30.0.0.0/24~      .1|                 |.1      ~50.0.0.0/24~
  ~           ~        |                 |        ~           ~
   ~~~~~~~~~~~         |                 |         ~~~~~~~~~~~
     .2|r1-eth0        |                 |           .2|r1-eth0
   +-----------+       |                 |     +-----------+
   |r4         |       |                 |     |r5         |
   |Analyser 1 |       |                 |     |Analyser 2 |
   +-----------+       |                 |     +-----------+
     .2|r1-eth1        |                 |           .2|r1-eth1
   ~~~~~~~~~~~         |                 |         ~~~~~~~~~~~ 
  ~     s4    ~      .1|                 |.1      ~    s6     ~
  ~40.0.0.0/24~--------|                 |--------~60.0.0.0/24~
   ~~~~~~~~~~~~ r1-eth3|                 |r1-eth5  ~~~~~~~~~~~
                       +--------+--------+
                                | 20.0.1.1 r1-eth1
                                | 2.2.2.1  r1-eth1
                            ~~~~~~~~~
                          ~~    s2   ~~
                      +---~~         ~~------+
                      |     ~~~~~~~~~        |
                      |                      |
                      |                      |
                      | .2  r1-eth0          |
                 +----+----+          +------+------+
                 |   r3    |          |    peer2    |
                 |victim   |          | BGP peer 2  |
                 | 2.2.2.2 |          |192.168.0.160|
                 | 3.3.3.3 |          |             |
                 +----+----+          +------+------+





"""

import json
import os
import sys
import pytest
import getopt
import functools

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import lUtil
from lib.lutil import luCommand

# Required to instantiate the topology builder class.
from mininet.topo import Topo


#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    # Setup Routers
    tgen.add_router("r1")

    # Setup Control Path Switch 1. r1-eth0
    switch1 = tgen.add_switch("s1")
    switch1.add_link(tgen.gears["r1"])

    # Setup Control Path Switch 2. r1-eth1
    switch2 = tgen.add_switch("s2")
    switch2.add_link(tgen.gears["r1"])

    ## Add eBGP ExaBGP neighbors
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="192.168.0.161", defaultRoute="via 192.168.0.161"
    )
    switch1.add_link(peer1)

    peer2 = tgen.add_exabgp_peer(
        "peer2", ip="192.168.0.160", defaultRoute="via 192.168.0.160"
    )
    switch2.add_link(peer2)

    # Setup Data Path Incoming r2 router
    tgen.add_router("r2")
    switch1.add_link(tgen.gears["r2"])

    # Setup Data Path Outgoing r3 router
    tgen.add_router("r3")
    switch2.add_link(tgen.gears["r3"])

    # Setup Data Path Redirect VRF
    switch3 = tgen.add_switch("s3")
    switch4 = tgen.add_switch("s4")
    tgen.add_router("r4")
    switch3.add_link(tgen.gears["r4"])
    switch4.add_link(tgen.gears["r4"])
    switch3.add_link(tgen.gears["r1"])
    switch4.add_link(tgen.gears["r1"])

    # Setup Data Path Redirect IP
    switch5 = tgen.add_switch("s5")
    switch6 = tgen.add_switch("s6")
    tgen.add_router("r5")
    switch5.add_link(tgen.gears["r5"])
    switch6.add_link(tgen.gears["r5"])
    switch5.add_link(tgen.gears["r1"])
    switch6.add_link(tgen.gears["r1"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)

    tgen.start_topology()

    # check for zebra capability
    r1 = tgen.gears["r1"]

    # create VRF r1-cust1
    # move r1-eth0 to VRF r1-cust1
    logger.info("Creating VRF context on r1")
    cmds = [
        "ip link add {0}-cust{1} type vrf table 10",
        "ip link set dev {0}-cust{1} up",
        "ip link set dev {0}-eth{2} master {0}-cust{1}",
        "ip ru add oif {0}-cust{1} table 10",
        "ip ru add iif {0}-cust{1} table 10",
    ]

    for cmd in cmds:
        cmd = cmd.format("r1", "1", "2")
        logger.info("cmd: " + cmd)
        output = r1.run(cmd.format("r1", "1", "2"))
        logger.info("output: " + output)

    # Start r2 to r5
    for i in range(2, 6):
        logger.info("Launching ZEBRA on r{} - for IP config only".format(i))
        router = tgen.gears["r{}".format(i)]
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format("r{}".format(i))),
        )
        router.start()

    # Get r1 reference and run Daemons
    logger.info("Launching BGP and ZEBRA on r1")
    r1 = tgen.gears["r1"]
    r1.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, "{}/zebra.conf".format("r1")),
        "-M wrap_script",
    )
    r1.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format("r1")))
    r1.start()

    # Starting Peer1 with ExaBGP

    peer_list = tgen.exabgp_peers()
    peer1 = tgen.gears["peer1"]
    peer_dir = os.path.join(CWD, "peer1")
    env_file = os.path.join(CWD, "exabgp.env")
    peer1.start(peer_dir, env_file)
    logger.info("peer1")


def teardown_module(module):
    tgen = get_topogen()
    tgen.stop_topology()


def show_bgp_flowspec_summary(r1, afi, peer):
    tgen = get_topogen()

    output = json.loads(
        tgen.gears[r1].vtysh_cmd("show bgp {} flowspec summary json".format(afi))
    )
    logger.info(output)
    status = output.get("peers", {}).get(peer, {}).get("state", "").lower()
    return status == "established"


def check_ping(router, dst, src, nb):
    tgen = get_topogen()

    router = tgen.gears[router]
    output = router.run("ping {} -I {} -f -c {}".format(dst, src, nb))

    return "{} packets transmitted, {} received".format(nb, nb) in output


def test_ping_r2_r3():
    tgen = get_topogen()

    msg = "Check Ping from R2(1.1.1.2) to R3(2.2.2.2)"
    logger.info(msg)
    test_func = functools.partial(check_ping, "r2", "2.2.2.2", "1.1.1.2", 1000)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=0.5)
    assert result, "{} NOK".format(msg)

    msg = "Check Ping from R2(1.1.1.2) to R3(3.3.3.3)"
    logger.info(msg)
    test_func = functools.partial(check_ping, "r2", "3.3.3.3", "1.1.1.2", 1000)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=0.5)
    assert result, "{} NOK".format(msg)


def test_bgp_convergence():
    "Test for BGP topology convergence with peer1"
    tgen = get_topogen()

    test_func = functools.partial(
        show_bgp_flowspec_summary, "r1", "ipv4", "192.168.0.161"
    )
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP r1 network did not converge"
    assert res, assertmsg


def test_bgp_flowspec_step1():
    "Check traffic from r2 to r3 with redirect VRF - standard ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    logger.info("Check Ping from R2(1.1.1.1) to R3(2.2.2.2) after FS redirect VRF")
    output = r2_attacker.run("ping 2.2.2.2 -f -c 1000")
    logger.info(output)
    assertmsg = "expected successful ping from R2 to R3(2.2.2.2)"
    assert "1000 packets transmitted, 1000 received" in output, assertmsg


def test_bgp_flowspec_step2():
    "Check traffic from r2 to r3 with IP redirect - standard ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    logger.info("Check Ping from R2(1.1.1.1) to R3(3.3.3.3) after FS redirect IP")
    output = r2_attacker.run("ping 3.3.3.3 -f -c 1000")
    logger.info(output)
    assertmsg = "expected successful ping from R2 to R3(3.3.3.3)"
    assert "1000 packets transmitted, 1000 received" in output, assertmsg


def test_bgp_flowspec_step3():
    "Check traffic from r2 to r3 with VRF redirect - 300 bytes ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    logger.info(
        "Check Ping > 200 Bytes from R2(1.1.1.1) to R3(3.3.3.3) after FS redirect VRF"
    )
    output = r2_attacker.run("ping 3.3.3.3 -f -c 1000 -s 300")
    logger.info(output)
    assertmsg = "expected successful ping from R3 to R3(3.3.3.3)"
    assert "1000 packets transmitted, 1000 received" in output, assertmsg

    msg = "Check BGP FS entry for 2.2.2.2 with redirect VRF"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 2.2.2.2")
    logger.info(output)
    assert "FS:redirect VRF RT:11:22" in output, assertmsg
    logger.info("Check BGP FS entry for 2.2.2.2 with redirect VRF OK")

    msg = "Check BGP FS entry for 3.3.3.3 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 3.3.3.3")
    logger.info(output)
    assert (
        "NH 50.0.0.2" in output
        and "FS:redirect IP" in output
        and "Packet Length < 200" in output
    ), assertmsg
    logger.info("Check BGP FS entry for 3.3.3.3 with redirect IP OK")

    # Dump for debug
    logger.info("Dump Routing information injected")
    output = r1.vtysh_cmd("show ip route table 256")
    logger.info(output)
    output = r1.vtysh_cmd("show ip route table 257")
    logger.info(output)

    logger.info("Dump PBR information injected")
    output = r1.vtysh_cmd("show pbr ipset")
    logger.info(output)
    output = r1.vtysh_cmd("show pbr iptable")
    logger.info(output)


def test_bgp_flowspec_step4():
    "Start peer2 and check bgp convergence on r1"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    peer2 = tgen.gears["peer2"]
    peer_dir = os.path.join(CWD, "peer2")
    env_file = os.path.join(CWD, "exabgp.env")
    peer2.start(peer_dir, env_file)

    test_func = functools.partial(
        show_bgp_flowspec_summary, "r1", "ipv4", "192.168.0.160"
    )
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP r1 network did not converge with peer2"
    assert res, assertmsg


def test_bgp_flowspec_step5():
    "Check that traffic from 1.1.1.2 to 2.2.2.2 is dropped"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    msg = "Check BGP FS entry: Traffic dropped from 1.1.1.2 to 2.2.2.2"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 2.2.2.2")
    output = topotest.flowspec_get(output, pattern="FS:rate 0.000000")
    logger.info(output)
    assert "Destination Address 2.2.2.2/32" in output, assertmsg
    assert "Source Address 1.1.1.2/32" in output, assertmsg
    assert output, assertmsg

    logger.info("Check Iptables entry: Traffic dropped from 1.1.1.2 to 2.2.2.2")
    entry = topotest.flowspec_get_iptable(output)
    assert entry, "Failed to find iptable entry"
    logger.info("Found IPtable entry: {}".format(entry))

    logger.info("Check ping from R2(1.1.1.2) to R3(2.2.2.2)")
    output = r2_attacker.run("ping -c 10 -I 1.1.1.2 2.2.2.2")
    logger.info(output)
    assertmsg = "expected UNsuccessful ping from R2(1.1.1.2) to R3(2.2.2.2)"
    assert "10 packets transmitted, 0 received" in output, assertmsg

    msg = "Check Zebra PBR iptable entry {0} counter".format(entry)
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr iptable {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg

    msg = "Check Zebra PBR ipset entry {0} counter".format(entry)
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr ipset {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg


def test_bgp_flowspec_step6():
    "Check that traffic from 3.3.3.3 to 1.1.1.2"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    msg = "Check BGP FS entry for ICMP Echo from 3.3.3.3 to 1.1.1.2 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 3.3.3.3 ")
    output = topotest.flowspec_get(output, pattern="ICMP Type = 0")
    assert output, assertmsg
    logger.info(output)

    logger.info(
        "Check IPtables entry for ICMP Echo from 3.3.3.3 to 1.1.1.2 with redirect IP"
    )
    entry = topotest.flowspec_get_iptable(output)
    assert entry, "Failed to find iptable entry"
    logger.info("Found IPtable entry: {}".format(entry))

    logger.info("Check ping from R3(3.3.3.3) to R2(1.1.1.2)")
    output = r3_victim.run("ping -c 10 -I 3.3.3.3 1.1.1.2")
    logger.info(output)
    assertmsg = "expected successful ping from R3(3.3.3.3) to R2(1.1.1.2)"
    assert "10 packets transmitted, 10 received" in output, assertmsg

    msg = "Check Zebra IPtables PBR entry {0} for ICMP Echo from 3.3.3.3 to 1.1.1.2 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr iptable {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg

    msg = "Check Zebra IPSet PBR entry {0} for ICMP Echo Reply from 1.1.1.2 to 3.3.3.3 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr ipset {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg


def test_bgp_flowspec_step7():
    "Check traffic DSCP 36 from 1.1.1.2 to 3.3.3.5 with redirect IP"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    msg = "Check BGP FS entry for traffic DSCP 36 from 1.1.1.2 to 3.3.3.5 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 3.3.3.5")
    output = topotest.flowspec_get(output, pattern="DSCP field = 36")
    assert output, assertmsg
    logger.info(output)

    logger.info("Check Iptables entry: DSCP 36 from 1.1.1.2 to 3.3.3.5")
    entry = topotest.flowspec_get_iptable(output)
    assert entry, "Failed to find iptable entry"
    logger.info("Found IPtable entry: {}".format(entry))

    """
    TClass 0x90 means DSCP 36
    Differentiated Services Field: 0x90 (DSCP: AF42, ECN: Not-ECT)
    1001 00.. = Differentiated Services Codepoint: Assured Forwarding 42 (36)
    .... ..00 = Explicit Congestion Notification: Not ECN-Capable Transport (0)
    """
    logger.info("Check ping: DSCP 36 from R2(1.1.1.2) R3(3.3.3.5)")
    output = r2_attacker.run("ping -c 10 -I 1.1.1.2 3.3.3.5 -Q 0x90")
    logger.info(output)
    assertmsg = "expected successful ping from R2(1.1.1.2) R3(3.3.3.5)"
    assert "10 packets transmitted, 10 received" in output, assertmsg

    msg = "Check IPtables PBR entry {0} for DSCP traffic from 1.1.1.2 to 3.3.3.5 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr iptable {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg

    msg = "Check IPSet PBR entry {0} for DSCP traffic from 1.1.1.2 to 3.3.3.5 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr ipset {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts 10" in outputtable, assertmsg


def test_bgp_flowspec_step8():
    "Check entries for traffic Fragment from 1.1.1.2 to 3.3.3.4 with redirect IP"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    msg = "Check BGP FS entry for traffic Fragment from 1.1.1.2 to 3.3.3.4 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 3.3.3.4")
    output = topotest.flowspec_get(output, pattern="Packet Fragment = 4")
    assert output, assertmsg
    logger.info(output)

    msg = "Check IPtables entry for traffic Fragment from 1.1.1.2 to 3.3.3.4 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = topotest.flowspec_get_iptable(output)
    assert output, assertmsg
    logger.info(output)

    # by default, reassembling is performed on Linux. So this test will be not applied to IPtable.
    #    logger.info('Check BGP FS entry for traffic Fragment from 1.1.1.2 to 3.3.3.4 with redirect IP. OK')
    #    r2_attacker.run('ping -c 10 3.3.3.4 -s 3000')
    #    logger.info('Check Zebra PBR entry {0} for Fragment traffic from 1.1.1.2 to 3.3.3.4 counter'.format(output))
    #    outputtable = r1.vtysh_cmd('show pbr iptable {0}'.format(output), isjson=False, daemon='zebra')
    #    if outputtable:
    #        logger.info(outputtable)

    #    if outputtable == None or 'pkts 10' not in outputtable:
    #    assertmsg = 'Check Zebra PBR entry {0} for Fragment traffic from 1.1.1.2 to 3.3.3.4 counter: IPTable. NOK'.format(output)
    #    assert 0, assertmsg
    #    outputtable = r1.vtysh_cmd('show pbr ipset {0}'.format(output), isjson=False, daemon='zebra')
    #    if outputtable:
    #        logger.info(outputtable)
    #    if outputtable == None or 'pkts 10' not in outputtable:
    #    assertmsg = 'Check Zebra PBR entry {0} for Fragment traffic from 1.1.1.2 to 3.3.3.4 counter: IPSet. NOK'.format(output)
    #       assert 0, assertmsg
    #   logger.info( 'Check Zebra PBR entry {0} for Fragment traffic from 1.1.1.2 to 3.3.3.4 counter. OK'.format(output))


def test_bgp_flowspec_step9():
    "Check traffic TCP SYN Flags from 1.1.1.2 to 6.1.1.232 with redirect IP"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2_attacker = tgen.gears["r2"]
    r3_victim = tgen.gears["r3"]
    r1 = tgen.gears["r1"]

    msg = "Check BGP FS entry for traffic TCP Flags from 1.1.1.2 to 6.1.1.232 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    output = r1.vtysh_cmd("show bgp ipv4 flowspec 6.1.1.232")
    output = topotest.flowspec_get(output, pattern="TCP Flags = 2")
    assert output, assertmsg
    logger.info(output)

    msg = "Check IPtables entry for traffic TCP Flags from 1.1.1.2 to 6.1.1.232 with redirect IP"
    logger.info(msg)
    assertmsg = msg + " NOK"
    entry = topotest.flowspec_get_iptable(output)
    assert entry, "Failed to find iptable entry"
    logger.info("Found IPtable entry: {}".format(entry))

    r2_attacker.run("telnet 6.1.1.232")
    topotest.sleep(5, "Waiting for telnet trials to 6.1.1.232")

    msg = "Check PBR IPtables entry {0} for TCP Flags traffic from 1.1.1.2 to 6.1.1.232 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr iptable {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts" in outputtable, assertmsg

    msg = "Check PBR IPset entry {0} for TCP Flags traffic from 1.1.1.2 to 6.1.1.232 counter".format(
        entry
    )
    logger.info(msg)
    assertmsg = msg + " NOK"
    outputtable = r1.vtysh_cmd("show pbr ipset {0}".format(entry))
    assert outputtable, assertmsg
    logger.info(outputtable)
    assert "pkts" in outputtable, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
