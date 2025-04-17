#!/usr/bin/env python

#
# test_bgp_flowspec_topo.py
# Part of NetDEF Topology Tests
#
# Copyright 2019 6WIND S.A.
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
test_bgp_flowspec_topo.py: Test BGP topology with Flowspec EBGP peering


                 +----+----+          +------+------+
                 |   r2    |          |    peer1    |
                 |attacker |          | BGP peer 1  |
                 | 1001::2 |          |192.168.0.161|
                 |         |          |             |
                 +----+----+          +------+------+
                      | .2  r1-eth0          |
                      |                      |
                      |     ~~~~~~~~~        |
                      +---~~    s1   ~~------+
                          ~~         ~~
                            ~~~~~~~~~
                                | 10.0.1.1 r1-eth0
                                | 1001::1  r1-eth0
           vrf r1-cust1+--------+--------+
   ~~~~~~~~~~~~ r1-eth2|    r1           |r1-eth4  ~~~~~~~~~~~
  ~    s3     ~--------|BGP 192.168.0.162|--------~    s5     ~
  ~33::/112   ~      .1|                 |.1      ~50::/112   ~
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
  ~40::/112   ~--------|                 |--------~60::/112   ~
   ~~~~~~~~~~~~ r1-eth3|                 |r1-eth5  ~~~~~~~~~~~
                       +--------+--------+
                                | 20.0.1.1 r1-eth1
                                | 2002::1  r1-eth1
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
                 | 2002::2 |          |192.168.0.160|
                 | 3003::3 |          |             |
                 +----+----+          +------+------+





"""

import json
import os
import sys
import platform
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


def check_ping6(router, dst, src, nb):
    tgen = get_topogen()

    router = tgen.gears[router]
    output = router.run("ping6 {} -I {} -f -c {}".format(dst, src, nb))

    return "{} packets transmitted, {} received".format(nb, nb) in output


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()
    router = tgen.gears["r1"]

    # create VRF r1-cust1
    # move r1-eth0 to VRF r1-cust1
    logger.info("Creating VRF context on r1")
    cmds = [
        "sysctl -w net.ipv4.conf.all.rp_filter=0",
        "sysctl -w net.ipv4.conf.default.rp_filter=0",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl -w net.ipv4.conf.all.forwarding=1",
        "sysctl -w net.ipv6.conf.default.forwarding=1",
        "sysctl -w net.ipv4.conf.default.forwarding=1",
    ]
    for cmd in cmds:
        output = router.run(cmd)
        logger.info("{} output: {}".format(router.name, output.strip()))

    cmds = [
        "ip link add {0}-cust{1} type vrf table 10",
        "ip link set dev {0}-cust{1} up",
        "ip link set dev {0}-eth{2} master {0}-cust{1}",
        "ip ru add oif {0}-cust{1} table 10",
        "ip ru add iif {0}-cust{1} table 10",
    ]

    for cmd in cmds:
        cmd = cmd.format("r1", "1", "2")
        logger.info("{}: {}".format(router.name, cmd))
        output = router.run(cmd)
        if output is not None and output != "":
            logger.info("{} output: {}".format(router.name, output.strip()))

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
    router = tgen.gears["r1"]
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, "{}/zebra.conf".format("r1")),
        "-M wrap_script",
    )
    router.load_config(
        TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format("r1"))
    )
    router.start()

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
configure
no ipv6 route 0::0/0 1001::1
ipv6 route 0::0/0 1001::1
"""
    )
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd(
        """
configure
no ipv6 route 0::0/0 2002::1
ipv6 route 0::0/0 2002::1
"""
    )
    r5 = tgen.gears["r5"]
    r5.vtysh_cmd(
        """
configure
no ipv6 route 1001::/112 50::1
ipv6 route 1001::/112 50::1
no ipv6 route 2002::/112 60::1
ipv6 route 2002::/112 60::1
no ipv6 route 3003::/112 60::1
ipv6 route 3003::/112 60::1
"""
    )

    r4 = tgen.gears["r4"]
    r4.vtysh_cmd(
        """
configure
no ipv6 route 1001::/112 30::1
no ipv6 route 2002::/112 40::1
no ipv6 route 3003::/112 40::1
ipv6 route 1001::/112 30::1
ipv6 route 2002::/112 40::1
ipv6 route 3003::/112 40::1
"""
    )
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        """
configure
no ipv6 route 0::0/0 30::2
ipv6 route 0::0/0 30::2
no ipv6 route 3003::/112 2002::2
ipv6 route 3003::/112 2002::2
"""
    )

    # Starting Peer1 with ExaBGP
    logger.info("Launching exaBGP on peer1")
    peer_list = tgen.exabgp_peers()
    peer1 = tgen.gears["peer1"]
    peer_dir = os.path.join(CWD, "peer1")
    env_file = os.path.join(CWD, "exabgp.env")
    topotest.sleep(1, "Running ExaBGP peer 1 now")
    peer1.start(peer_dir, env_file)
    logger.info("peer1")


def teardown_module(module):
    tgen = get_topogen()

    cmds = ["ip netns del r1-cust1", "ip netns del xvrf"]
    for cmd in cmds:
        tgen.net["r1"].cmd(cmd)
    tgen.stop_topology()


def show_bgp_flowspec_summary(router, afi, peer):
    tgen = get_topogen()

    output = json.loads(
        tgen.gears[router].vtysh_cmd("show bgp {} flowspec summary json".format(afi))
    )
    logger.info(output)
    status = output.get("peers", {}).get(peer, {}).get("state", "").lower()
    return status == "established"


def test_ping_r2_r3():
    tgen = get_topogen()

    msg = "Check Ping from R2(1001::2) to R3(2002::2)"
    logger.info(msg)
    test_func = functools.partial(check_ping6, "r2", "2002::2", "1001::2", 1000)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=0.5)
    assert result, "{} NOK".format(msg)

    msg = "Check Ping from R2(1001::2) to R3(3003::3)"
    logger.info(msg)
    test_func = functools.partial(check_ping6, "r2", "3003::3", "1001::2", 1000)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=0.5)
    assert result, "{} NOK".format(msg)


def test_bgp_convergence():
    "Test for BGP topology convergence with peer1"
    tgen = get_topogen()

    test_func = functools.partial(
        show_bgp_flowspec_summary, "r1", "ipv6", "192.168.0.161"
    )
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP router network did not converge"
    assert res, assertmsg


def test_bgp_flowspec_step1():
    "Check traffic from r2 to r3 with redirect VRF - standard ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info("Check Ping from  R2(1001::1) to R3(2002::2) after FS redirect VRF")
    output = attacker.run("ping6 2002::2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping from R2 to R3(2002::2) should be ok"
        assert 0, assertmsg
    else:
        logger.info(
            "Check Ping from  R2(1001::1) to R3(2002::2) after FS redirect VRF OK"
        )


def test_bgp_flowspec_step2():
    "Check traffic from r2 to r3 with IP redirect - standard ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info("Check Ping from  R2(1001::1) to R3(3003::3) after FS redirect IP")
    output = attacker.run("ping6 3003::3 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping from R3 to R3(3003::3) should be ok"
        assert 0, assertmsg
    else:
        logger.info(
            "Check Ping from  R2(1001::1) to R3(3003::3) after FS redirect IP OK"
        )


def test_bgp_flowspec_step3():
    "Check traffic from r2 to r3 with redirect VRF - ping of 300 bytes"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info(
        "Check Ping > 200 Bytes from  R2(1001::1) to R3(3003::3) after FS redirect VRF"
    )
    output = attacker.run("ping6 3003::3 -f -c 1000 -s 300")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping from R3 to R3(3003::3) should be ok"
        assert 0, assertmsg
    else:
        logger.info(
            "Check Ping > 200 Bytes from  R2(1001::1) to R3(3003::3) after FS redirect VRF  OK"
        )

    logger.info("Check BGP FS entry for 2002::2 with redirect VRF")

    output = router.vtysh_cmd("show bgp ipv6 flowspec 2002::2")
    logger.info(output)
    if "FS:redirect VRF RT:33::2:0" not in output:
        assertmsg = "traffic to 2002::2 should have been detected as FS entry. NOK"
        assert 0, assertmsg
    else:
        logger.info("Check BGP FS entry for 2002::2 with redirect VRF OK")

    logger.info("Check BGP FS entry for 3003::3 with redirect IP")
    output = router.vtysh_cmd("show bgp ipv6 flowspec 3003::3")
    logger.info(output)
    if (
        "NH 50::2" not in output
        or "FS:redirect IP" not in output
        or "Packet Length < 200" not in output
    ):
        assertmsg = "traffic to 3003::3 should have been detected as FS entry. NOK"
        assert 0, assertmsg
    else:
        logger.info("Check BGP FS entry for 3003::3 with redirect IP OK")

    logger.info("Dump Routing information injected")
    output = router.vtysh_cmd("show ipv6 route table 256")
    logger.info(output)
    output = router.vtysh_cmd("show ipv6 route table 257")
    logger.info(output)

    logger.info("Dump PBR information injected")
    output = router.vtysh_cmd("show pbr ipset")
    logger.info(output)
    output = router.vtysh_cmd("show pbr iptable")
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
    topotest.sleep(1, "Running ExaBGP peer 2 now")
    peer2.start(peer_dir, env_file)
    logger.info("peer2")

    test_func = functools.partial(
        show_bgp_flowspec_summary, "r1", "ipv6", "192.168.0.160"
    )
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP r1 network did not converge"
    assert res, assertmsg


def test_bgp_flowspec_step5():
    "Check traffic from r2 to r3 - standard ping"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info("Check BGP FS entry for ICMP Ping from 1001::2 to 3003::3 is dropped")
    output = router.cmd("vtysh -c 'show bgp ipv6 flowspec 3003::3'")
    output = topotest.flowspec_get(output, pattern="FS:rate 0.000000")
    if output:
        logger.info(output)
        output = topotest.flowspec_get_iptable(output)

    if output == None:
        assertmsg = (
            "Check BGP FS entry for ICMP Ping from 1001::10 to 3003::3 is dropped. NOK"
        )
        assert 0, assertmsg

    logger.info(
        "Check BGP FS entry for ICMP Ping from 1001::10 to 3003::3 is dropped. OK"
    )
    attacker.run("ping6 -c 10 3003::3 -I 1001::10")
    logger.info("Check Zebra PBR entry {0} counter".format(output))
    outputtable = router.vtysh_cmd("show pbr iptable {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR IPtable entry {0} counter".format(output)
        assert 0, assertmsg
    outputtable = router.vtysh_cmd("show pbr ipset {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR IPSet entry {0} counter".format(output)
        assert 0, assertmsg
    logger.info("Check Zebra PBR entry {0} counter OK".format(output))

    logger.info(
        "Check BGP FS entry for ICMP Echo Reply from 1001::11 to 3003::3 with redirect IP"
    )
    output = router.vtysh_cmd("show bgp ipv6 flowspec 3003::3")
    output = topotest.flowspec_get(output, pattern="ICMP Type = 129")
    if output:
        logger.info(output)
        output = topotest.flowspec_get_iptable(output)
    if output == None:
        assertmsg = "Check BGP FS entry for ICMP Echo Reply from 1001::11 to 3003::3 with redirect IP. NOK"
        assert 0, assertmsg

    logger.info(
        "Check BGP FS entry for ICMP Echo Reply from 1001::11 to 3003::3 with redirect IP. OK"
    )
    victim.run("ping6 -c 10 1001::11 -I 3003::3")
    logger.info(
        "Check Zebra PBR entry {0} for ICMP Echo Reply from 1001::11 to 3003::3 counter".format(
            output
        )
    )
    outputtable = router.vtysh_cmd("show pbr iptable {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for ICMP Echo Reply from 1001::11 to 3003::3 counter: IPTable. NOK".format(
            output
        )
        assert 0, assertmsg
    outputtable = router.vtysh_cmd("show pbr ipset {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for ICMP Echo Reply from 1001::11 to 3003::3 counter: IPSet. NOK".format(
            output
        )
        assert 0, assertmsg
    logger.info(
        "Check Zebra PBR entry {0} for ICMP Echo Reply from 1001::11 to 3003::3 counter. OK".format(
            output
        )
    )


def test_bgp_flowspec_step6():
    "Check traffic from r2 to r3 with IP redirect - ping DSCP value of 36"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info(
        "Check BGP FS entry for traffic DSCP 36 from 1001::2 to 2002::2 with redirect IP"
    )
    output = router.vtysh_cmd("show bgp ipv6 flowspec 2002::2")
    output = topotest.flowspec_get(output, pattern="DSCP field = 36")
    if output:
        logger.info(output)
        output = topotest.flowspec_get_iptable(output)
    if output == None:
        assertmsg = "Check BGP FS entry for traffic DSCP 36 from 1001::2 to 2002::2 with redirect IP. NOK"
        assert 0, assertmsg
    logger.info(
        "Check BGP FS entry for traffic DSCP 36 from 1001::2 to 2002::2 with redirect IP. OK"
    )
    attacker.run("ping6 -c 10 2002::2 -I 1001::11 -Q 0x90")
    logger.info(
        "Check Zebra PBR entry {0} for DSCP traffic from 1001::11 to 2002::2 counter".format(
            output
        )
    )
    outputtable = router.vtysh_cmd("show pbr iptable {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for DSCP traffic from 1001::11 to 2002::2 counter: IPTable. NOK".format(
            output
        )
        assert 0, assertmsg
    outputtable = router.vtysh_cmd("show pbr ipset {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts 10" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for DSCP traffic from 1001::2 to 2002::2 counter: IPSet. NOK".format(
            output
        )
        assert 0, assertmsg
    logger.info(
        "Check Zebra PBR entry {0} for DSCP traffic from 1001::2 to 2002::2 counter. OK".format(
            output
        )
    )

    #    logger.info('Check BGP FS entry for traffic Fragment from 1001::2 to 3003::4 with redirect IP')
    #    output = router.vtysh_cmd('show bgp ipv6 flowspec 3003::4', isjson=False, daemon='bgpd')
    #    output = topotest.flowspec_get(output, pattern='Packet Fragment')
    #    if output:
    #        logger.info(output)
    #        output = topotest.flowspec_get_iptable(output)
    #    if output == None:
    #        assertmsg = 'Check BGP FS entry for traffic Fragment from 1001::2 to 3003::4 with redirect IP. NOK'
    #        assert 0, assertmsg
    # by default, reassembling is performed on Linux. So this test will be not applied to IPtable.
    #    logger.info('Check BGP FS entry for traffic Fragment from 1001::2 to 3003::4 with redirect IP. OK')
    #    attacker.run('ping6 -c 10 3003::4 -s 3000')
    #    logger.info('Check Zebra PBR entry {0} for Fragment traffic from 1001::2 to 3003::4 counter'.format(output))
    #    outputtable = router.vtysh_cmd('show pbr iptable {0}'.format(output), isjson=False, daemon='zebra')
    #    if outputtable:
    #        logger.info(outputtable)

    #    if outputtable == None or 'pkts 10' not in outputtable:
    #        assertmsg = 'Check Zebra PBR entry {0} for Fragment traffic from 1001::2 to 3003::4 counter: IPTable. NOK'.format(output)
    #        assert 0, assertmsg
    #    outputtable = router.vtysh_cmd('show pbr ipset {0}'.format(output), isjson=False, daemon='zebra')
    #    if outputtable:
    #        logger.info(outputtable)
    #    if outputtable == None or 'pkts 10' not in outputtable:
    #        assertmsg = 'Check Zebra PBR entry {0} for Fragment traffic from 1001::2 to 3003::4 counter: IPSet. NOK'.format(output)
    #       assert 0, assertmsg
    #   logger.info( 'Check Zebra PBR entry {0} for Fragment traffic from 1001::2 to 3003::4 counter. OK'.format(output))


def test_bgp_flowspec_step7():
    "Check traffic from r2 to r3 with IP redirect - TCP traffic"

    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]

    logger.info(
        "Check BGP FS entry for traffic TCP Flags from 1001::2 to 6001::232 with redirect IP"
    )
    output = router.vtysh_cmd("show bgp ipv6 flowspec 6::232")
    output = topotest.flowspec_get(output, pattern="TCP Flags")
    if output:
        logger.info(output)
        output = topotest.flowspec_get_iptable(output)
    if output == None:
        assertmsg = "Check BGP FS entry for traffic TCP Flags from 1001::2 to 6001::232 with redirect IP"
        assert 0, assertmsg
    logger.info(
        "Check BGP FS entry for traffic TCP Flags from 1001::2 to 6001::232 with redirect IP. OK"
    )
    attacker.run("nc -w 3 -z -s 1001::2 6::232 23")
    attacker.run("nc -w 3 -z -s 1001::2 6::232 23")
    attacker.run("nc -w 3 -z -s 1001::2 6::232 23")
    topotest.sleep(5, "Waiting telnet trials")
    logger.info(
        "Check Zebra PBR entry {0} for TCP Flags traffic from 1001::2 to 6001::232 counter".format(
            output
        )
    )
    outputtable = router.vtysh_cmd("show pbr iptable {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for TCP Flags traffic from 1001::2 to 6001::232 counter: IPTable. NOK".format(
            output
        )
        assert 0, assertmsg
    outputtable = router.vtysh_cmd("show pbr ipset {0}".format(output))
    if outputtable:
        logger.info(outputtable)
    if outputtable == None or "pkts" not in outputtable:
        assertmsg = "Check Zebra PBR entry {0} for TCP Flags traffic from 1001::2 to 6001::232 counter: IPSet. NOK".format(
            output
        )
        assert 0, assertmsg

    logger.info(
        "Check Zebra PBR entry {0} for TCP Flags traffic from 1001::2 to 6001::232 counter. OK".format(
            output
        )
    )

    logger.info("Check Ping from  R2(1001::1) to R3(2002::2) after FS discard")
    output = attacker.run("ping6 2002::2 -I 1001::2 -f -c 100")
    logger.info(output)
    if "100 packets transmitted, 0 received" not in output:
        assertmsg = "expected ping from R2 to R3(2002::2) should not pass"
        assert 0, assertmsg
    else:
        logger.info("Check Ping from  R2(1001::2) to R3(2002::2) after FS discard OK")
    logger.info("Check Ping from  R2(1001::10) to R3(3003::3) after FS discard")
    output = attacker.run("ping6 3003::3 -I 1001::10 -f -c 100")
    logger.info(output)
    if "100 packets transmitted, 0 received" not in output:
        assertmsg = "expected ping from R2 to R3(3003::3) should not pass"
        assert 0, assertmsg
    else:
        logger.info("Check Ping from  R2(1001::10) to R3(3003::3) after FS discard OK")

    logger.info("Dump PBR information injected")
    output = router.vtysh_cmd("show pbr ipset")
    logger.info(output)
    output = router.vtysh_cmd("show pbr iptable")
    logger.info(output)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
