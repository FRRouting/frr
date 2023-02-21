#!/usr/bin/env python
#
# test_bgp_flowspec_iprule.py
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
test_bgp_flowspec_ip6rule.py: Test BGP topology with Flowspec EBGP peering


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
                          ~~         ~~----------------------------------
                            ~~~~~~~~~                                   |
                                | 10.0.1.1 r1-eth0                      |
                                | 1001::1  r1-eth0                      |
           vrf r1-cust1+--------+--------+                              |
   ~~~~~~~~~~~~ r1-eth2|    r1           |r1-eth4  ~~~~~~~~~~~          |
  ~    s3     ~--------|BGP 192.168.0.162|--------~    s5     ~         |
  ~33::0/112  ~      .1|                 |.1      ~50::0/112  ~         |
  ~           ~        |                 |        ~           ~         |
   ~~~~~~~~~~~         |                 |         ~~~~~~~~~~~          |
     .2|r1-eth0        |                 |           .2|r1-eth0         |
   +-----------+       |                 |     +-----------+            |
   |r4         |       |                 |     |r5         |            |
   |Analyser 1 |       |                 |     |Analyser 2 |            |
   +-----------+       |                 |     +-----------+            |
     .4|r1-eth1        |                 |           .5|r1-eth1         |
       |               |                 |             |                |
       |                +--------+--------+            |                |
       |                         | 20.0.1.1 r1-eth1    |                |
       |                         | 2001::1  r1-eth1    |                |
       |                     ~~~~~~~~~                 |                |
       -------------------~~    s2   ~~----------------                 |
                      +---~~         ~~                                 |
                      |     ~~~~~~~~~                                   |
                      |                                                 |
                      |                                                 |
                      | .2  r1-eth0                                     |
                 +----+----+                                            |
                 |   r3    |--------------------------------------------
                 |victim   |
                 | 2002::2 |
                 | 3003::3 |
                 +----+----+





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

    # Setup Data Path Incoming r2 router
    tgen.add_router("r2")
    switch1.add_link(tgen.gears["r2"])

    # Setup Data Path Outgoing r3 router
    tgen.add_router("r3")
    switch2.add_link(tgen.gears["r3"])
    switch1.add_link(tgen.gears["r3"])

    # Setup Data Path Redirect VRF
    switch3 = tgen.add_switch("s3")
    tgen.add_router("r4")
    switch3.add_link(tgen.gears["r4"])
    switch2.add_link(tgen.gears["r4"])
    switch3.add_link(tgen.gears["r1"])

    # Setup Data Path Redirect IP
    switch5 = tgen.add_switch("s5")
    tgen.add_router("r5")
    switch5.add_link(tgen.gears["r5"])
    switch2.add_link(tgen.gears["r5"])
    switch5.add_link(tgen.gears["r1"])


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

    # create VRF r1-cust1
    # move r1-eth0 to VRF r1-cust1
    logger.info("Creating VRF context on r1")
    router = tgen.gears["r1"]
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
        logger.info("output: " + output)

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
        output = router.run(cmd.format("r1", "1", "2"))
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

    msg = "Check Ping from  R2(1001::2) to R3(2002::2)"
    logger.info(msg)
    test_func = functools.partial(check_ping6, "r2", "2002::2", "1001::2", 1000)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=0.5)
    assert result, "{} NOK".format(msg)

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


def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    def _show_bgp_flowspec_summary(router, afi):
        output = json.loads(
            tgen.gears[router].vtysh_cmd(
                "show bgp {} flowspec summary json".format(afi)
            )
        )
        logger.info(output)
        status = (
            output.get("peers", {}).get("192.168.0.161", {}).get("state", "").lower()
        )
        return status == "established"

    test_func = functools.partial(_show_bgp_flowspec_summary, "r1", "ipv4")
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP router network did not converge - IPv4"
    assert res, assertmsg

    test_func = functools.partial(_show_bgp_flowspec_summary, "r1", "ipv6")
    _, res = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assertmsg = "BGP router network did not converge - IPv6"
    assert res, assertmsg


def test_bgp_flowspec():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears["r2"]
    victim = tgen.gears["r3"]
    router = tgen.gears["r1"]
    # tgen.mininet_cli()

    logger.info("Check Ping from  R2(1001::2) to R3(2002::2) after FS redirect IP Rule")
    output = attacker.run("ping6 2002::2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping from R2 to R3(2002::2) should be ok"
        assert 0, assertmsg
    else:
        logger.info(
            "Check Ping from  R2(1001::2) to R3(2002::2) after FS redirect IP Rule OK"
        )

    msg = "Check Routing Flowspec : show bgp ipv6 flowspec"
    logger.info(msg)
    output = router.vtysh_cmd("show bgp ipv6 flowspec", isjson=False, daemon="bgpd")
    logger.info(output)
    assert "to ::/0/off 0" in output, "{} NOK".format(msg)

    msg = "Check Routing Flowspec : show bgp ipv6 flowspec detail"
    logger.info(msg)
    output = router.vtysh_cmd(
        "show bgp ipv6 flowspec detail", isjson=False, daemon="bgpd"
    )
    logger.info(output)
    assert "FS:redirect IP 0x0 FS:rate 55.0" in output, "{} NOK".format(msg)
    assert "installed in PBR" in output, "{} NOK".format(msg)

    msg = "Check Routing injected information on table 256"
    logger.info(msg)
    output = router.vtysh_cmd("show ipv6 route table 256", isjson=False, daemon="zebra")
    assert "::/0 [20/0] via 50::2" in output, "{} NOK".format(msg)

    msg = "Check Routing information on -ip -6 rule list- from linux"
    logger.info(msg)
    output = router.run("ip -6 rule list")
    logger.info(output)
    assert "from all lookup 256 proto zebra" in output, "{} NOK".format(msg)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
