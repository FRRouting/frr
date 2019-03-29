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
test_bgp_flowspec_topo.py: Test BGP topology with Flowspec EBGP peering


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
                          ~~         ~~----------------------------------
                            ~~~~~~~~~                                   |
                                | 10.0.1.1 r1-eth0                      |
                                | 1.1.1.1  r1-eth0                      |
           vrf r1-cust1+--------+--------+                              |
   ~~~~~~~~~~~~ r1-eth2|    r1           |r1-eth4  ~~~~~~~~~~~          |
  ~    s3     ~--------|BGP 192.168.0.162|--------~    s5     ~         |
  ~30.0.0.0/24~      .1|                 |.1      ~50.0.0.0/24~         |
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
       |                         | 2.2.2.1  r1-eth1    |                |
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
                 | 2.2.2.2 |
                 | 3.3.3.3 |
                 +----+----+





"""

import json
import os
import sys
import pytest
import getopt

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.lutil import lUtil
from lib.lutil import luCommand

# Required to instantiate the topology builder class.
from mininet.topo import Topo

total_ebgp_peers = 1

#####################################################
##
##   Network Topology Definition
##
#####################################################

class BGPFLOWSPECRULETopo1(Topo):
    "BGP EBGP Flowspec Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Setup Routers
        tgen.add_router('r1')

        # Setup Control Path Switch 1. r1-eth0
        switch = tgen.add_switch('s1')
        switch.add_link(tgen.gears['r1'])

        # Setup Control Path Switch 2. r1-eth1
        switch2 = tgen.add_switch('s2')
        switch2.add_link(tgen.gears['r1'])

        ## Add eBGP ExaBGP neighbors
        peer_ip = '192.168.0.161'
        peer_route = 'via 10.0.1.1'
        peer = tgen.add_exabgp_peer('peer1',
                                    ip=peer_ip, defaultRoute=peer_route)
        switch = tgen.gears['s1']
        switch.add_link(peer)

        # Setup Data Path Incoming r2 router
        switch2 = tgen.gears['s2']
        tgen.add_router('r2')
        switch.add_link(tgen.gears['r2'])

        # Setup Data Path Outgoing r3 router
        tgen.add_router('r3')
        switch2.add_link(tgen.gears['r3'])
        switch.add_link(tgen.gears['r3'])

        # Setup Data Path Redirect VRF
        switch3 = tgen.add_switch('s3')
        tgen.add_router('r4')
        switch3.add_link(tgen.gears['r4'])
        switch2.add_link(tgen.gears['r4'])
        switch3.add_link(tgen.gears['r1'])

        # Setup Data Path Redirect IP
        switch5 = tgen.add_switch('s5')
        tgen.add_router('r5')
        switch5.add_link(tgen.gears['r5'])
        switch2.add_link(tgen.gears['r5'])
        switch5.add_link(tgen.gears['r1'])


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    tgen = Topogen(BGPFLOWSPECRULETopo1, module.__name__)
    CustomizeVrfWithNetns = True
    option_vrf_mode = os.getenv('VRF_MODE_PARAM', 'netns')
    if option_vrf_mode == 'vrf-lite':
        CustomizeVrfWithNetns = False

    # set to disabled RPF
    os.system('echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter')
    os.system('echo 0 > /proc/sys/net/ipv4/conf/default/rp_filter')
    os.system('echo 1 > /proc/sys/net/ipv4/conf/all/forwarding')
    os.system('echo 1 > /proc/sys/net/ipv4/conf/default/forwarding')
    tgen.start_topology()
    # tgen.mininet_cli()
    # check for zebra capability
    router = tgen.gears['r1']
    if CustomizeVrfWithNetns:
        if router.check_capability(
                TopoRouter.RD_ZEBRA,
                '--vrfwnetns'
                ) == False:
            return  pytest.skip('Skipping BGP VRF NETNS Test. VRF NETNS backend not available on FRR')
        if os.system('ip netns list') != 0:
            return  pytest.skip('Skipping BGP VRF NETNS Test. NETNS not available on System')
    # retrieve VRF backend kind
    if CustomizeVrfWithNetns:
        logger.info('Testing with VRF Namespace support')

    # create VRF r1-cust1
    # move r1-eth0 to VRF r1-cust1
    logger.info('Creating VRF context on r1')
    if CustomizeVrfWithNetns:
        cmds = ['if [ -e /var/run/netns/xvrf ] ; then ip netns del xvrf ; fi',
                'if [ -e /var/run/netns/{0}-cust{1} ] ; then ip netns del {0}-cust{1} ; fi',
                'ip netns add {0}-cust{1}',
                'ip link set dev {0}-eth{2} netns {0}-cust{1}',
                'ip netns exec {0}-cust{1} ifconfig {0}-eth{2} up']
    else:
        cmds = ['ip link add {0}-cust{1} type vrf table 10',
                'ip link set dev {0}-cust{1} up',
                'ip link set dev {0}-eth{2} master {0}-cust{1}',
                'ip ru add oif {0}-cust{1} table 10',
                'ip ru add iif {0}-cust{1} table 10']

    for cmd in cmds:
        cmd = cmd.format('r1','1','2')
        logger.info('cmd: '+cmd);
        output = router.run(cmd.format('r1','1','2'))
        logger.info('output: '+output);

    if CustomizeVrfWithNetns:
        logger.info('Creating cross VRF context')
        cmds = ['ip netns add xvrf',
                'ip netns exec xvrf brctl addbr xvrf-bridge',
                'ip netns exec xvrf ip link set xvrf-bridge up',
                'ip link add xvrf0 type veth peer name from-vrf0 netns xvrf',
                'ip link set xvrf0 address 00:09:C0:00:00:00 up',
                'ip netns exec xvrf ip link set from-vrf0 up',
                'ip address add 169.254.0.20/16 dev xvrf0',
                'ip netns exec xvrf brctl addif xvrf-bridge from-vrf0',
                'ip netns exec r1-cust1 ip link add xvrf1 type veth peer name from-vrf1 netns xvrf',
                'ip netns exec r1-cust1 ip link set xvrf1 address 00:09:C0:00:00:01 up',
                'ip netns exec xvrf ip link set from-vrf1 up',
                'ip netns exec r1-cust1 ip address add 169.254.0.1/16 dev xvrf1',
                'ip netns exec xvrf brctl addif xvrf-bridge from-vrf1']
        for cmd in cmds:
            logger.info('cmd: '+cmd)
            output = router.run(cmd)

    # Start r2, r3, and r4 and r5
    # Get r2 reference and run Daemons
    logger.info('Launching ZEBRA on r2 - for IP config only -')
    router = tgen.gears['r2']
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, '{}/zebra.conf'.format('r2'))
    )
    router.start()

    logger.info('Launching ZEBRA on r3 - for IP config only -')
    router = tgen.gears['r3']
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, '{}/zebra.conf'.format('r3'))
    )
    router.start()

    logger.info('Launching ZEBRA on r4 - for IP config only -')
    router = tgen.gears['r4']
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, '{}/zebra.conf'.format('r4'))
    )
    router.start()

    logger.info('Launching ZEBRA on r5 - for IP config only -')
    router = tgen.gears['r5']
    router.load_config(
        TopoRouter.RD_ZEBRA,
        os.path.join(CWD, '{}/zebra.conf'.format('r5'))
    )
    router.start()

    # Get r1 reference and run Daemons
    logger.info('Launching BGP and ZEBRA on r1')
    router = tgen.gears['r1']
    if CustomizeVrfWithNetns:
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format('r1')),
            '--vrfwnetns'
           )
    else:
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format('r1'))
           )
    router.load_config(
        TopoRouter.RD_BGP,
        os.path.join(CWD, '{}/bgpd.conf'.format('r1'))
    )
    router.start()
    pingrouter = tgen.gears['r2']
    logger.info('Check Ping from  R2(1.1.1.2) to R3(2.2.2.2)')
    output = pingrouter.run('ping 2.2.2.2 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping from R2 to R3(2.2.2.2) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping from  R2(1.1.1.1) to R3(2.2.2.2) OK')

    # Starting Peer1 with ExaBGP
    logger.info('Launching exaBGP on peer1')
    peer_list = tgen.exabgp_peers()
    peer1 = tgen.gears['peer1']
    peer_dir = os.path.join(CWD, 'peer1')
    env_file = os.path.join(CWD, 'exabgp.env')
    topotest.sleep(1, 'Running ExaBGP peer 1 now')
    peer1.start(peer_dir, env_file)
    logger.info('peer1')

def teardown_module(module):
    tgen = get_topogen()

    cmds = ['ip netns del r1-cust1',
            'ip netns del xvrf']
    for cmd in cmds:
        tgen.net['r1'].cmd(cmd)
    tgen.stop_topology()
    
def test_bgp_convergence():
    "Test for BGP topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    topotest.sleep(10, 'starting BGP peering with peer1')
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

def test_bgp_flowspec():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    attacker = tgen.gears['r2']
    victim = tgen.gears['r3']
    router = tgen.gears['r1']
    # tgen.mininet_cli()

    logger.info('Check Ping from  R2(1.1.1.2) to R3(2.2.2.2) after FS redirect IP Rule')
    output = attacker.run('ping 2.2.2.2 -f -c 1000')
    logger.info(output)
    if '1000 packets transmitted, 1000 received' not in output:
        assertmsg = 'expected ping from R2 to R3(2.2.2.2) should be ok'
        assert 0, assertmsg
    else:
        logger.info('Check Ping from  R2(1.1.1.2) to R3(2.2.2.2) after FS redirect IP Rule OK')

    logger.info('Dump Routing Flowspec : show bgp ipv4 flowspec')
    output = router.vtysh_cmd('show bgp ipv4 flowspec', isjson=False, daemon='bgpd')
    logger.info(output)
    logger.info('Dump Routing Flowspec : show bgp ipv4 flowspec detail')
    output = router.vtysh_cmd('show bgp ipv4 flowspec detail', isjson=False, daemon='bgpd')
    logger.info(output)

    logger.info('Dump Routing information injected on table 256')
    output = router.vtysh_cmd('show ip route table 256', isjson=False, daemon='zebra')
    logger.info(output)

    logger.info('Dump Routing information on -ip rule list- from linux')
    output = router.run('ip rule list')
    logger.info(output)

if __name__ == '__main__':

    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)
