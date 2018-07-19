#!/usr/bin/env python

#
# test_rip_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
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
test_rip_topo1_vrf.py: Testing RIPv2 under VRF

"""

import os
import re
import sys
import platform
import pytest
import getopt
from time import sleep

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
from mininet.topo import Topo

CustomizeVrfWithNetns = True


#####################################################
##
##   Network Topology Definition
##
#####################################################

class RIPVRFTopo1(Topo):
    "RIP VRF Topology 1"

    def build(self, **_opts):
        tgen = get_topogen(self)

        # Setup RIP Routers
        for i in range(1, 4):
            tgen.add_router('r%s' % i)

        # Setup Switches
        #
        # On main router
        # Switches for RIP
        # First switch is for a dummy interface (for local network)
        switch1 = tgen.add_switch('s1')
        switch1.add_link(tgen.gears['r1'], nodeif='r1-eth0')

        # switch 2 switch is for connection to RIP router
        switch2 = tgen.add_switch('s2')
        switch2.add_link(tgen.gears['r1'], nodeif='r1-eth1')
        switch2.add_link(tgen.gears['r2'], nodeif='r2-eth0')

        # switch 3 is between RIP routers
        switch3 = tgen.add_switch('s3')
        switch3.add_link(tgen.gears['r2'], nodeif='r2-eth1')
        switch3.add_link(tgen.gears['r3'], nodeif='r3-eth1')

        # switch 4 is stub on remote RIP router
        switch4 = tgen.add_switch('s4')
        switch4.add_link(tgen.gears['r3'], nodeif='r3-eth0')


        switch5 = tgen.add_switch('sw5')
        switch5.add_link(tgen.gears['r1'], nodeif='r1-eth2')

        switch6 = tgen.add_switch('sw6')
        switch6.add_link(tgen.gears['r1'], nodeif='r1-eth3')


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    global CustomizeVrfWithNetns

    tgen = Topogen(RIPVRFTopo1, module.__name__)
    tgen.start_topology()
    CustomizeVrfWithNetns = True
    option_vrf_mode = os.getenv('VRF_MODE_PARAM', 'netns')
    if option_vrf_mode == 'vrf-lite':
        CustomizeVrfWithNetns = False

    # Get r1 reference
    router = tgen.gears['r1']

    # check for zebra capability
    if CustomizeVrfWithNetns:
        if os.system('ip netns list') != 0:
            return  pytest.skip('Skipping RIP VRF NETNS Test. NETNS not available on System')
    # retrieve VRF backend kind
    if CustomizeVrfWithNetns:
        logger.info('Testing with VRF Namespace support')

    krel = platform.release()
    l3mdev_accept = 0
    if topotest.version_cmp(krel, '4.15') >= 0 and \
       topotest.version_cmp(krel, '4.18') <= 0:
        l3mdev_accept = 1

    if topotest.version_cmp(krel, '5.0') >= 0:
        l3mdev_accept = 1

    if CustomizeVrfWithNetns:
        cmds = ['if [ -e /var/run/netns/r{0}-cust1 ] ; then ip netns del r{0}-cust1 ; fi',
                'ip netns add r{0}-cust1',
                'ip link set dev r{0}-eth0 netns r{0}-cust1',
                'ip netns exec r{0}-cust1 ifconfig r{0}-eth0 up',
                'ip netns exec r{0}-cust1 ifconfig lo 127.0.0.1 up',
                'ip link set dev r{0}-eth1 netns r{0}-cust1',
                'ip netns exec r{0}-cust1 ifconfig r{0}-eth1 up']
    else:
        cmds = ['sysctl -w net.ipv4.udp_l3mdev_accept={}'.format(l3mdev_accept),
                'ip link del r{0}-cust1',
                'ip link add r{0}-cust1 type vrf table 10',
                'ip link set dev r{0}-cust1 up',
                'ip link set dev r{0}-eth0 master r{0}-cust1',
                'ip link set dev r{0}-eth1 master r{0}-cust1']

    # create VRF rx-cust1 and link rx-eth0 to rx-cust1
    for i in range(1, 4):
        for cmd in cmds:
            tgen.gears['r%s' % i].run(cmd.format(i))

    if CustomizeVrfWithNetns:
        cmds_r1 = ['ip link set dev r1-eth2 netns r1-cust1',
                   'ip netns exec r1-cust1 ifconfig r1-eth2 up',
                   'ip link set dev r1-eth3 netns r1-cust1',
                   'ip netns exec r1-cust1 ifconfig r1-eth3 up']
    else:
        cmds_r1 = ['ip link set dev r1-eth2 master r1-cust1',
                   'ip link set dev r1-eth3 master r1-cust1']

    for cmd in cmds_r1:
            tgen.gears['r1'].run(cmd)

    # Starting Routers
    #
    for i in range(1, 4):
        router = tgen.gears['r%s' % i]
        zebra_option = '--vrfwnetns' if CustomizeVrfWithNetns else ''
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, '{}/zebra.conf'.format('r%s' % i)),
            zebra_option
        )
        router.load_config(
            TopoRouter.RD_RIP,
            os.path.join(CWD, '{}/ripd.conf'.format('r%s' % i))
        )
        router.start()

    # For debugging after starting Quagga/FRR daemons, uncomment the next line
    # tgen.mininet_cli()


def teardown_module(module):
    tgen = get_topogen()

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    if CustomizeVrfWithNetns:
        cmds = ['ip netns exec r{0}-cust1 ip link set r{0}-eth0 netns 1',
                'ip netns exec r{0}-cust1 ip link set r{0}-eth1 netns 1',
                'ip netns delete r{0}-cust1']
    else:
        cmds = ['ip link delete r{0}-cust1']

    for i in range(1, 4):
        for cmd in cmds:
            tgen.gears['r%s' % i].run(cmd.format(i))

    tgen.stop_topology()

def test_converge_protocols():
    "Test for RIP topology convergence"
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    print("\n\n** Waiting for protocols convergence")
    print("******************************************\n")

    # Not really implemented yet - just sleep 60 secs for now
    # tgen.mininet_cli()
    sleep(60)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # tgen.mininet_cli()


def test_rip_status():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP status")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/rip_status.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = tgen.gears['r%s' % i].run('vtysh -c "show ip rip vrf r{0}-cust1 status" 2> /dev/null'.format(i)).rstrip()
            # Drop time in next due
            actual = re.sub(r"in [0-9]+ seconds", "in XX seconds", actual)
            # Drop time in last update
            actual = re.sub(r" [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", " XX:XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual IP RIP status",
                title2="expected IP RIP status")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed IP RIP status check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IP RIP status failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = tgen.gears['r%s' % i].check_router_running()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # tgen.mininet_cli()


def test_rip_routes():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify RIP Status
    print("\n\n** Verifing RIP routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/show_ip_rip.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = tgen.gears['r%s' % i].run('vtysh -c "show ip rip vrf r{0}-cust1" 2> /dev/null'.format(i)).rstrip()
            # Drop Time
            actual = re.sub(r"[0-9][0-9]:[0-5][0-9]", "XX:XX", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual SHOW IP RIP",
                title2="expected SHOW IP RIP")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed SHOW IP RIP check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "SHOW IP RIP failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = tgen.gears['r%s' % i].check_router_running()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # tgen.mininet_cli()


def test_zebra_ipv4_routingTable():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 4):
        refTableFile = '%s/r%s/show_ip_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = tgen.gears['r%s' % i].run('vtysh -c "show ip route vrf r{0}-cust1" 2> /dev/null | grep "^R"'.format(i)).rstrip()
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = topotest.get_textdiff(actual, expected,
                title1="actual Zebra IPv4 routing table",
                title2="expected Zebra IPv4 routing table")

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed Zebra IPv4 Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Zebra IPv4 Routing Table verification failed for router r%s:\n%s" % (i, diff)

    # Make sure that all daemons are still running
    for i in range(1, 4):
        fatal_error = tgen.gears['r%s' % i].check_router_running()
        assert fatal_error == "", fatal_error

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # tgen.mininet_cli()


def test_shutdown_check_stderr():
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    if os.environ.get('TOPOTESTS_CHECK_STDERR') is None:
        pytest.skip('Skipping test for Stderr output and memory leaks')

    thisDir = os.path.dirname(os.path.realpath(__file__))

    print("\n\n** Verifing unexpected STDERR output from daemons")
    print("******************************************\n")

    tgen.gears['r1'].stop()


if __name__ == '__main__':

    args = ["-s"] + sys.argv[1:]
    ret = pytest.main(args)

    sys.exit(ret)

