#!/usr/bin/env python

#
# ospf6-test1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2016 by 
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
test_ospf6_topo1.py:

                                                  -----\
  SW1 - Stub Net 1            SW2 - Stub Net 2          \
  fc00:1:1:1::/64             fc00:2:2:2::/64            \
\___________________/      \___________________/          |
          |                          |                    |
          |                          |                    |
          | ::1                      | ::2                |
+---------+---------+      +---------+---------+          |
|        R1         |      |        R2         |          |
|      Quagga       |      |      Quagga       |          |
| Rtr-ID: 10.0.0.1  |      | Rtr-ID: 10.0.0.2  |          |
+---------+---------+      +---------+---------+          |
          | ::1                      | ::2                 \
           \______        ___________/                      OSPFv3
                  \      /                               Area 0.0.0.0
                   \    /                                  /
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW5        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:A:A:A::/64 ~~                         |
             ~~~~~~~~~~~~~~~~~~                           |
                     |                 /----              |
                     | ::3            | SW3 - Stub Net 3  | 
           +---------+---------+    /-+ fc00:3:3:3::/64   |
           |        R3         |   /  |                  /
           |      Quagga       +--/    \----            /
           | Rtr-ID: 10.0.0.3  | ::3        ___________/
           +---------+---------+                       \
                     | ::3                              \
                     |                                   \
             ~~~~~~~~~~~~~~~~~~                           |
           ~~       SW6        ~~                         |
         ~~       Switch         ~~                       |
           ~~  fc00:B:B:B::/64 ~~                          \
             ~~~~~~~~~~~~~~~~~~                             OSPFv3
                     |                                   Area 0.0.0.1
                     | ::4                                 /
           +---------+---------+       /----              |
           |        R4         |      | SW4 - Stub Net 4  |
           |      Quagga       +------+ fc00:4:4:4::/64   |
           | Rtr-ID: 10.0.0.4  | ::4  |                   /
           +-------------------+       \----             /
                                                   -----/
"""

import os
import re
import StringIO
import sys
import difflib

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from functools import partial
from time import sleep

import pytest

def int2dpid(dpid):
    "Converting Integer to DPID"

    try:
        dpid = hex(dpid)[2:]
        dpid = '0'*(16-len(dpid))+dpid
        return dpid
    except IndexError:
        raise Exception('Unable to derive default datapath ID - '
                        'please either specify a dpid or use a '
                        'canonical switch name such as s23.')
class LinuxRouter(Node):
    "A Node with IPv4/IPv6 forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=1')
    def terminate(self):
        """
        Terminate generic LinuxRouter Mininet instance
        """
        self.cmd('sysctl net.ipv4.ip_forward=0')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=0')
        super(LinuxRouter, self).terminate()

class QuaggaRouter(Node):
    "A Node with IPv4/IPv6 forwarding enabled and Quagga as Routing Engine"

    def config(self, **params):
        super(QuaggaRouter, self).config(**params)
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=1') 
        self.cmd('chown quagga:quaggavty /etc/quagga')
        self.daemons = {'zebra': 0, 'ripd': 0, 'ripngd': 0, 'ospfd': 0,
                        'ospf6d': 0, 'isisd': 0, 'bgpd': 0, 'pimd': 0}
    def terminate(self):
        # Delete Running Quagga Daemons
        rundaemons = self.cmd('ls -1 /var/run/quagga/*.pid')
        for d in StringIO.StringIO(rundaemons):
            self.cmd('kill -7 `cat %s`' % d.rstrip())
            self.waitOutput()
        # Disable forwarding
        self.cmd('sysctl net.ipv4.ip_forward=0')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=0')
        super(QuaggaRouter, self).terminate()
    def removeIPs(self):
        for interface in self.intfNames():
            self.cmd('ip address flush', interface)
    def loadConf(self, daemon, source=None):
        # print "Daemons before:", self.daemons
        if daemon in self.daemons.keys():
            self.daemons[daemon] = 1
            if source is None:
                self.cmd('touch /etc/quagga/%s.conf' % daemon)
                self.waitOutput()
            else:
                self.cmd('cp %s /etc/quagga/%s.conf' % (source, daemon))
                self.waitOutput()
            self.cmd('chmod 640 /etc/quagga/%s.conf' % daemon)
            self.waitOutput()
            self.cmd('chown quagga:quagga /etc/quagga/%s.conf' % daemon)
            self.waitOutput()
        else:
            print("No daemon %s known" % daemon)
        # print "Daemons after:", self.daemons
    def startQuagga(self):
        # Disable integrated-vtysh-config
        self.cmd('echo "no service integrated-vtysh-config" > /etc/quagga/vtysh.conf')
        with open("/etc/quagga/vtysh.conf", "w") as vtyshfile:
            vtyshfile.write('no service integrated-vtysh-config')
        self.cmd('chown quagga:quaggavty /etc/quagga/vtysh.conf')
        # Remove IP addresses from OS first - we have them in zebra.conf
        self.removeIPs()
        # Start Zebra first
        if self.daemons['zebra'] == 1:
            self.cmd('/usr/lib/quagga/zebra -d')
            self.waitOutput()
            print('%s: zebra started' % self)
            sleep(1)
        # Fix Link-Local Addresses
        # Somehow (on Mininet only), Zebra removes the IPv6 Link-Local addresses on start. Fix this
        self.cmd('for i in `ls /sys/class/net/` ; do mac=`cat /sys/class/net/$i/address`; IFS=\':\'; set $mac; unset IFS; ip address add dev $i scope link fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64; done')
        # Now start all the other daemons
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1) and (daemon != 'zebra'):
                self.cmd('/usr/lib/quagga/%s -d' % daemon)
                self.waitOutput()
                print('%s: %s started' % (self, daemon))
    def checkQuaggaRunning(self):
        daemonsRunning = self.cmd('vtysh -c "show log" | grep "Logging configuration for"')
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1):
                assert daemon in daemonsRunning, "Daemon %s not running" % daemon


class LegacySwitch(OVSSwitch):
    "A Legacy Switch without OpenFlow"

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, failMode='standalone', **params)
        self.switchIP = None

#####################################################
##
##   Network Topology Definition
##
#####################################################

class NetworkTopo(Topo):
    "A Quagga Topology with direct peering router and IXP connection"

    def build(self, **_opts):

        quaggaPrivateDirs = ['/etc/quagga',
                             '/var/run/quagga',
                             '/var/log']
        #
        # Define Switches first
        #
        switch = {}
        for i in range(1, 7):
            switch[i] = self.addSwitch('SW%s' % i, dpid=int2dpid(i),
                                       cls=LegacySwitch)
        #
        # Define Quagga Routers
        #
        router = {}
        for i in range(1, 5):
            router[i] = self.addNode('r%s' % i, cls=QuaggaRouter,
                                     privateDirs=quaggaPrivateDirs)
        #
        # Wire up the switches and routers
        #
        # Stub nets
        for i in range(1, 5):
            self.addLink(switch[i], router[i], intfName2='r%s-stubnet' % i)
        # Switch 5
        self.addLink(switch[5], router[1], intfName2='r1-sw5')
        self.addLink(switch[5], router[2], intfName2='r2-sw5')
        self.addLink(switch[5], router[3], intfName2='r3-sw5')
        # Switch 6
        self.addLink(switch[6], router[3], intfName2='r3-sw6')
        self.addLink(switch[6], router[4], intfName2='r4-sw6')


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    global topo, net

    print ("\n\n** Setup Topology: %s\n" % module.__name__)
    print("******************************************\n")

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    # For debugging after starting net, but before starting Quagga, uncomment the next line
    # CLI(net)

    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospf6d', '%s/r%s/ospf6d.conf' % (thisDir, i))
        net['r%s' % i].startQuagga()

    # For debugging after starting Quagga daemons, uncomment the next line
    # CLI(net)


def teardown_module(module):
    global net

    print ("\n\n** Shutdown Topology: %s\n" % module.__name__)
    print("******************************************\n")

    # End - Shutdown network
    net.stop()


def test_quagga_running():
    global net

    print ("\n\n** Check if Quagga is running on each Router node\n")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].checkQuaggaRunning()


def test_ospf6_converged():
    global net

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify for OSPF6 daemons to converge\n")
    print("******************************************\n")
    timeout = 60
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 5):
            notConverged = net['r%s' % i].cmd('vtysh -c "show ipv6 ospf neigh" 2> /dev/null | grep ^[0-9] | grep -v Full')
            if notConverged:
                print('Waiting for r%s' %i),
                sys.stdout.flush()
                break
        if notConverged:
            sleep(2)
            timeout -= 2
            print('\r                                            \r'),
        else:
            print('\rDone                                        ')
            print(notConverged)
            break
    else:
        # Bail out with error if a router fails to converge
        ospfStatus = net['r%s' % i].cmd('vtysh -c "show ipv6 ospf neigh"')

        assert False, "OSPFv6 did not converge:\n%s" % ospfStatus

    print("OSPFv3 converged.")

    if timeout < 60:
        # Only wait if we actually went through a convergence
        print("\nwaiting 15s for routes to populate")
        sleep(15)

def test_ospf6_routingTable():
    global net

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing OSPFv3 Routing Table\n")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_ipv6_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ipv6 route" 2> /dev/null | grep "^O"').rstrip()
            # Mask out Link-Local mac address portion. They are random...
            actual = re.sub(r" fe80::[0-9a-f:]+", " fe80::XXXX:XXXX:XXXX:XXXX", actual)
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff=difflib.unified_diff(actual, expected)
            diff=''.join(diff)
            # Empty string if it matches, otherwise diff contains unified diff

            if diff:
                sys.stderr.write('r%s failed Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Routing Table verification failed for router r%s:\n%s" % (i, diff)


if __name__ == '__main__':

    setLogLevel('info')
    retval = pytest.main(["-s"])
    sys.exit(retval)
