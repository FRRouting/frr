#!/usr/bin/env python

#
# test_bgp_multiview_topo1.py
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
test_bgp_multiview_topo1.py: Simple Quagga Route-Server Test

+----------+ +----------+ +----------+ +----------+ +----------+
|  peer1   | |  peer2   | |  peer3   | |  peer4   | |  peer5   |
| AS 65001 | | AS 65002 | | AS 65003 | | AS 65004 | | AS 65005 |
+-----+----+ +-----+----+ +-----+----+ +-----+----+ +-----+----+
      | .1         | .2         | .3         | .4         | .5 
      |     ______/            /            /   _________/
       \   /  ________________/            /   /     
        | |  /   _________________________/   /     +----------+  
        | | |  /   __________________________/   ___|  peer6   |
        | | | |  /  ____________________________/.6 | AS 65006 |
        | | | | |  /  _________________________     +----------+
        | | | | | |  /  __________________     \    +----------+ 
        | | | | | | |  /                  \     \___|  peer7   |
        | | | | | | | |                    \     .7 | AS 65007 |
     ~~~~~~~~~~~~~~~~~~~~~                  \       +----------+
   ~~         SW1         ~~                 \      +----------+
   ~~       Switch           ~~               \_____|  peer8   |  
   ~~    172.16.1.0/24     ~~                    .8 | AS 65008 |
     ~~~~~~~~~~~~~~~~~~~~~                          +----------+
              |
              | .254
    +---------+---------+
    |     Quagga R1     |
    |   BGP Multi-View  |
    | Peer 1-3 > View 1 |       
    | Peer 4-5 > View 2 |
    | Peer 6-8 > View 3 |
    +---------+---------+
              | .1
              |
        ~~~~~~~~~~~~~        Stub Network is redistributed
      ~~     SW0     ~~      into each BGP view with different
    ~~   172.20.0.1/28  ~~   attributes (using route-map)
      ~~ Stub Switch ~~
        ~~~~~~~~~~~~~
"""  

import os
import re
import sys
import difflib
import StringIO
import glob
import subprocess

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf

from functools import partial
from time import sleep

import pytest

fatal_error = ""

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
        # Enable coredumps
        self.cmd('sysctl kernel.core_uses_pid=1')
        self.cmd('sysctl fs.suid_dumpable=2')
        self.cmd("sysctl kernel.core_pattern=/tmp/%s_%%e_core-sig_%%s-pid_%%p.dmp" % self.name)
        self.cmd('ulimit -c unlimited')
        # Set ownership of config files
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
        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob("/tmp/*%s*.log" % self.name))
        # Remove old core files
        map(os.remove, glob.glob("/tmp/%s*.dmp" % self.name))
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
        global fatal_error

        daemonsRunning = self.cmd('vtysh -c "show log" | grep "Logging configuration for"')
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1) and not (daemon in daemonsRunning):
                sys.stderr.write("%s: Daemon %s not running\n" % (self.name, daemon))
                # Look for core file
                corefiles = glob.glob("/tmp/%s_%s_core*.dmp" % (self.name, daemon))
                if (len(corefiles) > 0):
                    backtrace = subprocess.check_output(["gdb /usr/lib/quagga/%s %s --batch -ex bt 2> /dev/null"  % (daemon, corefiles[0])], shell=True)
                    sys.stderr.write("\n%s: %s crashed. Core file found - Backtrace follows:\n" % (self.name, daemon))
                    sys.stderr.write("%s\n" % backtrace)
                else:
                    # No core found - If we find matching logfile in /tmp, then print last 20 lines from it.
                    if os.path.isfile("/tmp/%s-%s.log" % (self.name, daemon)):
                        log_tail = subprocess.check_output(["tail -n20 /tmp/%s-%s.log 2> /dev/null"  % (self.name, daemon)], shell=True)
                        sys.stderr.write("\nFrom quagga %s %s log file:\n" % (self.name, daemon))
                        sys.stderr.write("%s\n" % log_tail)

                fatal_error = "%s: Daemon %s not running" % (self.name, daemon)
                assert False, "%s: Daemon %s not running" % (self.name, daemon)

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
    "A LinuxRouter connecting three IP subnets"

    def build(self, **_opts):

        quaggaPrivateDirs = ['/etc/quagga',
                             '/var/run/quagga',
                             '/var/log',
                             '/var/run/ssh']
        exabgpPrivateDirs = ['/etc/exabgp',
                             '/var/run/exabgp',
                             '/var/log']
        
        # Setup Routers
        quagga = {}
        for i in range(1, 2):
            quagga[i] = self.addNode('r%s' % i, cls=QuaggaRouter,
                                     privateDirs=quaggaPrivateDirs)

        # Setup Provider BGP peers
        peer = {}
        for i in range(1, 9):
            peer[i] = self.addHost('peer%s' % i, ip='172.16.1.%s/24' % i,
                                    defaultRoute='via 172.16.1.254',
                                    privateDirs=exabgpPrivateDirs)

        # Setup Switches
        switch = {}
        # First switch is for a dummy interface (for local network)
        switch[0] = self.addSwitch('sw0', cls=LegacySwitch)
        self.addLink(switch[0], quagga[1], intfName2='r1-stub')
        # Second switch is for connection to all peering routers
        switch[1] = self.addSwitch('sw1', cls=LegacySwitch)
        self.addLink(switch[1], quagga[1], intfName2='r1-eth0')
        for j in range(1, 9):
            self.addLink(switch[1], peer[j], intfName2='peer%s-eth0' % j)


#####################################################
##
##   Tests starting
##
#####################################################

def setup_module(module):
    global topo, net

    print("\n\n** %s: Setup Topology" % module.__name__)
    print("******************************************\n")

    print("Cleanup old Mininet runs")
    os.system('sudo mn -c > /dev/null 2>&1')

    thisDir = os.path.dirname(os.path.realpath(__file__))
    topo = NetworkTopo()

    net = Mininet(controller=None, topo=topo)
    net.start()

    # Starting Routers
    for i in range(1, 2):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('bgpd', '%s/r%s/bgpd.conf' % (thisDir, i))
        net['r%s' % i].startQuagga()

    # Starting PE Hosts and init ExaBGP on each of them
    print('*** Starting BGP on all 8 Peers in 10s')
    sleep(10)
    for i in range(1, 9):
        net['peer%s' % i].cmd('cp %s/exabgp.env /etc/exabgp/exabgp.env' % thisDir)
        net['peer%s' % i].cmd('cp %s/peer%s/* /etc/exabgp/' % (thisDir, i))
        net['peer%s' % i].cmd('chmod 644 /etc/exabgp/*')
        net['peer%s' % i].cmd('chmod 755 /etc/exabgp/*.py')
        net['peer%s' % i].cmd('chown -R exabgp:exabgp /etc/exabgp')
        net['peer%s' % i].cmd('exabgp -e /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg')
        print('peer%s' % i),
    print('')

    # For debugging after starting Quagga daemons, uncomment the next line
    # CLI(net)

def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    # Shutdown - clean up everything
    print('*** Killing BGP on Peer routers')
    # Killing ExaBGP
    for i in range(1, 9):
        net['peer%s' % i].cmd('kill `cat /var/run/exabgp/exabgp.pid`')

    # End - Shutdown network
    net.stop()

def test_quagga_running():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check if Quagga is running on each Router node")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 2):
        net['r%s' % i].checkQuaggaRunning()

def test_bgp_converge():
    "Check for BGP converged on all peers and BGP views"

    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Wait for BGP to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify for BGP to converge")
    print("******************************************\n")
    timeout = 60
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 2):
            for view in range(1, 4):
                notConverged = net['r%s' % i].cmd('vtysh -c "show ip bgp view %s summary" 2> /dev/null | grep ^[0-9] | grep -v " 11$"' % view)
                if notConverged:
                    print('Waiting for r%s, view %s' % (i, view))
                    sys.stdout.flush()
                    break
            if notConverged:
                break
        if notConverged:
            sleep(5)
            timeout -= 5
        else:
            print('Done')
            break
    else:
        # Bail out with error if a router fails to converge
        bgpStatus = net['r%s' % i].cmd('show ip bgp view %s summary"')
        assert False, "BGP did not converge:\n%s" % bgpStatus

    print("BGP converged.")

    # if timeout < 60:
    #     # Only wait if we actually went through a convergence
    #     print("\nwaiting 15s for routes to populate")
    #     sleep(15)

    # For debugging after starting Quagga daemons, uncomment the next line
    # CLI(net)

def test_bgp_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing BGP Routing Tables")
    print("******************************************\n")
    failures = 0
    for i in range(1, 2):
        for view in range(1, 4):
            refTableFile = '%s/r%s/show_ip_bgp_view_%s.ref' % (thisDir, i, view)
            if os.path.isfile(refTableFile):
                # Read expected result from file
                expected = open(refTableFile).read().rstrip()
                # Fix newlines (make them all the same)
                expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

                # Actual output from router
                actual = net['r%s' % i].cmd('vtysh -c "show ip bgp view %s" 2> /dev/null' % view).rstrip()
    
                # Fix inconsitent spaces between 0.99.24 and newer versions of Quagga...
                actual = re.sub('0             0', '0              0', actual)
                actual = re.sub(r'([0-9])         32768', r'\1          32768', actual)
                # Remove summary line (changed recently)
                actual = re.sub(r'Total number.*', '', actual)
                actual = re.sub(r'Displayed.*', '', actual)
                actual = actual.rstrip()

                # Fix newlines (make them all the same)
                actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual BGP routing table", 
                tofile="expected BGP routing table"))
            # Empty string if it matches, otherwise diff contains unified diff

            if diff:
                sys.stderr.write('r%s failed Routing Table Check for view %s:\n%s\n' 
                                 % (i, view, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Routing Table verification failed for router r%s, view %s:\n%s" % (i, view, diff)

    # For debugging after starting Quagga daemons, uncomment the next line
    # CLI(net)


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
