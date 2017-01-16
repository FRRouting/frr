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
test_ldp_topo1.py: Simple FRR/Quagga LDP Test

             +---------+
             |    r1   |
             | 1.1.1.1 |
             +----+----+
                  | .1  r1-eth0
                  |
            ~~~~~~~~~~~~~
          ~~     sw0     ~~
          ~~ 10.0.1.0/24 ~~
            ~~~~~~~~~~~~~
                  |10.0.1.0/24
                  |
                  | .2  r2-eth0
             +----+----+
             |    r2   |
             | 2.2.2.2 |
             +--+---+--+
    r2-eth2  .2 |   | .2  r2-eth1
         ______/     \______
        /                   \
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
~~     sw2     ~~    ~~     sw1     ~~
~~ 10.0.3.0/24 ~~    ~~ 10.0.2.0/24 ~~
  ~~~~~~~~~~~~~        ~~~~~~~~~~~~~
        |                 /    |
         \      _________/     |
          \    /                \
r3-eth1 .3 |  | .3  r3-eth0      | .4 r4-eth0
      +----+--+---+         +----+----+
      |     r3    |         |    r4   |
      |  3.3.3.3  |         | 4.4.4.4 |
      +-----------+         +---------+
"""  

import os
import re
import sys
import difflib
import StringIO
import glob
import subprocess
import platform

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
        # Check if Quagga or FRR is installed
        if os.path.isfile('/usr/lib/frr/zebra'):
            self.routertype = 'frr'
        elif os.path.isfile('/usr/lib/quagga/zebra'):
            self.routertype = 'quagga'
        else:
            raise Exception('No FRR or Quagga found in ususal location')
        # Enable forwarding on the router
        self.cmd('sysctl net.ipv4.ip_forward=1')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=1')
        # Enable coredumps
        self.cmd('sysctl kernel.core_uses_pid=1')
        self.cmd('sysctl fs.suid_dumpable=2')
        self.cmd("sysctl kernel.core_pattern=/tmp/%s_%%e_core-sig_%%s-pid_%%p.dmp" % self.name)
        self.cmd('ulimit -c unlimited')
        # Set ownership of config files
        self.cmd('chown %s:%svty /etc/%s' % (self.routertype, self.routertype, self.routertype))
        self.daemons = {'zebra': 0, 'ripd': 0, 'ripngd': 0, 'ospfd': 0,
                        'ospf6d': 0, 'isisd': 0, 'bgpd': 0, 'pimd': 0, 
                        'ldpd': 0}
    def terminate(self):
        # Delete Running Quagga Daemons
        rundaemons = self.cmd('ls -1 /var/run/%s/*.pid' % self.routertype)
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
                self.cmd('touch /etc/%s/%s.conf' % (self.routertype, daemon))
                self.waitOutput()
            else:
                self.cmd('cp %s /etc/%s/%s.conf' % (source, self.routertype, daemon))
                self.waitOutput()
            self.cmd('chmod 640 /etc/%s/%s.conf' % (self.routertype, daemon))
            self.waitOutput()
            self.cmd('chown %s:%s /etc/%s/%s.conf' % (self.routertype, self.routertype, self.routertype, daemon))
            self.waitOutput()
        else:
            print("No daemon %s known" % daemon)
        # print "Daemons after:", self.daemons
    def startQuagga(self):
        global fatal_error

        # Disable integrated-vtysh-config
        with open('/etc/%s/vtysh.conf' % self.routertype, "w") as vtyshfile:
            vtyshfile.write('no service integrated-vtysh-config')
        self.cmd('chown %s:%svty /etc/%s/vtysh.conf' % (self.routertype, self.routertype, self.routertype))
        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob("/tmp/*%s*.log" % self.name))
        # Remove old core files
        map(os.remove, glob.glob("/tmp/%s*.dmp" % self.name))
        # Remove IP addresses from OS first - we have them in zebra.conf
        self.removeIPs()
        # If ldp is used, check for LDP to be compiled and Linux Kernel to be 4.5 or higher
        # No error - but return message and skip all the tests
        if self.daemons['ldpd'] == 1:
            if not os.path.isfile('/usr/lib/%s/ldpd' % self.routertype):
                fatal_error = "LDP Test, but no ldpd compiled or installed"
                print("LDP Test, but no ldpd compiled or installed")
                return
            kernel_version = re.search(r'([0-9]+\.[0-9]+).*', platform.release())
            if kernel_version:
                if float(kernel_version.group(1)) < 4.5:
                    fatal_error = "LDP Test need Linux Kernel 4.5 minimum"
                    print("LDP Test need Linux Kernel 4.5 minimum")
                    return
        # Add mpls modules to kernel if we use LDP
        if self.daemons['ldpd'] == 1:
            self.cmd('/sbin/modprobe mpls-router')
            self.cmd('/sbin/modprobe mpls-iptunnel')
            self.cmd('echo 100000 > /proc/sys/net/mpls/platform_labels')
        # Start Zebra first
        if self.daemons['zebra'] == 1:
            self.cmd('/usr/lib/%s/zebra -d' % self.routertype)
            self.waitOutput()
            print('%s: %s zebra started' % (self, self.routertype))
            sleep(1)
        # Fix Link-Local Addresses
        # Somehow (on Mininet only), Zebra removes the IPv6 Link-Local addresses on start. Fix this
        self.cmd('for i in `ls /sys/class/net/` ; do mac=`cat /sys/class/net/$i/address`; IFS=\':\'; set $mac; unset IFS; ip address add dev $i scope link fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64; done')
        # Now start all the other daemons
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1) and (daemon != 'zebra'):
                self.cmd('/usr/lib/%s/%s -d' % (self.routertype, daemon))
                self.waitOutput()
                print('%s: %s %s started' % (self, self.routertype, daemon))
    def checkQuaggaRunning(self):
        global fatal_error

        daemonsRunning = self.cmd('vtysh -c "show log" | grep "Logging configuration for"')
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1) and not (daemon in daemonsRunning):
                sys.stderr.write("%s: Daemon %s not running\n" % (self.name, daemon))
                # Look for core file
                corefiles = glob.glob("/tmp/%s_%s_core*.dmp" % (self.name, daemon))
                if (len(corefiles) > 0):
                    backtrace = subprocess.check_output(["gdb /usr/lib/%s/%s %s --batch -ex bt 2> /dev/null"  % (self.routertype, daemon, corefiles[0])], shell=True)
                    sys.stderr.write("\n%s: %s crashed. Core file found - Backtrace follows:\n" % (self.name, daemon))
                    sys.stderr.write("%s\n" % backtrace)
                else:
                    # No core found - If we find matching logfile in /tmp, then print last 20 lines from it.
                    if os.path.isfile("/tmp/%s-%s.log" % (self.name, daemon)):
                        log_tail = subprocess.check_output(["tail -n20 /tmp/%s-%s.log 2> /dev/null"  % (self.name, daemon)], shell=True)
                        sys.stderr.write("\nFrom %s %s %s log file:\n" % (self.routertype, self.name, daemon))
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
                             '/etc/frr',
                             '/var/run/quagga',
                             '/var/run/frr',
                             '/var/log']
        exabgpPrivateDirs = ['/etc/exabgp',
                             '/var/run/exabgp',
                             '/var/log']
        
        # Setup Routers
        router = {}
        for i in range(1, 5):
            router[i] = self.addNode('r%s' % i, cls=QuaggaRouter,
                                     privateDirs=quaggaPrivateDirs)

        # Setup Switches
        switch = {}
        # First switch
        switch[0] = self.addSwitch('sw0', cls=LegacySwitch)
        self.addLink(switch[0], router[1], intfName2='r1-eth0', addr1='80:AA:00:00:00:00', addr2='00:11:00:01:00:00')
        self.addLink(switch[0], router[2], intfName2='r2-eth0', addr1='80:AA:00:00:00:01', addr2='00:11:00:02:00:00')
        # Second switch
        switch[1] = self.addSwitch('sw1', cls=LegacySwitch)
        self.addLink(switch[1], router[2], intfName2='r2-eth1', addr1='80:AA:00:01:00:00', addr2='00:11:00:02:00:01')
        self.addLink(switch[1], router[3], intfName2='r3-eth0', addr1='80:AA:00:01:00:01', addr2='00:11:00:03:00:00')
        self.addLink(switch[1], router[4], intfName2='r4-eth0', addr1='80:AA:00:01:00:02', addr2='00:11:00:04:00:00')
        # Third switch
        switch[2] = self.addSwitch('sw2', cls=LegacySwitch)
        self.addLink(switch[2], router[2], intfName2='r2-eth2', addr1='80:AA:00:02:00:00', addr2='00:11:00:02:00:02')
        self.addLink(switch[2], router[3], intfName2='r3-eth1', addr1='80:AA:00:02:00:01', addr2='00:11:00:03:00:01')

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
    for i in range(1, 5):
        net['r%s' % i].loadConf('zebra', '%s/r%s/zebra.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ospfd', '%s/r%s/ospfd.conf' % (thisDir, i))
        net['r%s' % i].loadConf('ldpd', '%s/r%s/ldpd.conf' % (thisDir, i))
        net['r%s' % i].startQuagga()

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)

def teardown_module(module):
    global net

    print("\n\n** %s: Shutdown Topology" % module.__name__)
    print("******************************************\n")

    # End - Shutdown network
    net.stop()


def test_quagga_running():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    print("\n\n** Check if FRR/Quagga is running on each Router node")
    print("******************************************\n")
    sleep(5)

    # Starting Routers
    for i in range(1, 5):
        net['r%s' % i].checkQuaggaRunning()


def test_mpls_interfaces():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing MPLS Interfaces")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_interface.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp interface" 2> /dev/null').rstrip()
            # Mask out Timer in Uptime
            actual = re.sub(r" [0-9][0-9]:[0-9][0-9]:[0-9][0-9] ", " xx:xx:xx ", actual)
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual MPLS LDP interface status", 
                tofile="expected MPLS LDP interface status"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP Interface status Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface status failed for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_ldp_neighbor_establish():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    # Wait for OSPF6 to converge  (All Neighbors in either Full or TwoWay State)
    print("\n\n** Verify MPLS LDP neighbors to establish")
    print("******************************************\n")
    timeout = 90
    while timeout > 0:
        print("Timeout in %s: " % timeout),
        sys.stdout.flush()
        # Look for any node not yet converged
        for i in range(1, 5):
            established = net['r%s' % i].cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null')
            if not established:
                print('Waiting for r%s' %i)
                sys.stdout.flush()
                break
        if not established:
            sleep(5)
            timeout -= 5
        else:
            print('Done')
            break
    else:
        # Bail out with error if a router fails to converge
        fatal_error = "MPLS LDP neighbors did not establish"
        assert False, "MPLS LDP neighbors did not establish" % ospfStatus

    print("MPLS LDP neighbors established.")

    if timeout < 60:
        # Only wait if we actually went through a convergence
        print("\nwaiting 15s for LDP sessions to establish")
        sleep(15)
  

def test_mpls_ldp_discovery():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing MPLS LDP discovery")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_discovery.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp discovery" 2> /dev/null').rstrip()

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual MPLS LDP discovery output", 
                tofile="expected MPLS LDP discovery output"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP discovery output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface discovery output for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_ldp_neighbor():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing MPLS LDP neighbor")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_neighbor.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp neighbor" 2> /dev/null').rstrip()
            # Mask out Timer in Uptime
            actual = re.sub(r"Up time: [0-9][0-9]:[0-9][0-9]:[0-9][0-9]", "Up time: xx:xx:xx", actual)
            # Mask out Port numbers in TCP connection
            actual = re.sub(r"TCP connection: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]):[0-9]+ - ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]):[0-9]+",
                r"TCP connection: \1:xxx - \2:xxx", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual MPLS LDP neighbor output", 
                tofile="expected MPLS LDP neighbor output"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP neighbor output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface neighbor output for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)


def test_mpls_ldp_binding():
    global fatal_error
    global net

    # Skip this test for now until proper sorting of the output
    # is implemented
    # pytest.skip("Skipping test_mpls_ldp_binding")

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing MPLS LDP binding")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_ldp_binding.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls ldp binding" 2> /dev/null').rstrip()
            # Mask out label
            actual = re.sub(r"label: [0-9]+", "label: xxx", actual)
            actual = re.sub(r"(\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[ ]+)[0-9]+", r"\1xxx", actual)
 
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Sort lines which start with "xx via inet "
            pattern = r'^\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+'
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual MPLS LDP binding output", 
                tofile="expected MPLS LDP binding output"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS LDP binding output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS LDP Interface binding output for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    #CLI(net)


def test_zebra_ipv4_routingTable():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing Zebra IPv4 Routing Table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_ipv4_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show ip route" 2> /dev/null | grep "^O"').rstrip()
            # Drop timers on end of line (older Quagga Versions)
            actual = re.sub(r", [0-2][0-9]:[0-5][0-9]:[0-5][0-9]", "", actual)
            # Mask out label
            actual = re.sub(r" label [0-9]+", " label xxx", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual IPv4 zebra routing table", 
                tofile="expected IPv4 zera routing table"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed IPv4 Zebra Routing Table Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "IPv4 Zebra Routing Table verification failed for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_mpls_table():
    global fatal_error
    global net

    # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing MPLS table")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/show_mpls_table.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('vtysh -c "show mpls table" 2> /dev/null').rstrip()
 
            # Fix inconsistent Label numbers at beginning of line
            actual = re.sub(r"(\s+)[0-9]+(\s+LDP)", r"\1XX\2", actual)
            # Fix inconsistent Label numbers at end of line
            actual = re.sub(r"(\s+[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\s+)[0-9][0-9]", r"\1XX", actual)

            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Sort lines which start with "      XX      LDP"
            pattern = r'^\s+[0-9X]+\s+LDP'
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual MPLS table output", 
                tofile="expected MPLS table output"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed MPLS table output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "MPLS table output for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


def test_linux_mpls_routes():
    global fatal_error
    global net

   # Skip if previous fatal error condition is raised
    if (fatal_error != ""):
        pytest.skip(fatal_error)

    thisDir = os.path.dirname(os.path.realpath(__file__))

    # Verify OSPFv3 Routing Table
    print("\n\n** Verifing Linux Kernel MPLS routes")
    print("******************************************\n")
    failures = 0
    for i in range(1, 5):
        refTableFile = '%s/r%s/ip_mpls_route.ref' % (thisDir, i)
        if os.path.isfile(refTableFile):
            # Read expected result from file
            expected = open(refTableFile).read().rstrip()
            # Fix newlines (make them all the same)
            expected = ('\n'.join(expected.splitlines()) + '\n').splitlines(1)

            # Actual output from router
            actual = net['r%s' % i].cmd('ip -family mpls route 2> /dev/null').rstrip()
             # Mask out label
            actual = re.sub(r"[0-9][0-9] via inet ", "xx via inet ", actual)
            actual = re.sub(r"[0-9][0-9]  proto zebra", "xx  proto zebra", actual)
            actual = re.sub(r"[0-9][0-9] as to ", "xx as to ", actual)
            actual = re.sub(r"proto zebra ", "proto zebra", actual)
 
            # Fix newlines (make them all the same)
            actual = ('\n'.join(actual.splitlines()) + '\n').splitlines(1)

            # Sort lines which start with "xx via inet "
            pattern = r'^xx via inet '
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Sort lines which start with "        nexthopvia"
            pattern = r'^\snexthopvia '
            swapped = True
            while swapped:
                swapped = False
                for j in range(1, len(actual)):
                    if re.search(pattern, actual[j]) and re.search(pattern, actual[j-1]):
                        if actual[j-1] > actual[j]:
                            temp = actual[j-1]
                            actual[j-1] = actual[j]
                            actual[j] = temp
                            swapped = True

            # Sort Sections of "xx  proto zebra" (with all the indented lines below)
            pattern = r'^xx via inet '
            # Join paragraphs first
            j = 0           
            temp = [actual[0].rstrip()]
            for k in range(1, len(actual)):
                if re.search(r'^\s', actual[k]):
                    # Continue line
                    temp[j] += '\n' + actual[k].rstrip()
                else:
                    j += 1
                    temp.append(actual[k].rstrip())
            # sort Array
            temp.sort()
            # Now write sort array back
            actual = []
            for k in range(0, len(temp)):
                actual.extend(temp[k].splitlines())
            # put \n back at line ends
            actual = ('\n'.join(actual) + '\n').splitlines(1)

            # Generate Diff
            diff = ''.join(difflib.context_diff(actual, expected, 
                fromfile="actual Linux Kernel MPLS route", 
                tofile="expected Linux Kernel MPLS route"))

            # Empty string if it matches, otherwise diff contains unified diff
            if diff:
                sys.stderr.write('r%s failed Linux Kernel MPLS route output Check:\n%s\n' % (i, diff))
                failures += 1
            else:
                print("r%s ok" % i)

            assert failures == 0, "Linux Kernel MPLS route output for router r%s:\n%s" % (i, diff)

    # For debugging after starting FRR/Quagga daemons, uncomment the next line
    # CLI(net)


if __name__ == '__main__':

    setLogLevel('info')
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
