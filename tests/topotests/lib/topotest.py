#!/usr/bin/env python

#
# topotest.py
# Library of helper functions for NetDEF Topology Tests
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

import os
import re
import sys
import glob
import StringIO
import subprocess
import platform

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf

from time import sleep

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

def addRouter(topo, name):
    "Adding a FreeRangeRouter (or Quagga) to Topology"

    MyPrivateDirs = ['/etc/frr',
                         '/etc/quagga',
                         '/var/run/frr',
                         '/var/run/quagga',
                         '/var/log']
    return topo.addNode(name, cls=Router, privateDirs=MyPrivateDirs)

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

class Router(Node):
    "A Node with IPv4/IPv6 forwarding enabled and Quagga as Routing Engine"

    def config(self, **params):
        super(Router, self).config(**params)

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
        # Delete Running Quagga or FRR Daemons
        self.stopRouter()
        # rundaemons = self.cmd('ls -1 /var/run/%s/*.pid' % self.routertype)
        # for d in StringIO.StringIO(rundaemons):
        #     self.cmd('kill -7 `cat %s`' % d.rstrip())
        #     self.waitOutput()
        # Disable forwarding
        self.cmd('sysctl net.ipv4.ip_forward=0')
        self.cmd('sysctl net.ipv6.conf.all.forwarding=0')
        super(Router, self).terminate()
    def stopRouter(self):
        # Stop Running Quagga or FRR Daemons
        rundaemons = self.cmd('ls -1 /var/run/%s/*.pid' % self.routertype)
        if rundaemons is not None:
            for d in StringIO.StringIO(rundaemons):
                self.cmd('kill -7 `cat %s`' % d.rstrip())
                self.waitOutput()
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
    def startRouter(self):
        # Disable integrated-vtysh-config
        self.cmd('echo "no service integrated-vtysh-config" >> /etc/%s/vtysh.conf' % self.routertype)
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
                print("LDP Test, but no ldpd compiled or installed")
                return "LDP Test, but no ldpd compiled or installed"
            kernel_version = re.search(r'([0-9]+\.[0-9]+).*', platform.release())
            if kernel_version:
                if float(kernel_version.group(1)) < 4.5:
                    print("LDP Test need Linux Kernel 4.5 minimum")
                    return "LDP Test need Linux Kernel 4.5 minimum"
        # Add mpls modules to kernel if we use LDP
        if self.daemons['ldpd'] == 1:
            self.cmd('/sbin/modprobe mpls-router')
            self.cmd('/sbin/modprobe mpls-iptunnel')
            self.cmd('echo 100000 > /proc/sys/net/mpls/platform_labels')
        # Init done - now restarting daemons
        self.restartRouter()
        return ""
    def restartRouter(self):
        # Starts actuall daemons without init (ie restart)
        # Start Zebra first
        if self.daemons['zebra'] == 1:
#            self.cmd('/usr/lib/%s/zebra -d' % self.routertype)
            self.cmd('/usr/lib/%s/zebra > /tmp/%s-zebra.out 2> /tmp/%s-zebra.err &' % (self.routertype, self.name, self.name))
            self.waitOutput()
            print('%s: %s zebra started' % (self, self.routertype))
            sleep(1)
        # Fix Link-Local Addresses
        # Somehow (on Mininet only), Zebra removes the IPv6 Link-Local addresses on start. Fix this
        self.cmd('for i in `ls /sys/class/net/` ; do mac=`cat /sys/class/net/$i/address`; IFS=\':\'; set $mac; unset IFS; ip address add dev $i scope link fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64; done')
        # Now start all the other daemons
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1) and (daemon != 'zebra'):
#                self.cmd('/usr/lib/%s/%s -d' % (self.routertype, daemon))
                self.cmd('/usr/lib/%s/%s > /tmp/%s-%s.out 2> /tmp/%s-%s.err &' % (self.routertype, daemon, self.name, daemon, self.name, daemon))
                self.waitOutput()
                print('%s: %s %s started' % (self, self.routertype, daemon))
    def getStdErr(self, daemon):
        return self.getLog('err', daemon)
    def getStdOut(self, daemon):
        return self.getLog('out', daemon)
    def getLog(self, log, daemon):
        return self.cmd('cat /tmp/%s-%s.%s' % (self.name, daemon, log) )
    def checkRouterRunning(self):
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

                return "%s: Daemon %s not running" % (self.name, daemon)
        return ""
    def get_ipv6_linklocal(self):
        "Get LinkLocal Addresses from interfaces"

        linklocal = []

        ifaces = self.cmd('ip -6 address')
        # Fix newlines (make them all the same)
        ifaces = ('\n'.join(ifaces.splitlines()) + '\n').splitlines()
        interface=""
        ll_per_if_count=0
        for line in ifaces:
            m = re.search('[0-9]+: ([^:@]+)[@if0-9:]+ <', line)
            if m:
                interface = m.group(1)
                ll_per_if_count = 0
            m = re.search('inet6 (fe80::[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+)[/0-9]* scope link', line)
            if m:
                local = m.group(1)
                ll_per_if_count += 1
                if (ll_per_if_count > 1):
                    linklocal += [["%s-%s" % (interface, ll_per_if_count), local]]
                else:
                    linklocal += [[interface, local]]
        return linklocal

class LegacySwitch(OVSSwitch):
    "A Legacy Switch without OpenFlow"

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, failMode='standalone', **params)
        self.switchIP = None

