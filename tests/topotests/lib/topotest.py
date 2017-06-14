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
import errno
import re
import sys
import glob
import StringIO
import subprocess
import platform
import difflib

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

def pid_exists(pid):
    "Check whether pid exists in the current process table."

    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError as err:
        if err.errno == errno.ESRCH:
            # ESRCH == No such process
            return False
        elif err.errno == errno.EPERM:
            # EPERM clearly means there's a process to deny access to
            return True
        else:
            # According to "man 2 kill" possible error values are
            # (EINVAL, EPERM, ESRCH)
            raise
    else:
        return True

def get_textdiff(text1, text2, title1="", title2=""):
    "Returns empty string if same or formatted diff"

    diff = '\n'.join(difflib.context_diff(text1, text2,
           fromfile=title1, tofile=title2))
    # Clean up line endings
    diff = os.linesep.join([s for s in diff.splitlines() if s])
    return diff

def checkAddressSanitizerError(output, router, component):
    "Checks for AddressSanitizer in output. If found, then logs it and returns true, false otherwise"

    addressSantizerError = re.search('(==[0-9]+==)ERROR: AddressSanitizer: ([^\s]*) ', output)
    if addressSantizerError:
        sys.stderr.write("%s: %s triggered an exception by AddressSanitizer\n" % (router, component))
        # Sanitizer Error found in log
        pidMark = addressSantizerError.group(1)
        addressSantizerLog = re.search('%s(.*)%s' % (pidMark, pidMark), output, re.DOTALL)
        if addressSantizerLog:
            callingTest = os.path.basename(sys._current_frames().values()[0].f_back.f_back.f_globals['__file__'])
            callingProc = sys._getframe(2).f_code.co_name
            with open("/tmp/AddressSanitzer.txt", "a") as addrSanFile:
                sys.stderr.write('\n'.join(addressSantizerLog.group(1).splitlines()) + '\n')
                addrSanFile.write("## Error: %s\n\n" % addressSantizerError.group(2))
                addrSanFile.write("### AddressSanitizer error in topotest `%s`, test `%s`, router `%s`\n\n" % (callingTest, callingProc, router))
                addrSanFile.write('    '+ '\n    '.join(addressSantizerLog.group(1).splitlines()) + '\n')
                addrSanFile.write("\n---------------\n")
        return True
    return False   

def addRouter(topo, name):
    "Adding a FRRouter (or Quagga) to Topology"

    MyPrivateDirs = ['/etc/frr',
                         '/etc/quagga',
                         '/var/run/frr',
                         '/var/run/quagga',
                         '/var/log']
    return topo.addNode(name, cls=Router, privateDirs=MyPrivateDirs)

def set_sysctl(node, sysctl, value):
    "Set a sysctl value and return None on success or an error string"
    valuestr = '{}'.format(value)
    command = "sysctl {0}={1}".format(sysctl, valuestr)
    cmdret = node.cmd(command)

    matches = re.search(r'([^ ]+) = ([^\s]+)', cmdret)
    if matches is None:
        return cmdret
    if matches.group(1) != sysctl:
        return cmdret
    if matches.group(2) != valuestr:
        return cmdret

    return None

def assert_sysctl(node, sysctl, value):
    "Set and assert that the sysctl is set with the specified value."
    assert set_sysctl(node, sysctl, value) is None

class LinuxRouter(Node):
    "A Node with IPv4/IPv6 forwarding enabled."

    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable forwarding on the router
        assert_sysctl(self, 'net.ipv4.ip_forward', 1)
        assert_sysctl(self, 'net.ipv6.conf.all.forwarding', 1)
    def terminate(self):
        """
        Terminate generic LinuxRouter Mininet instance
        """
        set_sysctl(self, 'net.ipv4.ip_forward', 0)
        set_sysctl(self, 'net.ipv6.conf.all.forwarding', 0)
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
        assert_sysctl(self, 'net.ipv4.ip_forward', 1)
        assert_sysctl(self, 'net.ipv6.conf.all.forwarding', 1)
        # Enable coredumps
        assert_sysctl(self, 'kernel.core_uses_pid', 1)
        assert_sysctl(self, 'fs.suid_dumpable', 2)
        corefile = '/tmp/{0}_%e_core-sig_%s-pid_%p.dmp'.format(self.name)
        assert_sysctl(self, 'kernel.core_pattern', corefile)
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
        set_sysctl(self, 'net.ipv4.ip_forward', 0)
        set_sysctl(self, 'net.ipv6.conf.all.forwarding', 0)
        super(Router, self).terminate()
    def stopRouter(self):
        # Stop Running Quagga or FRR Daemons
        rundaemons = self.cmd('ls -1 /var/run/%s/*.pid' % self.routertype)
        if rundaemons is not None:
            for d in StringIO.StringIO(rundaemons):
                daemonpid = self.cmd('cat %s' % d.rstrip()).rstrip()
                if (daemonpid.isdigit() and pid_exists(int(daemonpid))):
                    self.cmd('kill -7 %s' % daemonpid)
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
            kernel_version = re.search(r'([0-9]+)\.([0-9]+).*', platform.release())

            if kernel_version:
                if (float(kernel_version.group(1)) < 4 or
                   (float(kernel_version.group(1)) == 4 and float(kernel_version.group(2)) < 5)):
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
        "Check if router daemons are running and collect crashinfo they don't run"

        global fatal_error

        daemonsRunning = self.cmd('vtysh -c "show log" | grep "Logging configuration for"')
        # Look for AddressSanitizer Errors in vtysh output and append to /tmp/AddressSanitzer.txt if found
        if checkAddressSanitizerError(daemonsRunning, self.name, "vtysh"):
            return "%s: vtysh killed by AddressSanitizer" % (self.name)

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

                # Look for AddressSanitizer Errors and append to /tmp/AddressSanitzer.txt if found
                if checkAddressSanitizerError(self.getStdErr(daemon), self.name, daemon):
                    return "%s: Daemon %s not running - killed by AddressSanitizer" % (self.name, daemon)

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
    def daemon_available(self, daemon):
        "Check if specified daemon is installed (and for ldp if kernel supports MPLS)"

        if not os.path.isfile('/usr/lib/%s/%s' % (self.routertype, daemon)):
            return False
        if (daemon == 'ldpd'):
            kernel_version = re.search(r'([0-9]+)\.([0-9]+).*', platform.release())
            if kernel_version:
                if (float(kernel_version.group(1)) < 4 or
                   (float(kernel_version.group(1)) == 4 and float(kernel_version.group(2)) < 5)):
                    return False
            else:
                return False
        return True
    def get_routertype(self):
        "Return the type of Router (frr or quagga)"

        return self.routertype
    def report_memory_leaks(self, filename_prefix, testscript):
        "Report Memory Leaks to file prefixed with given string"

        leakfound = False
        filename = filename_prefix + re.sub(r"\.py", "", testscript) + ".txt"
        for daemon in self.daemons:
            if (self.daemons[daemon] == 1):
                log = self.getStdErr(daemon)
                if "memstats" in log:
                    # Found memory leak
                    print("\nRouter %s %s StdErr Log:\n%s" % (self.name, daemon, log))        
                    if not leakfound:
                        leakfound = True
                        # Check if file already exists
                        fileexists = os.path.isfile(filename)
                        leakfile = open(filename, "a")
                        if not fileexists:
                            # New file - add header
                            leakfile.write("# Memory Leak Detection for topotest %s\n\n" % testscript)
                        leakfile.write("## Router %s\n" % self.name)
                    leakfile.write("### Process %s\n" % daemon)
                    log = re.sub("core_handler: ", "", log)
                    log = re.sub(r"(showing active allocations in memory group [a-zA-Z0-9]+)", r"\n#### \1\n", log)
                    log = re.sub("memstats:  ", "    ", log)
                    leakfile.write(log)
                    leakfile.write("\n")
        if leakfound:
            leakfile.close()


class LegacySwitch(OVSSwitch):
    "A Legacy Switch without OpenFlow"

    def __init__(self, name, **params):
        OVSSwitch.__init__(self, name, failMode='standalone', **params)
        self.switchIP = None

