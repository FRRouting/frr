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
import tempfile
import platform
import difflib

from lib.topolog import logger

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch, Host
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import Intf

from time import sleep

class json_cmp_result(object):
    "json_cmp result class for better assertion messages"

    def __init__(self):
        self.errors = []

    def add_error(self, error):
        "Append error message to the result"
        self.errors.append(error)

    def has_errors(self):
        "Returns True if there were errors, otherwise False."
        return len(self.errors) > 0


def json_cmp(d1, d2, reason=False):
    """
    JSON compare function. Receives two parameters:
    * `d1`: json value
    * `d2`: json subset which we expect

    Returns `None` when all keys that `d1` has matches `d2`,
    otherwise a string containing what failed.

    Note: key absence can be tested by adding a key with value `None`.
    """
    squeue = [(d1, d2, 'json')]
    result = json_cmp_result()
    for s in squeue:
        nd1, nd2, parent = s
        s1, s2 = set(nd1), set(nd2)

        # Expect all required fields to exist.
        s2_req = set([key for key in nd2 if nd2[key] is not None])
        diff = s2_req - s1
        if diff != set({}):
            result.add_error('expected key(s) {} in {} (have {})'.format(
                str(list(diff)), parent, str(list(s1))))

        for key in s2.intersection(s1):
            # Test for non existence of key in d2
            if nd2[key] is None:
                result.add_error('"{}" should not exist in {} (have {})'.format(
                    key, parent, str(s1)))
                continue
            # If nd1 key is a dict, we have to recurse in it later.
            if isinstance(nd2[key], type({})):
                if not isinstance(nd1[key], type({})):
                    result.add_error(
                        '{}["{}"] has different type than expected '.format(parent, key) +
                        '(have {}, expected {})'.format(type(nd1[key]), type(nd2[key])))
                    continue
                nparent = '{}["{}"]'.format(parent, key)
                squeue.append((nd1[key], nd2[key], nparent))
                continue
            # Check list items
            if isinstance(nd2[key], type([])):
                if not isinstance(nd1[key], type([])):
                    result.add_error(
                        '{}["{}"] has different type than expected '.format(parent, key) +
                        '(have {}, expected {})'.format(type(nd1[key]), type(nd2[key])))
                    continue
                # Check list size
                if len(nd2[key]) > len(nd1[key]):
                    result.add_error(
                        '{}["{}"] too few items '.format(parent, key) +
                        '(have ({}) "{}", expected ({}) "{}")'.format(
                            len(nd1[key]), str(nd1[key]), len(nd2[key]), str(nd2[key])))
                    continue

                # List all unmatched items errors
                unmatched = []
                for expected in nd2[key]:
                    matched = False
                    for value in nd1[key]:
                        if json_cmp({'json': value}, {'json': expected}) is None:
                            matched = True
                            break

                    if matched:
                        break
                    if not matched:
                        unmatched.append(expected)

                # If there are unmatched items, error out.
                if unmatched:
                    result.add_error(
                        '{}["{}"] value is different (have "{}", expected "{}")'.format(
                            parent, key, str(nd1[key]), str(nd2[key])))
                continue

            # Compare JSON values
            if nd1[key] != nd2[key]:
                result.add_error(
                    '{}["{}"] value is different (have "{}", expected "{}")'.format(
                        parent, key, str(nd1[key]), str(nd2[key])))
                continue

    if result.has_errors():
        return result

    return None

def run_and_expect(func, what, count=20, wait=3):
    """
    Run `func` and compare the result with `what`. Do it for `count` times
    waiting `wait` seconds between tries. By default it tries 20 times with
    3 seconds delay between tries.

    Returns (True, func-return) on success or
    (False, func-return) on failure.
    """
    while count > 0:
        result = func()
        if result != what:
            sleep(wait)
            count -= 1
            continue
        return (True, result)
    return (False, result)


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

def difflines(text1, text2, title1='', title2=''):
    "Wrapper for get_textdiff to avoid string transformations."
    text1 = ('\n'.join(text1.rstrip().splitlines()) + '\n').splitlines(1)
    text2 = ('\n'.join(text2.rstrip().splitlines()) + '\n').splitlines(1)
    return get_textdiff(text1, text2, title1, title2)

def get_file(content):
    """
    Generates a temporary file in '/tmp' with `content` and returns the file name.
    """
    fde = tempfile.NamedTemporaryFile(mode='w', delete=False)
    fname = fde.name
    fde.write(content)
    fde.close()
    return fname

def normalize_text(text):
    """
    Strips formating spaces/tabs and carriage returns.
    """
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\r', '', text)
    return text

def version_cmp(v1, v2):
    """
    Compare two version strings and returns:

    * `-1`: if `v1` is less than `v2`
    * `0`: if `v1` is equal to `v2`
    * `1`: if `v1` is greater than `v2`

    Raises `ValueError` if versions are not well formated.
    """
    vregex = r'(?P<whole>\d+(\.(\d+))*)'
    v1m = re.match(vregex, v1)
    v2m = re.match(vregex, v2)
    if v1m is None or v2m is None:
        raise ValueError("got a invalid version string")

    # Split values
    v1g = v1m.group('whole').split('.')
    v2g = v2m.group('whole').split('.')

    # Get the longest version string
    vnum = len(v1g)
    if len(v2g) > vnum:
        vnum = len(v2g)

    # Reverse list because we are going to pop the tail
    v1g.reverse()
    v2g.reverse()
    for _ in range(vnum):
        try:
            v1n = int(v1g.pop())
        except IndexError:
            while v2g:
                v2n = int(v2g.pop())
                if v2n > 0:
                    return -1
            break

        try:
            v2n = int(v2g.pop())
        except IndexError:
            if v1n > 0:
                return 1
            while v1g:
                v1n = int(v1g.pop())
                if v1n > 0:
                    return -1
            break

        if v1n > v2n:
            return 1
        if v1n < v2n:
            return -1
    return 0

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

    def __init__(self, name, **params):
        super(Router, self).__init__(name, **params)
        self.logdir = params.get('logdir', '/tmp')
        self.daemondir = None
        self.routertype = 'frr'
        self.daemons = {'zebra': 0, 'ripd': 0, 'ripngd': 0, 'ospfd': 0,
                        'ospf6d': 0, 'isisd': 0, 'bgpd': 0, 'pimd': 0,
                        'ldpd': 0}

    def _config_frr(self, **params):
        "Configure FRR binaries"
        self.daemondir = params.get('frrdir')
        if self.daemondir is None:
            self.daemondir = '/usr/lib/frr'

        zebra_path = os.path.join(self.daemondir, 'zebra')
        if not os.path.isfile(zebra_path):
            raise Exception("FRR zebra binary doesn't exist at {}".format(zebra_path))

    def _config_quagga(self, **params):
        "Configure Quagga binaries"
        self.daemondir = params.get('quaggadir')
        if self.daemondir is None:
            self.daemondir = '/usr/lib/quagga'

        zebra_path = os.path.join(self.daemondir, 'zebra')
        if not os.path.isfile(zebra_path):
            raise Exception("Quagga zebra binary doesn't exist at {}".format(zebra_path))

    # pylint: disable=W0221
    # Some params are only meaningful for the parent class.
    def config(self, **params):
        super(Router, self).config(**params)

        # User did not specify the daemons directory, try to autodetect it.
        self.daemondir = params.get('daemondir')
        if self.daemondir is None:
            self.routertype = params.get('routertype', 'frr')
            if self.routertype == 'quagga':
                self._config_quagga(**params)
            else:
                self._config_frr(**params)
        else:
            # Test the provided path
            zpath = os.path.join(self.daemondir, 'zebra')
            if not os.path.isfile(zpath):
                raise Exception('No zebra binary found in {}'.format(zpath))
            # Allow user to specify routertype when the path was specified.
            if params.get('routertype') is not None:
                self.routertype = self.params.get('routertype')

        # Enable forwarding on the router
        assert_sysctl(self, 'net.ipv4.ip_forward', 1)
        assert_sysctl(self, 'net.ipv6.conf.all.forwarding', 1)
        # Enable coredumps
        assert_sysctl(self, 'kernel.core_uses_pid', 1)
        assert_sysctl(self, 'fs.suid_dumpable', 2)
        corefile = '{}/{}_%e_core-sig_%s-pid_%p.dmp'.format(self.logdir, self.name)
        assert_sysctl(self, 'kernel.core_pattern', corefile)
        self.cmd('ulimit -c unlimited')
        # Set ownership of config files
        self.cmd('chown {0}:{0}vty /etc/{0}'.format(self.routertype))

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
            logger.warning('No daemon {} known'.format(daemon))
        # print "Daemons after:", self.daemons
    def startRouter(self):
        # Disable integrated-vtysh-config
        self.cmd('echo "no service integrated-vtysh-config" >> /etc/%s/vtysh.conf' % self.routertype)
        self.cmd('chown %s:%svty /etc/%s/vtysh.conf' % (self.routertype, self.routertype, self.routertype))
        # TODO remove the following lines after all tests are migrated to Topogen.
        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob("/tmp/*%s*.log" % self.name))
        # Remove old core files
        map(os.remove, glob.glob("/tmp/%s*.dmp" % self.name))
        # Remove IP addresses from OS first - we have them in zebra.conf
        self.removeIPs()
        # If ldp is used, check for LDP to be compiled and Linux Kernel to be 4.5 or higher
        # No error - but return message and skip all the tests
        if self.daemons['ldpd'] == 1:
            ldpd_path = os.path.join(self.daemondir, 'ldpd')
            if not os.path.isfile(ldpd_path):
                logger.warning("LDP Test, but no ldpd compiled or installed")
                return "LDP Test, but no ldpd compiled or installed"
            kernel_version = re.search(r'([0-9]+)\.([0-9]+).*', platform.release())

            if kernel_version:
                if (float(kernel_version.group(1)) < 4 or
                   (float(kernel_version.group(1)) == 4 and float(kernel_version.group(2)) < 5)):
                    logger.warning("LDP Test need Linux Kernel 4.5 minimum")
                    return "LDP Test need Linux Kernel 4.5 minimum"

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
            zebra_path = os.path.join(self.daemondir, 'zebra')
            self.cmd('{0} > {1}/{2}-zebra.out 2> {1}/{2}-zebra.err &'.format(
                zebra_path, self.logdir, self.name
            ))
            self.waitOutput()
            logger.debug('{}: {} zebra started'.format(self, self.routertype))
            sleep(1)
        # Fix Link-Local Addresses
        # Somehow (on Mininet only), Zebra removes the IPv6 Link-Local addresses on start. Fix this
        self.cmd('for i in `ls /sys/class/net/` ; do mac=`cat /sys/class/net/$i/address`; IFS=\':\'; set $mac; unset IFS; ip address add dev $i scope link fe80::$(printf %02x $((0x$1 ^ 2)))$2:${3}ff:fe$4:$5$6/64; done')
        # Now start all the other daemons
        for daemon in self.daemons:
            # Skip disabled daemons and zebra
            if self.daemons[daemon] == 0 or daemon == 'zebra':
                continue

            daemon_path = os.path.join(self.daemondir, daemon)
            self.cmd('{0} > {1}/{2}-{3}.out 2> {1}/{2}-{3}.err &'.format(
                daemon_path, self.logdir, self.name, daemon
            ))
            self.waitOutput()
            logger.debug('{}: {} {} started'.format(self, self.routertype, daemon))
    def getStdErr(self, daemon):
        return self.getLog('err', daemon)
    def getStdOut(self, daemon):
        return self.getLog('out', daemon)
    def getLog(self, log, daemon):
        return self.cmd('cat {}/{}-{}.{}'.format(self.logdir, self.name, daemon, log))
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
                corefiles = glob.glob('{}/{}_{}_core*.dmp'.format(
                    self.logdir, self.name, daemon))
                if (len(corefiles) > 0):
                    daemon_path = os.path.join(self.daemondir, daemon)
                    backtrace = subprocess.check_output([
                        "gdb {} {} --batch -ex bt 2> /dev/null".format(daemon_path, corefiles[0])
                    ], shell=True)
                    sys.stderr.write("\n%s: %s crashed. Core file found - Backtrace follows:\n" % (self.name, daemon))
                    sys.stderr.write("%s\n" % backtrace)
                else:
                    # No core found - If we find matching logfile in /tmp, then print last 20 lines from it.
                    if os.path.isfile('{}/{}-{}.log'.format(self.logdir, self.name, daemon)):
                        log_tail = subprocess.check_output([
                            "tail -n20 {}/{}-{}.log 2> /dev/null".format(
                                self.logdir, self.name, daemon)
                            ], shell=True)
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

        daemon_path = os.path.join(self.daemondir, daemon)
        if not os.path.isfile(daemon_path):
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
                    logger.info('\nRouter {} {} StdErr Log:\n{}'.format(
                        self.name, daemon, log))
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
