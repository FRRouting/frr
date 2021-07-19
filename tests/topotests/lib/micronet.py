# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 9 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; see the file COPYING; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
#
import logging
import re
import shlex
import subprocess
import sys

logger = logging.getLogger(__name__)


def shell_quote(command):
    """Return command wrapped in single quotes."""
    if sys.version_info[0] >= 3:
        return shlex.quote(command)
    return "'{}'".format(command.replace("'", "'\"'\"'"))  # type: ignore


class Commander(object):  # pylint: disable=R0205
    """
    Commander.

    An object that can execute commands.
    """

    def __init__(self, name):
        """Create a Commander."""
        self.name = name
        self.pre_cmd = []
        self.pre_cmd_str = ""
        self.cwd = self.cmd("pwd").strip()

    def set_pre_cmd(self, pre_cmd=None):
        if not pre_cmd:
            self.pre_cmd = []
            self.pre_cmd_str = ""
        else:
            self.pre_cmd = pre_cmd
            self.pre_cmd_str = " ".join(self.pre_cmd) + " "

    @staticmethod
    def is_string(value):
        """Return True if value is a string."""
        try:
            return isinstance(value, basestring)  # type: ignore
        except NameError:
            return isinstance(value, str)

    def __str__(self):
        return "Commander({})".format(self.name)

    def _get_cmd_str(self, cmd):
        if LinuxNamespace.is_string(cmd):
            return self.pre_cmd_str + cmd
        cmd = self.pre_cmd + cmd
        return " ".join(cmd)

    def _get_sub_args(self, cmd, defaults, **kwargs):
        if LinuxNamespace.is_string(cmd):
            defaults["shell"] = True
            pre_cmd = self.pre_cmd_str
        else:
            defaults["shell"] = False
            pre_cmd = self.pre_cmd
        defaults.update(kwargs)
        return pre_cmd, cmd, defaults

    def _popen(self, method, cmd, **kwargs):
        if sys.version_info[0] >= 3:
            defaults = {
                "encoding": "utf-8",
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
        else:
            defaults = {
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
        pre_cmd, cmd, defaults = self._get_sub_args(cmd, defaults, **kwargs)

        logger.debug('%s: %s("%s", kwargs: %s)', self, method, cmd, defaults)
        return subprocess.Popen(pre_cmd + cmd, **defaults)

    def set_cwd(self, cwd):
        logger.warning("%s: 'cd' (%s) does not work outside namespaces", self, cwd)
        self.cwd = cwd

    def popen(self, cmd, **kwargs):
        """Create a Popen object."""
        return self._popen("popen", cmd, **kwargs)

    def cmd_status(self, cmd, **kwargs):
        """Execute a command."""

        # We not a shell like mininet, so we need to intercept this
        # XXX we can drop this when the code stops assuming it works
        chdir = False
        m = re.match(r"cd(\s*|\s+(\S+))$", cmd)
        if m and m.group(2):
            assert LinuxNamespace.is_string(cmd)
            chdir = True
            cmd += " && pwd"
        cmd = "bash -c {}".format(shell_quote(cmd))

        p = self._popen("cmd", cmd, **kwargs)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            cmd_str = self._get_cmd_str(cmd)
            logger.warning(
                '%s: cmd("%s"): Failed: %d%s%s:',
                self,
                cmd_str,
                rc,
                '\n:stdout: "{}"'.format(stdout) if stdout else "",
                '\n:stderr: "{}"'.format(stderr) if stderr else "",
            )
        elif chdir:
            self.set_cwd(stdout.strip())

        return rc, stdout, stderr

    def cmd(self, cmd, **kwargs):
        """Execute a command."""

        _, stdout, _ = self.cmd_status(cmd, **kwargs)
        return stdout

    def delete(self):
        pass


class LinuxNamespace(Commander):
    """
    A linux Namespace.

    An object that creates and executes commands in a linux namespace
    """

    def __init__(
        self,
        name,
        net=True,
        mount=True,
        uts=True,
        cgroup=False,
        ipc=False,
        pid=False,
        time=False,
        user=False,
        set_hostname=True,
        private_mounts=None,
    ):
        """
        Create a new linux namespace.

        Paramaters
        ----------
        * `name` :: internal name for the namespace
        * `net` :: create network namespace
        * `mount` :: create network namespace
        * `uts` :: create UTS (hostname) namespace
        * `cgroup` :: create cgroup namespace
        * `ipc` :: create IPC namespace
        * `pid` :: create PID namespace, also mounts new /proc
        * `time` :: create time namespace
        * `user` :: create user namespace, also keeps capabilities
        * `set_hostname` :: set the hostname to `name`, uts must also be True.
        * `private_mounts` :: list of strings of the form "[/external/path:]/internal/path. If no
                              external path is specified a tmpfs is mounted on the internal path.
                              Any paths specified are first passed to `mkdir -p`.
        """
        super(LinuxNamespace, self).__init__(name)

        logger.debug("%s: Creating", self)

        cmd = ["/usr/bin/unshare"]
        flags = "-"

        if cgroup:
            flags += "C"
        if ipc:
            flags += "i"
        if mount:
            flags += "m"
        if net:
            flags += "n"
        if pid:
            flags += "p"
            cmd.append("--mount-proc")
        if time:
            flags += "T"
        if user:
            flags += "U"
            cmd.append("--keep-caps")
        if uts:
            flags += "u"

        cmd.append(flags)
        cmd.append("/bin/cat")

        # Using cat and a stdin PIPE is nice as it will exit when we do.
        logger.debug("Creating namespace process: %s", cmd)
        self.p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=open("/dev/null", "w"),
            stderr=open("/dev/null", "w"),
            shell=False,
        )
        self.pid = self.p.pid

        self.intfs = []

        # Set pre-command based on our namespace proc
        self.set_pre_cmd(
            ["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + self.cwd]
        )

        # Set the hostname to the namespace name
        if uts and set_hostname:
            self.cmd("hostname " + self.name)

        # Remount /sys to pickup any changes
        self.cmd("mount -t sysfs none /sys")

        if private_mounts:
            if LinuxNamespace.is_string(private_mounts):
                private_mounts = [private_mounts]
            for m in private_mounts:
                s = m.split(":", 1)
                e, i = s if len(s) != 1 else (None, s[0])
                self.cmd("mkdir -p " + i)
                if not e:
                    self.cmd("mount -n -t tmpfs tmpfs " + i)
                else:
                    self.cmd("mkdir -p " + e)
                    self.cmd("mount --bind {} {} ".format(e, i))

        # Doing this here messes up all_protocols ipv6 check
        self.cmd("ip link set lo up")

    def __str__(self):
        return "LinuxNamespace({})".format(self.name)

    def set_cwd(self, cwd):
        # Set pre-command based on our namespace proc
        logger.debug("%s: new CWD %s", self, cwd)
        self.set_pre_cmd(["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + cwd])

    def get_uniq_name(self, ifname):  # pylint: disable=R0201
        return ifname

    def register_interface(self, ifname):
        if ifname not in self.intfs:
            self.intfs.append(ifname)

    def delete(self):
        if self.p:
            if sys.version_info[0] >= 3:
                try:
                    self.p.terminate()
                    self.p.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    self.p.kill()
                    self.p.communicate(timeout=2)
            else:
                self.p.kill()
                self.p.communicate()


class SharedNamespace(Commander):
    """
    Share another namespace.

    An object that executes commands in an existing pid's linux namespace
    """

    def __init__(self, name, pid):
        """
        Share a linux namespace.

        Paramaters
        ----------
        * `name` :: internal name for the namespace
        * `pid` :: pid of the process to share with
        """
        super(SharedNamespace, self).__init__(name)

        logger.debug("%s: Creating", self)

        self.pid = pid
        self.intfs = []

        # Set pre-command based on our namespace proc
        self.set_pre_cmd(
            ["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + self.cwd]
        )

    def __str__(self):
        return "SharedNamespace({})".format(self.name)

    def set_cwd(self, cwd):
        # Set pre-command based on our namespace proc
        logger.debug("%s: new CWD %s", self, cwd)
        self.set_pre_cmd(["/usr/bin/nsenter", "-a", "-t", str(self.pid), "--wd=" + cwd])

    def register_interface(self, ifname):
        if ifname not in self.intfs:
            self.intfs.append(ifname)


class Bridge(SharedNamespace):
    """
    A linux bridge.
    """

    next_brid_ord = 0

    @classmethod
    def _get_next_brid(cls):
        brid_ord = cls.next_brid_ord
        cls.next_brid_ord += 1
        return brid_ord

    def __init__(self, name=None, unet=None):
        """Create a linux Bridge."""
        logger.debug("Bridge: Creating")

        self.brid_ord = self._get_next_brid()
        if name:
            self.brid = name
        else:
            self.brid = "br{}".format(self.brid_ord)
            name = self.brid

        super(Bridge, self).__init__(name, unet.pid)

        assert len(self.brid) <= 16  # Make sure fits in IFNAMSIZE
        self.cmd("ip link delete {} || true".format(self.brid))
        self.cmd("ip link add {} type bridge".format(self.brid))
        self.cmd("ip link set {} up".format(self.brid))

        logger.debug("%s: Created, Running", self)

    def __str__(self):
        return "Bridge({})".format(self.brid)

    def delete(self):
        """Stop the bridge (i.e., delete the linux resources)."""

        self.cmd("ip link delete {}".format(self.brid))

        logger.debug("%s: Deleted.", self)


class Micronet(LinuxNamespace):  # pylint: disable=R0205
    """
    Micronet.
    """

    g_unet_inst = None

    def __init__(self):
        """
        Create a Micronet.
        """
        logger.debug("%s: Creating", self)

        self.hosts = {}
        self.switches = {}
        self.links = {}
        self.macs = {}
        self.rmacs = {}

        super(Micronet, self).__init__("micronet", net=True, mount=False, uts=False)

    def __str__(self):
        return "Micronet()"

    def __getitem__(self, key):
        if key in self.switches:
            return self.switches[key]
        return self.hosts[key]

    def add_host(self, name, cls=LinuxNamespace, **kwargs):
        """Add a host to micronet."""

        logger.debug("%s: add_host %s", self, name)

        self.hosts[name] = cls(name, **kwargs)

    def add_link(self, name1, name2, if1, if2):
        """Add a link between switch and host to micronet."""
        isp2p = False
        if name1 in self.switches:
            assert name2 in self.hosts
        elif name2 in self.switches:
            assert name1 in self.hosts
            name1, name2 = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            isp2p = True

        lname = "{}:{}-{}:{}".format(name1, if1, name2, if2)
        logger.debug("%s: add_link %s%s", self, lname, " p2p" if isp2p else "")
        self.links[lname] = (name1, if1, name2, if2)

        # And create the veth now.
        if isp2p:
            lhost, rhost = self.hosts[name1], self.hosts[name2]
            self.cmd("ip link add {} type veth peer name {}".format(if1, if2))

            self.cmd("ip link set {} netns {}".format(if1, lhost.pid))
            lhost.cmd("ip link set {} up".format(if1))
            lhost.register_interface(if1)

            self.cmd("ip link set {} netns {}".format(if2, rhost.pid))
            rhost.cmd("ip link set {} up".format(if2))
            rhost.register_interface(if2)
        else:
            switch = self.switches[name1]
            host = self.hosts[name2]

            assert len(if1) <= 16 and len(if2) <= 16  # Make sure fits in IFNAMSIZE

            logger.debug("%s: Creating veth pair for link %s", self, lname)
            self.cmd(
                "ip link add {} type veth peer name {} netns {}".format(
                    if1, if2, host.pid
                )
            )
            switch.register_interface(if1)
            host.register_interface(if2)
            self.cmd("ip link set {} master {}".format(if1, switch.brid))
            self.cmd("ip link set {} up".format(if1))
            host.cmd("ip link set {} up".format(if2))

        # Cache the MAC values, and reverse mapping
        self.get_mac(name1, if1)
        self.get_mac(name2, if2)

    def add_switch(self, name):
        """Add a switch to micronet."""

        logger.debug("%s: add_switch %s", self, name)
        self.switches[name] = Bridge(name, self)

    def get_mac(self, name, ifname):
        if name in self.hosts:
            dev = self.hosts[name]
        else:
            dev = self.switches[name]

        if (name, ifname) not in self.macs:
            _, output, _ = dev.cmd_status("ip -o link show " + ifname)
            m = re.match(".*link/(loopback|ether) ([0-9a-fA-F:]+) .*", output)
            mac = m.group(2)
            self.macs[(name, ifname)] = mac
            self.rmacs[mac] = (name, ifname)

        return self.macs[(name, ifname)]

    def delete(self):
        """Delete the micronet topology."""

        logger.debug("%s: Deleting.", self)

        for lname, (_, _, rname, rif) in self.links.items():
            host = self.hosts[rname]

            logger.debug("%s: Deleting veth pair for link %s", self, lname)
            host.cmd("ip link delete {}".format(rif))
        self.links = {}

        for host in self.hosts.values():
            host.delete()
        self.hosts = {}

        for switch in self.switches.values():
            switch.delete()
        self.switches = {}

        logger.debug("%s: Deleted.", self)

        super(Micronet, self).delete()
