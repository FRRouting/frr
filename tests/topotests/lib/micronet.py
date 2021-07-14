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
import datetime
import logging
import os
import pdb
import re
import readline
import shlex
import subprocess
import sys
import time as time_mod
import traceback

root_hostname = subprocess.check_output("hostname")


class Timeout(object):
    def __init__(self, delta):
        self.expires_on = datetime.datetime.now()
        self.expires_on += datetime.timedelta(seconds=delta)

    def is_expired(self):
        return datetime.datetime.now() > self.expires_on


def is_string(value):
    """Return True if value is a string."""
    try:
        return isinstance(value, basestring)  # type: ignore
    except NameError:
        return isinstance(value, str)


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

    def __init__(self, name, logger=None):
        """Create a Commander."""
        self.name = name
        self.last = None
        self.exec_paths = {}
        self.pre_cmd = []
        self.pre_cmd_str = ""

        if not logger:
            self.logger = logging.getLogger(__name__ + ".commander." + name)
        else:
            self.logger = logger

        self.cwd = self.cmd_raises("pwd").strip()

    def set_logger(self, logfile):
        self.logger = logging.getLogger(__name__ + ".commander." + self.name)
        if is_string(logfile):
            handler = logging.FileHandler(logfile, mode="w")
        else:
            handler = logging.StreamHandler(logfile)

        fmtstr = "%(asctime)s.%(msecs)03d %(levelname)s: {}({}): %(message)s".format(
            self.__class__.__name__, self.name
        )
        handler.setFormatter(logging.Formatter(fmt=fmtstr))
        self.logger.addHandler(handler)

    def set_pre_cmd(self, pre_cmd=None):
        if not pre_cmd:
            self.pre_cmd = []
            self.pre_cmd_str = ""
        else:
            self.pre_cmd = pre_cmd
            self.pre_cmd_str = " ".join(self.pre_cmd) + " "

    def __str__(self):
        return "Commander({})".format(self.name)

    def get_exec_path(self, binary):
        """Return the full path to the binary executable.

        `binary` :: binary name or list of binary names
        """
        if is_string(binary):
            bins = [binary]
        else:
            bins = binary
        for b in bins:
            if b in self.exec_paths:
                return self.exec_paths[b]

            rc, output, _ = self.cmd_status("which " + b)
            if not rc:
                return os.path.abspath(output.strip())
            return None

    def _get_cmd_str(self, cmd):
        if is_string(cmd):
            return self.pre_cmd_str + cmd
        cmd = self.pre_cmd + cmd
        return " ".join(cmd)

    def _get_sub_args(self, cmd, defaults, **kwargs):
        if is_string(cmd):
            defaults["shell"] = True
            pre_cmd = self.pre_cmd_str
        else:
            defaults["shell"] = False
            pre_cmd = self.pre_cmd
            cmd = [str(x) for x in cmd]
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

        self.logger.debug('%s: %s("%s", kwargs: %s)', self, method, cmd, defaults)
        p = subprocess.Popen(pre_cmd + cmd, **defaults)
        return p, pre_cmd + cmd

    def set_cwd(self, cwd):
        self.logger.warning("%s: 'cd' (%s) does not work outside namespaces", self, cwd)
        self.cwd = cwd

    def popen(self, cmd, **kwargs):
        """Creates a pipe with the given `command`.

        Paramaters
        ----------
        * `command` :: `str` or `list` of command to open a pipe with.

        Also same args as python Popen. If `command` is a string then will be invoked
        with shell=True, otherwise `command` is a list and will be invoked with shell=False.

        Returns a popen object.
        """
        p, _ = self._popen("popen", cmd, **kwargs)
        return p

    def cmd_status(self, cmd, raises=False, **kwargs):
        """Execute a command."""


        # We are not a shell like mininet, so we need to intercept this
        chdir = False
        if not is_string(cmd):
            cmds = cmd
        else:
            # XXX we can drop this when the code stops assuming it works
            m = re.match(r"cd(\s*|\s+(\S+))$", cmd)
            if m and m.group(2):
                self.logger.warning(
                    "Bad call to 'cd' (chdir) emulating, use self.set_cwd():\n%s",
                    "".join(traceback.format_stack(limit=12)),
                )
                assert is_string(cmd)
                chdir = True
                cmd += " && pwd"

            # If we are going to run under bash then we don't need shell=True!
            cmds = [ "/bin/bash", "-c", cmd ]

        p, actual_cmd = self._popen("cmd_status", cmds, **kwargs)
        stdout, stderr = p.communicate()
        rc = p.wait()

        # For debugging purposes.
        self.last = (rc, actual_cmd, cmd, stdout, stderr)

        if rc:
            self.logger.warning(
                '%s: cmd("%s"): Failed: %d%s%s:',
                self,
                actual_cmd,
                rc,
                '\n:stdout: "{}"'.format(stdout.strip()) if stdout else "",
                '\n:stderr: "{}"'.format(stderr.strip()) if stderr else "",
            )
            if raises:
                error = subprocess.CalledProcessError(rc, actual_cmd)
                error.stdout, error.stderr = stdout, stderr
                raise error
        elif chdir:
            self.set_cwd(stdout.strip())

        return rc, stdout, stderr

    def cmd_legacy(self, cmd, **kwargs):
        """Execute a command with stdout and stderr joined, *IGNORES ERROR*."""

        defaults = {"stderr": subprocess.STDOUT}
        defaults.update(kwargs)
        _, stdout, _ = self.cmd_status(cmd, raises=False, **defaults)
        return stdout

    def cmd_raises(self, cmd, **kwargs):
        """Execute a command. Raise an exception on errors"""

        rc, stdout, _ = self.cmd_status(cmd, raises=True, **kwargs)
        assert rc == 0
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
        logger=None,
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
        * `logger` :: passed to superclass
        """
        super(LinuxNamespace, self).__init__(name, logger)

        self.logger.debug("%s: Creating", self)

        self.intfs = []

        nslist = []
        cmd = ["/usr/bin/unshare"]
        flags = "-"

        if cgroup:
            nslist.append("cgroup")
            flags += "C"
        if ipc:
            nslist.append("ipc")
            flags += "i"
        if mount:
            nslist.append("mnt")
            flags += "m"
        if net:
            nslist.append("net")
            flags += "n"
        if pid:
            nslist.append("pid")
            flags += "p"
            cmd.append("--mount-proc")
        if time:
            # XXX this filename is probably wrong
            nslist.append("time")
            flags += "T"
        if user:
            nslist.append("user")
            flags += "U"
            cmd.append("--keep-caps")
        if uts:
            nslist.append("uts")
            cmd.append("--uts")

        cmd.append(flags)
        cmd.append("/bin/cat")

        # Using cat and a stdin PIPE is nice as it will exit when we do.
        self.logger.debug("Creating namespace process: %s", cmd)
        p = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=open("/dev/null", "w"),
            stderr=open("/dev/null", "w"),
            shell=False,
        )
        self.p = p
        self.pid = p.pid

        self.logger.debug("Namespace pid: %d", self.pid)

        # -----------------------------------------------
        # Now let's wait until unshare completes it's job
        # -----------------------------------------------
        timeout = Timeout(4)
        while p.poll() is None and not timeout.is_expired():
            for fname in tuple(nslist):
                ours = os.readlink("/proc/self/ns/{}".format(fname))
                theirs = os.readlink("/proc/{}/ns/{}".format(self.pid, fname))
                # See if their namespace is different
                if ours != theirs:
                    nslist.remove(fname)
            if not nslist:
                break
            time_mod.sleep(0.1)
        assert p.poll() is None, "unshare unexpectedly exited!"
        assert not nslist, "unshare never unshared!"

        # Set pre-command based on our namespace proc
        self.base_pre_cmd = ["/usr/bin/nsenter", "-a", "-t", str(self.pid)]
        if not pid:
            self.base_pre_cmd.append("-F")
        self.set_pre_cmd(self.base_pre_cmd + ["--wd=" + self.cwd])


        # Hide everything else we do
        self.cmd_raises("mount --make-rprivate /")

        # Remount /sys to pickup any changes
        self.cmd_raises("mount -t sysfs sysfs /sys")

        # Set the hostname to the namespace name
        if uts and set_hostname:
            # Debugging get the root hostname
            self.cmd_raises("hostname " + self.name)
            nroot = subprocess.check_output("hostname")
            if root_hostname != nroot:
                result = self.p.poll()
                assert root_hostname == nroot, "STATE of namespace process {}".format(
                    result
                )

        if private_mounts:
            if is_string(private_mounts):
                private_mounts = [private_mounts]
            for m in private_mounts:
                s = m.split(":", 1)
                e, i = s if len(s) != 1 else (None, s[0])
                self.cmd_raises("mkdir -p " + i)
                if not e:
                    self.cmd_raises("mount -n -t tmpfs tmpfs " + i)
                else:
                    self.cmd_raises("mkdir -p " + e)
                    self.cmd_raises("mount --bind {} {} ".format(e, i))

        # Doing this here messes up all_protocols ipv6 check
        self.cmd_raises("ip link set lo up")

    def __str__(self):
        return "LinuxNamespace({})".format(self.name)

    def set_cwd(self, cwd):
        # Set pre-command based on our namespace proc
        self.logger.debug("%s: new CWD %s", self, cwd)
        self.set_pre_cmd(self.base_pre_cmd + ["--wd=" + cwd])

    # Run a command in a new window (gnome-terminal, screen, tmux, xterm)
    def run_in_window(self, cmd, title=None, forcex=False):
        nscmd = "sudo " + self.pre_cmd_str + cmd
        if "TMUX" in os.environ and not forcex:
            tmux_pane_arg = os.getenv("TMUX_PANE", "")
            tmux_pane_arg = " -t " + tmux_pane_arg if tmux_pane_arg else ""
            wcmd = "tmux split-window -h"
            if tmux_pane_arg:
                wcmd += tmux_pane_arg
            cmd = "{} {}".format(wcmd, nscmd)
        elif "STY" in os.environ and not forcex:
            if os.path.exists(
                "/run/screen/S-{}/{}".format(os.environ["USER"], os.environ["STY"])
            ):
                wcmd = "screen"
            else:
                wcmd = "sudo -u {} screen".format(os.environ["SUDO_USER"])
            cmd = "{} {}".format(wcmd, nscmd)
        elif "DISPLAY" in os.environ:
            wcmd = "xterm"
            if title:
                wcmd = " -T {}".format(title)
            cmd = "{} -e {}".format(wcmd, nscmd)
            return self.popen(
                cmd,
                stdin=None,
                stdout=open("/dev/null", "w"),
                stderr=open("/dev/null", "w"),
            )
        else:
            self.logger.error(
                "DISPLAY, STY, and TMUX not in environment, can't open window"
            )
            return

        self.cmd_status(cmd)

        # Re-adjust the layout
        if "TMUX" in os.environ:
            self.cmd_status("tmux select-layout main-horizontal")

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

    def __init__(self, name, pid, logger=None):
        """
        Share a linux namespace.

        Paramaters
        ----------
        * `name` :: internal name for the namespace
        * `pid` :: pid of the process to share with
        """
        super(SharedNamespace, self).__init__(name, logger)

        self.logger.debug("%s: Creating", self)

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
        self.logger.debug("%s: new CWD %s", self, cwd)
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

    def __init__(self, name=None, unet=None, logger=None):
        """Create a linux Bridge."""

        self.brid_ord = self._get_next_brid()
        if name:
            self.brid = name
        else:
            self.brid = "br{}".format(self.brid_ord)
            name = self.brid

        super(Bridge, self).__init__(name, unet.pid, logger)

        self.logger.debug("Bridge: Creating")

        assert len(self.brid) <= 16  # Make sure fits in IFNAMSIZE
        self.cmd_raises("ip link delete {} || true".format(self.brid))
        self.cmd_raises("ip link add {} type bridge".format(self.brid))
        self.cmd_raises("ip link set {} up".format(self.brid))

        self.logger.debug("%s: Created, Running", self)

    def __str__(self):
        return "Bridge({})".format(self.brid)

    def delete(self):
        """Stop the bridge (i.e., delete the linux resources)."""

        self.cmd_raises("ip link delete {}".format(self.brid))

        self.logger.debug("%s: Deleted.", self)


class Micronet(LinuxNamespace):  # pylint: disable=R0205
    """
    Micronet.
    """

    def __init__(self):
        """Create a Micronet."""

        self.hosts = {}
        self.switches = {}
        self.links = {}
        self.macs = {}
        self.rmacs = {}

        super(Micronet, self).__init__("micronet", mount=True, net=True, uts=True)

        self.logger.debug("%s: Creating", self)

    def __str__(self):
        return "Micronet()"

    def __getitem__(self, key):
        if key in self.switches:
            return self.switches[key]
        return self.hosts[key]

    def add_host(self, name, cls=LinuxNamespace, **kwargs):
        """Add a host to micronet."""

        self.logger.debug("%s: add_host %s", self, name)

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
        self.logger.debug("%s: add_link %s%s", self, lname, " p2p" if isp2p else "")
        self.links[lname] = (name1, if1, name2, if2)

        # And create the veth now.
        if isp2p:
            lhost, rhost = self.hosts[name1], self.hosts[name2]
            lifname = "i1{:x}".format(lhost.pid)
            rifname = "i2{:x}".format(rhost.pid)
            self.cmd_raises(
                "ip link add {} type veth peer name {}".format(lifname, rifname)
            )

            self.cmd_raises("ip link set {} netns {}".format(lifname, lhost.pid))
            lhost.cmd_raises("ip link set {} name {}".format(lifname, if1))
            lhost.cmd_raises("ip link set {} up".format(if1))
            lhost.register_interface(if1)

            self.cmd_raises("ip link set {} netns {}".format(rifname, rhost.pid))
            rhost.cmd_raises("ip link set {} name {}".format(rifname, if2))
            rhost.cmd_raises("ip link set {} up".format(if2))
            rhost.register_interface(if2)
        else:
            switch = self.switches[name1]
            host = self.hosts[name2]

            assert len(if1) <= 16 and len(if2) <= 16  # Make sure fits in IFNAMSIZE

            self.logger.debug("%s: Creating veth pair for link %s", self, lname)
            self.cmd_raises(
                "ip link add {} type veth peer name {} netns {}".format(
                    if1, if2, host.pid
                )
            )
            switch.register_interface(if1)
            host.register_interface(if2)
            self.cmd_raises("ip link set {} master {}".format(if1, switch.brid))
            self.cmd_raises("ip link set {} up".format(if1))
            host.cmd_raises("ip link set {} up".format(if2))

        # Cache the MAC values, and reverse mapping
        self.get_mac(name1, if1)
        self.get_mac(name2, if2)

    def add_switch(self, name):
        """Add a switch to micronet."""

        self.logger.debug("%s: add_switch %s", self, name)
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

        self.logger.debug("%s: Deleting.", self)

        for lname, (_, _, rname, rif) in self.links.items():
            host = self.hosts[rname]

            self.logger.debug("%s: Deleting veth pair for link %s", self, lname)
            host.cmd("ip link delete {}".format(rif))
        self.links = {}

        for host in self.hosts.values():
            host.delete()
        self.hosts = {}

        for switch in self.switches.values():
            switch.delete()
        self.switches = {}

        self.logger.debug("%s: Deleted.", self)

        super(Micronet, self).delete()
