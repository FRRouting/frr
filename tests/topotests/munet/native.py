# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# October 1 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021-2022, LabN Consulting, L.L.C.
#
# pylint: disable=protected-access
"""A module that defines objects for standalone use."""
import asyncio
import errno
import getpass
import ipaddress
import logging
import os
import random
import re
import shlex
import socket
import subprocess
import time

from pathlib import Path

from . import cli
from .base import BaseMunet
from .base import Bridge
from .base import Commander
from .base import LinuxNamespace
from .base import MunetError
from .base import Timeout
from .base import _async_get_exec_path
from .base import _get_exec_path
from .base import cmd_error
from .base import commander
from .base import fsafe_name
from .base import get_exec_path_host
from .config import config_subst
from .config import config_to_dict_with_key
from .config import find_matching_net_config
from .config import find_with_kv
from .config import merge_kind_config
from .watchlog import WatchLog


class L3ContainerNotRunningError(MunetError):
    """Exception if no running container exists."""


def get_loopback_ips(c, nid):
    if ip := c.get("ip"):
        if ip == "auto":
            return [ipaddress.ip_interface("10.255.0.0/32") + nid]
        if isinstance(ip, str):
            return [ipaddress.ip_interface(ip)]
        return [ipaddress.ip_interface(x) for x in ip]
    return []


def make_ip_network(net, inc):
    n = ipaddress.ip_network(net)
    return ipaddress.ip_network(
        (n.network_address + inc * n.num_addresses, n.prefixlen)
    )


def make_ip_interface(ia, inc):
    ia = ipaddress.ip_interface(ia)
    # this turns into a /32 fix this
    ia = ia + ia.network.num_addresses * inc
    # IPv6
    ia = ipaddress.ip_interface(str(ia).replace("/32", "/24").replace("/128", "/64"))
    return ia


def get_ip_network(c, brid, ipv6=False):
    ip = c.get("ipv6" if ipv6 else "ip")
    if ip and str(ip) != "auto":
        try:
            ifip = ipaddress.ip_interface(ip)
            if ifip.ip == ifip.network.network_address:
                return ifip.network
            return ifip
        except ValueError:
            return ipaddress.ip_network(ip)
    if ipv6:
        return make_ip_interface("fc00::fe/64", brid)
    return make_ip_interface("10.0.0.254/24", brid)


def parse_pciaddr(devaddr):
    comp = re.match(
        "(?:([0-9A-Fa-f]{4}):)?([0-9A-Fa-f]{2}):([0-9A-Fa-f]{2}).([0-7])", devaddr
    ).groups()
    if comp[0] is None:
        comp[0] = "0000"
    return [int(x, 16) for x in comp]


def read_int_value(path):
    return int(open(path, encoding="ascii").read())


def read_str_value(path):
    return open(path, encoding="ascii").read().strip()


def read_sym_basename(path):
    return os.path.basename(os.readlink(path))


async def to_thread(func):
    """to_thread for python < 3.9."""
    try:
        return await asyncio.to_thread(func)
    except AttributeError:
        logging.warning("Using backport to_thread")
        return await asyncio.get_running_loop().run_in_executor(None, func)


def convert_ranges_to_bitmask(ranges):
    bitmask = 0
    for r in ranges.split(","):
        if "-" not in r:
            bitmask |= 1 << int(r)
        else:
            x, y = (int(x) for x in r.split("-"))
            for b in range(x, y + 1):
                bitmask |= 1 << b
    return bitmask


class L2Bridge(Bridge):
    """A linux bridge with no IP network address."""

    def __init__(self, name=None, unet=None, logger=None, mtu=None, config=None):
        """Create a linux Bridge."""
        super().__init__(name=name, unet=unet, logger=logger, mtu=mtu)

        self.config = config if config else {}

    async def _async_delete(self):
        self.logger.debug("%s: deleting", self)
        await super()._async_delete()


class L3Bridge(Bridge):
    """A linux bridge with associated IP network address."""

    def __init__(self, name=None, unet=None, logger=None, mtu=None, config=None):
        """Create a linux Bridge."""
        super().__init__(name=name, unet=unet, logger=logger, mtu=mtu)

        self.config = config if config else {}

        self.ip_interface = get_ip_network(self.config, self.id)
        if hasattr(self.ip_interface, "network"):
            self.ip_address = self.ip_interface.ip
            self.ip_network = self.ip_interface.network
            self.cmd_raises(f"ip addr add {self.ip_interface} dev {name}")
        else:
            self.ip_address = None
            self.ip_network = self.ip_interface

        self.logger.debug("%s: set IPv4 network address to %s", self, self.ip_interface)
        self.cmd_raises("sysctl -w net.ipv4.ip_forward=1")

        self.ip6_interface = None
        if self.unet.ipv6_enable:
            self.ip6_interface = get_ip_network(self.config, self.id, ipv6=True)
            if hasattr(self.ip6_interface, "network"):
                self.ip6_address = self.ip6_interface.ip
                self.ip6_network = self.ip6_interface.network
                self.cmd_raises(f"ip addr add {self.ip6_interface} dev {name}")
            else:
                self.ip6_address = None
                self.ip6_network = self.ip6_interface

            self.logger.debug(
                "%s: set IPv6 network address to %s", self, self.ip_interface
            )
            self.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")

        self.is_nat = self.config.get("nat", False)
        if self.is_nat:
            self.cmd_raises(
                "iptables -t nat -A POSTROUTING "
                f"-s {self.ip_network} ! -d {self.ip_network} "
                f"! -o {self.name} -j MASQUERADE"
            )

    def get_intf_addr(self, ifname, ipv6=False):
        # None is a valid interface, we have the same address for all interfaces
        # just make sure they aren't asking for something we don't have.
        if ifname is not None and ifname not in self.intfs:
            return None
        return self.ip6_interface if ipv6 else self.ip_interface

    async def _async_delete(self):
        self.logger.debug("%s: deleting", self)

        if self.config.get("nat", False):
            self.cmd_status(
                "iptables -t nat -D POSTROUTING "
                f"-s {self.ip_network} ! -d {self.ip_network} "
                f"! -o {self.name} -j MASQUERADE"
            )
        await super()._async_delete()


class NodeMixin:
    """Node attributes and functionality."""

    next_ord = 1

    @classmethod
    def _get_next_ord(cls):
        # Do not use `cls` here b/c that makes the variable class specific
        n = L3NodeMixin.next_ord
        L3NodeMixin.next_ord = n + 1
        return n

    def __init__(self, *args, config=None, **kwargs):
        """Create a Node."""
        super().__init__(*args, **kwargs)

        self.config = config if config else {}
        config = self.config

        self.id = int(config["id"]) if "id" in config else self._get_next_ord()

        self.cmd_p = None
        self.container_id = None
        self.cleanup_called = False

        # Clear and create rundir early
        assert self.unet is not None
        self.rundir = self.unet.rundir.joinpath(self.name)
        commander.cmd_raises(f"rm -rf {self.rundir}")
        commander.cmd_raises(f"mkdir -p {self.rundir}")

    def _shebang_prep(self, config_key):
        cmd = self.config.get(config_key, "").strip()
        if not cmd:
            return []

        script_name = fsafe_name(config_key)

        # shell_cmd is a union and can be boolean or string
        shell_cmd = self.config.get("shell", "/bin/bash")
        if not isinstance(shell_cmd, str):
            if shell_cmd:
                # i.e., "shell: true"
                shell_cmd = "/bin/bash"
            else:
                # i.e., "shell: false"
                shell_cmd = ""

        # If we have a shell_cmd then we create a cleanup_cmds file in run_cmd
        # and volume mounted it
        if shell_cmd:
            # Create cleanup cmd file
            cmd = cmd.replace("%CONFIGDIR%", str(self.unet.config_dirname))
            cmd = cmd.replace("%RUNDIR%", str(self.rundir))
            cmd = cmd.replace("%NAME%", str(self.name))
            cmd += "\n"

            # Write out our cleanup cmd file at this time too.
            cmdpath = os.path.join(self.rundir, f"{script_name}.shebang")
            with open(cmdpath, mode="w+", encoding="utf-8") as cmdfile:
                cmdfile.write(f"#!{shell_cmd}\n")
                cmdfile.write(cmd)
                cmdfile.flush()
            commander.cmd_raises(f"chmod 755 {cmdpath}")

            if self.container_id:
                # XXX this counts on it being mounted in container, ugly
                cmds = [f"/tmp/{script_name}.shebang"]
            else:
                cmds = [cmdpath]
        else:
            cmds = []
            if isinstance(cmd, str):
                cmds.extend(shlex.split(cmd))
            else:
                cmds.extend(cmd)
            cmds = [
                x.replace("%CONFIGDIR%", str(self.unet.config_dirname)) for x in cmds
            ]
            cmds = [x.replace("%RUNDIR%", str(self.rundir)) for x in cmds]
            cmds = [x.replace("%NAME%", str(self.name)) for x in cmds]

        return cmds

    async def _async_shebang_cmd(self, config_key, warn=True):
        cmds = self._shebang_prep(config_key)
        if not cmds:
            return 0

        rc, o, e = await self.async_cmd_status(cmds, warn=warn)
        if not rc and warn and (o or e):
            self.logger.info(
                f"async_shebang_cmd ({config_key}): %s", cmd_error(rc, o, e)
            )
        elif rc and warn:
            self.logger.warning(
                f"async_shebang_cmd ({config_key}): %s", cmd_error(rc, o, e)
            )
        else:
            self.logger.debug(
                f"async_shebang_cmd ({config_key}): %s", cmd_error(rc, o, e)
            )

        return rc

    def has_run_cmd(self) -> bool:
        return bool(self.config.get("cmd", "").strip())

    async def get_proc_child_pid(self, p):
        # commander is right for both unshare inline (our proc pidns)
        # and non-inline (root pidns).

        # This doesn't work b/c we can't get back to the root pidns

        rootcmd = self.unet.rootcmd
        pgrep = rootcmd.get_exec_path("pgrep")
        spid = str(p.pid)
        for _ in Timeout(4):
            if p.returncode is not None:
                self.logger.debug("%s: proc %s exited before getting child", self, p)
                return None

            rc, o, e = await rootcmd.async_cmd_status(
                [pgrep, "-o", "-P", spid], warn=False
            )
            if rc == 0:
                return int(o.strip())

            await asyncio.sleep(0.1)
            self.logger.debug(
                "%s: no child of proc %s: %s", self, p, cmd_error(rc, o, e)
            )
        self.logger.warning("%s: timeout getting child pid of proc %s", self, p)
        return None

    async def run_cmd(self):
        """Run the configured commands for this node."""
        self.logger.debug(
            "[rundir %s exists %s]", self.rundir, os.path.exists(self.rundir)
        )

        cmds = self._shebang_prep("cmd")
        if not cmds:
            return

        stdout = open(os.path.join(self.rundir, "cmd.out"), "wb")
        stderr = open(os.path.join(self.rundir, "cmd.err"), "wb")
        self.cmd_pid = None
        self.cmd_p = await self.async_popen(
            cmds,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,  # allows us to signal all children to exit
        )

        # If our process is actually the child of an nsenter fetch its pid.
        if self.nsenter_fork:
            self.cmd_pid = await self.get_proc_child_pid(self.cmd_p)

        self.logger.debug(
            "%s: async_popen %s => %s (cmd_pid %s)",
            self,
            cmds,
            self.cmd_p.pid,
            self.cmd_pid,
        )

        self.pytest_hook_run_cmd(stdout, stderr)

        return self.cmd_p

    async def _async_cleanup_cmd(self):
        """Run the configured cleanup commands for this node.

        This function is called by subclass' async_cleanup_cmd
        """
        self.cleanup_called = True

        return await self._async_shebang_cmd("cleanup-cmd")

    def has_cleanup_cmd(self) -> bool:
        return bool(self.config.get("cleanup-cmd", "").strip())

    async def async_cleanup_cmd(self):
        """Run the configured cleanup commands for this node."""
        return await self._async_cleanup_cmd()

    def has_ready_cmd(self) -> bool:
        return bool(self.config.get("ready-cmd", "").strip())

    async def async_ready_cmd(self):
        """Run the configured ready commands for this node."""
        return not await self._async_shebang_cmd("ready-cmd", warn=False)

    def cmd_completed(self, future):
        self.logger.debug("%s: cmd completed callback", self)
        try:
            status = future.result()
            self.logger.debug(
                "%s: node cmd_p completed result: %s cmd: %s", self, status, self.cmd_p
            )
            self.cmd_pid = None
            self.cmd_p = None
        except asyncio.CancelledError:
            # Should we stop the container if we have one?
            self.logger.debug("%s: node cmd_p.wait() canceled", future)

    def pytest_hook_run_cmd(self, stdout, stderr):
        """Handle pytest options related to running the node cmd.

        This function does things such as launch tail'ing windows
        on the given files if requested by the user.

        Args:
            stdout: file-like object with a ``name`` attribute, or a path to a file.
            stderr: file-like object with a ``name`` attribute, or a path to a file.
        """
        if not self.unet:
            return

        outopt = self.unet.cfgopt.getoption("--stdout")
        outopt = outopt if outopt is not None else ""
        if outopt == "all" or self.name in outopt.split(","):
            outname = stdout.name if hasattr(stdout, "name") else stdout
            self.run_in_window(f"tail -F {outname}", title=f"O:{self.name}")

        if stderr:
            erropt = self.unet.cfgopt.getoption("--stderr")
            erropt = erropt if erropt is not None else ""
            if erropt == "all" or self.name in erropt.split(","):
                errname = stderr.name if hasattr(stderr, "name") else stderr
                self.run_in_window(f"tail -F {errname}", title=f"E:{self.name}")

    def pytest_hook_open_shell(self):
        if not self.unet:
            return

        gdbcmd = self.config.get("gdb-cmd")
        shellopt = self.unet.cfgopt.getoption("--gdb", "")
        should_gdb = gdbcmd and (shellopt == "all" or self.name in shellopt.split(","))
        use_emacs = self.unet.cfgopt.getoption("--gdb-use-emacs", False)

        if should_gdb and not use_emacs:
            cmds = self.config.get("gdb-target-cmds", [])
            for cmd in cmds:
                gdbcmd += f" '-ex={cmd}'"

            bps = self.unet.cfgopt.getoption("--gdb-breakpoints", "").split(",")
            for bp in bps:
                if bp:
                    gdbcmd += f" '-ex=b {bp}'"

            cmds = self.config.get("gdb-run-cmds", [])
            for cmd in cmds:
                gdbcmd += f" '-ex={cmd}'"

            self.run_in_window(gdbcmd, ns_only=True)
        elif should_gdb and use_emacs:
            gdbcmd = gdbcmd.replace("gdb ", "gdb -i=mi ")
            ecbin = self.get_exec_path("emacsclient")
            # output = self.cmd_raises(
            #     [ecbin, "--eval", f"(gdb \"{gdbcmd} -ex='p 123456'\")"]
            # )
            _ = self.cmd_raises([ecbin, "--eval", f'(gdb "{gdbcmd}")'])

            # can't figure out how to wait until symbols are loaded, until we do we just
            # have to wait "long enough" for the symbol load to finish :/
            # for _ in range(100):
            #     output = self.cmd_raises(
            #         [
            #             ecbin,
            #             "--eval",
            #             f"gdb-first-prompt",
            #         ]
            #     )
            #     if output == "nil\n":
            #         break
            #     time.sleep(0.25)

            time.sleep(10)

            cmds = self.config.get("gdb-target-cmds", [])
            for cmd in cmds:
                # we may want to quote quotes in the cmd string
                self.cmd_raises(
                    [
                        ecbin,
                        "--eval",
                        f'(gud-gdb-run-command-fetch-lines "{cmd}" "*gud-gdb*")',
                    ]
                )

            bps = self.unet.cfgopt.getoption("--gdb-breakpoints", "").split(",")
            for bp in bps:
                cmd = f"br {bp}"
                self.cmd_raises(
                    [
                        ecbin,
                        "--eval",
                        f'(gud-gdb-run-command-fetch-lines "{cmd}" "*gud-gdb*")',
                    ]
                )

            cmds = self.config.get("gdb-run-cmds", [])
            for cmd in cmds:
                # we may want to quote quotes in the cmd string
                self.cmd_raises(
                    [
                        ecbin,
                        "--eval",
                        f'(gud-gdb-run-command-fetch-lines "{cmd}" "*gud-gdb*")',
                    ]
                )
                gdbcmd += f" '-ex={cmd}'"

        shellopt = self.unet.cfgopt.getoption("--shell")
        shellopt = shellopt if shellopt else ""
        if shellopt == "all" or self.name in shellopt.split(","):
            self.run_in_window("bash")

    async def _async_delete(self):
        self.logger.debug("%s: NodeMixin sub-class _async_delete", self)

        if self.cmd_p:
            await self.async_cleanup_proc(self.cmd_p, self.cmd_pid)
            self.cmd_p = None

        # Next call users "cleanup_cmd:"
        try:
            if not self.cleanup_called:
                await self.async_cleanup_cmd()
        except Exception as error:
            self.logger.warning(
                "Got an error during delete from async_cleanup_cmd: %s", error
            )

        # delete the LinuxNamespace/InterfaceMixin
        await super()._async_delete()


class SSHRemote(NodeMixin, Commander):
    """SSHRemote a node representing an ssh connection to something."""

    def __init__(
        self,
        name,
        server,
        port=22,
        user=None,
        password=None,
        idfile=None,
        **kwargs,
    ):
        super().__init__(name, **kwargs)

        self.logger.debug("%s: creating", self)

        # Things done in LinuxNamepsace we need to replicate here.
        self.rundir = self.unet.rundir.joinpath(self.name)
        self.unet.cmd_raises(f"rm -rf {self.rundir}")
        self.unet.cmd_raises(f"mkdir -p {self.rundir}")

        self.mgmt_ip = None
        self.mgmt_ip6 = None

        self.port = port

        if user:
            self.user = user
        elif "SUDO_USER" in os.environ:
            self.user = os.environ["SUDO_USER"]
        else:
            self.user = getpass.getuser()
        self.password = password
        self.idfile = idfile

        self.server = f"{self.user}@{server}"

        # Setup our base `pre-cmd` values
        #
        # We maybe should add environment variable transfer here in particular
        # MUNET_NODENAME. The problem is the user has to explicitly approve
        # of SendEnv variables.
        self.__base_cmd = [
            get_exec_path_host("sudo"),
            "-E",
            f"-u{self.user}",
            get_exec_path_host("ssh"),
        ]
        if port != 22:
            self.__base_cmd.append(f"-p{port}")
        self.__base_cmd.append("-q")
        self.__base_cmd.append("-oStrictHostKeyChecking=no")
        self.__base_cmd.append("-oUserKnownHostsFile=/dev/null")
        if self.idfile:
            self.__base_cmd.append(f"-i{self.idfile}")
        # Would be nice but has to be accepted by server config so not very useful.
        # self.__base_cmd.append("-oSendVar='TEST'")
        self.__base_cmd_pty = list(self.__base_cmd)
        self.__base_cmd_pty.append("-t")
        self.__base_cmd.append(self.server)
        self.__base_cmd_pty.append(self.server)
        # self.set_pre_cmd(pre_cmd, pre_cmd_tty)

        self.logger.info("%s: created", self)

    def has_ready_cmd(self) -> bool:
        return bool(self.config.get("ready-cmd", "").strip())

    def _get_pre_cmd(self, use_str, use_pty, ns_only=False, **kwargs):
        pre_cmd = []
        if self.unet:
            pre_cmd = self.unet._get_pre_cmd(False, use_pty, ns_only=False, **kwargs)
        if ns_only:
            return pre_cmd

        # XXX grab the env from kwargs and add to podman exec
        # env = kwargs.get("env", {})
        if use_pty:
            pre_cmd = pre_cmd + self.__base_cmd_pty
        else:
            pre_cmd = pre_cmd + self.__base_cmd
        return shlex.join(pre_cmd) if use_str else list(pre_cmd)

    def _get_cmd_as_list(self, cmd):
        """Given a list or string return a list form for execution.

        If cmd is a string then [cmd] is returned, for most other
        node types ["bash", "-c", cmd] is returned but in our case
        ssh is the shell.

        Args:
            cmd: list or string representing the command to execute.
            str_shell: if True and `cmd` is a string then run the
              command using bash -c
        Returns:
            list of commands to execute.
        """
        return [cmd] if isinstance(cmd, str) else cmd


# Would maybe like to refactor this into L3 and Node
class L3NodeMixin(NodeMixin):
    """A linux namespace with IP attributes."""

    def __init__(self, *args, unet=None, **kwargs):
        """Create an L3Node."""
        # logging.warning(
        #     "L3NodeMixin: config %s unet %s kwargs %s", config, unet, kwargs
        # )
        super().__init__(*args, unet=unet, **kwargs)

        self.mgmt_ip = None  # set in parser.py
        self.mgmt_ip6 = None  # set in parser.py
        self.host_intfs = {}
        self.phy_intfs = {}
        self.phycount = 0
        self.phy_odrivers = {}
        self.tapmacs = {}
        self.watched_logs = {}

        self.intf_tc_count = 0

        # super().__init__(name=name, **kwargs)

        self.mount_volumes()

        # -----------------------
        # Setup node's networking
        # -----------------------
        if not unet.ipv6_enable:
            # Disable IPv6
            self.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
            self.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
        else:
            self.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=1")
            self.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

        self.next_p2p_network = ipaddress.ip_network(f"10.254.{self.id}.0/31")
        self.next_p2p_network6 = ipaddress.ip_network(f"fcff:ffff:{self.id:02x}::/127")

        self.loopback_ip = None
        self.loopback_ips = get_loopback_ips(self.config, self.id)
        self.loopback_ip = self.loopback_ips[0] if self.loopback_ips else None
        if self.loopback_ip:
            self.cmd_raises_nsonly(f"ip addr add {self.loopback_ip} dev lo")
            self.cmd_raises_nsonly("ip link set lo up")
            for i, ip in enumerate(self.loopback_ips[1:]):
                self.cmd_raises_nsonly(f"ip addr add {ip} dev lo:{i}")

        # -------------------
        # Setup node's rundir
        # -------------------

        # Not host path based, but we assume same
        self.set_ns_cwd(self.rundir)

        # Save the namespace pid
        with open(os.path.join(self.rundir, "nspid"), "w", encoding="ascii") as f:
            f.write(f"{self.pid}\n")

        with open(os.path.join(self.rundir, "nspids"), "w", encoding="ascii") as f:
            f.write(f'{" ".join([str(x) for x in self.pids])}\n')

        # Create a hosts file to map our name
        hosts_file = os.path.join(self.rundir, "hosts.txt")
        with open(hosts_file, "w", encoding="ascii") as hf:
            hf.write(
                f"""127.0.0.1\tlocalhost {self.name}
::1\tip6-localhost ip6-loopback
fe00::0\tip6-localnet
ff00::0\tip6-mcastprefix
ff02::1\tip6-allnodes
ff02::2\tip6-allrouters
"""
            )
        if hasattr(self, "bind_mount"):
            self.bind_mount(hosts_file, "/etc/hosts")

    def add_watch_log(self, path, watchfor_re=None):
        """Add a WatchLog to this nodes watched logs.

        Args:
            path: If relative is relative to the nodes ``rundir``
            watchfor_re: Regular expression to watch the log for and raise an exception
                         if found.

        Return:
            The watching task if request or None otherwise.
        """
        path = Path(path)
        if not path.is_absolute():
            path = self.rundir.joinpath(path)

        wl = WatchLog(path)
        self.watched_logs[wl.path] = wl
        task = wl.raise_if_match_task(watchfor_re) if watchfor_re else None
        return task

    async def console(
        self,
        concmd,
        prompt=r"(^|\r?\n)[^#\$]*[#\$] ",
        is_bourne=True,
        user=None,
        password=None,
        expects=None,
        sends=None,
        use_pty=False,
        will_echo=False,
        logfile_prefix="console",
        trace=True,
        **kwargs,
    ):
        """Create a REPL (read-eval-print-loop) driving a console.

        Args:
            concmd: string or list to popen with, or an already open socket
            prompt: the REPL prompt to look for, the function returns when seen
            is_bourne: True if the console is a bourne shell
            user: user name to log in with
            password: password to log in with
            expects: a list of regex other than the prompt, the standard user, or
                password to look for. "ogin:" or "[Pp]assword:"r.
            sends: what to send when an element of `expects` matches. Can be the
                empty string to send nothing.
            use_pty: true for pty based expect, otherwise uses popen (pipes/files)
            will_echo: bash is buggy in that it echo's to non-tty unlike any other
                sh/ksh, set this value to true if running back
            logfile_prefix: prefix for 3 logfiles opened to track the console i/o
            trace: trace the send/expect sequence
            **kwargs: kwargs passed on the _spawn.
        """
        lfname = os.path.join(self.rundir, f"{logfile_prefix}-log.txt")
        logfile = open(lfname, "a+", encoding="utf-8")
        logfile.write("-- start logging for: '{}' --\n".format(concmd))

        lfname = os.path.join(self.rundir, f"{logfile_prefix}-read-log.txt")
        logfile_read = open(lfname, "a+", encoding="utf-8")
        logfile_read.write("-- start read logging for: '{}' --\n".format(concmd))

        lfname = os.path.join(self.rundir, f"{logfile_prefix}-send-log.txt")
        logfile_send = open(lfname, "a+", encoding="utf-8")
        logfile_send.write("-- start send logging for: '{}' --\n".format(concmd))

        expects = [] if expects is None else expects
        sends = [] if sends is None else sends
        if user:
            expects.append("ogin:")
            sends.append(user + "\n")
        if password is not None:
            expects.append("assword:")
            sends.append(password + "\n")
        repl = await self.shell_spawn(
            concmd,
            prompt,
            expects=expects,
            sends=sends,
            use_pty=use_pty,
            will_echo=will_echo,
            is_bourne=is_bourne,
            logfile=logfile,
            logfile_read=logfile_read,
            logfile_send=logfile_send,
            trace=trace,
            **kwargs,
        )
        return repl

    async def monitor(
        self,
        sockpath,
        prompt=r"\(qemu\) ",
    ):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(sockpath)

        pfx = os.path.basename(sockpath)

        lfname = os.path.join(self.rundir, f"{pfx}-log.txt")
        logfile = open(lfname, "a+", encoding="utf-8")
        logfile.write("-- start logging for: '{}' --\n".format(sock))

        lfname = os.path.join(self.rundir, f"{pfx}-read-log.txt")
        logfile_read = open(lfname, "a+", encoding="utf-8")
        logfile_read.write("-- start read logging for: '{}' --\n".format(sock))

        p = self.spawn(sock, prompt, logfile=logfile, logfile_read=logfile_read)
        from .base import ShellWrapper  # pylint: disable=C0415

        p.send("\n")
        return ShellWrapper(p, prompt, None, will_echo=True, escape_ansi=True)

    def mount_volumes(self):
        for m in self.config.get("volumes", []):
            if isinstance(m, str):
                s = m.split(":", 1)
                if len(s) == 1:
                    self.tmpfs_mount(s[0])
                else:
                    spath = s[0]
                    if spath[0] == ".":
                        spath = os.path.abspath(
                            os.path.join(self.unet.config_dirname, spath)
                        )
                    self.bind_mount(spath, s[1])
                continue
            raise NotImplementedError("complex mounts for non-containers")

    def get_ifname(self, netname):
        for c in self.config["connections"]:
            if c["to"] == netname:
                return c["name"]
        return None

    def set_lan_addr(self, switch, cconf):
        if ip := cconf.get("ip"):
            ipaddr = ipaddress.ip_interface(ip)
            assert ipaddr.version == 4
        elif self.unet.autonumber and "ip" not in cconf:
            self.logger.debug(
                "%s: prefixlen of switch %s is %s",
                self,
                switch.name,
                switch.ip_network.prefixlen,
            )
            n = switch.ip_network
            ipaddr = ipaddress.ip_interface((n.network_address + self.id, n.prefixlen))
        else:
            ipaddr = None

        if ip := cconf.get("ipv6"):
            ip6addr = ipaddress.ip_interface(ip)
            assert ipaddr.version == 6
        elif self.unet.ipv6_enable and self.unet.autonumber and "ipv6" not in cconf:
            self.logger.debug(
                "%s: prefixlen of switch %s is %s",
                self,
                switch.name,
                switch.ip6_network.prefixlen,
            )
            n = switch.ip6_network
            ip6addr = ipaddress.ip_interface((n.network_address + self.id, n.prefixlen))
        else:
            ip6addr = None

        dns_network = self.unet.topoconf.get("dns-network")
        for ip in (ipaddr, ip6addr):
            if not ip:
                continue
            ipcmd = "ip " if ip.version == 4 else "ip -6 "
            if dns_network and dns_network == switch.name:
                if ip.version == 4:
                    self.mgmt_ip = ip.ip
                else:
                    self.mgmt_ip6 = ip.ip
            ifname = cconf["name"]
            self.set_intf_addr(ifname, ip)
            self.logger.debug("%s: adding %s to lan intf %s", self, ip, ifname)
            if not self.is_vm:
                self.intf_ip_cmd(ifname, ipcmd + f"addr add {ip} dev {ifname}")
                if hasattr(switch, "is_nat") and switch.is_nat:
                    swaddr = (
                        switch.ip_address if ip.version == 4 else switch.ip6_address
                    )
                    self.cmd_raises(ipcmd + f"route add default via {swaddr}")

    def _set_p2p_addr(self, other, cconf, occonf, ipv6=False):
        ipkey = "ipv6" if ipv6 else "ip"
        ipaddr = ipaddress.ip_interface(cconf[ipkey]) if cconf.get(ipkey) else None
        oipaddr = ipaddress.ip_interface(occonf[ipkey]) if occonf.get(ipkey) else None
        self.logger.debug(
            "%s: set_p2p_addr %s %s %s", self, other.name, ipaddr, oipaddr
        )

        if not ipaddr and not oipaddr:
            if self.unet.autonumber:
                if ipv6:
                    n = self.next_p2p_network6
                    self.next_p2p_network6 = make_ip_network(n, 1)
                else:
                    n = self.next_p2p_network
                    self.next_p2p_network = make_ip_network(n, 1)

                ipaddr = ipaddress.ip_interface(n)
                oipaddr = ipaddress.ip_interface((ipaddr.ip + 1, n.prefixlen))
            else:
                return

        if ipaddr:
            ifname = cconf["name"]
            self.set_intf_addr(ifname, ipaddr)
            self.logger.debug("%s: adding %s to p2p intf %s", self, ipaddr, ifname)
            if "physical" not in cconf and not self.is_vm:
                self.intf_ip_cmd(ifname, f"ip addr add {ipaddr} dev {ifname}")

        if oipaddr:
            oifname = occonf["name"]
            other.set_intf_addr(oifname, oipaddr)
            self.logger.debug(
                "%s: adding %s to other p2p intf %s", other, oipaddr, oifname
            )
            if "physical" not in occonf and not other.is_vm:
                other.intf_ip_cmd(oifname, f"ip addr add {oipaddr} dev {oifname}")

    def set_p2p_addr(self, other, cconf, occonf):
        self._set_p2p_addr(other, cconf, occonf, ipv6=False)
        if self.unet.ipv6_enable:
            self._set_p2p_addr(other, cconf, occonf, ipv6=True)

    async def add_host_intf(self, hname, lname, mtu=None):
        if hname in self.host_intfs:
            return
        self.host_intfs[hname] = lname

        # See if this interace is missing and needs to be fixed
        rc, o, _ = self.unet.rootcmd.cmd_status("ip -o link show")
        m = re.search(rf"\d+:\s+(\S+):.*altname {re.escape(hname)}\W", o)
        if m:
            # need to rename
            dname = m.group(1)
            self.logger.info("Fixing misnamed %s to %s", dname, hname)
            self.unet.rootcmd.cmd_status(
                f"ip link property del dev {dname} altname {hname}"
            )
            self.unet.rootcmd.cmd_status(f"ip link set {dname} name {hname}")

        rc, o, _ = self.unet.rootcmd.cmd_status("ip -o link show")
        m = re.search(rf"\d+:\s+{re.escape(hname)}:.*", o)
        if m:
            self.unet.rootcmd.cmd_nostatus(f"ip link set {hname} down ")
            self.unet.rootcmd.cmd_raises(f"ip link set {hname} netns {self.pid}")
        # Wait for interface to show up in namespace
        for retry in range(0, 10):
            rc, o, _ = self.cmd_status(f"ip -o link show {hname}")
            if not rc:
                if re.search(rf"\d+: {re.escape(hname)}:.*", o):
                    break
            if retry > 0:
                await asyncio.sleep(1)
        self.cmd_raises(f"ip link set {hname} name {lname}")
        if mtu:
            self.cmd_raises(f"ip link set {lname} mtu {mtu}")
        self.cmd_raises(f"ip link set {lname} up")

    async def rem_host_intf(self, hname):
        lname = self.host_intfs[hname]
        self.cmd_raises(f"ip link set {lname} down")
        self.cmd_raises(f"ip link set {lname} name {hname}")
        self.cmd_status(f"ip link set netns 1 dev {hname}")
        # The above is failing sometimes and not sure why
        # logging.error(
        #     "XXX after setns %s",
        #     self.unet.rootcmd.cmd_nostatus(f"ip link show {hname}"),
        # )
        del self.host_intfs[hname]

    async def add_phy_intf(self, devaddr, lname):
        """Add a physical inteface (i.e. mv it to vfio-pci driver.

        This is primarily useful for Qemu, but also for things like TREX or DPDK
        """
        if devaddr in self.phy_intfs:
            return
        self.phy_intfs[devaddr] = lname
        index = len(self.phy_intfs)

        _, _, off, fun = parse_pciaddr(devaddr)
        doffset = off * 8 + fun

        is_virtual = self.unet.rootcmd.path_exists(
            f"/sys/bus/pci/devices/{devaddr}/physfn"
        )
        if is_virtual:
            pfname = self.unet.rootcmd.cmd_raises(
                f"ls -1 /sys/bus/pci/devices/{devaddr}/physfn/net"
            ).strip()
            pdevaddr = read_sym_basename(f"/sys/bus/pci/devices/{devaddr}/physfn")
            _, _, poff, pfun = parse_pciaddr(pdevaddr)
            poffset = poff * 8 + pfun

            offset = read_int_value(
                f"/sys/bus/pci/devices/{devaddr}/physfn/sriov_offset"
            )
            stride = read_int_value(
                f"/sys/bus/pci/devices/{devaddr}/physfn/sriov_stride"
            )
            vf = (doffset - offset - poffset) // stride
            mac = f"02:cc:cc:cc:{index:02x}:{self.id:02x}"
            # Some devices require the parent to be up (e.g., ixbge)
            self.unet.rootcmd.cmd_raises(f"ip link set {pfname} up")
            self.unet.rootcmd.cmd_raises(f"ip link set {pfname} vf {vf} mac {mac}")
            self.unet.rootcmd.cmd_status(f"ip link set {pfname} vf {vf} trust on")
            self.tapmacs[devaddr] = mac

        self.logger.info("Adding physical PCI device %s as %s", devaddr, lname)

        # Get interface name and set to down if present
        ec, ifname, _ = self.unet.rootcmd.cmd_status(
            f"ls /sys/bus/pci/devices/{devaddr}/net/", warn=False
        )
        ifname = ifname.strip()
        if not ec and ifname:
            # XXX Should only do this is the device is up, and then likewise return it
            # up on exit self.phy_intfs_hostname[devaddr] = ifname
            self.logger.info(
                "Setting physical PCI device %s named %s down", devaddr, ifname
            )
            self.unet.rootcmd.cmd_status(
                f"ip link set {ifname} down 2> /dev/null || true"
            )

        # Get the current bound driver, and unbind
        try:
            driver = read_sym_basename(f"/sys/bus/pci/devices/{devaddr}/driver")
            driver = driver.strip()
        except Exception:
            driver = ""
        if driver:
            if driver == "vfio-pci":
                self.logger.info(
                    "Physical PCI device %s already bound to vfio-pci", devaddr
                )
                return

            self.logger.info(
                "Unbinding physical PCI device %s from driver %s", devaddr, driver
            )
            self.phy_odrivers[devaddr] = driver
            self.unet.rootcmd.cmd_raises(
                f"echo {devaddr} | timeout 10 tee /sys/bus/pci/drivers/{driver}/unbind"
            )

        # Add the device vendor and device id to vfio-pci in case it's the first time
        vendor = read_str_value(f"/sys/bus/pci/devices/{devaddr}/vendor")
        devid = read_str_value(f"/sys/bus/pci/devices/{devaddr}/device")
        self.logger.info("Adding device IDs %s:%s to vfio-pci", vendor, devid)
        ec, _, _ = self.unet.rootcmd.cmd_status(
            f"echo {vendor} {devid} > /sys/bus/pci/drivers/vfio-pci/new_id", warn=False
        )

        for retry in range(0, 10):
            if self.unet.rootcmd.path_exists(
                f"/sys/bus/pci/drivers/vfio-pci/{devaddr}"
            ):
                break
            if retry > 0:
                await asyncio.sleep(1)

            # Bind to vfio-pci if wasn't added with new_id
            self.logger.info("Binding physical PCI device %s to vfio-pci", devaddr)
            ec, _, _ = self.unet.rootcmd.cmd_status(
                f"echo {devaddr} > /sys/bus/pci/drivers/vfio-pci/bind"
            )

    async def rem_phy_intf(self, devaddr):
        """Remove a physical inteface (i.e. mv it away from vfio-pci driver.

        This is primarily useful for Qemu, but also for things like TREX or DPDK
        """
        lname = self.phy_intfs.get(devaddr, "")
        if lname:
            del self.phy_intfs[devaddr]

        # ifname = self.phy_intfs_hostname.get(devaddr, "")
        # if ifname
        #     del self.phy_intfs_hostname[devaddr]

        driver = self.phy_odrivers.get(devaddr, "")
        if not driver:
            self.logger.info(
                "Physical PCI device %s was bound to vfio-pci on entry", devaddr
            )
            return

        self.logger.info(
            "Unbinding physical PCI device %s from driver vfio-pci", devaddr
        )
        self.unet.rootcmd.cmd_status(
            f"echo {devaddr} | timeout 10 tee /sys/bus/pci/drivers/vfio-pci/unbind"
        )

        self.logger.info("Binding physical PCI device %s to driver %s", devaddr, driver)
        ec, _, _ = self.unet.rootcmd.cmd_status(
            f"echo {devaddr} > /sys/bus/pci/drivers/{driver}/bind"
        )
        if not ec:
            del self.phy_odrivers[devaddr]

    async def _async_delete(self):
        self.logger.debug("%s: L3NodeMixin sub-class _async_delete", self)

        # XXX do we need to run the cleanup command before these infra changes?

        # remove any hostintf interfaces
        for hname in list(self.host_intfs):
            await self.rem_host_intf(hname)

        # delete the LinuxNamespace/InterfaceMixin
        await super()._async_delete()

        # remove any hostintf interfaces, needs to come after normal exits
        for devaddr in list(self.phy_intfs):
            await self.rem_phy_intf(devaddr)


class L3NamespaceNode(L3NodeMixin, LinuxNamespace):
    """A namespace L3 node."""

    def __init__(self, name, pid=True, **kwargs):
        # logging.warning(
        #     "L3NamespaceNode: name %s MRO: %s kwargs %s",
        #     name,
        #     L3NamespaceNode.mro(),
        #     kwargs,
        # )
        super().__init__(name, pid=pid, **kwargs)
        super().pytest_hook_open_shell()

    async def _async_delete(self):
        self.logger.debug("%s: deleting", self)
        await super()._async_delete()


class L3ContainerNode(L3NodeMixin, LinuxNamespace):
    """An container (podman) based L3 node."""

    def __init__(self, name, config, **kwargs):
        """Create a Container Node."""
        self.cont_exec_paths = {}
        self.container_id = None
        self.container_image = config["image"]
        self.extra_mounts = []
        assert self.container_image

        self.cmd_p = None
        self.cmd_pid = None
        self.__base_cmd = []
        self.__base_cmd_pty = []

        # don't we have a mutini or cat process?
        super().__init__(
            name=name,
            config=config,
            # pid=True,
            # cgroup=True,
            # private_mounts=["/sys/fs/cgroup:/sys/fs/cgroup"],
            **kwargs,
        )

    @property
    def is_container(self):
        return True

    def get_exec_path(self, binary):
        """Return the full path to the binary executable inside the image.

        `binary` :: binary name or list of binary names
        """
        return _get_exec_path(binary, self.cmd_status, self.cont_exec_paths)

    async def async_get_exec_path(self, binary):
        """Return the full path to the binary executable inside the image.

        `binary` :: binary name or list of binary names
        """
        path = await _async_get_exec_path(
            binary, self.async_cmd_status, self.cont_exec_paths
        )
        return path

    def get_exec_path_host(self, binary):
        """Return the full path to the binary executable on the host.

        `binary` :: binary name or list of binary names
        """
        return get_exec_path_host(binary)

    def _get_pre_cmd(self, use_str, use_pty, ns_only=False, root_level=False, **kwargs):
        if ns_only:
            return super()._get_pre_cmd(
                use_str, use_pty, ns_only=True, root_level=root_level, **kwargs
            )
        if not self.cmd_p:
            if self.container_id:
                s = f"{self}: Running command in namespace b/c container exited"
                self.logger.warning("%s", s)
                raise L3ContainerNotRunningError(s)
            self.logger.debug("%s: Running command in namespace b/c no container", self)
            return super()._get_pre_cmd(
                use_str, use_pty, ns_only=True, root_level=root_level, **kwargs
            )

        # We need to enter our namespaces when running the podman command
        pre_cmd = super()._get_pre_cmd(
            False, use_pty, ns_only=True, root_level=root_level, **kwargs
        )

        # XXX grab the env from kwargs and add to podman exec
        # env = kwargs.get("env", {})
        if use_pty:
            pre_cmd = pre_cmd + self.__base_cmd_pty
        else:
            pre_cmd = pre_cmd + self.__base_cmd
        return shlex.join(pre_cmd) if use_str else pre_cmd

    def tmpfs_mount(self, inner):
        # eventually would be nice to support live mounting
        assert not self.container_id
        self.logger.debug("Mounting tmpfs on %s", inner)
        self.extra_mounts.append(f"--mount=type=tmpfs,destination={inner}")

    def bind_mount(self, outer, inner):
        # eventually would be nice to support live mounting
        assert not self.container_id
        # First bind the mount in the parent this allows things like /etc/hosts to work
        # correctly when running "nsonly" commands
        super().bind_mount(outer, inner)
        # Then arrange for binding in the container as well.
        self.logger.debug("Bind mounting %s on %s", outer, inner)
        if not self.test_nsonly("-e", outer):
            self.cmd_raises_nsonly(f"mkdir -p {outer}")
        self.extra_mounts.append(f"--mount=type=bind,src={outer},dst={inner}")

    def mount_volumes(self):
        args = []
        for m in self.config.get("volumes", []):
            if isinstance(m, str):
                s = m.split(":", 1)
                if len(s) == 1:
                    args.append("--mount=type=tmpfs,destination=" + m)
                else:
                    spath = s[0]
                    spath = os.path.abspath(
                        os.path.join(
                            os.path.dirname(self.unet.config["config_pathname"]), spath
                        )
                    )
                    if not self.test_nsonly("-e", spath):
                        self.cmd_raises_nsonly(f"mkdir -p {spath}")
                    args.append(f"--mount=type=bind,src={spath},dst={s[1]}")
                continue

        for m in self.config.get("mounts", []):
            margs = ["type=" + m["type"]]
            for k, v in m.items():
                if k == "type":
                    continue
                if v:
                    if k in ("src", "source"):
                        v = os.path.abspath(
                            os.path.join(
                                os.path.dirname(self.unet.config["config_pathname"]), v
                            )
                        )
                        if not self.test_nsonly("-e", v):
                            self.cmd_raises_nsonly(f"mkdir -p {v}")
                    margs.append(f"{k}={v}")
                else:
                    margs.append(f"{k}")
            args.append("--mount=" + ",".join(margs))

        if args:
            # Need to work on a way to mount into live container too
            self.extra_mounts += args

    def has_run_cmd(self) -> bool:
        return True

    async def run_cmd(self):
        """Run the configured commands for this node."""
        self.logger.debug("%s: starting container", self.name)
        self.logger.debug(
            "[rundir %s exists %s]", self.rundir, os.path.exists(self.rundir)
        )

        self.container_id = f"{self.name}-{os.getpid()}"
        proc_path = self.unet.proc_path if self.unet else "/proc"
        cmds = [
            get_exec_path_host("podman"),
            "run",
            f"--name={self.container_id}",
            # f"--net=ns:/proc/{self.pid}/ns/net",
            f"--net=ns:{proc_path}/{self.pid}/ns/net",
            f"--hostname={self.name}",
            f"--add-host={self.name}:127.0.0.1",
            # We can't use --rm here b/c podman fails on "stop".
            # u"--rm",
        ]

        if self.config.get("init", True):
            cmds.append("--init")

        if self.config.get("privileged", False):
            cmds.append("--privileged")
            # If we don't do this then the host file system is remounted read-only on
            # exit!
            cmds.append("--systemd=false")
        else:
            cmds.extend(
                [
                    # "--cap-add=SYS_ADMIN",
                    "--cap-add=NET_ADMIN",
                    "--cap-add=NET_RAW",
                ]
            )

        # Add volumes:
        if self.extra_mounts:
            cmds += self.extra_mounts

        # Add environment variables:
        envdict = self.config.get("env", {})
        if envdict is None:
            envdict = {}
        for k, v in envdict.items():
            cmds.append(f"--env={k}={v}")

        # Update capabilities
        cmds += [f"--cap-add={x}" for x in self.config.get("cap-add", [])]
        cmds += [f"--cap-drop={x}" for x in self.config.get("cap-drop", [])]
        # cmds += [f"--expose={x.split(':')[0]}" for x in self.config.get("ports", [])]
        cmds += [f"--publish={x}" for x in self.config.get("ports", [])]

        # Add extra flags from user:
        if "podman" in self.config:
            for x in self.config["podman"].get("extra-args", []):
                cmds.append(x.strip())

        # shell_cmd is a union and can be boolean or string
        shell_cmd = self.config.get("shell", "/bin/bash")
        if not isinstance(shell_cmd, str):
            if shell_cmd:
                shell_cmd = "/bin/bash"
            else:
                shell_cmd = ""

        # Create shebang files, filled later on
        for key in ("cleanup-cmd", "ready-cmd"):
            shebang_cmd = self.config.get(key, "").strip()
            if shell_cmd and shebang_cmd:
                script_name = fsafe_name(key)
                # Will write the file contents out when the command is run
                shebang_cmdpath = os.path.join(self.rundir, f"{script_name}.shebang")
                await self.async_cmd_raises_nsonly(f"touch {shebang_cmdpath}")
                await self.async_cmd_raises_nsonly(f"chmod 755 {shebang_cmdpath}")
                cmds += [
                    # How can we override this?
                    # u'--entrypoint=""',
                    f"--volume={shebang_cmdpath}:/tmp/{script_name}.shebang",
                ]

        cmd = self.config.get("cmd", "").strip()

        # See if we have a custom update for this `kind`
        if kind := self.config.get("kind", None):
            if kind in kind_run_cmd_update:
                cmds, cmd = await kind_run_cmd_update[kind](self, shell_cmd, cmds, cmd)

        # Create running command file
        if shell_cmd and cmd:
            assert isinstance(cmd, str)
            # make cmd \n terminated for script
            cmd = cmd.rstrip()
            cmd = cmd.replace("%CONFIGDIR%", str(self.unet.config_dirname))
            cmd = cmd.replace("%RUNDIR%", str(self.rundir))
            cmd = cmd.replace("%NAME%", str(self.name))
            cmd += "\n"
            cmdpath = os.path.join(self.rundir, "cmd.shebang")
            with open(cmdpath, mode="w+", encoding="utf-8") as cmdfile:
                cmdfile.write(f"#!{shell_cmd}\n")
                cmdfile.write(cmd)
                cmdfile.flush()
            self.cmd_raises_nsonly(f"chmod 755 {cmdpath}")
            cmds += [
                # How can we override this?
                # u'--entrypoint=""',
                f"--volume={cmdpath}:/tmp/cmds.shebang",
                self.container_image,
                "/tmp/cmds.shebang",
            ]
        else:
            # `cmd` is a direct run (no shell) cmd
            cmds.append(self.container_image)
            if cmd:
                if isinstance(cmd, str):
                    cmds.extend(shlex.split(cmd))
                else:
                    cmds.extend(cmd)

            cmds = [
                x.replace("%CONFIGDIR%", str(self.unet.config_dirname)) for x in cmds
            ]
            cmds = [x.replace("%RUNDIR%", str(self.rundir)) for x in cmds]
            cmds = [x.replace("%NAME%", str(self.name)) for x in cmds]

        stdout = open(os.path.join(self.rundir, "cmd.out"), "wb")
        stderr = open(os.path.join(self.rundir, "cmd.err"), "wb")
        # Using nsonly avoids using `podman exec` to execute the cmds.
        self.cmd_p = await self.async_popen_nsonly(
            cmds,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,  # keeps main tty signals away from podman
        )

        # If our process is actually the child of an nsenter fetch its pid.
        if self.nsenter_fork:
            self.cmd_pid = await self.get_proc_child_pid(self.cmd_p)

        self.logger.debug(
            "%s: async_popen => %s (%s)", self, self.cmd_p.pid, self.cmd_pid
        )

        self.pytest_hook_run_cmd(stdout, stderr)

        # ---------------------------------------
        # Now let's wait until container shows up
        # ---------------------------------------
        timeout = Timeout(30)
        while self.cmd_p.returncode is None and not timeout.is_expired():
            o = await self.async_cmd_raises_nsonly(
                f"podman ps -q -f name={self.container_id}"
            )
            if o.strip():
                break
            elapsed = int(timeout.elapsed())
            if elapsed <= 3:
                await asyncio.sleep(0.1)
            else:
                self.logger.info("%s: run_cmd taking more than %ss", self, elapsed)
                await asyncio.sleep(1)
        if self.cmd_p.returncode is not None:
            # leave self.container_id set to cause exception on use
            self.logger.warning(
                "%s: run_cmd exited quickly (%ss) rc: %s",
                self,
                timeout.elapsed(),
                self.cmd_p.returncode,
            )
        elif timeout.is_expired():
            self.logger.critical(
                "%s: timeout (%ss) waiting for container to start",
                self.name,
                timeout.elapsed(),
            )
            assert not timeout.is_expired()

        #
        # Set our precmd for executing in the container
        #
        self.__base_cmd = [
            get_exec_path_host("podman"),
            "exec",
            f"-eMUNET_RUNDIR={self.unet.rundir}",
            f"-eMUNET_NODENAME={self.name}",
            "-i",
        ]
        self.__base_cmd_pty = list(self.__base_cmd)  # copy list to pty
        self.__base_cmd.append(self.container_id)  # end regular list
        self.__base_cmd_pty.append("-t")  # add pty flags
        self.__base_cmd_pty.append(self.container_id)  # end pty list
        # self.set_pre_cmd(self.__base_cmd, self.__base_cmd_pty)  # set both pre_cmd

        self.logger.info("%s: started container", self.name)

        self.pytest_hook_open_shell()

        return self.cmd_p

    async def async_cleanup_cmd(self):
        """Run the configured cleanup commands for this node."""
        self.cleanup_called = True

        if "cleanup-cmd" not in self.config:
            return

        if not self.cmd_p:
            self.logger.warning("async_cleanup_cmd: container no longer running")
            return

        return await self._async_cleanup_cmd()

    def cmd_completed(self, future):
        try:
            log = self.logger.debug if self.deleting else self.logger.warning
            n = future.result()
            if self.deleting:
                log("contianer `cmd:` result: %s", n)
            else:
                log(
                    "contianer `cmd:` exited early, "
                    "try adding `tail -f /dev/null` to `cmd:`, result: %s",
                    n,
                )
        except asyncio.CancelledError as error:
            # Should we stop the container if we have one? or since we are canceled
            # we know we will be deleting soon?
            self.logger.warning(
                "node container cmd wait() canceled: %s:%s", future, error
            )
        self.cmd_p = None

    async def _async_delete(self):
        self.logger.debug("%s: deleting", self)

        if contid := self.container_id:
            try:
                if not self.cleanup_called:
                    self.logger.debug("calling user cleanup cmd")
                    await self.async_cleanup_cmd()
            except Exception as error:
                self.logger.warning(
                    "Got an error during delete from async_cleanup_cmd: %s", error
                )

            # Clear the container_id field we want to act like a namespace now.
            self.container_id = None

            o = ""
            e = ""
            if self.cmd_p:
                self.logger.debug("podman stop on container: %s", contid)
                if (rc := self.cmd_p.returncode) is None:
                    rc, o, e = await self.async_cmd_status_nsonly(
                        [get_exec_path_host("podman"), "stop", "--time=2", contid]
                    )
                if rc and rc < 128:
                    self.logger.warning(
                        "%s: podman stop on cmd failed: %s",
                        self,
                        cmd_error(rc, o, e),
                    )
                else:
                    # It's gone
                    self.cmd_p = None

            # now remove the container
            self.logger.debug("podman rm on container: %s", contid)
            rc, o, e = await self.async_cmd_status_nsonly(
                [get_exec_path_host("podman"), "rm", contid]
            )
            if rc:
                self.logger.warning(
                    "%s: podman rm failed: %s", self, cmd_error(rc, o, e)
                )
            else:
                self.logger.debug(
                    "podman removed container %s: %s", contid, cmd_error(rc, o, e)
                )

        await super()._async_delete()


class L3QemuVM(L3NodeMixin, LinuxNamespace):
    """An VM (qemu) based L3 node."""

    def __init__(self, name, config, **kwargs):
        """Create a Container Node."""
        self.cont_exec_paths = {}
        self.launch_p = None
        self.launch_pid = None
        self.qemu_config = config["qemu"]
        self.extra_mounts = []
        assert self.qemu_config
        self.cmdrepl = None
        self.conrepl = None
        self.is_kvm = False
        self.monrepl = None
        self.tapfds = {}
        self.cpu_thread_map = {}

        self.tapnames = {}

        self.use_ssh = False
        self.__base_cmd = []
        self.__base_cmd_pty = []

        super().__init__(name=name, config=config, pid=False, **kwargs)

        self.sockdir = self.rundir.joinpath("s")
        self.cmd_raises(f"mkdir -p {self.sockdir}")

        self.qemu_config = config_subst(
            self.qemu_config,
            name=self.name,
            rundir=os.path.join(self.rundir, self.name),
            configdir=self.unet.config_dirname,
        )
        self.ssh_keyfile = self.qemu_config.get("sshkey")

    @property
    def is_vm(self):
        return True

    def __setup_ssh(self):
        if not self.ssh_keyfile:
            self.logger.warning("%s: No sshkey config", self)
            return False
        if not self.mgmt_ip and not self.mgmt_ip6:
            self.logger.warning("%s: No mgmt IP to ssh to", self)
            return False
        mgmt_ip = self.mgmt_ip if self.mgmt_ip else self.mgmt_ip6

        #
        # Since we have a keyfile shouldn't need to sudo
        # self.user = os.environ.get("SUDO_USER", "")
        # if not self.user:
        #     self.user = getpass.getuser()
        # self.__base_cmd = [
        #     get_exec_path_host("sudo"),
        #     "-E",
        #     f"-u{self.user}",
        #     get_exec_path_host("ssh"),
        # ]
        #
        port = 22
        self.__base_cmd = [get_exec_path_host("ssh")]
        if port != 22:
            self.__base_cmd.append(f"-p{port}")
        self.__base_cmd.append("-i")
        self.__base_cmd.append(self.ssh_keyfile)
        self.__base_cmd.append("-q")
        self.__base_cmd.append("-oStrictHostKeyChecking=no")
        self.__base_cmd.append("-oUserKnownHostsFile=/dev/null")
        # Would be nice but has to be accepted by server config so not very useful.
        # self.__base_cmd.append("-oSendVar='TEST'")
        self.__base_cmd_pty = list(self.__base_cmd)
        self.__base_cmd_pty.append("-t")

        user = self.qemu_config.get("sshuser", "root")
        self.__base_cmd.append(f"{user}@{mgmt_ip}")
        self.__base_cmd.append("--")
        self.__base_cmd_pty.append(f"{user}@{mgmt_ip}")
        # self.__base_cmd_pty.append("--")
        return True

    def _get_cmd_as_list(self, cmd):
        """Given a list or string return a list form for execution.

        If cmd is a string then [cmd] is returned, for most other
        node types ["bash", "-c", cmd] is returned but in our case
        ssh is the shell.

        Args:
            cmd: list or string representing the command to execute.
            str_shell: if True and `cmd` is a string then run the
              command using bash -c
        Returns:
            list of commands to execute.
        """
        if self.use_ssh and self.launch_p:
            return [cmd] if isinstance(cmd, str) else cmd
        return super()._get_cmd_as_list(cmd)

    def _get_pre_cmd(self, use_str, use_pty, ns_only=False, root_level=False, **kwargs):
        if ns_only:
            return super()._get_pre_cmd(
                use_str, use_pty, ns_only=True, root_level=root_level, **kwargs
            )

        if not self.launch_p:
            self.logger.debug("%s: Running command in namespace b/c no VM", self)
            return super()._get_pre_cmd(
                use_str, use_pty, ns_only=True, root_level=root_level, **kwargs
            )

        if not self.use_ssh:
            self.logger.debug(
                "%s: Running command in namespace b/c no SSH configured", self
            )
            return super()._get_pre_cmd(
                use_str, use_pty, ns_only=True, root_level=root_level, **kwargs
            )

        pre_cmd = self.unet._get_pre_cmd(use_str, use_pty, ns_only=True)

        # This is going to run in the process namespaces.
        # We really want it to run in the munet namespace which will
        # be different unless unshare_inline was used.
        #
        # XXX grab the env from kwargs and add to podman exec
        # env = kwargs.get("env", {})
        if use_pty:
            pre_cmd = pre_cmd + self.__base_cmd_pty
        else:
            pre_cmd = pre_cmd + self.__base_cmd
        return shlex.join(pre_cmd) if use_str else pre_cmd

    async def moncmd(self):
        """Uses internal REPL to send cmmand to qemu monitor and get reply."""

    def tmpfs_mount(self, inner):
        # eventually would be nice to support live mounting
        self.logger.debug("Mounting tmpfs on %s", inner)
        self.extra_mounts.append(("", inner, ""))

    #
    # bind_mount is actually being used to mount into the namespace
    #
    # def bind_mount(self, outer, inner):
    #     # eventually would be nice to support live mounting
    #     assert not self.container_id
    #     if self.test_host("-f", outer):
    #         self.logger.warning("Can't bind mount files with L3QemuVM: %s", outer)
    #         return
    #     self.logger.debug("Bind mounting %s on %s", outer, inner)
    #     if not self.test_host("-e", outer):
    #         self.cmd_raises(f"mkdir -p {outer}")
    #     self.extra_mounts.append((outer, inner, ""))

    def mount_volumes(self):
        """Mount volumes from the config."""
        args = []
        for m in self.config.get("volumes", []):
            if not isinstance(m, str):
                continue
            s = m.split(":", 1)
            if len(s) == 1:
                args.append(("", s[0], ""))
            else:
                spath = s[0]
                spath = os.path.abspath(
                    os.path.join(
                        os.path.dirname(self.unet.config["config_pathname"]), spath
                    )
                )
                if not self.test_nsonly("-e", spath):
                    self.cmd_raises_nsonly(f"mkdir -p {spath}")
                args.append((spath, s[1], ""))

        for m in self.config.get("mounts", []):
            src = m.get("src", m.get("source", ""))
            if src:
                src = os.path.abspath(
                    os.path.join(
                        os.path.dirname(self.unet.config["config_pathname"]), src
                    )
                )
                if not self.test_nsonly("-e", src):
                    self.cmd_raises_nsonly(f"mkdir -p {src}")
            dst = m.get("dst", m.get("destination"))
            assert dst, "destination path required for mount"

            margs = []
            for k, v in m.items():
                if k in ["destination", "dst", "source", "src"]:
                    continue
                if k == "type":
                    assert v in ["bind", "tmpfs"]
                    continue
                if not v:
                    margs.append(k)
                else:
                    margs.append(f"{k}={v}")
            args.append((src, dst, ",".join(margs)))

        if args:
            self.extra_mounts += args

    async def run_cmd(self):
        """Run the configured commands for this node inside VM."""
        self.logger.debug(
            "[rundir %s exists %s]", self.rundir, os.path.exists(self.rundir)
        )

        cmd = self.config.get("cmd", "").strip()
        if not cmd:
            self.logger.debug("%s: no `cmd` to run", self)
            return None

        shell_cmd = self.config.get("shell", "/bin/bash")
        if not isinstance(shell_cmd, str):
            if shell_cmd:
                shell_cmd = "/bin/bash"
            else:
                shell_cmd = ""

        if shell_cmd:
            cmd = cmd.rstrip()
            cmd = f"#!{shell_cmd}\n" + cmd
            cmd = cmd.replace("%CONFIGDIR%", str(self.unet.config_dirname))
            cmd = cmd.replace("%RUNDIR%", str(self.rundir))
            cmd = cmd.replace("%NAME%", str(self.name))
            cmd += "\n"

            # Write a copy to the rundir
            cmdpath = os.path.join(self.rundir, "cmd.shebang")
            with open(cmdpath, mode="w+", encoding="utf-8") as cmdfile:
                cmdfile.write(cmd)
            commander.cmd_raises(f"chmod 755 {cmdpath}")

            # Now write a copy inside the VM
            self.conrepl.cmd_status("cat > /tmp/cmd.shebang << EOF\n" + cmd + "\nEOF")
            self.conrepl.cmd_status("chmod 755 /tmp/cmd.shebang")
            cmds = "/tmp/cmd.shebang"
        else:
            cmd = cmd.replace("%CONFIGDIR%", str(self.unet.config_dirname))
            cmd = cmd.replace("%RUNDIR%", str(self.rundir))
            cmd = cmd.replace("%NAME%", str(self.name))
            cmds = cmd

        # class future_proc:
        #     """Treat awaitable minimally as a proc."""
        #     def __init__(self, aw):
        #         self.aw = aw
        #         # XXX would be nice to have a real value here
        #         self.returncode = 0
        #     async def wait(self):
        #         if self.aw:
        #             return await self.aw
        #         return None

        class now_proc:
            """Treat awaitable minimally as a proc."""

            def __init__(self, output):
                self.output = output
                self.returncode = 0

            async def wait(self):
                return self.output

        if self.cmdrepl:
            # self.cmd_p = future_proc(
            #     # We need our own console here b/c this is async and not returning
            #     # immediately
            #     # self.cmdrepl.run_command(cmds, timeout=120, async_=True)
            #     self.cmdrepl.run_command(cmds, timeout=120)
            # )

            # When run_command supports async_ arg we can use the above...
            self.cmd_p = now_proc(self.cmdrepl.run_command(cmds, timeout=120))

            # stdout and err both combined into logfile from the spawned repl
            stdout = os.path.join(self.rundir, "_cmdcon-log.txt")
            self.pytest_hook_run_cmd(stdout, None)
        else:
            # If we only have a console we can't run in parallel, so run to completion
            self.cmd_p = now_proc(self.conrepl.run_command(cmds, timeout=120))

        return self.cmd_p

    # InterfaceMixin override
    # We need a name unique in the shared namespace.
    def get_ns_ifname(self, ifname):
        return self.name + ifname

    async def add_host_intf(self, hname, lname, mtu=None):
        # L3QemuVM needs it's own add_host_intf for macvtap, We need to create the tap
        # in the host then move that interface so that the ifindex/devfile are
        # different.

        if hname in self.host_intfs:
            return

        self.host_intfs[hname] = lname
        index = len(self.host_intfs)

        tapindex = self.unet.tapcount
        self.unet.tapcount = self.unet.tapcount + 1

        tapname = f"tap{tapindex}"
        self.tapnames[hname] = tapname

        mac = f"02:bb:bb:bb:{index:02x}:{self.id:02x}"
        self.tapmacs[hname] = mac

        self.unet.rootcmd.cmd_raises(
            f"ip link add link {hname} name {tapname} type macvtap"
        )
        if mtu:
            self.unet.rootcmd.cmd_raises(f"ip link set {tapname} mtu {mtu}")
        self.unet.rootcmd.cmd_raises(f"ip link set {tapname} address {mac} up")
        ifindex = self.unet.rootcmd.cmd_raises(
            f"cat /sys/class/net/{tapname}/ifindex"
        ).strip()
        # self.unet.rootcmd.cmd_raises(f"ip link set {tapname} netns {self.pid}")

        tapfile = f"/dev/tap{ifindex}"
        fd = os.open(tapfile, os.O_RDWR)
        self.tapfds[hname] = fd
        self.logger.info(
            "%s: Add host intf: created macvtap interface %s (%s) on %s fd %s",
            self,
            tapname,
            tapfile,
            hname,
            fd,
        )

    async def rem_host_intf(self, hname):
        tapname = self.tapnames[hname]
        self.unet.rootcmd.cmd_raises(f"ip link set {tapname} down")
        self.unet.rootcmd.cmd_raises(f"ip link delete {tapname} type macvtap")
        del self.tapnames[hname]
        del self.host_intfs[hname]

    async def create_tap(self, index, ifname, mtu=None, driver="virtio-net-pci"):
        # XXX we shouldn't be doign a tap on a bridge with a veth
        # we should just be using a tap created earlier which was connected to the
        # bridge. Except we need to handle the case of p2p qemu <-> namespace
        #
        ifname = self.get_ns_ifname(ifname)
        brname = f"{self.name}br{index}"

        tapindex = self.unet.tapcount
        self.unet.tapcount += 1

        mac = f"02:aa:aa:aa:{index:02x}:{self.id:02x}"
        # nic = "tap,model=virtio-net-pci"
        # qemu -net nic,model=virtio,addr=1a:46:0b:ca:bc:7b -net tap,fd=3 3<>/dev/tap11
        self.cmd_raises(f"ip address flush dev {ifname}")
        self.cmd_raises(f"ip tuntap add tap{tapindex} mode tap")
        self.cmd_raises(f"ip link add name {brname} type bridge")
        self.cmd_raises(f"ip link set dev {ifname} master {brname}")
        self.cmd_raises(f"ip link set dev tap{tapindex} master {brname}")
        if mtu:
            self.cmd_raises(f"ip link set dev tap{tapindex} mtu {mtu}")
            self.cmd_raises(f"ip link set dev {ifname} mtu {mtu}")
        self.cmd_raises(f"ip link set dev tap{tapindex} up")
        self.cmd_raises(f"ip link set dev {ifname} up")
        self.cmd_raises(f"ip link set dev {brname} up")
        dev = f"{driver},netdev=n{index},mac={mac}"
        return [
            "-netdev",
            f"tap,id=n{index},ifname=tap{tapindex},script=no,downscript=no",
            "-device",
            dev,
        ]

    async def mount_mounts(self):
        """Mount any shared directories."""
        self.logger.info("Mounting shared directories")
        con = self.conrepl
        for i, m in enumerate(self.extra_mounts):
            outer, mp, uargs = m
            if not outer:
                con.cmd_raises(f"mkdir -p {mp}")
                margs = f"-o {uargs}" if uargs else ""
                con.cmd_raises(f"mount {margs} -t tmpfs tmpfs {mp}")
                continue

            uargs = "" if uargs is None else uargs
            margs = "trans=virtio"
            if uargs:
                margs += f",{uargs}"
            self.logger.info("Mounting %s on %s with %s", outer, mp, margs)
            con.cmd_raises(f"mkdir -p {mp}")
            con.cmd_raises(f"mount -t 9p -o {margs} shared{i} {mp}")

    async def renumber_interfaces(self):
        """Re-number the interfaces.

        After VM comes up need to renumber the interfaces now on the inside.
        """
        self.logger.info("Renumbering interfaces")
        con = self.conrepl
        con.cmd_raises("sysctl -w net.ipv4.ip_forward=1")
        if self.unet.ipv6_enable:
            self.cmd_raises("sysctl -w net.ipv6.conf.all.forwarding=1")
        for ifname in sorted(self.intfs):
            conn = find_with_kv(self.config.get("connections"), "name", ifname)
            to = conn["to"]
            switch = self.unet.switches.get(to)
            mtu = conn.get("mtu")
            if not mtu and switch:
                mtu = switch.config.get("mtu")
            if mtu:
                con.cmd_raises(f"ip link set {ifname} mtu {mtu}")
            con.cmd_raises(f"ip link set {ifname} up")
            # In case there was some preconfig e.g., cloud-init
            con.cmd_raises(f"ip -4 addr flush dev {ifname}")
            sw_is_nat = switch and hasattr(switch, "is_nat") and switch.is_nat
            if ifaddr := self.get_intf_addr(ifname, ipv6=False):
                con.cmd_raises(f"ip addr add {ifaddr} dev {ifname}")
                if sw_is_nat:
                    # In case there was some preconfig e.g., cloud-init
                    con.cmd_raises("ip route flush exact default")
                    con.cmd_raises(f"ip route add default via {switch.ip_address}")
            if ifaddr := self.get_intf_addr(ifname, ipv6=True):
                con.cmd_raises(f"ip -6 addr add {ifaddr} dev {ifname}")
                if sw_is_nat:
                    # In case there was some preconfig e.g., cloud-init
                    con.cmd_raises("ip -6 route flush exact default")
                    con.cmd_raises(f"ip -6 route add default via {switch.ip6_address}")
        con.cmd_raises("ip link set lo up")

        # This is already mounted now
        # if self.unet.cfgopt.getoption("--coverage"):
        #     con.cmd_raises("mount -t debugfs none /sys/kernel/debug")

    async def gather_coverage_data(self):
        con = self.conrepl

        gcda = "/sys/kernel/debug/gcov"
        tmpdir = con.cmd_raises("mktemp -d").strip()
        dest = "/gcov-data.tgz"
        con.cmd_raises(rf"find {gcda} -type d -exec mkdir -p {tmpdir}/{{}} \;")
        con.cmd_raises(
            rf"find {gcda} -name '*.gcda' -exec sh -c 'cat < $0 > {tmpdir}/$0' {{}} \;"
        )
        con.cmd_raises(
            rf"find {gcda} -name '*.gcno' -exec sh -c 'cp -d $0 {tmpdir}/$0' {{}} \;"
        )
        con.cmd_raises(rf"tar cf - -C {tmpdir} sys | gzip -c > {dest}")
        con.cmd_raises(rf"rm -rf {tmpdir}")
        self.logger.info("Saved coverage data in VM at %s", dest)
        if self.use_ssh:
            ldest = os.path.join(self.rundir, "gcov-data.tgz")
            self.cmd_raises(["/bin/cat", dest], stdout=open(ldest, "wb"))
            self.logger.info("Saved coverage data on host at %s", ldest)

    async def _opencons(
        self,
        *cnames,
        prompt=None,
        is_bourne=True,
        user="root",
        password="",
        expects=None,
        sends=None,
        timeout=-1,
    ):
        """Open consoles based on socket file names."""
        timeo = Timeout(timeout)
        cons = []
        for cname in cnames:
            sockpath = os.path.join(self.sockdir, cname)
            connected = False
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            while self.launch_p.returncode is None and not timeo.is_expired():
                try:
                    sock.connect(sockpath)
                    connected = True
                    break
                except OSError as error:
                    if error.errno == errno.ENOENT:
                        self.logger.debug("waiting for console socket: %s", sockpath)
                    else:
                        self.logger.warning(
                            "can't open console socket: %s", error.strerror
                        )
                        raise
                elapsed = int(timeo.elapsed())
                if elapsed <= 3:
                    await asyncio.sleep(0.25)
                else:
                    self.logger.info(
                        "%s: launch (qemu) taking more than %ss", self, elapsed
                    )
                    await asyncio.sleep(1)

            if connected:
                if prompt is None:
                    prompt = r"(^|\r\n)[^#\$]*[#\$] "
                cons.append(
                    await self.console(
                        sock,
                        prompt=prompt,
                        is_bourne=is_bourne,
                        user=user,
                        password=password,
                        use_pty=False,
                        logfile_prefix=cname,
                        will_echo=True,
                        expects=expects,
                        sends=sends,
                        timeout=timeout,
                        trace=True,
                    )
                )
            elif self.launch_p.returncode is not None:
                self.logger.warning(
                    "%s: launch (qemu) exited quickly (%ss) rc: %s",
                    self,
                    timeo.elapsed(),
                    self.launch_p.returncode,
                )
                raise Exception("Qemu launch exited early")
            elif timeo.is_expired():
                self.logger.critical(
                    "%s: timeout (%ss) waiting for qemu to start",
                    self,
                    timeo.elapsed(),
                )
                assert not timeo.is_expired()

        return cons

    async def set_cpu_affinity(self, afflist):
        for i, aff in enumerate(afflist):
            if not aff:
                continue
            # affmask = convert_ranges_to_bitmask(aff)
            if i not in self.cpu_thread_map:
                logging.warning("affinity %s given for missing vcpu %s", aff, i)
                continue
            logging.info("setting vcpu %s affinity to %s", i, aff)
            tid = self.cpu_thread_map[i]
            self.cmd_raises_nsonly(f"taskset -cp {aff} {tid}")

    async def launch(self):
        """Launch qemu."""
        self.logger.info("%s: Launch Qemu", self)

        qc = self.qemu_config
        cc = qc.get("console", {})
        bootd = "d" if "iso" in qc else "c"
        # args = [get_exec_path_host("qemu-system-x86_64"),
        #         "-nodefaults", "-boot", bootd]
        args = [get_exec_path_host("qemu-system-x86_64"), "-boot", bootd]

        args += ["-machine", "q35"]

        if qc.get("kvm"):
            rc, _, e = await self.async_cmd_status_nsonly("ls -l /dev/kvm")
            if rc:
                self.logger.warning("Can't enable KVM no /dev/kvm: %s", e)
            else:
                # [args += ["-enable-kvm", "-cpu", "host"]
                # uargs += ["-accel", "kvm", "-cpu", "Icelake-Server-v5"]
                args += ["-accel", "kvm", "-cpu", "host"]

        if ncpu := qc.get("ncpu"):
            # args += ["-smp", f"sockets={ncpu}"]
            args += ["-smp", f"cores={ncpu}"]
            # args += ["-smp", f"{ncpu},sockets={ncpu},cores=1,threads=1"]

        args.extend(["-m", str(qc.get("memory", "512M"))])

        if "bios" in qc:
            if qc["bios"] == "open-firmware":
                args.extend(["-bios", "/usr/share/qemu/OVMF.fd"])
            else:
                args.extend(["-bios", qc["bios"]])
        if "kernel" in qc:
            args.extend(["-kernel", qc["kernel"]])
        if "initrd" in qc:
            args.extend(["-initrd", qc["initrd"]])
        if "iso" in qc:
            args.extend(["-cdrom", qc["iso"]])

        # we only have append if we have a kernel
        if "kernel" in qc:
            args.append("-append")
            root = qc.get("root", "/dev/ram0")
            # Only 1 serial console the other ports (ttyS[123] hvc[01]) should have
            # gettys in inittab
            append = f"root={root} rw console=ttyS0"
            if "cmdline-extra" in qc:
                append += f" {qc['cmdline-extra']}"
            args.append(append)

        if "extra-args" in qc:
            if isinstance(qc["extra-args"], list):
                args.extend(qc["extra-args"])
            else:
                args.extend(shlex.split(qc["extra-args"]))

        # Walk the list of connections in order so we attach them the same way
        pass_fds = []
        nnics = 0
        pciaddr = 3
        for index, conn in enumerate(self.config["connections"]):
            devaddr = conn.get("physical", "")
            hostintf = conn.get("hostintf", "")
            if devaddr:
                # if devaddr in self.tapmacs:
                #     mac = f",mac={self.tapmacs[devaddr]}"
                # else:
                #     mac = ""
                args += ["-device", f"vfio-pci,host={devaddr},addr={pciaddr}"]
            elif hostintf:
                fd = self.tapfds[hostintf]
                mac = self.tapmacs[hostintf]
                args += [
                    "-nic",
                    f"tap,model=virtio-net-pci,mac={mac},fd={fd},addr={pciaddr}",
                ]
                pass_fds.append(fd)
                nnics += 1
            elif not hostintf:
                driver = conn.get("driver", "virtio-net-pci")
                mtu = conn.get("mtu")
                if not mtu and conn["to"] in self.unet.switches:
                    mtu = self.unet.switches[conn["to"]].config.get("mtu")
                tapargs = await self.create_tap(
                    index, conn["name"], mtu=mtu, driver=driver
                )
                tapargs[-1] += f",addr={pciaddr}"
                args += tapargs
                nnics += 1
            pciaddr += 1
        if not nnics:
            args += ["-nic", "none"]

        dtpl = qc.get("disk-template")
        diskpath = disk = qc.get("disk")
        if dtpl and not disk:
            disk = qc["disk"] = f"{self.name}-{os.path.basename(dtpl)}"
            diskpath = os.path.join(self.rundir, disk)
            if self.path_exists(diskpath):
                logging.debug("Disk '%s' file exists, using.", diskpath)
            else:
                dtplpath = os.path.abspath(
                    os.path.join(
                        os.path.dirname(self.unet.config["config_pathname"]), dtpl
                    )
                )
                logging.info("Create disk '%s' from template '%s'", diskpath, dtplpath)
                self.cmd_raises(
                    f"qemu-img create -f qcow2 -F qcow2 -b {dtplpath} {diskpath}"
                )

        if diskpath:
            args.extend(
                ["-drive", f"file={diskpath},if=none,id=sata-disk0,format=qcow2"]
            )
            args.extend(["-device", "ahci,id=ahci"])
            args.extend(["-device", "ide-hd,bus=ahci.0,drive=sata-disk0"])

        use_stdio = cc.get("stdio", True)
        has_cmd = self.config.get("cmd")
        use_cmdcon = has_cmd and use_stdio

        #
        # Any extra serial/console ports beyond thw first, require entries in
        # inittab to have getty running on them, modify inittab
        #
        # Use -serial stdio for output only, and as the first serial console
        # which kernel uses for printk, as it has serious issues with dropped
        # input chars for some reason.
        #
        # 4 serial ports (max), we'll add extra ports using virtual consoles.
        _sd = self.sockdir
        if use_stdio:
            args += ["-serial", "stdio"]
        args += ["-serial", f"unix:{_sd}/_console,server,nowait"]
        if use_cmdcon:
            args += [
                "-serial",
                f"unix:{_sd}/_cmdcon,server,nowait",
            ]
        args += [
            "-serial",
            f"unix:{_sd}/console,server,nowait",
            # A 2 virtual consoles - /dev/hvc[01]
            # Requires CONFIG_HVC_DRIVER=y CONFIG_VIRTIO_CONSOLE=y
            "-device",
            "virtio-serial",  # serial console bus
            "-chardev",
            f"socket,path={_sd}/vcon0,server=on,wait=off,id=vcon0",
            "-chardev",
            f"socket,path={_sd}/vcon1,server=on,wait=off,id=vcon1",
            "-device",
            "virtconsole,chardev=vcon0",
            "-device",
            "virtconsole,chardev=vcon1",
            # 2 monitors
            "-monitor",
            f"unix:{_sd}/_monitor,server,nowait",
            "-monitor",
            f"unix:{_sd}/monitor,server,nowait",
            "-gdb",
            f"unix:{_sd}/gdbserver,server,nowait",
        ]

        for i, m in enumerate(self.extra_mounts):
            args += [
                "-virtfs",
                f"local,path={m[0]},mount_tag=shared{i},security_model=passthrough",
            ]

        args += ["-nographic"]

        #
        # Launch Qemu
        #

        stdout = open(os.path.join(self.rundir, "qemu.out"), "wb")
        stderr = open(os.path.join(self.rundir, "qemu.err"), "wb")
        self.launch_p = await self.async_popen_nsonly(
            args,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            pass_fds=pass_fds,
            # Don't want Keybaord interrupt etc to pass to child.
            # start_new_session=True,
            preexec_fn=os.setsid,
        )

        if self.nsenter_fork:
            self.launch_pid = await self.get_proc_child_pid(self.launch_p)

        self.pytest_hook_run_cmd(stdout, stderr)

        # We've passed these on, so don't need these open here anymore.
        for fd in pass_fds:
            os.close(fd)

        self.logger.debug(
            "%s: popen => %s (%s)", self, self.launch_p.pid, self.launch_pid
        )

        confiles = ["_console"]
        if use_cmdcon:
            confiles.append("_cmdcon")

        #
        # Connect to the console socket, retrying
        #
        prompt = cc.get("prompt")
        cons = await self._opencons(
            *confiles,
            prompt=prompt,
            is_bourne=not bool(prompt),
            user=cc.get("user", "root"),
            password=cc.get("password", ""),
            expects=cc.get("expects"),
            sends=cc.get("sends"),
            timeout=int(cc.get("timeout", 60)),
        )
        self.conrepl = cons[0]
        if use_cmdcon:
            self.cmdrepl = cons[1]
        self.monrepl = await self.monitor(os.path.join(self.sockdir, "_monitor"))

        # the monitor output has super annoying ANSI escapes in it

        output = self.monrepl.cmd_nostatus("info status")
        self.logger.debug("VM status: %s", output)

        output = self.monrepl.cmd_nostatus("info kvm")
        self.logger.debug("KVM status: %s", output)

        #
        # Set thread affinity
        #
        output = self.monrepl.cmd_nostatus("info cpus")
        matches = re.findall(r"CPU #(\d+): *thread_id=(\d+)", output)
        self.cpu_thread_map = {int(k): int(v) for k, v in matches}
        if cpuaff := self.qemu_config.get("cpu-affinity"):
            await self.set_cpu_affinity(cpuaff)

        self.is_kvm = "disabled" not in output

        if qc.get("unix-os", True):
            await self.renumber_interfaces()

        if self.extra_mounts:
            await self.mount_mounts()

        self.use_ssh = bool(self.ssh_keyfile)
        if self.use_ssh:
            self.use_ssh = self.__setup_ssh()

        self.pytest_hook_open_shell()

        return self.launch_p

    def launch_completed(self, future):
        self.logger.debug("%s: launch (qemu) completed called", self)
        self.use_ssh = False
        try:
            n = future.result()
            self.logger.debug("%s: node launch (qemu) completed result: %s", self, n)
        except asyncio.CancelledError as error:
            self.logger.debug(
                "%s: node launch (qemu) cmd wait() canceled: %s", future, error
            )

    async def async_cleanup_cmd(self):
        """Run the configured cleanup commands for this node."""
        self.cleanup_called = True

        if "cleanup-cmd" not in self.config:
            return

        if not self.launch_p:
            self.logger.warning("async_cleanup_cmd: qemu no longer running")
            return

        raise NotImplementedError("Needs to be like run_cmd")
        # return await self._async_cleanup_cmd()

    async def _async_delete(self):
        self.logger.debug("%s: deleting", self)

        # Need to cleanup early b/c it is running on the VM
        if self.cmd_p:
            await self.async_cleanup_proc(self.cmd_p, self.cmd_pid)
            self.cmd_p = None

        try:
            # Need to cleanup early b/c it is running on the VM
            if not self.cleanup_called:
                await self.async_cleanup_cmd()
        except Exception as error:
            self.logger.warning(
                "Got an error during delete from async_cleanup_cmd: %s", error
            )

        try:
            if not self.launch_p:
                self.logger.warning("async_delete: qemu is not running")
            else:
                await self.async_cleanup_proc(self.launch_p, self.launch_pid)
        except Exception as error:
            self.logger.warning("%s: failed to cleanup qemu process: %s", self, error)

        await super()._async_delete()


class Munet(BaseMunet):
    """Munet."""

    def __init__(
        self,
        rundir=None,
        config=None,
        pid=True,
        logger=None,
        **kwargs,
    ):
        # logging.warning("Munet")

        if not rundir:
            rundir = "/tmp/munet"

        if logger is None:
            logger = logging.getLogger("munet.unet")

        super().__init__("munet", pid=pid, rundir=rundir, logger=logger, **kwargs)

        self.built = False
        self.tapcount = 0

        self.cmd_raises(f"mkdir -p {self.rundir} && chmod 755 {self.rundir}")
        self.set_ns_cwd(self.rundir)

        if not config:
            config = {}
        self.config = config
        if "config_pathname" in config:
            self.config_pathname = os.path.realpath(config["config_pathname"])
            self.config_dirname = os.path.dirname(self.config_pathname)
        else:
            self.config_pathname = ""
            self.config_dirname = ""

        # Done in BaseMunet now
        # # We need some way to actually get back to the root namespace
        # if not self.isolated:
        #     self.rootcmd = commander
        # else:
        #     spid = str(pid)
        #     nsflags = (f"--mount={self.proc_path / spid / 'ns/mnt'}",
        #                f"--net={self.proc_path / spid / 'ns/net'}",
        #                f"--uts={self.proc_path / spid / 'ns/uts'}",
        #                f"--ipc={self.proc_path / spid / 'ns/ipc'}",
        #                f"--cgroup={self.proc_path / spid / 'ns/cgroup'}",
        #                f"--pid={self.proc_path / spid / 'ns/net'}",
        #     self.rootcmd = SharedNamespace("host", pid=1, nsflags=nsflags)

        # Save the namespace pid
        with open(os.path.join(self.rundir, "nspid"), "w", encoding="ascii") as f:
            f.write(f"{self.pid}\n")

        with open(os.path.join(self.rundir, "nspids"), "w", encoding="ascii") as f:
            f.write(f'{" ".join([str(x) for x in self.pids])}\n')

        hosts_file = os.path.join(self.rundir, "hosts.txt")
        with open(hosts_file, "w", encoding="ascii") as hf:
            hf.write(
                f"""127.0.0.1\tlocalhost {self.name}
::1\tip6-localhost ip6-loopback
fe00::0\tip6-localnet
ff00::0\tip6-mcastprefix
ff02::1\tip6-allnodes
ff02::2\tip6-allrouters
"""
            )
        self.bind_mount(hosts_file, "/etc/hosts")

        # Common CLI commands for any topology
        cdict = {
            "commands": [
                {
                    "name": "pcap",
                    "format": "pcap NETWORK",
                    "help": (
                        "capture packets from NETWORK into file capture-NETWORK.pcap"
                        " the command is run within a new window which also shows"
                        " packet summaries. NETWORK can also be an interface specified"
                        " as HOST:INTF. To capture inside the host namespace."
                    ),
                    "exec": "tshark -s 9200 -i {0} -P -w capture-{0}.pcap",
                    "top-level": True,
                    "new-window": {"background": True},
                },
                {
                    "name": "nsterm",
                    "format": "nsterm HOST [HOST ...]",
                    "help": (
                        "open terminal[s] in the namespace only"
                        " (outside containers or VM), * for all"
                    ),
                    "exec": "bash",
                    "new-window": {"ns_only": True},
                },
                {
                    "name": "term",
                    "format": "term HOST [HOST ...]",
                    "help": "open terminal[s] (TMUX or XTerm) on HOST[S], * for all",
                    "exec": "bash",
                    "new-window": True,
                },
                {
                    "name": "xterm",
                    "format": "xterm HOST [HOST ...]",
                    "help": "open XTerm[s] on HOST[S], * for all",
                    "exec": "bash",
                    "new-window": {
                        "forcex": True,
                    },
                },
                {
                    "name": "sh",
                    "format": "[HOST ...] sh <SHELL-COMMAND>",
                    "help": "execute <SHELL-COMMAND> on hosts",
                    "exec": "{}",
                },
                {
                    "name": "shi",
                    "format": "[HOST ...] shi <INTERACTIVE-COMMAND>",
                    "help": "execute <INTERACTIVE-COMMAND> on HOST[s]",
                    "exec": "{}",
                    "interactive": True,
                },
                {
                    "name": "stdout",
                    "exec": (
                        "[ -e %RUNDIR%/qemu.out ] && tail -F %RUNDIR%/qemu.out "
                        "|| tail -F %RUNDIR%/cmd.out"
                    ),
                    "format": "stdout HOST [HOST ...]",
                    "help": "tail -f on the stdout of the qemu/cmd for this node",
                    "new-window": True,
                },
                {
                    "name": "stderr",
                    "exec": (
                        "[ -e %RUNDIR%/qemu.err ] && tail -F %RUNDIR%/qemu.err "
                        "|| tail -F %RUNDIR%/cmd.err"
                    ),
                    "format": "stderr HOST [HOST ...]",
                    "help": "tail -f on the stdout of the qemu/cmd for this node",
                    "new-window": True,
                },
            ]
        }

        cli.add_cli_config(self, cdict)

        if "cli" in config:
            cli.add_cli_config(self, config["cli"])

        if "topology" not in self.config:
            self.config["topology"] = {}

        self.topoconf = self.config["topology"]
        self.ipv6_enable = self.topoconf.get("ipv6-enable", False)

        if self.isolated:
            if not self.ipv6_enable:
                # Disable IPv6
                self.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=0")
                self.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=1")
            else:
                self.cmd_raises("sysctl -w net.ipv6.conf.all.autoconf=1")
                self.cmd_raises("sysctl -w net.ipv6.conf.all.disable_ipv6=0")

        # we really need overlay, but overlay-layers (used by overlay-images)
        # counts on things being present in overlay so this temp stuff doesn't work.
        # if self.isolated:
        #     # Let's hide podman details
        #     self.tmpfs_mount("/var/lib/containers/storage/overlay-containers")

        shellopt = self.cfgopt.getoption("--shell")
        shellopt = shellopt if shellopt else ""
        if shellopt == "all" or "." in shellopt.split(","):
            self.run_in_window("bash")

    def __del__(self):
        """Catch case of build object but not async_deleted."""
        if hasattr(self, "built"):
            if not self.deleting:
                logging.critical(
                    "Munet object deleted without calling `async_delete` for cleanup."
                )
        s = super()
        if hasattr(s, "__del__"):
            s.__del__(self)

    async def _async_build(self, logger=None):
        """Build the topology based on config."""
        if self.built:
            self.logger.warning("%s: is already built", self)
            return

        self.built = True

        # Allow for all networks to be auto-numbered
        topoconf = self.topoconf
        autonumber = self.autonumber
        ipv6_enable = self.ipv6_enable

        # ---------------------------------------------
        # Merge Kinds and perform variable substitution
        # ---------------------------------------------

        kinds = self.config.get("kinds", {})

        for name, conf in config_to_dict_with_key(topoconf, "networks", "name").items():
            if kind := conf.get("kind"):
                if kconf := kinds[kind]:
                    conf = merge_kind_config(kconf, conf)
            conf = config_subst(
                conf, name=name, rundir=self.rundir, configdir=self.config_dirname
            )
            if "ip" not in conf and autonumber:
                conf["ip"] = "auto"
            if "ipv6" not in conf and autonumber and ipv6_enable:
                conf["ipv6"] = "auto"
            topoconf["networks"][name] = conf
            self.add_network(name, conf, logger=logger)

        for name, conf in config_to_dict_with_key(topoconf, "nodes", "name").items():
            if kind := conf.get("kind"):
                if kconf := kinds[kind]:
                    conf = merge_kind_config(kconf, conf)

            config_to_dict_with_key(
                conf, "env", "name"
            )  # convert list of env objects to dict

            conf = config_subst(
                conf,
                name=name,
                rundir=os.path.join(self.rundir, name),
                configdir=self.config_dirname,
            )
            topoconf["nodes"][name] = conf
            self.add_l3_node(name, conf, logger=logger)

        # ------------------
        # Create connections
        # ------------------

        # Go through all connections and name them so they are sane to the user
        # otherwise when we do p2p links the names/ords skip around based oddly
        for name, node in self.hosts.items():
            nconf = node.config
            if "connections" not in nconf:
                continue
            nconns = []
            for cconf in nconf["connections"]:
                # Replace string only with a dictionary
                if isinstance(cconf, str):
                    splitconf = cconf.split(":", 1)
                    cconf = {"to": splitconf[0]}
                    if len(splitconf) == 2:
                        cconf["name"] = splitconf[1]
                # Allocate a name if not already assigned
                if "name" not in cconf:
                    cconf["name"] = node.get_next_intf_name()
                nconns.append(cconf)
            nconf["connections"] = nconns

        for name, node in self.hosts.items():
            nconf = node.config
            if "connections" not in nconf:
                continue
            for cconf in nconf["connections"]:
                # Eventually can add support for unconnected intf here.
                if "to" not in cconf:
                    continue
                to = cconf["to"]
                if to in self.switches:
                    switch = self.switches[to]
                    swconf = find_matching_net_config(name, cconf, switch.config)
                    await self.add_native_link(switch, node, swconf, cconf)
                elif cconf["name"] not in node.intfs:
                    # Only add the p2p interface if not already there.
                    other = self.hosts[to]
                    oconf = find_matching_net_config(name, cconf, other.config)
                    await self.add_native_link(node, other, cconf, oconf)

    @property
    def autonumber(self):
        return self.topoconf.get("networks-autonumber", False)

    @autonumber.setter
    def autonumber(self, value):
        self.topoconf["networks-autonumber"] = bool(value)

    async def add_native_link(self, node1, node2, c1=None, c2=None):
        """Add a link between switch and node or 2 nodes."""
        isp2p = False

        c1 = {} if c1 is None else c1
        c2 = {} if c2 is None else c2

        if node1.name in self.switches:
            assert node2.name in self.hosts
        elif node2.name in self.switches:
            assert node1.name in self.hosts
            node1, node2 = node2, node1
            c1, c2 = c2, c1
        else:
            # p2p link
            assert node1.name in self.hosts
            assert node1.name in self.hosts
            isp2p = True

        if "name" not in c1:
            c1["name"] = node1.get_next_intf_name()
        if1 = c1["name"]

        if "name" not in c2:
            c2["name"] = node2.get_next_intf_name()
        if2 = c2["name"]

        do_add_link = True
        for n, c in ((node1, c1), (node2, c2)):
            if "hostintf" in c:
                await n.add_host_intf(c["hostintf"], c["name"], mtu=c.get("mtu"))
                do_add_link = False
            elif "physical" in c:
                await n.add_phy_intf(c["physical"], c["name"])
                do_add_link = False
        if do_add_link:
            assert "hostintf" not in c1
            assert "hostintf" not in c2
            assert "physical" not in c1
            assert "physical" not in c2

            if isp2p:
                mtu1 = c1.get("mtu")
                mtu2 = c2.get("mtu")
                mtu = mtu1 if mtu1 else mtu2
                if mtu1 and mtu2 and mtu1 != mtu2:
                    self.logger.error("mtus differ for add_link %s != %s", mtu1, mtu2)
            else:
                mtu = c2.get("mtu")

            super().add_link(node1, node2, if1, if2, mtu=mtu)

        if isp2p:
            node1.set_p2p_addr(node2, c1, c2)
        else:
            node2.set_lan_addr(node1, c2)

        if "physical" not in c1 and not node1.is_vm:
            node1.set_intf_constraints(if1, **c1)
        if "physical" not in c2 and not node2.is_vm:
            node2.set_intf_constraints(if2, **c2)

    def add_l3_node(self, name, config=None, **kwargs):
        """Add a node to munet."""
        if config and config.get("image"):
            cls = L3ContainerNode
        elif config and config.get("qemu"):
            cls = L3QemuVM
        elif config and config.get("server"):
            cls = SSHRemote
            kwargs["server"] = config["server"]
            kwargs["port"] = int(config.get("server-port", 22))
            if "ssh-identity-file" in config:
                kwargs["idfile"] = config.get("ssh-identity-file")
            if "ssh-user" in config:
                kwargs["user"] = config.get("ssh-user")
            if "ssh-password" in config:
                kwargs["password"] = config.get("ssh-password")
        else:
            cls = L3NamespaceNode
        return super().add_host(name, cls=cls, config=config, **kwargs)

    def add_network(self, name, config=None, **kwargs):
        """Add a l2 or l3 switch to munet."""
        if config is None:
            config = {}

        cls = L3Bridge if config.get("ip") else L2Bridge
        mtu = kwargs.get("mtu", config.get("mtu"))
        return super().add_switch(name, cls=cls, config=config, mtu=mtu, **kwargs)

    async def run(self):
        tasks = []

        hosts = self.hosts.values()
        launch_nodes = [x for x in hosts if hasattr(x, "launch")]
        launch_nodes = [x for x in launch_nodes if x.config.get("qemu")]
        run_nodes = [x for x in hosts if hasattr(x, "has_run_cmd") and x.has_run_cmd()]
        ready_nodes = [
            x for x in hosts if hasattr(x, "has_ready_cmd") and x.has_ready_cmd()
        ]

        pcapopt = self.cfgopt.getoption("--pcap")
        pcapopt = pcapopt if pcapopt else ""
        if pcapopt == "all":
            pcapopt = self.switches.keys()
        if pcapopt:
            for pcap in pcapopt.split(","):
                if ":" in pcap:
                    host, intf = pcap.split(":")
                    pcap = f"{host}-{intf}"
                    host = self.hosts[host]
                else:
                    host = self
                    intf = pcap
                host.run_in_window(
                    f"tshark -s 9200 -i {intf} -P -w capture-{pcap}.pcap",
                    background=True,
                    title=f"cap:{pcap}",
                )

        if launch_nodes:
            # would like a info when verbose here.
            logging.debug("Launching nodes")
            await asyncio.gather(*[x.launch() for x in launch_nodes])

        logging.debug("Launched nodes -- Queueing Waits")

        # Watch for launched processes to exit
        for node in launch_nodes:
            task = asyncio.create_task(
                node.launch_p.wait(), name=f"Node-{node.name}-launch"
            )
            task.add_done_callback(node.launch_completed)
            tasks.append(task)

        logging.debug("Wait complete queued, running cmd")

        if run_nodes:
            # would like a info when verbose here.
            logging.debug("Running `cmd` on nodes")
            await asyncio.gather(*[x.run_cmd() for x in run_nodes])

        logging.debug("Ran cmds -- Queueing Waits")

        # Watch for run_cmd processes to exit
        for node in run_nodes:
            task = asyncio.create_task(node.cmd_p.wait(), name=f"Node-{node.name}-cmd")
            task.add_done_callback(node.cmd_completed)
            tasks.append(task)

        logging.debug("Wait complete queued, waiting for ready")

        # Wait for nodes to be ready
        if ready_nodes:

            async def wait_until_ready(x):
                while not await x.async_ready_cmd():
                    logging.debug("Waiting for ready on: %s", x)
                    await asyncio.sleep(0.25)
                logging.debug("%s is ready!", x)

            logging.debug("Waiting for ready on nodes: %s", ready_nodes)
            _, pending = await asyncio.wait(
                [wait_until_ready(x) for x in ready_nodes], timeout=30
            )
            if pending:
                logging.warning("Timeout waiting for ready: %s", pending)
                for nr in pending:
                    nr.cancel()
                raise asyncio.TimeoutError()
            logging.debug("All nodes ready")

        logging.debug("All done returning tasks: %s", tasks)

        return tasks

    async def _async_delete(self):
        from .testing.util import async_pause_test  # pylint: disable=C0415

        self.logger.debug("%s: deleting.", self)

        if self.cfgopt.getoption("--coverage"):
            nodes = (
                x for x in self.hosts.values() if hasattr(x, "gather_coverage_data")
            )
            try:
                await asyncio.gather(*(x.gather_coverage_data() for x in nodes))
            except Exception as error:
                logging.warning("Error gathering coverage data: %s", error)

        pause = bool(self.cfgopt.getoption("--pause-at-end"))
        pause = pause or bool(self.cfgopt.getoption("--pause"))
        if pause:
            try:
                await async_pause_test("Before MUNET delete")
            except KeyboardInterrupt:
                print("^C...continuing")
            except Exception as error:
                self.logger.error("\n...continuing after error: %s", error)

        # XXX should we cancel launch and run tasks?

        try:
            await super()._async_delete()
        except Exception as error:
            self.logger.error("Error cleaning up: %s", error, exc_info=True)
            raise


async def run_cmd_update_ceos(node, shell_cmd, cmds, cmd):
    cmd = cmd.strip()
    if shell_cmd or cmd != "/sbin/init":
        return cmds, cmd

    #
    # Add flash dir and mount it
    #
    flashdir = os.path.join(node.rundir, "flash")
    node.cmd_raises_nsonly(f"mkdir -p {flashdir} && chmod 775 {flashdir}")
    cmds += [f"--volume={flashdir}:/mnt/flash"]

    #
    # Startup config (if not present already)
    #
    if startup_config := node.config.get("startup-config", None):
        dest = os.path.join(flashdir, "startup-config")
        if os.path.exists(dest):
            node.logger.info("Skipping copy of startup-config, already present")
        else:
            source = os.path.join(node.unet.config_dirname, startup_config)
            node.cmd_raises_nsonly(f"cp {source} {dest} && chmod 664 {dest}")

    #
    # system mac address (if not present already
    #
    dest = os.path.join(flashdir, "system_mac_address")
    if os.path.exists(dest):
        node.logger.info("Skipping system-mac generation, already present")
    else:
        random_arista_mac = "00:1c:73:%02x:%02x:%02x" % (
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255),
        )
        system_mac = node.config.get("system-mac", random_arista_mac)
        with open(dest, "w", encoding="ascii") as f:
            f.write(system_mac + "\n")
        node.cmd_raises_nsonly(f"chmod 664 {dest}")

    args = []

    # Pass special args for the environment variables
    if "env" in node.config:
        args += [f"systemd.setenv={k}={v}" for k, v in node.config["env"].items()]

    return cmds, [cmd] + args


# XXX this is only used by the container code
kind_run_cmd_update = {"ceos": run_cmd_update_ceos}
