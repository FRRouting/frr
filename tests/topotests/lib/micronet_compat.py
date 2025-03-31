# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# July 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021-2023, LabN Consulting, L.L.C
#
import ipaddress
import os

from munet import cli
from munet.base import BaseMunet, LinuxNamespace


class Node(LinuxNamespace):
    """Node (mininet compat)."""

    def __init__(self, name, rundir=None, **kwargs):
        nkwargs = {}

        if "unet" in kwargs:
            nkwargs["unet"] = kwargs["unet"]
        if "private_mounts" in kwargs:
            nkwargs["private_mounts"] = kwargs["private_mounts"]
        if "logger" in kwargs:
            nkwargs["logger"] = kwargs["logger"]

        # This is expected by newer munet CLI code
        self.config_dirname = ""
        self.config = {"kind": "frr"}
        self.mgmt_ip = None
        self.mgmt_ip6 = None

        super().__init__(name, **nkwargs)

        self.rundir = self.unet.rundir.joinpath(self.name)

    def cmd(self, cmd, **kwargs):
        """Execute a command, joins stdout, stderr, ignores exit status."""

        return super(Node, self).cmd_legacy(cmd, **kwargs)

    def config_host(self, lo="up", **params):
        """Called by Micronet when topology is built (but not started)."""
        # mininet brings up loopback here.
        del params
        del lo

    def intfNames(self):
        return self.intfs

    def terminate(self):
        return

    def add_vlan(self, vlanname, linkiface, vlanid):
        self.logger.debug("Adding VLAN interface: %s (%s)", vlanname, vlanid)
        ip_path = self.get_exec_path("ip")
        assert ip_path, "XXX missing ip command!"
        self.cmd_raises(
            [
                ip_path,
                "link",
                "add",
                "link",
                linkiface,
                "name",
                vlanname,
                "type",
                "vlan",
                "id",
                vlanid,
            ]
        )
        self.cmd_raises([ip_path, "link", "set", "dev", vlanname, "up"])

    def add_loop(self, loopname):
        self.logger.debug("Adding Linux iface: %s", loopname)
        ip_path = self.get_exec_path("ip")
        assert ip_path, "XXX missing ip command!"
        self.cmd_raises([ip_path, "link", "add", loopname, "type", "dummy"])
        self.cmd_raises([ip_path, "link", "set", "dev", loopname, "up"])

    def add_l3vrf(self, vrfname, tableid):
        self.logger.debug("Adding Linux VRF: %s", vrfname)
        ip_path = self.get_exec_path("ip")
        assert ip_path, "XXX missing ip command!"
        self.cmd_raises(
            [ip_path, "link", "add", vrfname, "type", "vrf", "table", tableid]
        )
        self.cmd_raises([ip_path, "link", "set", "dev", vrfname, "up"])

    def del_iface(self, iface):
        self.logger.debug("Removing Linux Iface: %s", iface)
        ip_path = self.get_exec_path("ip")
        assert ip_path, "XXX missing ip command!"
        self.cmd_raises([ip_path, "link", "del", iface])

    def attach_iface_to_l3vrf(self, ifacename, vrfname):
        self.logger.debug("Attaching Iface %s to Linux VRF %s", ifacename, vrfname)
        ip_path = self.get_exec_path("ip")
        assert ip_path, "XXX missing ip command!"
        if vrfname:
            self.cmd_raises(
                [ip_path, "link", "set", "dev", ifacename, "master", vrfname]
            )
        else:
            self.cmd_raises([ip_path, "link", "set", "dev", ifacename, "nomaster"])

    set_cwd = LinuxNamespace.set_ns_cwd


class Topo(object):  # pylint: disable=R0205
    def __init__(self, *args, **kwargs):
        raise Exception("Remove Me")


class Mininet(BaseMunet):
    """
    Mininet using Micronet.
    """

    g_mnet_inst = None

    def __init__(self, rundir=None, pytestconfig=None, logger=None):
        """
        Create a Micronet.
        """
        if Mininet.g_mnet_inst is not None:
            Mininet.g_mnet_inst.stop()
        Mininet.g_mnet_inst = self

        self.configured_hosts = set()
        self.host_params = {}
        self.prefix_len = 8

        # SNMPd used to require this, which was set int he mininet shell
        # that all commands executed from. This is goofy default so let's not
        # do it if we don't have to. The snmpd.conf files have been updated
        # to set permissions to root:frr 770 to make this unneeded in that case
        # os.umask(0)

        super(Mininet, self).__init__(
            pid=False, rundir=rundir, pytestconfig=pytestconfig, logger=logger
        )

        # From munet/munet/native.py
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
                #
                # Window commands.
                #
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
                    "name": "term",
                    "format": "term HOST [HOST ...]",
                    "help": "open terminal[s] (TMUX or XTerm) on HOST[S], * for all",
                    "exec": "bash",
                    "new-window": True,
                },
                {
                    "name": "vtysh",
                    "exec": "/usr/bin/vtysh",
                    "format": "vtysh ROUTER [ROUTER ...]",
                    "new-window": True,
                    "kinds": ["frr"],
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
                    "name": "logd",
                    "exec": "tail -F %RUNDIR%/{}.log",
                    "format": "logd HOST [HOST ...] DAEMON",
                    "help": (
                        "tail -f on the logfile of the given "
                        "DAEMON for the given HOST[S]"
                    ),
                    "new-window": True,
                },
                {
                    "name": "stdlog",
                    "exec": (
                        "[ -e %RUNDIR%/frr.log ] && tail -F %RUNDIR%/frr.log "
                        "|| tail -F /var/log/frr.log"
                    ),
                    "format": "stdlog HOST [HOST ...]",
                    "help": "tail -f on the `frr.log` for the given HOST[S]",
                    "new-window": True,
                },
                {
                    "name": "stdout",
                    "exec": "tail -F %RUNDIR%/{0}.err",
                    "format": "stdout HOST [HOST ...] DAEMON",
                    "help": (
                        "tail -f on the stdout of the given DAEMON for the given HOST[S]"
                    ),
                    "new-window": True,
                },
                {
                    "name": "stderr",
                    "exec": "tail -F %RUNDIR%/{0}.out",
                    "format": "stderr HOST [HOST ...] DAEMON",
                    "help": (
                        "tail -f on the stderr of the given DAEMON for the given HOST[S]"
                    ),
                    "new-window": True,
                },
                #
                # Non-window commands.
                #
                {
                    "name": "",
                    "exec": "vtysh -c '{}'",
                    "format": "[ROUTER ...] COMMAND",
                    "help": "execute vtysh COMMAND on the router[s]",
                    "kinds": ["frr"],
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
            ]
        }

        cli.add_cli_config(self, cdict)

        shellopt = self.cfgopt.get_option_list("--shell")
        if "all" in shellopt or "." in shellopt:
            self.run_in_window("bash", title="munet")

        # This is expected by newer munet CLI code
        self.config_dirname = ""
        self.config = {}

        self.logger.debug("%s: Creating", self)

    def __str__(self):
        return "Mininet()"

    def configure_hosts(self):
        """
        Configure hosts once the topology has been built.

        This function can be called multiple times if routers are added to the topology
        later.
        """
        if not self.hosts:
            return

        self.logger.debug("Configuring hosts: %s", self.hosts.keys())

        for name in sorted(self.hosts.keys()):
            if name in self.configured_hosts:
                continue

            host = self.hosts[name]
            first_intf = host.intfs[0] if host.intfs else None
            params = self.host_params[name]

            if first_intf and "ip" in params:
                ip = params["ip"]
                i = ip.find("/")
                if i == -1:
                    plen = self.prefix_len
                else:
                    plen = int(ip[i + 1 :])
                    ip = ip[:i]

                host.cmd_raises("ip addr add {}/{} dev {}".format(ip, plen, first_intf))

                # can be used by munet cli
                host.mgmt_ip = ipaddress.ip_address(ip)

            if "defaultRoute" in params:
                host.cmd_raises(
                    "ip route add default {}".format(params["defaultRoute"])
                )

            host.config_host()

            self.configured_hosts.add(name)

    def add_host(self, name, cls=Node, **kwargs):
        """Add a host to micronet."""

        self.host_params[name] = kwargs
        super(Mininet, self).add_host(name, cls=cls, **kwargs)

    def start(self):
        """Start the micronet topology."""
        pcapopt = self.cfgopt.get_option_list("--pcap")
        if "all" in pcapopt:
            pcapopt = self.switches.keys()
        for pcap in pcapopt:
            if ":" in pcap:
                host, intf = pcap.split(":")
                pcap = f"{host}-{intf}"
                host = self.hosts[host]
            else:
                host = self
                intf = pcap
            pcapfile = f"{self.rundir}/capture-{pcap}.pcap"
            host.run_in_window(
                f"tshark -s 9200 -i {intf} -P -w {pcapfile}",
                background=True,
                title=f"cap:{pcap}",
            )

        self.logger.debug("%s: Starting (no-op).", self)

    def stop(self):
        """Stop the mininet topology (deletes)."""
        self.logger.debug("%s: Stopping (deleting).", self)

        self.delete()

        self.logger.debug("%s: Stopped (deleted).", self)

        if Mininet.g_mnet_inst == self:
            Mininet.g_mnet_inst = None

    def cli(self):
        cli.cli(self)
