# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# July 11 2021, Christian Hopps <chopps@labn.net>
#
# Copyright (c) 2021, LabN Consulting, L.L.C
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
import os
import subprocess
import traceback

import glob
import logging
import os
import signal
import time

from lib.micronet import LinuxNamespace, Micronet
from lib.micronet_cli import cli


def get_pids_with_env(has_var, has_val=None):
    result = {}
    for pidenv in glob.iglob("/proc/*/environ"):
        pid = pidenv.split("/")[2]
        with open(pidenv, "rb") as rfb:
            envlist = [x.decode("utf-8").split("=", 1) for x in rfb.read().split(b"\0")]
            envlist = [[x[0], ""] if len(x) == 1 else x for x in envlist]
            envdict = dict(envlist)
            if has_var not in envdict:
                continue
            if has_val is None:
                result[pid] = envdict
            elif envdict[has_var] == str(has_val):
                result[pid] = envdict
    return result


def _kill_piddict(pids_by_upid, sig):
    for upid, pids in pids_by_upid:
        logging.info(
            "Sending %s to (%s) of micronet pid %s", sig, ", ".join(pids), upid
        )
        for pid in pids:
            try:
                os.kill(int(pid), sig)
            except Exception:
                pass


def _get_our_pids():
    ourpid = str(os.getpid())
    piddict = get_pids_with_env("MICRONET_PID", ourpid)
    pids = [x for x in piddict if x != ourpid]
    if pids:
        return {ourpid: pids}
    return {}


def _get_other_pids():
    piddict = get_pids_with_env("MICRONET_PID")
    unet_pids = {d["MICRONET_PID"] for d in piddict.values()}
    pids_by_upid = {p: set() for p in unet_pids}
    for pid, envdict in piddict.items():
        pids_by_upid[envdict["MICRONET_PID"]].add(pid)
    # Filter out any child pid sets whos micronet pid is still running
    return {x: y for x, y in pids_by_upid.items() if x not in y}


def _get_pids_by_upid(ours):
    if ours:
        return _get_our_pids()
    return _get_other_pids()


def _cleanup_pids(ours):
    pids_by_upid = _get_pids_by_upid(ours).items()
    if not pids_by_upid:
        return

    _kill_piddict(pids_by_upid, signal.SIGTERM)

    # Give them 5 second to exit cleanly
    logging.info("Waiting up to 5s to allow for clean exit of abandon'd pids")
    for _ in range(0, 5):
        pids_by_upid = _get_pids_by_upid(ours).items()
        if not pids_by_upid:
            return
        time.sleep(1)

    pids_by_upid = _get_pids_by_upid(ours).items()
    _kill_piddict(pids_by_upid, signal.SIGKILL)


def cleanup_current():
    """Attempt to cleanup preview runs.

    Currently this only scans for old processes.
    """
    logging.info("reaping current micronet processes")
    _cleanup_pids(True)


def cleanup_previous():
    """Attempt to cleanup preview runs.

    Currently this only scans for old processes.
    """
    logging.info("reaping past micronet processes")
    _cleanup_pids(False)


class Node(LinuxNamespace):
    """Node (mininet compat)."""

    def __init__(self, name, **kwargs):
        """
        Create a Node.
        """
        self.params = kwargs

        if "private_mounts" in kwargs:
            private_mounts = kwargs["private_mounts"]
        else:
            private_mounts = kwargs.get("privateDirs", [])

        logger = kwargs.get("logger")

        super(Node, self).__init__(name, logger=logger, private_mounts=private_mounts)

    def cmd(self, cmd, **kwargs):
        """Execute a command, joins stdout, stderr, ignores exit status."""

        return super(Node, self).cmd_legacy(cmd, **kwargs)

    def config(self, lo="up", **params):
        """Called by Micronet when topology is built (but not started)."""
        # mininet brings up loopback here.
        del params
        del lo

    def intfNames(self):
        return self.intfs

    def terminate(self):
        return


class Topo(object):  # pylint: disable=R0205
    """
    Topology object passed to Micronet to build actual topology.
    """

    def __init__(self, *args, **kwargs):
        self.params = kwargs
        self.name = kwargs["name"] if "name" in kwargs else "unnamed"
        self.tgen = kwargs["tgen"] if "tgen" in kwargs else None

        self.logger = logging.getLogger(__name__ + ".topo")

        self.logger.debug("%s: Creating", self)

        self.nodes = {}
        self.hosts = {}
        self.switches = {}
        self.links = {}

        # if "no_init_build" in kwargs and kwargs["no_init_build"]:
        #     return

        # This needs to move outside of here. Current tests count on it being called on init;
        # however, b/c of this there is lots of twisty logic to support topogen based tests where
        # the build routine must get get_topogen() so topogen can then set it's topogen.topo to the
        # class it's in the process of instantiating (this one) b/c build will use topogen before
        # the instantiation completes.
        self.build(*args, **kwargs)

    def __str__(self):
        return "Topo({})".format(self.name)

    def build(self, *args, **kwargs):
        "Overriden by real class"
        del args
        del kwargs
        raise NotImplementedError("Needs to be overriden")

    def addHost(self, name, **kwargs):
        self.logger.debug("%s: addHost %s", self, name)
        self.nodes[name] = dict(**kwargs)
        self.hosts[name] = self.nodes[name]
        return name

    addNode = addHost

    def addSwitch(self, name, **kwargs):
        self.logger.debug("%s: addSwitch %s", self, name)
        self.nodes[name] = dict(**kwargs)
        if "cls" in self.nodes[name]:
            self.logger.warning("Overriding Bridge class with micronet.Bridge")
            del self.nodes[name]["cls"]
        self.switches[name] = self.nodes[name]
        return name

    def addLink(self, name1, name2, **kwargs):
        """Link up switch and a router.

        possible kwargs:
        - intfName1 :: switch-side interface name - sometimes missing
        - intfName2 :: router-side interface name
        - addr1 :: switch-side MAC used by test_ldp_topo1 only
        - addr2 :: router-side MAC used by test_ldp_topo1 only
        """
        if1 = (
            kwargs["intfName1"]
            if "intfName1" in kwargs
            else "{}-{}".format(name1, name2)
        )
        if2 = (
            kwargs["intfName2"]
            if "intfName2" in kwargs
            else "{}-{}".format(name2, name1)
        )

        self.logger.debug("%s: addLink %s %s if1: %s if2: %s", self, name1, name2, if1, if2)

        if name1 in self.switches:
            assert name2 in self.hosts
            swname, rname = name1, name2
        elif name2 in self.switches:
            assert name1 in self.hosts
            swname, rname = name2, name1
            if1, if2 = if2, if1
        else:
            # p2p link
            assert name1 in self.hosts
            assert name2 in self.hosts
            swname, rname = name1, name2

        if swname not in self.links:
            self.links[swname] = {}

        if rname not in self.links[swname]:
            self.links[swname][rname] = set()

        self.links[swname][rname].add((if1, if2))


class Mininet(Micronet):
    """
    Mininet using Micronet.
    """

    g_mnet_inst = None

    def __init__(self, controller=None, topo=None):
        """
        Create a Micronet.
        """
        assert not controller

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

        super(Mininet, self).__init__()

        self.logger.debug("%s: Creating", self)

        if topo and topo.hosts:
            self.logger.debug("Adding hosts: %s", topo.hosts.keys())
            for name in topo.hosts:
                self.add_host(name, **topo.hosts[name])

        if topo and topo.switches:
            self.logger.debug("Adding switches: %s", topo.switches.keys())
            for name in topo.switches:
                self.add_switch(name, **topo.switches[name])

        if topo and topo.links:
            self.logger.debug("Adding links: ")
            for swname in sorted(topo.links):
                for rname in sorted(topo.links[swname]):
                    for link in topo.links[swname][rname]:
                        self.add_link(swname, rname, link[0], link[1])

        if topo:
            # Now that topology is built, configure hosts
            self.configure_hosts()

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

            if "defaultRoute" in params:
                host.cmd_raises(
                    "ip route add default {}".format(params["defaultRoute"])
                )

            host.config()

            self.configured_hosts.add(name)

    def add_host(self, name, cls=Node, **kwargs):
        """Add a host to micronet."""

        self.host_params[name] = kwargs
        super(Mininet, self).add_host(name, cls=cls, **kwargs)

    def start(self):
        """Start the micronet topology."""
        self.logger.debug("%s: Starting (no-op).", self)

    def stop(self):
        """Stop the mininet topology (deletes)."""
        self.logger.debug("%s: Stopping (deleting).", self)

        self.delete()

        self.logger.debug("%s: Stopped (deleted).", self)

        if Mininet.g_mnet_inst == self:
            Mininet.g_mnet_inst = None

    def cli(self):
        cli(self)
