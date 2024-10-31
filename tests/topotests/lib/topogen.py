# SPDX-License-Identifier: ISC
#
# topogen.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Topogen (Topology Generator) is an abstraction around Topotest and Mininet to
help reduce boilerplate code and provide a stable interface to build topology
tests on.

Basic usage instructions:

* Define a Topology class with a build method using mininet.topo.Topo.
  See examples/test_template.py.
* Use Topogen inside the build() method with get_topogen.
  e.g. get_topogen(self).
* Start up your topology with: Topogen(YourTopology)
* Initialize the Mininet with your topology with: tgen.start_topology()
* Configure your routers/hosts and start them
* Run your tests / mininet cli.
* After running stop Mininet with: tgen.stop_topology()
"""

import configparser
import grp
import inspect
import json
import logging
import os
import platform
import pwd
import re
import shlex
import subprocess
import sys
from collections import OrderedDict

import lib.topolog as topolog
from lib.micronet import Commander
from lib.micronet_compat import Mininet
from lib.topolog import logger
from munet.testing.util import pause_test

from lib import topotest

CWD = os.path.dirname(os.path.realpath(__file__))

# pylint: disable=C0103
# Global Topogen variable. This is being used to keep the Topogen available on
# all test functions without declaring a test local variable.
global_tgen = None


def get_topogen(topo=None):
    """
    Helper function to retrieve Topogen. Must be called with `topo` when called
    inside the build() method of Topology class.
    """
    if topo is not None:
        global_tgen.topo = topo
    return global_tgen


def set_topogen(tgen):
    "Helper function to set Topogen"
    # pylint: disable=W0603
    global global_tgen
    global_tgen = tgen


def is_string(value):
    """Return True if value is a string."""
    try:
        return isinstance(value, basestring)  # type: ignore
    except NameError:
        return isinstance(value, str)


def get_exabgp_cmd(commander=None):
    """Return the command to use for ExaBGP version >= 4.2.11"""

    if commander is None:
        commander = Commander("exabgp", logger=logging.getLogger("exabgp"))

    def exacmd_version_ok(exacmd):
        logger.debug("checking %s for exabgp version >= 4.2.11", exacmd)
        _, stdout, _ = commander.cmd_status(exacmd + " -v", warn=False)
        m = re.search(r"ExaBGP\s*:\s*((\d+)\.(\d+)(?:\.(\d+))?)", stdout)
        if not m:
            return False
        version = m.group(1)
        if topotest.version_cmp(version, "4.2.11") < 0:
            logging.debug(
                "found exabgp version < 4.2.11 in %s will keep looking", exacmd
            )
            return False
        logger.info("Using ExaBGP version %s in %s", version, exacmd)
        return True

    exacmd = commander.get_exec_path("exabgp")
    if exacmd and exacmd_version_ok(exacmd):
        return exacmd
    py3_path = commander.get_exec_path("python3")
    if py3_path:
        exacmd = py3_path + " -m exabgp"
        if exacmd_version_ok(exacmd):
            return exacmd
    py3_path = commander.get_exec_path("python")
    if py3_path:
        exacmd = py3_path + " -m exabgp"
        if exacmd_version_ok(exacmd):
            return exacmd
    return None


#
# Main class: topology builder
#

# Topogen configuration defaults
tgen_defaults = {
    "verbosity": "info",
    "frrdir": "/usr/lib/frr",
    "routertype": "frr",
    "memleak_path": "",
}


class Topogen(object):
    "A topology test builder helper."

    CONFIG_SECTION = "topogen"

    def __init__(self, topodef, modname="unnamed"):
        """
        Topogen initialization function, takes the following arguments:
        * `cls`: OLD:uthe topology class that is child of mininet.topo or a build function.
        * `topodef`: A dictionary defining the topology, a filename of a json file, or a
          function that will do the same
        * `modname`: module name must be a unique name to identify logs later.
        """
        self.config = None
        self.net = None
        self.gears = {}
        self.routern = 1
        self.switchn = 1
        self.modname = modname
        self.errorsd = {}
        self.errors = ""
        self.peern = 1
        self.cfg_gen = 0
        self.exabgp_cmd = None
        self._init_topo(topodef)

        logger.info("loading topology: {}".format(self.modname))

    # @staticmethod
    # def _mininet_reset():
    #     "Reset the mininet environment"
    #     # Clean up the mininet environment
    #     os.system("mn -c > /dev/null 2>&1")

    def __str__(self):
        return "Topogen()"

    def _init_topo(self, topodef):
        """
        Initialize the topogily provided by the user. The user topology class
        must call get_topogen() during build() to get the topogen object.
        """
        # Set the global variable so the test cases can access it anywhere
        set_topogen(self)

        # Increase host based limits
        topotest.fix_host_limits()

        # Test for MPLS Kernel modules available
        self.hasmpls = False
        if not topotest.module_present("mpls-router"):
            logger.info("MPLS tests will not run (missing mpls-router kernel module)")
        elif not topotest.module_present("mpls-iptunnel"):
            logger.info("MPLS tests will not run (missing mpls-iptunnel kernel module)")
        else:
            self.hasmpls = True

        # Load the default topology configurations
        self._load_config()

        # Create new log directory
        self.logdir = topotest.get_logs_path(topotest.g_pytest_config.option.rundir)
        subprocess.check_call(
            "mkdir -p {0} && chmod 1777 {0}".format(self.logdir), shell=True
        )
        try:
            routertype = self.config.get(self.CONFIG_SECTION, "routertype")
            # Only allow group, if it exist.
            gid = grp.getgrnam(routertype)[2]
            os.chown(self.logdir, 0, gid)
            os.chmod(self.logdir, 0o775)
        except KeyError:
            # Allow anyone, but set the sticky bit to avoid file deletions
            os.chmod(self.logdir, 0o1777)

        # Remove old twisty way of creating sub-classed topology object which has it's
        # build method invoked which calls Topogen methods which then call Topo methods
        # to create a topology within the Topo object, which is then used by
        # Mininet(Micronet) to build the actual topology.
        assert not inspect.isclass(topodef)

        self.net = Mininet(
            rundir=self.logdir,
            pytestconfig=topotest.g_pytest_config,
            logger=topolog.get_logger("mu", log_level="debug"),
        )

        # Adjust the parent namespace
        topotest.fix_netns_limits(self.net)

        # New direct way: Either a dictionary defines the topology or a build function
        # is supplied, or a json filename all of which build the topology by calling
        # Topogen methods which call Mininet(Micronet) methods to create the actual
        # topology.
        if not inspect.isclass(topodef):
            if callable(topodef):
                topodef(self)
                self.net.configure_hosts()
            elif is_string(topodef):
                # topojson imports topogen in one function too,
                # switch away from this use here to the topojson
                # fixutre and remove this case
                from lib.topojson import build_topo_from_json

                with open(topodef, "r") as topof:
                    self.json_topo = json.load(topof)
                build_topo_from_json(self, self.json_topo)
                self.net.configure_hosts()
            elif topodef:
                self.add_topology_from_dict(topodef)

    def add_topology_from_dict(self, topodef):
        keylist = (
            topodef.keys()
            if isinstance(topodef, OrderedDict)
            else sorted(topodef.keys())
        )
        # ---------------------------
        # Create all referenced hosts
        # ---------------------------
        for oname in keylist:
            tup = (topodef[oname],) if is_string(topodef[oname]) else topodef[oname]
            for e in tup:
                desc = e.split(":")
                name = desc[0]
                if name not in self.gears:
                    logging.debug("Adding router: %s", name)
                    self.add_router(name)

        # ------------------------------
        # Create all referenced switches
        # ------------------------------
        for oname in keylist:
            if oname is not None and oname not in self.gears:
                logging.debug("Adding switch: %s", oname)
                self.add_switch(oname)

        # ----------------
        # Create all links
        # ----------------
        for oname in keylist:
            if oname is None:
                continue
            tup = (topodef[oname],) if is_string(topodef[oname]) else topodef[oname]
            for e in tup:
                desc = e.split(":")
                name = desc[0]
                ifname = desc[1] if len(desc) > 1 else None
                sifname = desc[2] if len(desc) > 2 else None
                self.add_link(self.gears[oname], self.gears[name], sifname, ifname)

        self.net.configure_hosts()

    def _load_config(self):
        """
        Loads the configuration file `pytest.ini` located at the root dir of
        topotests.
        """
        self.config = configparser.ConfigParser(tgen_defaults)
        pytestini_path = os.path.join(CWD, "../pytest.ini")
        self.config.read(pytestini_path)

    def add_router(self, name=None, cls=None, **params):
        """
        Adds a new router to the topology. This function has the following
        options:
        * `name`: (optional) select the router name
        * `daemondir`: (optional) custom daemon binary directory
        * `routertype`: (optional) `frr`
        Returns a TopoRouter.
        """
        if cls is None:
            cls = topotest.Router
        if name is None:
            name = "r{}".format(self.routern)
        if name in self.gears:
            raise KeyError("router already exists")

        params["frrdir"] = self.config.get(self.CONFIG_SECTION, "frrdir")
        params["memleak_path"] = self.config.get(self.CONFIG_SECTION, "memleak_path")
        if "routertype" not in params:
            params["routertype"] = self.config.get(self.CONFIG_SECTION, "routertype")

        self.gears[name] = TopoRouter(self, cls, name, **params)
        self.routern += 1
        return self.gears[name]

    def add_switch(self, name=None):
        """
        Adds a new switch to the topology. This function has the following
        options:
        name: (optional) select the switch name
        Returns the switch name and number.
        """
        if name is None:
            name = "s{}".format(self.switchn)
        if name in self.gears:
            raise KeyError("switch already exists")

        self.gears[name] = TopoSwitch(self, name)
        self.switchn += 1
        return self.gears[name]

    def add_exabgp_peer(self, name, ip, defaultRoute):
        """
        Adds a new ExaBGP peer to the topology. This function has the following
        parameters:
        * `ip`: the peer address (e.g. '1.2.3.4/24')
        * `defaultRoute`: the peer default route (e.g. 'via 1.2.3.1')
        """
        if name is None:
            name = "peer{}".format(self.peern)
        if name in self.gears:
            raise KeyError("exabgp peer already exists")

        self.gears[name] = TopoExaBGP(self, name, ip=ip, defaultRoute=defaultRoute)
        self.peern += 1
        return self.gears[name]

    def add_host(self, name, ip, defaultRoute):
        """
        Adds a new host to the topology. This function has the following
        parameters:
        * `ip`: the peer address (e.g. '1.2.3.4/24')
        * `defaultRoute`: the peer default route (e.g. 'via 1.2.3.1')
        """
        if name is None:
            name = "host{}".format(self.peern)
        if name in self.gears:
            raise KeyError("host already exists")

        self.gears[name] = TopoHost(self, name, ip=ip, defaultRoute=defaultRoute)
        self.peern += 1
        return self.gears[name]

    def add_bmp_server(self, name, ip, defaultRoute, port=1789):
        """Add the bmp collector gear"""
        if name in self.gears:
            raise KeyError("The bmp server already exists")

        self.gears[name] = TopoBMPCollector(
            self, name, ip=ip, defaultRoute=defaultRoute, port=port
        )

    def add_link(self, node1, node2, ifname1=None, ifname2=None):
        """
        Creates a connection between node1 and node2. The nodes can be the
        following:
        * TopoGear
          * TopoRouter
          * TopoSwitch
        """
        if not isinstance(node1, TopoGear):
            raise ValueError("invalid node1 type")
        if not isinstance(node2, TopoGear):
            raise ValueError("invalid node2 type")

        if ifname1 is None:
            ifname1 = node1.new_link()
        if ifname2 is None:
            ifname2 = node2.new_link()

        node1.register_link(ifname1, node2, ifname2)
        node2.register_link(ifname2, node1, ifname1)
        self.net.add_link(node1.name, node2.name, ifname1, ifname2)

    def get_gears(self, geartype):
        """
        Returns a dictionary of all gears of type `geartype`.

        Normal usage:
        * Dictionary iteration:
        ```py
        tgen = get_topogen()
        router_dict = tgen.get_gears(TopoRouter)
        for router_name, router in router_dict.items():
            # Do stuff
        ```
        * List iteration:
        ```py
        tgen = get_topogen()
        peer_list = tgen.get_gears(TopoExaBGP).values()
        for peer in peer_list:
            # Do stuff
        ```
        """
        return dict(
            (name, gear)
            for name, gear in self.gears.items()
            if isinstance(gear, geartype)
        )

    def routers(self):
        """
        Returns the router dictionary (key is the router name and value is the
        router object itself).
        """
        return self.get_gears(TopoRouter)

    def exabgp_peers(self):
        """
        Returns the exabgp peer dictionary (key is the peer name and value is
        the peer object itself).
        """
        return self.get_gears(TopoExaBGP)

    def get_bmp_servers(self):
        """
        Retruns the bmp servers dictionnary (the key is the bmp server the
        value is the bmp server object itself).
        """
        return self.get_gears(TopoBMPCollector)

    def start_topology(self):
        """Starts the topology class."""
        logger.info("starting topology: {}".format(self.modname))
        self.net.start()

    def start_router(self, router=None):
        """
        Call the router startRouter method.
        If no router is specified it is called for all registered routers.
        """
        if router is None:
            # pylint: disable=r1704
            # XXX should be hosts?
            for _, router in self.routers().items():
                router.start()
        else:
            if isinstance(router, str):
                router = self.gears[router]

            router.start()

    def stop_topology(self):
        """
        Stops the network topology. This function will call the stop() function
        of all gears before calling the mininet stop function, so they can have
        their oportunity to do a graceful shutdown. stop() is called twice. The
        first is a simple kill with no sleep, the second will sleep if not
        killed and try with a different signal.
        """
        pause = bool(self.net.cfgopt.get_option("--pause-at-end"))
        pause = pause or bool(self.net.cfgopt.get_option("--pause"))
        if pause:
            try:
                pause_test("Before MUNET delete")
            except KeyboardInterrupt:
                print("^C...continuing")
            except Exception as error:
                self.logger.error("\n...continuing after error: %s", error)

        logger.info("stopping topology: {}".format(self.modname))

        errors = ""
        for gear in self.gears.values():
            errors += gear.stop()
        if len(errors) > 0:
            logger.error(
                "Errors found post shutdown - details follow: {}".format(errors)
            )

        try:
            self.net.stop()

        except OSError as error:
            # OSError exception is raised when mininet tries to stop switch
            # though switch is stopped once but mininet tries to stop same
            # switch again, where it ended up with exception

            logger.info(error)
            logger.info("Exception ignored: switch is already stopped")

    def get_exabgp_cmd(self):
        if not self.exabgp_cmd:
            self.exabgp_cmd = get_exabgp_cmd(self.net)
        return self.exabgp_cmd

    def cli(self):
        """
        Interrupt the test and call the command line interface for manual
        inspection. Should be only used on non production code.
        """
        self.net.cli()

    mininet_cli = cli

    def is_memleak_enabled(self):
        "Returns `True` if memory leak report is enable, otherwise `False`."
        # On router failure we can't run the memory leak test
        if self.routers_have_failure():
            return False

        memleak_file = os.environ.get("TOPOTESTS_CHECK_MEMLEAK") or self.config.get(
            self.CONFIG_SECTION, "memleak_path"
        )
        if memleak_file == "" or memleak_file is None:
            return False
        return True

    def report_memory_leaks(self, testname=None):
        "Run memory leak test and reports."
        if not self.is_memleak_enabled():
            return

        # If no name was specified, use the test module name
        if testname is None:
            testname = self.modname

        router_list = self.routers().values()
        for router in router_list:
            router.report_memory_leaks(self.modname)

    def set_error(self, message, code=None):
        "Sets an error message and signal other tests to skip."
        logger.info("setting error msg: %s", message)

        # If no code is defined use a sequential number
        if code is None:
            code = len(self.errorsd)

        self.errorsd[code] = message
        self.errors += "\n{}: {}".format(code, message)

    def has_errors(self):
        "Returns whether errors exist or not."
        return len(self.errorsd) > 0

    def routers_have_failure(self):
        "Runs an assertion to make sure that all routers are running."
        if self.has_errors():
            return True

        errors = ""
        router_list = self.routers().values()
        for router in router_list:
            result = router.check_router_running()
            if result != "":
                errors += result + "\n"

        if errors != "":
            self.set_error(errors, "router_error")
            assert False, errors
            return True
        return False


#
# Topology gears (equipment)
#


class TopoGear(object):
    "Abstract class for type checking"

    def __init__(self, tgen, name, **params):
        self.tgen = tgen
        self.name = name
        self.params = params
        self.links = {}
        self.linkn = 0

        # Would be nice for this to point at the gears log directory rather than the
        # test's.
        self.logdir = tgen.logdir
        self.gearlogdir = None

    def __str__(self):
        links = ""
        for myif, dest in self.links.items():
            _, destif = dest
            if links != "":
                links += ","
            links += '"{}"<->"{}"'.format(myif, destif)

        return 'TopoGear<name="{}",links=[{}]>'.format(self.name, links)

    @property
    def net(self):
        return self.tgen.net[self.name]

    def start(self):
        "Basic start function that just reports equipment start"
        logger.info('starting "{}"'.format(self.name))

    def stop(self, wait=True, assertOnError=True):
        "Basic stop function that just reports equipment stop"
        logger.info('"{}" base stop called'.format(self.name))
        return ""

    def cmd(self, command, **kwargs):
        """
        Runs the provided command string in the router and returns a string
        with the response.
        """
        return self.net.cmd_legacy(command, **kwargs)

    def cmd_raises(self, command, **kwargs):
        """
        Runs the provided command string in the router and returns a string
        with the response. Raise an exception on any error.
        """
        return self.net.cmd_raises(command, **kwargs)

    run = cmd

    def popen(self, *params, **kwargs):
        """
        Creates a pipe with the given command. Same args as python Popen.
        If `command` is a string then will be invoked with shell, otherwise
        `command` is a list and will be invoked w/o shell. Returns a popen object.
        """
        return self.net.popen(*params, **kwargs)

    def add_link(self, node, myif=None, nodeif=None):
        """
        Creates a link (connection) between myself and the specified node.
        Interfaces name can be speficied with:
        myif: the interface name that will be created in this node
        nodeif: the target interface name that will be created on the remote node.
        """
        self.tgen.add_link(self, node, myif, nodeif)

    def link_enable(self, myif, enabled=True, netns=None):
        """
        Set this node interface administrative state.
        myif: this node interface name
        enabled: whether we should enable or disable the interface
        """
        if myif not in self.links.keys():
            raise KeyError("interface doesn't exists")

        if enabled is True:
            operation = "up"
        else:
            operation = "down"

        logger.info(
            'setting node "{}" link "{}" to state "{}"'.format(
                self.name, myif, operation
            )
        )
        extract = ""
        if netns is not None:
            extract = "ip netns exec {} ".format(netns)

        return self.run("{}ip link set dev {} {}".format(extract, myif, operation))

    def peer_link_enable(self, myif, enabled=True, netns=None):
        """
        Set the peer interface administrative state.
        myif: this node interface name
        enabled: whether we should enable or disable the interface

        NOTE: this is used to simulate a link down on this node, since when the
        peer disables their interface our interface status changes to no link.
        """
        if myif not in self.links.keys():
            raise KeyError("interface doesn't exists")

        node, nodeif = self.links[myif]
        node.link_enable(nodeif, enabled, netns)

    def new_link(self):
        """
        Generates a new unique link name.

        NOTE: This function should only be called by Topogen.
        """
        ifname = "{}-eth{}".format(self.name, self.linkn)
        self.linkn += 1
        return ifname

    def register_link(self, myif, node, nodeif):
        """
        Register link between this node interface and outside node.

        NOTE: This function should only be called by Topogen.
        """
        if myif in self.links.keys():
            raise KeyError("interface already exists")

        self.links[myif] = (node, nodeif)

    def _setup_tmpdir(self):
        topotest.setup_node_tmpdir(self.logdir, self.name)
        self.gearlogdir = "{}/{}".format(self.logdir, self.name)
        return "{}/{}.log".format(self.logdir, self.name)


class TopoRouter(TopoGear):
    """
    Router abstraction.
    """

    # The default required directories by FRR
    PRIVATE_DIRS = [
        "/etc/frr",
        "/etc/snmp",
        "/var/run/frr",
        "/var/lib/frr",
        "/var/log",
    ]

    # Router Daemon enumeration definition.
    RD_FRR = 0  # not a daemon, but use to setup unified configs
    RD_ZEBRA = 1
    RD_RIP = 2
    RD_RIPNG = 3
    RD_OSPF = 4
    RD_OSPF6 = 5
    RD_ISIS = 6
    RD_BGP = 7
    RD_LDP = 8
    RD_PIM = 9
    RD_EIGRP = 10
    RD_NHRP = 11
    RD_STATIC = 12
    RD_BFD = 13
    RD_SHARP = 14
    RD_BABEL = 15
    RD_PBRD = 16
    RD_PATH = 17
    RD_SNMP = 18
    RD_PIM6 = 19
    RD_MGMTD = 20
    RD_TRAP = 21
    RD_FPM_LISTENER = 22
    RD = {
        RD_FRR: "frr",
        RD_ZEBRA: "zebra",
        RD_RIP: "ripd",
        RD_RIPNG: "ripngd",
        RD_OSPF: "ospfd",
        RD_OSPF6: "ospf6d",
        RD_ISIS: "isisd",
        RD_BGP: "bgpd",
        RD_PIM: "pimd",
        RD_PIM6: "pim6d",
        RD_LDP: "ldpd",
        RD_EIGRP: "eigrpd",
        RD_NHRP: "nhrpd",
        RD_STATIC: "staticd",
        RD_BFD: "bfdd",
        RD_SHARP: "sharpd",
        RD_BABEL: "babeld",
        RD_PBRD: "pbrd",
        RD_PATH: "pathd",
        RD_SNMP: "snmpd",
        RD_MGMTD: "mgmtd",
        RD_TRAP: "snmptrapd",
        RD_FPM_LISTENER: "fpm_listener",
    }

    def __init__(self, tgen, cls, name, **params):
        """
        The constructor has the following parameters:
        * tgen: Topogen object
        * cls: router class that will be used to instantiate
        * name: router name
        * daemondir: daemon binary directory
        * routertype: 'frr'
        """
        super(TopoRouter, self).__init__(tgen, name, **params)
        self.routertype = params.get("routertype", "frr")
        if "private_mounts" not in params:
            params["private_mounts"] = self.PRIVATE_DIRS

        # Propagate the router log directory
        logfile = self._setup_tmpdir()
        params["logdir"] = self.logdir

        self.logger = topolog.get_logger(name, log_level="debug", target=logfile)
        params["logger"] = self.logger
        tgen.net.add_host(self.name, cls=cls, **params)
        topotest.fix_netns_limits(tgen.net[name])

        # Mount gear log directory on a common path
        self.net.bind_mount(self.gearlogdir, "/tmp/gearlogdir")

        # Ensure pid file
        with open(os.path.join(self.logdir, self.name + ".pid"), "w") as f:
            f.write(str(self.net.pid) + "\n")

    def __str__(self):
        gear = super(TopoRouter, self).__str__()
        gear += " TopoRouter<>"
        return gear

    def check_capability(self, daemon, param):
        """
        Checks a capability daemon against an argument option
        Return True if capability available. False otherwise
        """
        daemonstr = self.RD.get(daemon)
        self.logger.info('check capability {} for "{}"'.format(param, daemonstr))
        return self.net.checkCapability(daemonstr, param)

    def load_frr_config(self, source, daemons=None):
        """
        Loads the unified configuration file source
        Start the daemons in the list
        If daemons is None, try to infer daemons from the config file
        `daemons` is a tuple (daemon, param) of daemons to start, e.g.:
        (TopoRouter.RD_ZEBRA, "-s 90000000").
        """
        source_path = self.load_config(self.RD_FRR, source)
        if not daemons:
            # Always add zebra
            self.load_config(self.RD_ZEBRA, "")
            for daemon in self.RD:
                # This will not work for all daemons
                daemonstr = self.RD.get(daemon).rstrip("d")
                if daemonstr == "path":
                    grep_cmd = "grep 'candidate-path' {}".format(source_path)
                else:
                    grep_cmd = "grep -w '{}' {}".format(daemonstr, source_path)
                result = self.run(grep_cmd, warn=False).strip()
                if result:
                    self.load_config(daemon, "")
        else:
            for item in daemons:
                daemon, param = item
                self.load_config(daemon, "", param)

    def load_config(self, daemon, source=None, param=None):
        """Loads daemon configuration from the specified source
        Possible daemon values are: TopoRouter.RD_ZEBRA, TopoRouter.RD_RIP,
        TopoRouter.RD_RIPNG, TopoRouter.RD_OSPF, TopoRouter.RD_OSPF6,
        TopoRouter.RD_ISIS, TopoRouter.RD_BGP, TopoRouter.RD_LDP,
        TopoRouter.RD_PIM, TopoRouter.RD_PIM6, TopoRouter.RD_PBR,
        TopoRouter.RD_SNMP, TopoRouter.RD_MGMTD, TopoRouter.RD_TRAP,
        TopoRouter.RD_FPM_LISTENER.

        Possible `source` values are `None` for an empty config file, a path name which is
        used directly, or a file name with no path components which is first looked for
        directly and then looked for under a sub-directory named after router.

        This API unfortunately allows for source to not exist for any and
        all routers.
        """
        daemonstr = self.RD.get(daemon)
        self.logger.debug('loading "{}" configuration: {}'.format(daemonstr, source))
        return self.net.loadConf(daemonstr, source, param)

    def check_router_running(self):
        """
        Run a series of checks and returns a status string.
        """
        self.logger.info("checking if daemons are running")
        return self.net.checkRouterRunning()

    def start(self):
        """
        Start router:
        * Load modules
        * Clean up files
        * Configure interfaces
        * Start daemons (e.g. FRR)
        * Configure daemon logging files
        """

        nrouter = self.net
        result = nrouter.startRouter(self.tgen)

        # Enable command logging

        # Enable all daemon command logging, logging files
        # and set them to the start dir.
        for daemon, enabled in nrouter.daemons.items():
            if (
                enabled
                and daemon != "snmpd"
                and daemon != "snmptrapd"
                and daemon != "fpm_listener"
            ):
                self.vtysh_cmd(
                    "\n".join(
                        [
                            "clear log cmdline-targets",
                            "conf t",
                            "log file {}.log debug".format(daemon),
                            "log commands",
                            "log timestamp precision 6",
                        ]
                    ),
                    daemon=daemon,
                )

        if result != "":
            self.tgen.set_error(result)
        elif nrouter.daemons["ldpd"] == 1 or nrouter.daemons["pathd"] == 1:
            # Enable MPLS processing on all interfaces.
            for interface in self.links:
                topotest.sysctl_assure(
                    nrouter, "net.mpls.conf.{}.input".format(interface), 1
                )

        return result

    def stop(self):
        """
        Stop router cleanly:
        * Signal daemons twice, once with SIGTERM, then with SIGKILL.
        """
        self.logger.debug("stopping (no assert)")
        return self.net.stopRouter(False)

    def startDaemons(self, daemons):
        """
        Start Daemons: to start specific daemon(user defined daemon only)
        * Start daemons (e.g. FRR)
        * Configure daemon logging files
        """
        self.logger.debug("starting")
        nrouter = self.net
        result = nrouter.startRouterDaemons(daemons)

        if daemons is None:
            daemons = nrouter.daemons.keys()

        # Enable all daemon command logging, logging files
        # and set them to the start dir.
        for daemon in daemons:
            enabled = nrouter.daemons[daemon]
            if enabled and daemon != "snmpd" and daemon != "fpm_listener":
                self.vtysh_cmd(
                    "\n".join(
                        [
                            "clear log cmdline-targets",
                            "conf t",
                            "log file {}.log debug".format(daemon),
                            "log commands",
                            "log timestamp precision 6",
                        ]
                    ),
                    daemon=daemon,
                )

        if result != "":
            self.tgen.set_error(result)

        return result

    def killDaemons(self, daemons, wait=True, assertOnError=True):
        """
        Kill specific daemon(user defined daemon only)
        forcefully using SIGKILL
        """
        self.logger.debug("Killing daemons using SIGKILL..")
        return self.net.killRouterDaemons(daemons, wait, assertOnError)

    def vtysh_cmd(self, command, isjson=False, daemon=None):
        """
        Runs the provided command string in the vty shell and returns a string
        with the response.

        This function also accepts multiple commands, but this mode does not
        return output for each command. See vtysh_multicmd() for more details.
        """
        # Detect multi line commands
        if command.find("\n") != -1:
            return self.vtysh_multicmd(command, daemon=daemon)

        dparam = ""
        if daemon is not None:
            dparam += "-d {}".format(daemon)

        vtysh_command = "vtysh {} -c {} 2>/dev/null".format(
            dparam, shlex.quote(command)
        )

        self.logger.debug("vtysh command => {}".format(shlex.quote(command)))
        output = self.run(vtysh_command)

        dbgout = output.strip()
        if dbgout:
            if "\n" in dbgout:
                dbgout = dbgout.replace("\n", "\n\t")
                self.logger.debug("vtysh result:\n\t{}".format(dbgout))
            else:
                self.logger.debug('vtysh result: "{}"'.format(dbgout))

        if isjson is False:
            return output

        try:
            return json.loads(output)
        except ValueError as error:
            logger.warning(
                "vtysh_cmd: %s: failed to convert json output: %s: %s",
                self.name,
                str(output),
                str(error),
            )
            return {}

    def vtysh_multicmd(self, commands, pretty_output=True, daemon=None):
        """
        Runs the provided commands in the vty shell and return the result of
        execution.

        pretty_output: defines how the return value will be presented. When
        True it will show the command as they were executed in the vty shell,
        otherwise it will only show lines that failed.
        """
        # Prepare the temporary file that will hold the commands
        fname = topotest.get_file(commands)

        dparam = ""
        if daemon is not None:
            dparam += "-d {}".format(daemon)

        # Run the commands and delete the temporary file
        if pretty_output:
            vtysh_command = "vtysh {} < {}".format(dparam, fname)
        else:
            vtysh_command = "vtysh {} -f {}".format(dparam, fname)

        dbgcmds = commands if is_string(commands) else "\n".join(commands)
        dbgcmds = "\t" + dbgcmds.replace("\n", "\n\t")
        self.logger.debug("vtysh command => FILE:\n{}".format(dbgcmds))

        res = self.run(vtysh_command)
        os.unlink(fname)

        dbgres = res.strip()
        if dbgres:
            if "\n" in dbgres:
                dbgres = dbgres.replace("\n", "\n\t")
                self.logger.debug("vtysh result:\n\t{}".format(dbgres))
            else:
                self.logger.debug('vtysh result: "{}"'.format(dbgres))
        return res

    def report_memory_leaks(self, testname):
        """
        Runs the router memory leak check test. Has the following parameter:
        testname: the test file name for identification

        NOTE: to run this you must have the environment variable
        TOPOTESTS_CHECK_MEMLEAK set or memleak_path configured in `pytest.ini`.
        """
        memleak_file = (
            os.environ.get("TOPOTESTS_CHECK_MEMLEAK") or self.params["memleak_path"]
        )
        if memleak_file == "" or memleak_file is None:
            return

        self.stop()

        self.logger.info("running memory leak report")
        self.net.report_memory_leaks(memleak_file, testname)

    def version_info(self):
        "Get equipment information from 'show version'."
        output = self.vtysh_cmd("show version").split("\n")[0]
        columns = topotest.normalize_text(output).split(" ")
        try:
            return {
                "type": columns[0],
                "version": columns[1],
            }
        except IndexError:
            return {
                "type": None,
                "version": None,
            }

    def has_version(self, cmpop, version):
        """
        Compares router version using operation `cmpop` with `version`.
        Valid `cmpop` values:
        * `>=`: has the same version or greater
        * '>': has greater version
        * '=': has the same version
        * '<': has a lesser version
        * '<=': has the same version or lesser

        Usage example: router.has_version('>', '1.0')
        """
        return self.net.checkRouterVersion(cmpop, version)

    def has_type(self, rtype):
        """
        Compares router type with `rtype`. Returns `True` if the type matches,
        otherwise `false`.
        """
        curtype = self.version_info()["type"]
        return rtype == curtype

    def has_mpls(self):
        return self.net.hasmpls


class TopoSwitch(TopoGear):
    """
    Switch abstraction. Has the following properties:
    * cls: switch class that will be used to instantiate
    * name: switch name
    """

    # pylint: disable=too-few-public-methods

    def __init__(self, tgen, name, **params):
        logger = topolog.get_logger(name, log_level="debug")
        super(TopoSwitch, self).__init__(tgen, name, **params)
        tgen.net.add_switch(name, logger=logger)

    def __str__(self):
        gear = super(TopoSwitch, self).__str__()
        gear += " TopoSwitch<>"
        return gear


class TopoHost(TopoGear):
    "Host abstraction."
    # pylint: disable=too-few-public-methods

    def __init__(self, tgen, name, **params):
        """
        Mininet has the following known `params` for hosts:
        * `ip`: the IP address (string) for the host interface
        * `defaultRoute`: the default route that will be installed
          (e.g. 'via 10.0.0.1')
        * `private_mounts`: directories that will be mounted on a different domain
          (e.g. '/etc/important_dir').
        """
        super(TopoHost, self).__init__(tgen, name, **params)

        # Propagate the router log directory
        logfile = self._setup_tmpdir()
        params["logdir"] = self.logdir

        # Odd to have 2 logfiles for each host
        self.logger = topolog.get_logger(name, log_level="debug", target=logfile)
        params["logger"] = self.logger
        tgen.net.add_host(name, **params)
        topotest.fix_netns_limits(tgen.net[name])

        # Mount gear log directory on a common path
        self.net.bind_mount(self.gearlogdir, "/tmp/gearlogdir")

    def __str__(self):
        gear = super(TopoHost, self).__str__()
        gear += ' TopoHost<ip="{}",defaultRoute="{}",private_mounts="{}">'.format(
            self.params["ip"],
            self.params["defaultRoute"],
            str(self.params["private_mounts"]),
        )
        return gear


class TopoExaBGP(TopoHost):
    "ExaBGP peer abstraction."
    # pylint: disable=too-few-public-methods

    PRIVATE_DIRS = [
        "/etc/exabgp",
        "/var/run/exabgp",
        "/var/log",
    ]

    def __init__(self, tgen, name, **params):
        """
        ExaBGP usually uses the following parameters:
        * `ip`: the IP address (string) for the host interface
        * `defaultRoute`: the default route that will be installed
          (e.g. 'via 10.0.0.1')

        Note: the different between a host and a ExaBGP peer is that this class
        has a private_mounts already defined and contains functions to handle
        ExaBGP things.
        """
        params["private_mounts"] = self.PRIVATE_DIRS
        super(TopoExaBGP, self).__init__(tgen, name, **params)

    def __str__(self):
        gear = super(TopoExaBGP, self).__str__()
        gear += " TopoExaBGP<>".format()
        return gear

    def start(self, peer_dir, env_file=None):
        """
        Start running ExaBGP daemon:
        * Copy all peer* folder contents into /etc/exabgp
        * Copy exabgp env file if specified
        * Make all python files runnable
        * Run ExaBGP with env file `env_file` and configuration peer*/exabgp.cfg
        """
        exacmd = self.tgen.get_exabgp_cmd()
        assert exacmd, "Can't find a usable ExaBGP (must be version >= 4.2.11)"

        self.run("mkdir -p /etc/exabgp")
        self.run("chmod 755 /etc/exabgp")
        self.run("cp {}/exa-* /etc/exabgp/".format(CWD))
        self.run("cp {}/* /etc/exabgp/".format(peer_dir))
        if env_file is not None:
            self.run("cp {} /etc/exabgp/exabgp.env".format(env_file))
        self.run("chmod 644 /etc/exabgp/*")
        self.run("chmod a+x /etc/exabgp/*.py")
        self.run("chown -R exabgp:exabgp /etc/exabgp")
        self.run("[ -p /var/run/exabgp.in ] || mkfifo /var/run/exabgp.in")
        self.run("[ -p /var/run/exabgp.out ] || mkfifo /var/run/exabgp.out")
        self.run("chown exabgp:exabgp /var/run/exabgp.{in,out}")
        self.run("chmod 600 /var/run/exabgp.{in,out}")

        log_dir = os.path.join(self.logdir, self.name)
        self.run("chmod 777 {}".format(log_dir))

        log_file = os.path.join(log_dir, "exabgp.log")

        env_cmd = "env exabgp.log.level=INFO "
        env_cmd += "exabgp.log.destination={} ".format(log_file)

        output = self.run(
            env_cmd + exacmd + " -e /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg "
        )
        if output is None or len(output) == 0:
            output = "<none>"

        logger.info("{} exabgp started, output={}".format(self.name, output))

    def stop(self, wait=True, assertOnError=True):
        "Stop ExaBGP peer and kill the daemon"
        self.run("kill `cat /var/run/exabgp/exabgp.pid`")
        return ""


class TopoBMPCollector(TopoHost):
    PRIVATE_DIRS = [
        "/var/log",
    ]

    def __init__(self, tgen, name, **params):
        params["private_mounts"] = self.PRIVATE_DIRS
        self.port = params["port"]
        self.ip = params["ip"]
        super(TopoBMPCollector, self).__init__(tgen, name, **params)

    def __str__(self):
        gear = super(TopoBMPCollector, self).__str__()
        gear += " TopoBMPCollector<>".format()
        return gear

    def start(self, log_file=None):
        log_dir = os.path.join(self.logdir, self.name)
        self.run("chmod 777 {}".format(log_dir))

        log_err = os.path.join(log_dir, "bmpserver.log")

        log_arg = "-l {}".format(log_file) if log_file else ""

        with open(log_err, "w") as err:
            self.run(
                "{}/bmp_collector/bmpserver -a {} -p {} {}&".format(
                    CWD, self.ip, self.port, log_arg
                ),
                stdout=None,
                stderr=err,
            )

    def stop(self):
        self.run("pkill -f bmpserver")
        return ""


#
# Diagnostic function
#


# Disable linter branch warning. It is expected to have these here.
# pylint: disable=R0912
def diagnose_env_linux(rundir):
    """
    Run diagnostics in the running environment. Returns `True` when everything
    is ok, otherwise `False`.
    """
    ret = True

    # Load configuration
    config = configparser.ConfigParser(defaults=tgen_defaults)
    pytestini_path = os.path.join(CWD, "../pytest.ini")
    config.read(pytestini_path)

    # Test log path exists before installing handler.
    os.system("mkdir -p " + rundir)
    # Log diagnostics to file so it can be examined later.
    fhandler = logging.FileHandler(filename="{}/diagnostics.txt".format(rundir))
    fhandler.setLevel(logging.DEBUG)
    fhandler.setFormatter(logging.Formatter(fmt=topolog.FORMAT))
    logger.addHandler(fhandler)

    logger.info("Running environment diagnostics")

    # Assert that we are running as root
    if os.getuid() != 0:
        logger.error("you must run topotest as root")
        ret = False

    # Assert that we have mininet
    # if os.system("which mn >/dev/null 2>/dev/null") != 0:
    #     logger.error("could not find mininet binary (mininet is not installed)")
    #     ret = False

    # Assert that we have iproute installed
    if os.system("which ip >/dev/null 2>/dev/null") != 0:
        logger.error("could not find ip binary (iproute is not installed)")
        ret = False

    # Assert that we have gdb installed
    if os.system("which gdb >/dev/null 2>/dev/null") != 0:
        logger.error("could not find gdb binary (gdb is not installed)")
        ret = False

    # Assert that FRR utilities exist
    frrdir = config.get("topogen", "frrdir")
    if not os.path.isdir(frrdir):
        logger.error("could not find {} directory".format(frrdir))
        ret = False
    else:
        try:
            pwd.getpwnam("frr")[2]
        except KeyError:
            logger.warning('could not find "frr" user')

        try:
            grp.getgrnam("frr")[2]
        except KeyError:
            logger.warning('could not find "frr" group')

        try:
            if "frr" not in grp.getgrnam("frrvty").gr_mem:
                logger.error(
                    '"frr" user and group exist, but user is not under "frrvty"'
                )
        except KeyError:
            logger.warning('could not find "frrvty" group')

        for fname in [
            "zebra",
            "ospfd",
            "ospf6d",
            "bgpd",
            "ripd",
            "ripngd",
            "isisd",
            "pimd",
            "pim6d",
            "ldpd",
            "pbrd",
            "mgmtd",
        ]:
            path = os.path.join(frrdir, fname)
            if not os.path.isfile(path):
                # LDPd is an exception
                if fname == "ldpd":
                    logger.info(
                        "could not find {} in {}".format(fname, frrdir)
                        + "(LDPd tests will not run)"
                    )
                    continue

                logger.error("could not find {} in {}".format(fname, frrdir))
                ret = False
            else:
                if fname != "zebra" or fname != "mgmtd":
                    continue

                os.system("{} -v 2>&1 >{}/frr_mgmtd.txt".format(path, rundir))
                os.system("{} -v 2>&1 >{}/frr_zebra.txt".format(path, rundir))

    # Test MPLS availability
    krel = platform.release()
    if topotest.version_cmp(krel, "4.5") < 0:
        logger.info(
            'LDPd tests will not run (have kernel "{}", but it requires 4.5)'.format(
                krel
            )
        )

    # Test for MPLS Kernel modules available
    if not topotest.module_present("mpls-router", load=False) != 0:
        logger.info("LDPd tests will not run (missing mpls-router kernel module)")
    if not topotest.module_present("mpls-iptunnel", load=False) != 0:
        logger.info("LDPd tests will not run (missing mpls-iptunnel kernel module)")

    if not get_exabgp_cmd():
        logger.warning("Failed to find exabgp >= 4.2.11")

    logger.removeHandler(fhandler)
    fhandler.close()

    return ret


def diagnose_env_freebsd():
    return True


def diagnose_env(rundir):
    if sys.platform.startswith("linux"):
        return diagnose_env_linux(rundir)
    elif sys.platform.startswith("freebsd"):
        return diagnose_env_freebsd()

    return False
