#
# topogen.py
# Library of helper functions for NetDEF Topology Tests
#
# Copyright (c) 2017 by
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

import os
import sys
import logging
import json

if sys.version_info[0] > 2:
    import configparser
else:
    import ConfigParser as configparser

import glob
import grp
import platform
import pwd
import subprocess
import pytest

from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI

from lib import topotest
from lib.topolog import logger, logger_config
from lib.topotest import set_sysctl

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

#
# Main class: topology builder
#

# Topogen configuration defaults
tgen_defaults = {
    'verbosity': 'info',
    'frrdir': '/usr/lib/frr',
    'quaggadir': '/usr/lib/quagga',
    'routertype': 'frr',
    'memleak_path': None,
}

class Topogen(object):
    "A topology test builder helper."

    CONFIG_SECTION = 'topogen'

    def __init__(self, cls, modname='unnamed'):
        """
        Topogen initialization function, takes the following arguments:
        * `cls`: the topology class that is child of mininet.topo
        * `modname`: module name must be a unique name to identify logs later.
        """
        self.config = None
        self.topo = None
        self.net = None
        self.gears = {}
        self.routern = 1
        self.switchn = 1
        self.modname = modname
        self.errorsd = {}
        self.errors = ''
        self.peern = 1
        self._init_topo(cls)
        logger.info('loading topology: {}'.format(self.modname))

    @staticmethod
    def _mininet_reset():
        "Reset the mininet environment"
        # Clean up the mininet environment
        os.system('mn -c > /dev/null 2>&1')

    def _init_topo(self, cls):
        """
        Initialize the topogily provided by the user. The user topology class
        must call get_topogen() during build() to get the topogen object.
        """
        # Set the global variable so the test cases can access it anywhere
        set_topogen(self)

        # Test for MPLS Kernel modules available
        self.hasmpls = False
        if not topotest.module_present('mpls-router'):
            logger.info('MPLS tests will not run (missing mpls-router kernel module)')
        elif not topotest.module_present('mpls-iptunnel'):
            logger.info('MPLS tests will not run (missing mpls-iptunnel kernel module)')
        else:
            self.hasmpls = True
        # Load the default topology configurations
        self._load_config()

        # Initialize the API
        self._mininet_reset()
        cls()
        self.net = Mininet(controller=None, topo=self.topo)
        for gear in self.gears.values():
            gear.net = self.net

    def _load_config(self):
        """
        Loads the configuration file `pytest.ini` located at the root dir of
        topotests.
        """
        self.config = configparser.ConfigParser(tgen_defaults)
        pytestini_path = os.path.join(CWD, '../pytest.ini')
        self.config.read(pytestini_path)

    def add_router(self, name=None, cls=topotest.Router, **params):
        """
        Adds a new router to the topology. This function has the following
        options:
        * `name`: (optional) select the router name
        * `daemondir`: (optional) custom daemon binary directory
        * `routertype`: (optional) `quagga` or `frr`
        Returns a TopoRouter.
        """
        if name is None:
            name = 'r{}'.format(self.routern)
        if name in self.gears:
            raise KeyError('router already exists')

        params['frrdir'] = self.config.get(self.CONFIG_SECTION, 'frrdir')
        params['quaggadir'] = self.config.get(self.CONFIG_SECTION, 'quaggadir')
        params['memleak_path'] = self.config.get(self.CONFIG_SECTION, 'memleak_path')
        if not params.has_key('routertype'):
            params['routertype'] = self.config.get(self.CONFIG_SECTION, 'routertype')

        self.gears[name] = TopoRouter(self, cls, name, **params)
        self.routern += 1
        return self.gears[name]

    def add_switch(self, name=None, cls=topotest.LegacySwitch):
        """
        Adds a new switch to the topology. This function has the following
        options:
        name: (optional) select the switch name
        Returns the switch name and number.
        """
        if name is None:
            name = 's{}'.format(self.switchn)
        if name in self.gears:
            raise KeyError('switch already exists')

        self.gears[name] = TopoSwitch(self, cls, name)
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
            name = 'peer{}'.format(self.peern)
        if name in self.gears:
            raise KeyError('exabgp peer already exists')

        self.gears[name] = TopoExaBGP(self, name, ip=ip, defaultRoute=defaultRoute)
        self.peern += 1
        return self.gears[name]

    def add_link(self, node1, node2, ifname1=None, ifname2=None):
        """
        Creates a connection between node1 and node2. The nodes can be the
        following:
        * TopoGear
          * TopoRouter
          * TopoSwitch
        """
        if not isinstance(node1, TopoGear):
            raise ValueError('invalid node1 type')
        if not isinstance(node2, TopoGear):
            raise ValueError('invalid node2 type')

        if ifname1 is None:
            ifname1 = node1.new_link()
        if ifname2 is None:
            ifname2 = node2.new_link()

        node1.register_link(ifname1, node2, ifname2)
        node2.register_link(ifname2, node1, ifname1)
        self.topo.addLink(node1.name, node2.name,
                          intfName1=ifname1, intfName2=ifname2)

    def get_gears(self, geartype):
        """
        Returns a dictionary of all gears of type `geartype`.

        Normal usage:
        * Dictionary iteration:
        ```py
        tgen = get_topogen()
        router_dict = tgen.get_gears(TopoRouter)
        for router_name, router in router_dict.iteritems():
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
        return dict((name, gear) for name, gear in self.gears.iteritems()
                    if isinstance(gear, geartype))

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

    def start_topology(self, log_level=None):
        """
        Starts the topology class. Possible `log_level`s are:
        'debug': all information possible
        'info': informational messages
        'output': default logging level defined by Mininet
        'warning': only warning, error and critical messages
        'error': only error and critical messages
        'critical': only critical messages
        """
        # If log_level is not specified use the configuration.
        if log_level is None:
            log_level = self.config.get(self.CONFIG_SECTION, 'verbosity')

        # Set python logger level
        logger_config.set_log_level(log_level)

        # Run mininet
        if log_level == 'debug':
            setLogLevel(log_level)

        logger.info('starting topology: {}'.format(self.modname))
        self.net.start()

    def start_router(self, router=None):
        """
        Call the router startRouter method.
        If no router is specified it is called for all registred routers.
        """
        if router is None:
            # pylint: disable=r1704
            for _, router in self.routers().iteritems():
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
        logger.info('stopping topology: {}'.format(self.modname))
        errors = ""
        for gear in self.gears.values():
            gear.stop(False, False)
        for gear in self.gears.values():
            errors += gear.stop(True, False)
        if len(errors) > 0:
            assert "Errors found post shutdown - details follow:" == 0, errors

        self.net.stop()

    def mininet_cli(self):
        """
        Interrupt the test and call the command line interface for manual
        inspection. Should be only used on non production code.
        """
        if not sys.stdin.isatty():
            raise EnvironmentError(
                'you must run pytest with \'-s\' in order to use mininet CLI')

        CLI(self.net)

    def is_memleak_enabled(self):
        "Returns `True` if memory leak report is enable, otherwise `False`."
        # On router failure we can't run the memory leak test
        if self.routers_have_failure():
            return False

        memleak_file = (os.environ.get('TOPOTESTS_CHECK_MEMLEAK') or
                        self.config.get(self.CONFIG_SECTION, 'memleak_path'))
        if memleak_file is None:
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
        logger.info(message)

        # If no code is defined use a sequential number
        if code is None:
            code = len(self.errorsd)

        self.errorsd[code] = message
        self.errors += '\n{}: {}'.format(code, message)

    def has_errors(self):
        "Returns whether errors exist or not."
        return len(self.errorsd) > 0

    def routers_have_failure(self):
        "Runs an assertion to make sure that all routers are running."
        if self.has_errors():
            return True

        errors = ''
        router_list = self.routers().values()
        for router in router_list:
            result = router.check_router_running()
            if result != '':
                errors += result + '\n'

        if errors != '':
            self.set_error(errors, 'router_error')
            assert False, errors
            return True
        return False

#
# Topology gears (equipment)
#

class TopoGear(object):
    "Abstract class for type checking"

    def __init__(self):
        self.tgen = None
        self.name = None
        self.cls = None
        self.links = {}
        self.linkn = 0

    def __str__(self):
        links = ''
        for myif, dest in self.links.iteritems():
            _, destif = dest
            if links != '':
                links += ','
            links += '"{}"<->"{}"'.format(myif, destif)

        return 'TopoGear<name="{}",links=[{}]>'.format(self.name, links)

    def start(self):
        "Basic start function that just reports equipment start"
        logger.info('starting "{}"'.format(self.name))

    def stop(self, wait=True, assertOnError=True):
        "Basic start function that just reports equipment stop"
        logger.info('stopping "{}"'.format(self.name))
        return ""

    def run(self, command):
        """
        Runs the provided command string in the router and returns a string
        with the response.
        """
        return self.tgen.net[self.name].cmd(command)

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
            raise KeyError('interface doesn\'t exists')

        if enabled is True:
            operation = 'up'
        else:
            operation = 'down'

        logger.info('setting node "{}" link "{}" to state "{}"'.format(
            self.name, myif, operation
        ))
        extract=''
        if netns is not None:
            extract = 'ip netns exec {} '.format(netns)
        return self.run('{}ip link set dev {} {}'.format(extract, myif, operation))

    def peer_link_enable(self, myif, enabled=True, netns=None):
        """
        Set the peer interface administrative state.
        myif: this node interface name
        enabled: whether we should enable or disable the interface

        NOTE: this is used to simulate a link down on this node, since when the
        peer disables their interface our interface status changes to no link.
        """
        if myif not in self.links.keys():
            raise KeyError('interface doesn\'t exists')

        node, nodeif = self.links[myif]
        node.link_enable(nodeif, enabled, netns)

    def new_link(self):
        """
        Generates a new unique link name.

        NOTE: This function should only be called by Topogen.
        """
        ifname = '{}-eth{}'.format(self.name, self.linkn)
        self.linkn += 1
        return ifname

    def register_link(self, myif, node, nodeif):
        """
        Register link between this node interface and outside node.

        NOTE: This function should only be called by Topogen.
        """
        if myif in self.links.keys():
            raise KeyError('interface already exists')

        self.links[myif] = (node, nodeif)

class TopoRouter(TopoGear):
    """
    Router abstraction.
    """

    # The default required directories by Quagga/FRR
    PRIVATE_DIRS = [
        '/etc/frr',
        '/etc/quagga',
        '/var/run/frr',
        '/var/run/quagga',
        '/var/log'
    ]

    # Router Daemon enumeration definition.
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
    RD = {
        RD_ZEBRA: 'zebra',
        RD_RIP: 'ripd',
        RD_RIPNG: 'ripngd',
        RD_OSPF: 'ospfd',
        RD_OSPF6: 'ospf6d',
        RD_ISIS: 'isisd',
        RD_BGP: 'bgpd',
        RD_PIM: 'pimd',
        RD_LDP: 'ldpd',
        RD_EIGRP: 'eigrpd',
        RD_NHRP: 'nhrpd',
        RD_STATIC: 'staticd',
        RD_BFD: 'bfdd',
        RD_SHARP: 'sharpd',
    }

    def __init__(self, tgen, cls, name, **params):
        """
        The constructor has the following parameters:
        * tgen: Topogen object
        * cls: router class that will be used to instantiate
        * name: router name
        * daemondir: daemon binary directory
        * routertype: 'quagga' or 'frr'
        """
        super(TopoRouter, self).__init__()
        self.tgen = tgen
        self.net = None
        self.name = name
        self.cls = cls
        self.options = {}
        self.routertype = params.get('routertype', 'frr')
        if not params.has_key('privateDirs'):
            params['privateDirs'] = self.PRIVATE_DIRS

        self.options['memleak_path'] = params.get('memleak_path', None)

        # Create new log directory
        self.logdir = '/tmp/topotests/{}'.format(self.tgen.modname)
        # Clean up before starting new log files: avoids removing just created
        # log files.
        self._prepare_tmpfiles()
        # Propagate the router log directory
        params['logdir'] = self.logdir

        #setup the per node directory
        dir = '{}/{}'.format(self.logdir, self.name)
        os.system('mkdir -p ' + dir)
        os.system('chmod -R go+rw /tmp/topotests')

        # Open router log file
        logfile = '{0}/{1}.log'.format(self.logdir, name)
        self.logger = logger_config.get_logger(name=name, target=logfile)

        self.tgen.topo.addNode(self.name, cls=self.cls, **params)

    def __str__(self):
        gear = super(TopoRouter, self).__str__()
        gear += ' TopoRouter<>'
        return gear

    def _prepare_tmpfiles(self):
        # Create directories if they don't exist
        try:
            os.makedirs(self.logdir, 0o755)
        except OSError:
            pass

        # Allow unprivileged daemon user (frr/quagga) to create log files
        try:
            # Only allow group, if it exist.
            gid = grp.getgrnam(self.routertype)[2]
            os.chown(self.logdir, 0, gid)
            os.chmod(self.logdir, 0o775)
        except KeyError:
            # Allow anyone, but set the sticky bit to avoid file deletions
            os.chmod(self.logdir, 0o1777)

        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob('{}/{}/*.log'.format(self.logdir, self.name)))
        # Remove old core files
        map(os.remove, glob.glob('{}/{}/*.dmp'.format(self.logdir, self.name)))

    def check_capability(self, daemon, param):
        """
        Checks a capability daemon against an argument option
        Return True if capability available. False otherwise
        """
        daemonstr = self.RD.get(daemon)
        self.logger.info('check capability {} for "{}"'.format(param, daemonstr))
        return self.tgen.net[self.name].checkCapability(daemonstr, param)

    def load_config(self, daemon, source=None, param=None):
        """
        Loads daemon configuration from the specified source
        Possible daemon values are: TopoRouter.RD_ZEBRA, TopoRouter.RD_RIP,
        TopoRouter.RD_RIPNG, TopoRouter.RD_OSPF, TopoRouter.RD_OSPF6,
        TopoRouter.RD_ISIS, TopoRouter.RD_BGP, TopoRouter.RD_LDP,
        TopoRouter.RD_PIM.
        """
        daemonstr = self.RD.get(daemon)
        self.logger.info('loading "{}" configuration: {}'.format(daemonstr, source))
        self.tgen.net[self.name].loadConf(daemonstr, source, param)

    def check_router_running(self):
        """
        Run a series of checks and returns a status string.
        """
        self.logger.info('checking if daemons are running')
        return self.tgen.net[self.name].checkRouterRunning()

    def start(self):
        """
        Start router:
        * Load modules
        * Clean up files
        * Configure interfaces
        * Start daemons (e.g. FRR/Quagga)
        * Configure daemon logging files
        """
        self.logger.debug('starting')
        nrouter = self.tgen.net[self.name]
        result = nrouter.startRouter(self.tgen)

        # Enable all daemon command logging, logging files
        # and set them to the start dir.
        for daemon, enabled in nrouter.daemons.iteritems():
            if enabled == 0:
                continue
            self.vtysh_cmd('configure terminal\nlog commands\nlog file {}.log'.format(
                daemon), daemon=daemon)

        if result != '':
            self.tgen.set_error(result)
        else:
            # Enable MPLS processing on all interfaces.
            for interface in self.links.keys():
                set_sysctl(nrouter, 'net.mpls.conf.{}.input'.format(interface), 1)

        return result

    def stop(self, wait=True, assertOnError=True):
        """
        Stop router:
        * Kill daemons
        """
        self.logger.debug('stopping')
        return self.tgen.net[self.name].stopRouter(wait, assertOnError)

    def vtysh_cmd(self, command, isjson=False, daemon=None):
        """
        Runs the provided command string in the vty shell and returns a string
        with the response.

        This function also accepts multiple commands, but this mode does not
        return output for each command. See vtysh_multicmd() for more details.
        """
        # Detect multi line commands
        if command.find('\n') != -1:
            return self.vtysh_multicmd(command, daemon=daemon)

        dparam = ''
        if daemon is not None:
            dparam += '-d {}'.format(daemon)

        vtysh_command = 'vtysh {} -c "{}" 2>/dev/null'.format(dparam, command)

        output = self.run(vtysh_command)
        self.logger.info('\nvtysh command => {}\nvtysh output <= {}'.format(
            command, output))
        if isjson is False:
            return output

        try:
            return json.loads(output)
        except ValueError:
            logger.warning('vtysh_cmd: failed to convert json output')
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

        dparam = ''
        if daemon is not None:
            dparam += '-d {}'.format(daemon)

        # Run the commands and delete the temporary file
        if pretty_output:
            vtysh_command = 'vtysh {} < {}'.format(dparam, fname)
        else:
            vtysh_command = 'vtysh {} -f {}'.format(dparam, fname)

        res = self.run(vtysh_command)
        os.unlink(fname)

        self.logger.info('\nvtysh command => "{}"\nvtysh output <= "{}"'.format(
            vtysh_command, res))

        return res

    def report_memory_leaks(self, testname):
        """
        Runs the router memory leak check test. Has the following parameter:
        testname: the test file name for identification

        NOTE: to run this you must have the environment variable
        TOPOTESTS_CHECK_MEMLEAK set or memleak_path configured in `pytest.ini`.
        """
        memleak_file = os.environ.get('TOPOTESTS_CHECK_MEMLEAK') or self.options['memleak_path']
        if memleak_file is None:
            return

        self.stop()
        self.logger.info('running memory leak report')
        self.tgen.net[self.name].report_memory_leaks(memleak_file, testname)

    def version_info(self):
        "Get equipment information from 'show version'."
        output = self.vtysh_cmd('show version').split('\n')[0]
        columns = topotest.normalize_text(output).split(' ')
        try:
            return {
                'type': columns[0],
                'version': columns[1],
            }
        except IndexError:
            return {
                'type': None,
                'version': None,
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
        return self.tgen.net[self.name].checkRouterVersion(cmpop, version)

    def has_type(self, rtype):
        """
        Compares router type with `rtype`. Returns `True` if the type matches,
        otherwise `false`.
        """
        curtype = self.version_info()['type']
        return rtype == curtype

    def has_mpls(self):
        nrouter = self.tgen.net[self.name]
        return nrouter.hasmpls

class TopoSwitch(TopoGear):
    """
    Switch abstraction. Has the following properties:
    * cls: switch class that will be used to instantiate
    * name: switch name
    """
    # pylint: disable=too-few-public-methods

    def __init__(self, tgen, cls, name):
        super(TopoSwitch, self).__init__()
        self.tgen = tgen
        self.net = None
        self.name = name
        self.cls = cls
        self.tgen.topo.addSwitch(name, cls=self.cls)

    def __str__(self):
        gear = super(TopoSwitch, self).__str__()
        gear += ' TopoSwitch<>'
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
        * `privateDirs`: directories that will be mounted on a different domain
          (e.g. '/etc/important_dir').
        """
        super(TopoHost, self).__init__()
        self.tgen = tgen
        self.net = None
        self.name = name
        self.options = params
        self.tgen.topo.addHost(name, **params)

    def __str__(self):
        gear = super(TopoHost, self).__str__()
        gear += ' TopoHost<ip="{}",defaultRoute="{}",privateDirs="{}">'.format(
            self.options['ip'], self.options['defaultRoute'],
            str(self.options['privateDirs']))
        return gear

class TopoExaBGP(TopoHost):
    "ExaBGP peer abstraction."
    # pylint: disable=too-few-public-methods

    PRIVATE_DIRS = [
        '/etc/exabgp',
        '/var/run/exabgp',
        '/var/log',
    ]

    def __init__(self, tgen, name, **params):
        """
        ExaBGP usually uses the following parameters:
        * `ip`: the IP address (string) for the host interface
        * `defaultRoute`: the default route that will be installed
          (e.g. 'via 10.0.0.1')

        Note: the different between a host and a ExaBGP peer is that this class
        has a privateDirs already defined and contains functions to handle ExaBGP
        things.
        """
        params['privateDirs'] = self.PRIVATE_DIRS
        super(TopoExaBGP, self).__init__(tgen, name, **params)
        self.tgen.topo.addHost(name, **params)

    def __str__(self):
        gear = super(TopoExaBGP, self).__str__()
        gear += ' TopoExaBGP<>'.format()
        return gear

    def start(self, peer_dir, env_file=None):
        """
        Start running ExaBGP daemon:
        * Copy all peer* folder contents into /etc/exabgp
        * Copy exabgp env file if specified
        * Make all python files runnable
        * Run ExaBGP with env file `env_file` and configuration peer*/exabgp.cfg
        """
        self.run('mkdir /etc/exabgp')
        self.run('chmod 755 /etc/exabgp')
        self.run('cp {}/* /etc/exabgp/'.format(peer_dir))
        if env_file is not None:
            self.run('cp {} /etc/exabgp/exabgp.env'.format(env_file))
        self.run('chmod 644 /etc/exabgp/*')
        self.run('chmod a+x /etc/exabgp/*.py')
        self.run('chown -R exabgp:exabgp /etc/exabgp')
        output = self.run('exabgp -e /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg')
        if output == None or len(output) == 0:
            output = '<none>'
        logger.info('{} exabgp started, output={}'.format(self.name, output))

    def stop(self, wait=True, assertOnError=True):
        "Stop ExaBGP peer and kill the daemon"
        self.run('kill `cat /var/run/exabgp/exabgp.pid`')
        return ""


#
# Diagnostic function
#

# Disable linter branch warning. It is expected to have these here.
# pylint: disable=R0912
def diagnose_env_linux():
    """
    Run diagnostics in the running environment. Returns `True` when everything
    is ok, otherwise `False`.
    """
    ret = True

    # Test log path exists before installing handler.
    if not os.path.isdir('/tmp'):
        logger.warning('could not find /tmp for logs')
    else:
        os.system('mkdir /tmp/topotests')
        # Log diagnostics to file so it can be examined later.
        fhandler = logging.FileHandler(filename='/tmp/topotests/diagnostics.txt')
        fhandler.setLevel(logging.DEBUG)
        fhandler.setFormatter(
            logging.Formatter(fmt='%(asctime)s %(levelname)s: %(message)s')
        )
        logger.addHandler(fhandler)

    logger.info('Running environment diagnostics')

    # Load configuration
    config = configparser.ConfigParser(tgen_defaults)
    pytestini_path = os.path.join(CWD, '../pytest.ini')
    config.read(pytestini_path)

    # Assert that we are running as root
    if os.getuid() != 0:
        logger.error('you must run topotest as root')
        ret = False

    # Assert that we have mininet
    if os.system('which mn >/dev/null 2>/dev/null') != 0:
        logger.error('could not find mininet binary (mininet is not installed)')
        ret = False

    # Assert that we have iproute installed
    if os.system('which ip >/dev/null 2>/dev/null') != 0:
        logger.error('could not find ip binary (iproute is not installed)')
        ret = False

    # Assert that we have gdb installed
    if os.system('which gdb >/dev/null 2>/dev/null') != 0:
        logger.error('could not find gdb binary (gdb is not installed)')
        ret = False

    # Assert that FRR utilities exist
    frrdir = config.get('topogen', 'frrdir')
    hasfrr = False
    if not os.path.isdir(frrdir):
        logger.error('could not find {} directory'.format(frrdir))
        ret = False
    else:
        hasfrr = True
        try:
            pwd.getpwnam('frr')[2]
        except KeyError:
            logger.warning('could not find "frr" user')

        try:
            grp.getgrnam('frr')[2]
        except KeyError:
            logger.warning('could not find "frr" group')

        try:
            if 'frr' not in grp.getgrnam('frrvty').gr_mem:
                logger.error('"frr" user and group exist, but user is not under "frrvty"')
        except KeyError:
            logger.warning('could not find "frrvty" group')

        for fname in ['zebra', 'ospfd', 'ospf6d', 'bgpd', 'ripd', 'ripngd',
                      'isisd', 'pimd', 'ldpd']:
            path = os.path.join(frrdir, fname)
            if not os.path.isfile(path):
                # LDPd is an exception
                if fname == 'ldpd':
                    logger.info('could not find {} in {}'.format(fname, frrdir) +
                                '(LDPd tests will not run)')
                    continue

                logger.warning('could not find {} in {}'.format(fname, frrdir))
                ret = False
            else:
                if fname != 'zebra':
                    continue

                os.system(
                    '{} -v 2>&1 >/tmp/topotests/frr_zebra.txt'.format(path)
                )

    # Assert that Quagga utilities exist
    quaggadir = config.get('topogen', 'quaggadir')
    if hasfrr:
        # if we have frr, don't check for quagga
        pass
    elif not os.path.isdir(quaggadir):
        logger.info('could not find {} directory (quagga tests will not run)'.format(quaggadir))
    else:
        ret = True
        try:
            pwd.getpwnam('quagga')[2]
        except KeyError:
            logger.info('could not find "quagga" user')

        try:
            grp.getgrnam('quagga')[2]
        except KeyError:
            logger.info('could not find "quagga" group')

        try:
            if 'quagga' not in grp.getgrnam('quaggavty').gr_mem:
                logger.error('"quagga" user and group exist, but user is not under "quaggavty"')
        except KeyError:
            logger.warning('could not find "quaggavty" group')

        for fname in ['zebra', 'ospfd', 'ospf6d', 'bgpd', 'ripd', 'ripngd',
                      'isisd', 'pimd']:
            path = os.path.join(quaggadir, fname)
            if not os.path.isfile(path):
                logger.warning('could not find {} in {}'.format(fname, quaggadir))
                ret = False
            else:
                if fname != 'zebra':
                    continue

                os.system(
                    '{} -v 2>&1 >/tmp/topotests/quagga_zebra.txt'.format(path)
                )

    # Test MPLS availability
    krel = platform.release()
    if topotest.version_cmp(krel, '4.5') < 0:
        logger.info('LDPd tests will not run (have kernel "{}", but it requires 4.5)'.format(krel))

    # Test for MPLS Kernel modules available
    if not topotest.module_present('mpls-router', load=False) != 0:
        logger.info('LDPd tests will not run (missing mpls-router kernel module)')
    if not topotest.module_present('mpls-iptunnel', load=False) != 0:
        logger.info('LDPd tests will not run (missing mpls-iptunnel kernel module)')

    # TODO remove me when we start supporting exabgp >= 4
    try:
        output = subprocess.check_output(['exabgp', '-v'])
        line = output.split('\n')[0]
        version = line.split(' ')[2]
        if topotest.version_cmp(version, '4') >= 0:
            logger.warning('BGP topologies are still using exabgp version 3, expect failures')

    # We want to catch all exceptions
    # pylint: disable=W0702
    except:
        logger.warning('failed to find exabgp or returned error')

    # After we logged the output to file, remove the handler.
    logger.removeHandler(fhandler)

    return ret

def diagnose_env_freebsd():
    return True

def diagnose_env():
    if sys.platform.startswith("linux"):
        return diagnose_env_linux()
    elif sys.platform.startswith("freebsd"):
        return diagnose_env_freebsd()

    return False
