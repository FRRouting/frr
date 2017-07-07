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
import json
import ConfigParser
import glob
import grp

from mininet.net import Mininet
from mininet.log import setLogLevel
from mininet.cli import CLI

from lib import topotest
from lib.topolog import logger, logger_config

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
        defaults = {
            'verbosity': 'info',
            'frrdir': '/usr/lib/frr',
            'quaggadir': '/usr/lib/quagga',
            'routertype': 'frr',
            'memleak_path': None,
        }
        self.config = ConfigParser.ConfigParser(defaults)
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

    def routers(self):
        """
        Returns the router dictionary (key is the router name and value is the
        router object itself).
        """
        return dict((rname, gear) for rname, gear in self.gears.iteritems()
                    if isinstance(gear, TopoRouter))

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
        "Stops the network topology"
        logger.info('stopping topology: {}'.format(self.modname))
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
        memleak_file = os.environ.get('TOPOTESTS_CHECK_MEMLEAK')
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

    def link_enable(self, myif, enabled=True):
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
        return self.run('ip link set dev {} {}'.format(myif, operation))

    def peer_link_enable(self, myif, enabled=True):
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
        node.link_enable(nodeif, enabled)

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

        # Open router log file
        logfile = '{}/{}.log'.format(self.logdir, name)
        self.logger = logger_config.get_logger(name=name, target=logfile)
        self.tgen.topo.addNode(self.name, cls=self.cls, **params)

    def __str__(self):
        gear = super(TopoRouter, self).__str__()
        gear += ' TopoRouter<>'
        return gear

    def _prepare_tmpfiles(self):
        # Create directories if they don't exist
        try:
            os.makedirs(self.logdir, 0755)
        except OSError:
            pass

        # Allow unprivileged daemon user (frr/quagga) to create log files
        try:
            # Only allow group, if it exist.
            gid = grp.getgrnam(self.routertype)[2]
            os.chown(self.logdir, 0, gid)
            os.chmod(self.logdir, 0775)
        except KeyError:
            # Allow anyone, but set the sticky bit to avoid file deletions
            os.chmod(self.logdir, 01777)

        # Try to find relevant old logfiles in /tmp and delete them
        map(os.remove, glob.glob('{}/*{}*.log'.format(self.logdir, self.name)))
        # Remove old core files
        map(os.remove, glob.glob('{}/{}*.dmp'.format(self.logdir, self.name)))

    def load_config(self, daemon, source=None):
        """
        Loads daemon configuration from the specified source
        Possible daemon values are: TopoRouter.RD_ZEBRA, TopoRouter.RD_RIP,
        TopoRouter.RD_RIPNG, TopoRouter.RD_OSPF, TopoRouter.RD_OSPF6,
        TopoRouter.RD_ISIS, TopoRouter.RD_BGP, TopoRouter.RD_LDP,
        TopoRouter.RD_PIM.
        """
        daemonstr = self.RD.get(daemon)
        self.logger.info('loading "{}" configuration: {}'.format(daemonstr, source))
        self.tgen.net[self.name].loadConf(daemonstr, source)

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
        result = nrouter.startRouter()

        # Enable all daemon logging files and set them to the logdir.
        for daemon, enabled in nrouter.daemons.iteritems():
            if enabled == 0:
                continue
            self.vtysh_cmd('configure terminal\nlog file {}/{}-{}.log'.format(
                self.logdir, self.name, daemon))

        return result

    def stop(self):
        """
        Stop router:
        * Kill daemons
        """
        self.logger.debug('stopping')
        return self.tgen.net[self.name].stopRouter()

    def vtysh_cmd(self, command, isjson=False):
        """
        Runs the provided command string in the vty shell and returns a string
        with the response.

        This function also accepts multiple commands, but this mode does not
        return output for each command. See vtysh_multicmd() for more details.
        """
        # Detect multi line commands
        if command.find('\n') != -1:
            return self.vtysh_multicmd(command)

        vtysh_command = 'vtysh -c "{}" 2>/dev/null'.format(command)
        output = self.run(vtysh_command)
        self.logger.info('\nvtysh command => {}\nvtysh output <= {}'.format(
            command, output))
        if isjson is False:
            return output

        return json.loads(output)

    def vtysh_multicmd(self, commands, pretty_output=True):
        """
        Runs the provided commands in the vty shell and return the result of
        execution.

        pretty_output: defines how the return value will be presented. When
        True it will show the command as they were executed in the vty shell,
        otherwise it will only show lines that failed.
        """
        # Prepare the temporary file that will hold the commands
        fname = topotest.get_file(commands)

        # Run the commands and delete the temporary file
        if pretty_output:
            vtysh_command = 'vtysh < {}'.format(fname)
        else:
            vtysh_command = 'vtysh -f {}'.format(fname)

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
