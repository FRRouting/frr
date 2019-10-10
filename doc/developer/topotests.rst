.. _topotests:

Topotests
=========

Topotests is a suite of topology tests for FRR built on top of Mininet.

Installation and Setup
----------------------

Only tested with Ubuntu 16.04 and Ubuntu 18.04 (which uses Mininet 2.2.x).

Instructions are the same for all setups (i.e. ExaBGP is only used for BGP
tests).

Installing Mininet Infrastructure
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: shell

   apt-get install mininet
   apt-get install python-pip
   apt-get install iproute
   pip install ipaddr
   pip install "pytest<5"
   pip install exabgp==3.4.17 (Newer 4.0 version of exabgp is not yet
   supported)
   useradd -d /var/run/exabgp/ -s /bin/false exabgp

Enable Coredumps
""""""""""""""""

Optional, will give better output.

.. code:: shell

   apt-get install gdb
   disable apport (which move core files)

Set ``enabled=0`` in ``/etc/default/apport``.

Next, update security limits by changing :file:`/etc/security/limits.conf` to::

   #<domain>      <type>  <item>         <value>
   *               soft    core          unlimited
   root            soft    core          unlimited
   *               hard    core          unlimited
   root            hard    core          unlimited

Reboot for options to take effect.

FRR Installation
^^^^^^^^^^^^^^^^

FRR needs to be installed separately. It is assume to be configured like the
standard Ubuntu Packages:

-  Binaries in :file:`/usr/lib/frr`
-  State Directory :file:`/var/run/frr`
-  Running under user ``frr``, group ``frr``
-  vtygroup: ``frrvty``
-  config directory: :file:`/etc/frr`
-  For FRR Packages, install the dbg package as well for coredump decoding

No FRR config needs to be done and no FRR daemons should be run ahead of the
test. They are all started as part of the test.

Manual FRR build
""""""""""""""""

If you prefer to manually build FRR, then use the following suggested config:

.. code:: shell

   ./configure \
       --prefix=/usr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-vtysh \
       --enable-pimd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --with-pkg-extra-version=-my-manual-build

And create ``frr`` user and ``frrvty`` group as follows:

.. code:: shell

   addgroup --system --gid 92 frr
   addgroup --system --gid 85 frrvty
   adduser --system --ingroup frr --home /var/run/frr/ \
      --gecos "FRRouting suite" --shell /bin/false frr
   usermod -G frrvty frr

Executing Tests
---------------

Execute all tests with output to console
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: shell

   py.test -s -v --tb=no

The above command must be executed from inside the topotests directory.

All test\_\* scripts in subdirectories are detected and executed (unless
disabled in ``pytest.ini`` file).

``--tb=no`` disables the python traceback which might be irrelevant unless the
test script itself is debugged.

Execute single test
^^^^^^^^^^^^^^^^^^^

.. code:: shell

   cd test_to_be_run
   ./test_to_be_run.py

For example, and assuming you are inside the frr directory:

.. code:: shell

   cd tests/topotests/bgp_l3vpn_to_bgp_vrf
   ./test_bgp_l3vpn_to_bgp_vrf.py

For further options, refer to pytest documentation.

Test will set exit code which can be used with ``git bisect``.

For the simulated topology, see the description in the python file.

If you need to clear the mininet setup between tests (if it isn't cleanly
shutdown), then use the ``mn -c`` command to clean up the environment.

StdErr log from daemos after exit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

To enable the reporting of any messages seen on StdErr after the daemons exit,
the following env variable can be set::

   export TOPOTESTS_CHECK_STDERR=Yes

(The value doesn't matter at this time. The check is whether the env
variable exists or not.) There is no pass/fail on this reporting; the
Output will be reported to the console.

Collect Memory Leak Information
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FRR processes can report unfreed memory allocations upon exit. To
enable the reporting of memory leaks, define an environment variable
``TOPOTESTS_CHECK_MEMLEAK`` with the file prefix, i.e.::

   export TOPOTESTS_CHECK_MEMLEAK="/home/mydir/memleak_"

This will enable the check and output to console and the writing of
the information to files with the given prefix (followed by testname),
ie :file:`/home/mydir/memcheck_test_bgp_multiview_topo1.txt` in case
of a memory leak.

Running Topotests with AddressSanitizer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Topotests can be run with AddressSanitizer. It requires GCC 4.8 or newer.
(Ubuntu 16.04 as suggested here is fine with GCC 5 as default). For more
information on AddressSanitizer, see
https://github.com/google/sanitizers/wiki/AddressSanitizer.

The checks are done automatically in the library call of ``checkRouterRunning``
(ie at beginning of tests when there is a check for all daemons running). No
changes or extra configuration for topotests is required beside compiling the
suite with AddressSanitizer enabled.

If a daemon crashed, then the errorlog is checked for AddressSanitizer output.
If found, then this is added with context (calling test) to
:file:`/tmp/AddressSanitizer.txt` in Markdown compatible format.

Compiling for GCC AddressSanitizer requires to use ``gcc`` as a linker as well
(instead of ``ld``). Here is a suggest way to compile frr with AddressSanitizer
for ``master`` branch:

.. code:: shell

   git clone https://github.com/FRRouting/frr.git
   cd frr
   ./bootstrap.sh
   ./configure \
       --enable-address-sanitizer \
       --prefix=/usr/lib/frr --sysconfdir=/etc/frr \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr --bindir=/usr/lib/frr \
       --enable-exampledir=/usr/lib/frr/examples \
       --with-moduledir=/usr/lib/frr/modules \
       --enable-multipath=0 --enable-rtadv \
       --enable-tcp-zebra --enable-fpm --enable-pimd \
       --enable-sharpd
   make
   sudo make install
   # Create symlink for vtysh, so topotest finds it in /usr/lib/frr
   sudo ln -s /usr/lib/frr/vtysh /usr/bin/

and create ``frr`` user and ``frrvty`` group as shown above.

.. _topotests_docker:

Running Tests with Docker
-------------------------

There is a Docker image which allows to run topotests.

Quickstart
^^^^^^^^^^

If you have Docker installed, you can run the topotests in Docker. The easiest
way to do this, is to use the make targets from this repository.

Your current user needs to have access to the Docker daemon.  Alternatively you
can run these commands as root.

.. code:: console

   make topotests

This command will pull the most recent topotests image from Dockerhub, compile
FRR inside of it, and run the topotests.

Advanced Usage
^^^^^^^^^^^^^^

Internally, the topotests make target uses a shell script to pull the image and
spawn the Docker container.

There are several environment variables which can be used to modify the
behavior of the script, these can be listed by calling it with ``-h``:

.. code:: console

   ./tests/topotests/docker/frr-topotests.sh -h

For example, a volume is used to cache build artifacts between multiple runs of
the image. If you need to force a complete recompile, you can set
``TOPOTEST_CLEAN``:

.. code:: console

   TOPOTEST_CLEAN=1 ./tests/topotests/docker/frr-topotests.sh

By default, ``frr-topotests.sh`` will build frr and run pytest. If you append
arguments and the first one starts with ``/`` or ``./``, they will replace the
call to pytest. If the appended arguments do not match this patttern, they will
be provided to pytest as arguments.  So, to run a specific test with more
verbose logging:

.. code:: console

   ./tests/topotests/docker/frr-topotests.sh -vv -s all-protocol-startup/test_all_protocol_startup.py

And to compile FRR but drop into a shell instead of running pytest:

.. code:: console

   ./tests/topotests/docker/frr-topotests.sh /bin/bash

Development
^^^^^^^^^^^

The Docker image just includes all the components to run the topotests, but not
the topotests themselves. So if you just want to write tests and don't want to
make changes to the environment provided by the Docker image. You don't need to
build your own Docker image if you do not want to.

When developing new tests, there is one caveat though: The startup script of
the container will run a ``git-clean`` on its copy of the FRR tree to avoid any
pollution of the container with build artefacts from the host. This will also
result in your newly written tests being unavailable in the container unless at
least added to the index with ``git-add``.

If you do want to test changes to the Docker image, you can locally build the
image and run the tests without pulling from the registry using the following
commands:

.. code:: console

   make topotests-build
   TOPOTEST_PULL=0 make topotests


.. _topotests-guidelines:

Guidelines
----------

Executing Tests
^^^^^^^^^^^^^^^

To run the whole suite of tests the following commands must be executed at the
top level directory of topotest:

.. code:: shell

   $ # Change to the top level directory of topotests.
   $ cd path/to/topotests
   $ # Tests must be run as root, since Mininet requires it.
   $ sudo pytest

In order to run a specific test, you can use the following command:

.. code:: shell

   $ # running a specific topology
   $ sudo pytest ospf-topo1/
   $ # or inside the test folder
   $ cd ospf-topo1
   $ sudo pytest # to run all tests inside the directory
   $ sudo pytest test_ospf_topo1.py # to run a specific test
   $ # or outside the test folder
   $ cd ..
   $ sudo pytest ospf-topo1/test_ospf_topo1.py # to run a specific one

The output of the tested daemons will be available at the temporary folder of
your machine:

.. code:: shell

   $ ls /tmp/topotest/ospf-topo1.test_ospf-topo1/r1
   ...
   zebra.err # zebra stderr output
   zebra.log # zebra log file
   zebra.out # zebra stdout output
   ...

You can also run memory leak tests to get reports:

.. code:: shell

   $ # Set the environment variable to apply to a specific test...
   $ sudo env TOPOTESTS_CHECK_MEMLEAK="/tmp/memleak_report_" pytest ospf-topo1/test_ospf_topo1.py
   $ # ...or apply to all tests adding this line to the configuration file
   $ echo 'memleak_path = /tmp/memleak_report_' >> pytest.ini
   $ # You can also use your editor
   $ $EDITOR pytest.ini
   $ # After running tests you should see your files:
   $ ls /tmp/memleak_report_*
   memleak_report_test_ospf_topo1.txt

Writing a New Test
^^^^^^^^^^^^^^^^^^

This section will guide you in all recommended steps to produce a standard
topology test.

This is the recommended test writing routine:

- Write a topology (Graphviz recommended)
- Obtain configuration files
- Write the test itself
- Create a Pull Request

Topotest File Hierarchy
"""""""""""""""""""""""

Before starting to write any tests one must know the file hierarchy. The
repository hierarchy looks like this:

.. code:: shell

   $ cd path/to/topotest
   $ find ./*
   ...
   ./README.md # repository read me
   ./GUIDELINES.md # this file
   ./conftest.py # test hooks - pytest related functions
   ./example-test # example test folder
   ./example-test/__init__.py # python package marker - must always exist.
   ./example-test/test_template.jpg # generated topology picture - see next section
   ./example-test/test_template.dot # Graphviz dot file
   ./example-test/test_template.py # the topology plus the test
   ...
   ./ospf-topo1 # the ospf topology test
   ./ospf-topo1/r1 # router 1 configuration files
   ./ospf-topo1/r1/zebra.conf # zebra configuration file
   ./ospf-topo1/r1/ospfd.conf # ospf configuration file
   ./ospf-topo1/r1/ospfroute.txt # 'show ip ospf' output reference file
   # removed other for shortness sake
   ...
   ./lib # shared test/topology functions
   ./lib/topogen.py # topogen implementation
   ./lib/topotest.py # topotest implementation

Guidelines for creating/editing topotest:

- New topologies that don't fit the existing directories should create its own
- Always remember to add the ``__init__.py`` to new folders, this makes auto
  complete engines and pylint happy
- Router (Quagga/FRR) specific code should go on topotest.py
- Generic/repeated router actions should have an abstraction in
  topogen.TopoRouter.
- Generic/repeated non-router code should go to topotest.py
- pytest related code should go to conftest.py (e.g. specialized asserts)

Defining the Topology
"""""""""""""""""""""

The first step to write a new test is to define the topology. This step can be
done in many ways, but the recommended is to use Graphviz to generate a drawing
of the topology. It allows us to see the topology graphically and to see the
names of equipment, links and addresses.

Here is an example of Graphviz dot file that generates the template topology
:file:`tests/topotests/example-test/test_template.dot` (the inlined code might
get outdated, please see the linked file)::

   graph template {
       label="template";

       # Routers
       r1 [
           shape=doubleoctagon,
           label="r1",
           fillcolor="#f08080",
           style=filled,
       ];
       r2 [
           shape=doubleoctagon,
           label="r2",
           fillcolor="#f08080",
           style=filled,
       ];

       # Switches
       s1 [
           shape=oval,
           label="s1\n192.168.0.0/24",
           fillcolor="#d0e0d0",
           style=filled,
       ];
       s2 [
           shape=oval,
           label="s2\n192.168.1.0/24",
           fillcolor="#d0e0d0",
           style=filled,
       ];

       # Connections
       r1 -- s1 [label="eth0\n.1"];

       r1 -- s2 [label="eth1\n.100"];
       r2 -- s2 [label="eth0\n.1"];
   }

Here is the produced graph:

.. graphviz::

   graph template {
       label="template";

       # Routers
       r1 [
           shape=doubleoctagon,
           label="r1",
           fillcolor="#f08080",
           style=filled,
       ];
       r2 [
           shape=doubleoctagon,
           label="r2",
           fillcolor="#f08080",
           style=filled,
       ];

       # Switches
       s1 [
           shape=oval,
           label="s1\n192.168.0.0/24",
           fillcolor="#d0e0d0",
           style=filled,
       ];
       s2 [
           shape=oval,
           label="s2\n192.168.1.0/24",
           fillcolor="#d0e0d0",
           style=filled,
       ];

       # Connections
       r1 -- s1 [label="eth0\n.1"];

       r1 -- s2 [label="eth1\n.100"];
       r2 -- s2 [label="eth0\n.1"];
   }

Generating / Obtaining Configuration Files
""""""""""""""""""""""""""""""""""""""""""

In order to get the configuration files or command output for each router, we
need to run the topology and execute commands in ``vtysh``. The quickest way to
achieve that is writing the topology building code and running the topology.

To bootstrap your test topology, do the following steps:

- Copy the template test

.. code:: shell

   $ mkdir new-topo/
   $ touch new-topo/__init__.py
   $ cp example-test/test_template.py new-topo/test_new_topo.py

- Modify the template according to your dot file

Here is the template topology described in the previous section in python code:

.. code:: py

   class TemplateTopo(Topo):
       "Test topology builder"
       def build(self, *_args, **_opts):
           "Build function"
           tgen = get_topogen(self)

           # Create 2 routers
           for routern in range(1, 3):
               tgen.add_router('r{}'.format(routern))

           # Create a switch with just one router connected to it to simulate a
           # empty network.
           switch = tgen.add_switch('s1')
           switch.add_link(tgen.gears['r1'])

           # Create a connection between r1 and r2
           switch = tgen.add_switch('s2')
           switch.add_link(tgen.gears['r1'])
           switch.add_link(tgen.gears['r2'])

- Run the topology

Topogen allows us to run the topology without running any tests, you can do
that using the following example commands:

.. code:: shell

   $ # Running your bootstraped topology
   $ sudo pytest -s --topology-only new-topo/test_new_topo.py
   $ # Running the test_template.py topology
   $ sudo pytest -s --topology-only example-test/test_template.py
   $ # Running the ospf_topo1.py topology
   $ sudo pytest -s --topology-only ospf-topo1/test_ospf_topo1.py

Parameters explanation:

.. program:: pytest

.. option:: -s

   Actives input/output capture. This is required by mininet in order to show
   the interactive shell.

.. option:: --topology-only

   Don't run any tests, just build the topology.

After executing the commands above, you should get the following terminal
output:

.. code:: shell

   === test session starts ===
   platform linux2 -- Python 2.7.12, pytest-3.1.2, py-1.4.34, pluggy-0.4.0
   rootdir: /media/sf_src/topotests, inifile: pytest.ini
   collected 3 items

   ospf-topo1/test_ospf_topo1.py *** Starting controller

   *** Starting 6 switches
   switch1 switch2 switch3 switch4 switch5 switch6 ...
   r2: frr zebra started
   r2: frr ospfd started
   r3: frr zebra started
   r3: frr ospfd started
   r1: frr zebra started
   r1: frr ospfd started
   r4: frr zebra started
   r4: frr ospfd started
   *** Starting CLI:
   mininet>

The last line shows us that we are now using the Mininet CLI (Command Line
Interface), from here you can call your router ``vtysh`` or even bash.

Here are some commands example:

.. code:: shell

   mininet> r1 ping 10.0.3.1
   PING 10.0.3.1 (10.0.3.1) 56(84) bytes of data.
   64 bytes from 10.0.3.1: icmp_seq=1 ttl=64 time=0.576 ms
   64 bytes from 10.0.3.1: icmp_seq=2 ttl=64 time=0.083 ms
   64 bytes from 10.0.3.1: icmp_seq=3 ttl=64 time=0.088 ms
   ^C
   --- 10.0.3.1 ping statistics ---
   3 packets transmitted, 3 received, 0% packet loss, time 1998ms
   rtt min/avg/max/mdev = 0.083/0.249/0.576/0.231 ms



   mininet> r1 ping 10.0.3.3
   PING 10.0.3.3 (10.0.3.3) 56(84) bytes of data.
   64 bytes from 10.0.3.3: icmp_seq=1 ttl=64 time=2.87 ms
   64 bytes from 10.0.3.3: icmp_seq=2 ttl=64 time=0.080 ms
   64 bytes from 10.0.3.3: icmp_seq=3 ttl=64 time=0.091 ms
   ^C
   --- 10.0.3.3 ping statistics ---
   3 packets transmitted, 3 received, 0% packet loss, time 2003ms
   rtt min/avg/max/mdev = 0.080/1.014/2.872/1.313 ms



   mininet> r3 vtysh

   Hello, this is FRRouting (version 3.1-devrzalamena-build).
   Copyright 1996-2005 Kunihiro Ishiguro, et al.

   frr-1# show running-config
   Building configuration...

   Current configuration:
   !
   frr version 3.1-devrzalamena-build
   frr defaults traditional
   hostname r3
   no service integrated-vtysh-config
   !
   log file zebra.log
   !
   log file ospfd.log
   !
   interface r3-eth0
    ip address 10.0.3.1/24
   !
   interface r3-eth1
    ip address 10.0.10.1/24
   !
   interface r3-eth2
    ip address 172.16.0.2/24
   !
   router ospf
    ospf router-id 10.0.255.3
    redistribute kernel
    redistribute connected
    redistribute static
    network 10.0.3.0/24 area 0
    network 10.0.10.0/24 area 0
    network 172.16.0.0/24 area 1
   !
   line vty
   !
   end
   frr-1#

After you successfully configured your topology, you can obtain the
configuration files (per-daemon) using the following commands:

.. code:: shell

   mininet> r3 vtysh -d ospfd

   Hello, this is FRRouting (version 3.1-devrzalamena-build).
   Copyright 1996-2005 Kunihiro Ishiguro, et al.

   frr-1# show running-config
   Building configuration...

   Current configuration:
   !
   frr version 3.1-devrzalamena-build
   frr defaults traditional
   no service integrated-vtysh-config
   !
   log file ospfd.log
   !
   router ospf
    ospf router-id 10.0.255.3
    redistribute kernel
    redistribute connected
    redistribute static
    network 10.0.3.0/24 area 0
    network 10.0.10.0/24 area 0
    network 172.16.0.0/24 area 1
   !
   line vty
   !
   end
   frr-1#

Writing Tests
"""""""""""""

Test topologies should always be bootstrapped from
:file:`tests/topotests/example-test/test_template.py` because it contains
important boilerplate code that can't be avoided, like:

- imports: os, sys, pytest, topotest/topogen and mininet topology class
- The global variable CWD (Current Working directory): which is most likely
  going to be used to reference the routers configuration file location

Example:

.. code:: py

   # For all registered routers, load the zebra configuration file
   for rname, router in router_list.iteritems():
       router.load_config(
           TopoRouter.RD_ZEBRA,
           os.path.join(CWD, '{}/zebra.conf'.format(rname))
       )
       # os.path.join() joins the CWD string with arguments adding the necessary
       # slashes ('/'). Arguments must not begin with '/'.

- The topology class that inherits from Mininet Topo class:

.. code:: py

   class TemplateTopo(Topo):
     def build(self, *_args, **_opts):
       tgen = get_topogen(self)
       # topology build code

- pytest ``setup_module()`` and ``teardown_module()`` to start the topology

.. code:: py

   def setup_module(_m):
       tgen = Topogen(TemplateTopo)
       tgen.start_topology('debug')

   def teardown_module(_m):
       tgen = get_topogen()
       tgen.stop_topology()

- ``__main__`` initialization code (to support running the script directly)

.. code:: py

   if __name__ == '__main__':
       sys.exit(pytest.main(["-s"]))

Requirements:

- Test code should always be declared inside functions that begin with the
  ``test_`` prefix. Functions beginning with different prefixes will not be run
  by pytest.
- Configuration files and long output commands should go into separated files
  inside folders named after the equipment.
- Tests must be able to run without any interaction. To make sure your test
  conforms with this, run it without the :option:`-s` parameter.

Tips:

- Keep results in stack variables, so people inspecting code with ``pdb`` can
  easily print their values.

Don't do this:

.. code:: py

   assert foobar(router1, router2)

Do this instead:

.. code:: py

   result = foobar(router1, router2)
   assert result

- Use ``assert`` messages to indicate where the test failed.

Example:

.. code:: py

   for router in router_list:
      # ...
      assert condition, 'Router "{}" condition failed'.format(router.name)

Debugging Execution
^^^^^^^^^^^^^^^^^^^

The most effective ways to inspect topology tests are:

- Run pytest with ``--pdb`` option. This option will cause a pdb shell to
  appear when an assertion fails

Example: ``pytest -s --pdb ospf-topo1/test_ospf_topo1.py``

- Set a breakpoint in the test code with ``pdb``

Example:

.. code:: py

   # Add the pdb import at the beginning of the file
   import pdb
   # ...

   # Add a breakpoint where you think the problem is
   def test_bla():
     # ...
     pdb.set_trace()
     # ...

The `Python Debugger <https://docs.python.org/2.7/library/pdb.html>`__ (pdb)
shell allows us to run many useful operations like:

- Setting breaking point on file/function/conditions (e.g. ``break``,
  ``condition``)
- Inspecting variables (e.g. ``p`` (print), ``pp`` (pretty print))
- Running python code

.. tip::

   The TopoGear (equipment abstraction class) implements the ``__str__`` method
   that allows the user to inspect equipment information.

Example of pdb usage:

.. code:: shell

   > /media/sf_src/topotests/ospf-topo1/test_ospf_topo1.py(121)test_ospf_convergence()
   -> for rnum in range(1, 5):
   (Pdb) help
   Documented commands (type help <topic>):
   ========================================
   EOF    bt         cont      enable  jump  pp       run      unt
   a      c          continue  exit    l     q        s        until
   alias  cl         d         h       list  quit     step     up
   args   clear      debug     help    n     r        tbreak   w
   b      commands   disable   ignore  next  restart  u        whatis
   break  condition  down      j       p     return   unalias  where

   Miscellaneous help topics:
   ==========================
   exec  pdb

   Undocumented commands:
   ======================
   retval  rv

   (Pdb) list
   116                                   title2="Expected output")
   117
   118     def test_ospf_convergence():
   119         "Test OSPF daemon convergence"
   120         pdb.set_trace()
   121  ->     for rnum in range(1, 5):
   122             router = 'r{}'.format(rnum)
   123
   124             # Load expected results from the command
   125             reffile = os.path.join(CWD, '{}/ospfroute.txt'.format(router))
   126             expected = open(reffile).read()
   (Pdb) step
   > /media/sf_src/topotests/ospf-topo1/test_ospf_topo1.py(122)test_ospf_convergence()
   -> router = 'r{}'.format(rnum)
   (Pdb) step
   > /media/sf_src/topotests/ospf-topo1/test_ospf_topo1.py(125)test_ospf_convergence()
   -> reffile = os.path.join(CWD, '{}/ospfroute.txt'.format(router))
   (Pdb) print rnum
   1
   (Pdb) print router
   r1
   (Pdb) tgen = get_topogen()
   (Pdb) pp tgen.gears[router]
   <lib.topogen.TopoRouter object at 0x7f74e06c9850>
   (Pdb) pp str(tgen.gears[router])
   'TopoGear<name="r1",links=["r1-eth0"<->"s1-eth0","r1-eth1"<->"s3-eth0"]> TopoRouter<>'
   (Pdb) l 125
   120         pdb.set_trace()
   121         for rnum in range(1, 5):
   122             router = 'r{}'.format(rnum)
   123
   124             # Load expected results from the command
   125  ->         reffile = os.path.join(CWD, '{}/ospfroute.txt'.format(router))
   126             expected = open(reffile).read()
   127
   128             # Run test function until we get an result. Wait at most 60 seconds.
   129             test_func = partial(compare_show_ip_ospf, router, expected)
   130             result, diff = topotest.run_and_expect(test_func, '',
   (Pdb) router1 = tgen.gears[router]
   (Pdb) router1.vtysh_cmd('show ip ospf route')
   '============ OSPF network routing table ============\r\nN    10.0.1.0/24           [10] area: 0.0.0.0\r\n                           directly attached to r1-eth0\r\nN    10.0.2.0/24           [20] area: 0.0.0.0\r\n                           via 10.0.3.3, r1-eth1\r\nN    10.0.3.0/24           [10] area: 0.0.0.0\r\n                           directly attached to r1-eth1\r\nN    10.0.10.0/24          [20] area: 0.0.0.0\r\n                           via 10.0.3.1, r1-eth1\r\nN IA 172.16.0.0/24         [20] area: 0.0.0.0\r\n                           via 10.0.3.1, r1-eth1\r\nN IA 172.16.1.0/24         [30] area: 0.0.0.0\r\n                           via 10.0.3.1, r1-eth1\r\n\r\n============ OSPF router routing table =============\r\nR    10.0.255.2            [10] area: 0.0.0.0, ASBR\r\n                           via 10.0.3.3, r1-eth1\r\nR    10.0.255.3            [10] area: 0.0.0.0, ABR, ASBR\r\n                           via 10.0.3.1, r1-eth1\r\nR    10.0.255.4         IA [20] area: 0.0.0.0, ASBR\r\n                           via 10.0.3.1, r1-eth1\r\n\r\n============ OSPF external routing table ===========\r\n\r\n\r\n'
    (Pdb) tgen.mininet_cli()
    *** Starting CLI:
    mininet>

To enable more debug messages in other Topogen subsystems (like Mininet), more
logging messages can be displayed by modifying the test configuration file
``pytest.ini``:

.. code:: ini

   [topogen]
   # Change the default verbosity line from 'info'...
   #verbosity = info
   # ...to 'debug'
   verbosity = debug

Instructions for use, write or debug topologies can be found in :ref:`topotests-guidelines`.
To learn/remember common code snippets see :ref:`topotests-snippets`.

Before creating a new topology, make sure that there isn't one already that
does what you need. If nothing is similar, then you may create a new topology,
preferably, using the newest template
(:file:`tests/topotests/example-test/test_template.py`).

.. include:: topotests-snippets.rst

License
-------

All the configs and scripts are licensed under a ISC-style license. See Python
scripts for details.
