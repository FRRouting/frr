.. _topotests:

Topotests
=========

Topotests is a suite of topology tests for FRR built on top of micronet.

Installation and Setup
----------------------

Topotests run under python3.

Tested with Ubuntu 22.04,Ubuntu 20.04, and Debian 12.

Python protobuf version < 4 is required b/c python protobuf >= 4 requires a
protoc >= 3.19, and older package versions are shipped by in the above distros.

Instructions are the same for all setups. However, ExaBGP is only used for
BGP tests.

Tshark is only required if you enable any packet captures on test runs.

Valgrind is only required if you enable valgrind on test runs.

Installing Topotest Requirements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: shell

   apt-get install \
       gdb \
       iproute2 \
       net-tools \
       python3-pip \
       iputils-ping \
       iptables \
       tshark \
       valgrind
   python3 -m pip install wheel
   python3 -m pip install 'pytest>=8.3.2' 'pytest-asyncio>=0.24.0' 'pytest-xdist>=3.6.1'
   python3 -m pip install 'scapy>=2.4.5'
   python3 -m pip install xmltodict
   python3 -m pip install git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311
   useradd -d /var/run/exabgp/ -s /bin/false exabgp

The version of protobuf package that is installed on your system will determine
which versions of the python protobuf packages you need to install.

.. code:: shell

   # - Either - For protobuf version <= 3.12
   python3 -m pip install 'protobuf<4'

   # - OR- for protobuf version >= 3.21
   python3 -m pip install 'protobuf>=4'

   # To enable the gRPC topotest also install:
   python3 -m pip install grpcio grpcio-tools


Enable Coredumps
""""""""""""""""

Optional, will give better output.

.. code:: shell

   disable apport (which move core files)

Set ``enabled=0`` in ``/etc/default/apport``.

Next, update security limits by changing :file:`/etc/security/limits.conf` to::

   #<domain>      <type>  <item>         <value>
   *               soft    core          unlimited
   root            soft    core          unlimited
   *               hard    core          unlimited
   root            hard    core          unlimited

Reboot for options to take effect.

SNMP Utilities Installation
"""""""""""""""""""""""""""

To run SNMP test you need to install SNMP utilities and MIBs. Unfortunately
there are some errors in the upstream MIBS which need to be patched up. The
following steps will get you there on Ubuntu 20.04.

.. code:: shell

   apt install libsnmp-dev
   apt install snmpd snmp
   apt install snmp-mibs-downloader
   download-mibs
   wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB
   wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU
   wget https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB
   edit /etc/snmp/snmp.conf to look like this
   # As the snmp packages come without MIB files due to license reasons, loading
   # of MIBs is disabled by default. If you added the MIBs you can reenable
   # loading them by commenting out the following line.
   mibs +ALL


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
       --sysconfdir=/etc \
       --localstatedir=/var \
       --sbindir=/usr/lib/frr \
       --enable-vtysh \
       --enable-pimd \
       --enable-pim6d \
       --enable-sharpd \
       --enable-multipath=64 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-vty-group=frrvty \
       --enable-snmp=agentx \
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

Configure your sudo environment
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Topotests must be run as root. Normally this will be accomplished through the
use of the ``sudo`` command. In order for topotests to be able to open new
windows (either XTerm or byobu/screen/tmux windows) certain environment
variables must be passed through the sudo command. One way to do this is to
specify the ``-E`` flag to ``sudo``. This will carry over most if not all
your environment variables include ``PATH``. For example:

.. code:: shell

   sudo -E python3 -m pytest -s -v

If you do not wish to use ``-E`` (e.g., to avoid ``sudo`` inheriting
``PATH``) you can modify your `/etc/sudoers` config file to specifically pass
the environment variables required by topotests. Add the following commands to
your ``/etc/sudoers`` config file.

.. code:: shell

   Defaults env_keep="TMUX"
   Defaults env_keep+="TMUX_PANE"
   Defaults env_keep+="STY"
   Defaults env_keep+="DISPLAY"

If there was already an ``env_keep`` configuration there be sure to use the
``+=`` rather than ``=`` on the first line above as well.


Execute all tests in distributed test mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code:: shell

   sudo -E pytest -s -v -nauto --dist=loadfile

The above command must be executed from inside the topotests directory.

All test\_\* scripts in subdirectories are detected and executed (unless
disabled in ``pytest.ini`` file). Pytest will execute up to N tests in parallel
where N is based on the number of cores on the host.

Analyze Test Results (``analyze.py``)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

By default router and execution logs are saved in ``/tmp/topotests`` and an XML
results file is saved in ``/tmp/topotests/topotests.xml``. An analysis tool
``analyze.py`` is provided to archive and analyze these results after the run
completes.

After the test run completes one should pick an archive directory to store the
results in and pass this value to ``analyze.py``. On first execution the results
are moved to that directory from ``/tmp/topotests``. Subsequent runs of
``analyze.py`` with the same args will use that directories contents for instead
of copying any new results from ``/tmp``. Below is an example of this which also
shows the default behavior which is to display all failed and errored tests in
the run.

.. code:: shell

   ~/frr/tests/topotests# ./analyze.py -Ar run-save
   bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_converge
   ospf_basic_functionality/test_ospf_lan.py::test_ospf_lan_tc1_p0
   bgp_gr_functionality_topo2/test_bgp_gr_functionality_topo2.py::test_BGP_GR_10_p2
   bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_routingTable

Here we see that 4 tests have failed. We can dig deeper by displaying the
captured logs and errors. First let's redisplay the results enumerated by adding
the ``-E`` flag

.. code:: shell

   ~/frr/tests/topotests# ./analyze.py -Ar run-save -E
   0 bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_converge
   1 ospf_basic_functionality/test_ospf_lan.py::test_ospf_lan_tc1_p0
   2 bgp_gr_functionality_topo2/test_bgp_gr_functionality_topo2.py::test_BGP_GR_10_p2
   3 bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_routingTable

Now to look at the error message for a failed test we use ``-T N`` where N is
the number of the test we are interested in along with ``--errmsg`` option.

.. code:: shell

    ~/frr/tests/topotests# ./analyze.py -Ar run-save -T0 --errmsg
    bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_converge: AssertionError: BGP did not converge:

      IPv4 Unicast Summary:
      BGP router identifier 172.30.1.1, local AS number 100 VIEW 1 vrf-id -1
      BGP table version 1
      RIB entries 1, using 184 bytes of memory
      Peers 3, using 2169 KiB of memory

      Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
      172.16.1.1      4      65001         0         0        0    0    0    never      Connect        0 N/A
      172.16.1.2      4      65002         0         0        0    0    0    never      Connect        0 N/A
      172.16.1.5      4      65005         0         0        0    0    0    never      Connect        0 N/A

      Total number of neighbors 3

     assert False

Now to look at the error text for a failed test we can use ``-T RANGES`` where
``RANGES`` can be a number (e.g., ``5``), a range (e.g., ``0-10``), or a comma
separated list numbers and ranges (e.g., ``5,10-20,30``) of the test cases we
are interested in along with ``--errtext`` option. In the example below we'll
select the first failed test case.

.. code:: shell

    ~/frr/tests/topotests# ./analyze.py -Ar run-save -T0 --errtext
    bgp_multiview_topo1/test_bgp_multiview_topo1.py::test_bgp_converge: def test_bgp_converge():
            "Check for BGP converged on all peers and BGP views"

            global fatal_error
            global net
            [...]
            else:
                # Bail out with error if a router fails to converge
                bgpStatus = net["r%s" % i].cmd('vtysh -c "show ip bgp view %s summary"' % view)
    >           assert False, "BGP did not converge:\n%s" % bgpStatus
    E           AssertionError: BGP did not converge:
    E
    E             IPv4 Unicast Summary:
    E             BGP router identifier 172.30.1.1, local AS number 100 VIEW 1 vrf-id -1
                  [...]
    E             Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
    E             172.16.1.1      4      65001         0         0        0    0    0    never      Connect        0 N/A
    E             172.16.1.2      4      65002         0         0        0    0    0    never      Connect        0 N/A
                  [...]

To look at the full capture for a test including the stdout and stderr which
includes full debug logs, use ``--full`` option, or specify a ``-T RANGES`` without
specifying ``--errmsg`` or ``--errtext``.

.. code:: shell

    ~/frr/tests/topotests# ./analyze.py -Ar run-save -T0
    @classname: bgp_multiview_topo1.test_bgp_multiview_topo1
    @name: test_bgp_converge
    @time: 141.401
    @message: AssertionError: BGP did not converge:
    [...]
    system-out: --------------------------------- Captured Log ---------------------------------
    2021-08-09 02:55:06,581 DEBUG: lib.micronet_compat.topo: Topo(unnamed): Creating
    2021-08-09 02:55:06,581 DEBUG: lib.micronet_compat.topo: Topo(unnamed): addHost r1
    [...]
    2021-08-09 02:57:16,932 DEBUG: topolog.r1: LinuxNamespace(r1): cmd_status("['/bin/bash', '-c', 'vtysh -c "show ip bgp view 1 summary" 2> /dev/null | grep ^[0-9] | grep -vP " 11\\s+(\\d+)"']", kwargs: {'encoding': 'utf-8', 'stdout': -1, 'stderr': -2, 'shell': False})
    2021-08-09 02:57:22,290 DEBUG: topolog.r1: LinuxNamespace(r1): cmd_status("['/bin/bash', '-c', 'vtysh -c "show ip bgp view 1 summary" 2> /dev/null | grep ^[0-9] | grep -vP " 11\\s+(\\d+)"']", kwargs: {'encoding': 'utf-8', 'stdout': -1, 'stderr': -2, 'shell': False})
    2021-08-09 02:57:27,636 DEBUG: topolog.r1: LinuxNamespace(r1): cmd_status("['/bin/bash', '-c', 'vtysh -c "show ip bgp view 1 summary"']", kwargs: {'encoding': 'utf-8', 'stdout': -1, 'stderr': -2, 'shell': False})
    --------------------------------- Captured Out ---------------------------------
    system-err: --------------------------------- Captured Err ---------------------------------

Filtered results
""""""""""""""""

There are 4 types of test results, [e]rrored, [f]ailed, [p]assed, and
[s]kipped. One can select the set of results to show with the ``-S`` or
``--select`` flags along with the letters for each type (i.e., ``-S efps``
would select all results). By default ``analyze.py`` will use ``-S ef`` (i.e.,
[e]rrors and [f]ailures) unless the ``--search`` filter is given in which case
the default is to search all results (i.e., ``-S efps``).

One can find all results which contain a ``REGEXP``. To filter results using a
regular expression use the ``--search REGEXP`` option. In this case, by default,
all result types will be searched for a match against the given ``REGEXP``. If a
test result output contains a match it is selected into the set of results to show.

An example of using ``--search`` would be to search all tests results for some
log message, perhaps a warning or error.

Using XML Results File from CI
""""""""""""""""""""""""""""""

``analyze.py`` actually only needs the ``topotests.xml`` file to run. This is
very useful for analyzing a CI run failure where one only need download the
``topotests.xml`` artifact from the run and then pass that to ``analyze.py``
with the ``-r`` or ``--results`` option.

For local runs if you wish to simply copy the ``topotests.xml`` file (leaving
the log files where they are), you can pass the ``-a`` (or ``--save-xml``)
instead of the ``-A`` (or ``-save``) options.

Analyze Results from a Container Run
""""""""""""""""""""""""""""""""""""

``analyze.py`` can also be used with ``docker`` or ``podman`` containers.
Everything works exactly as with a host run except that you specify the name of
the container, or the container-id, using the `-C` or ``--container`` option.
``analyze.py`` will then use the results inside that containers
``/tmp/topotests`` directory. It will extract and save those results when you
pass the ``-A`` or ``-a`` options just as withe host results.


Execute single test
^^^^^^^^^^^^^^^^^^^

.. code:: shell

   cd test_to_be_run
   sudo -E pytest ./test_to_be_run.py

For example, and assuming you are inside the frr directory:

.. code:: shell

   cd tests/topotests/bgp_l3vpn_to_bgp_vrf
   sudo -E pytest ./test_bgp_l3vpn_to_bgp_vrf.py

For further options, refer to pytest documentation.

Test will set exit code which can be used with ``git bisect``.

For the simulated topology, see the description in the python file.

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
       --prefix=/usr/lib/frr \
       --sysconfdir=/etc \
       --localstatedir=/var \
       --sbindir=/usr/lib/frr --bindir=/usr/lib/frr \
       --with-moduledir=/usr/lib/frr/modules \
       --enable-multipath=0 --enable-rtadv \
       --enable-tcp-zebra --enable-fpm --enable-pimd \
       --enable-sharpd
   make
   sudo make install
   # Create symlink for vtysh, so topotest finds it in /usr/lib/frr
   sudo ln -s /usr/lib/frr/vtysh /usr/bin/

and create ``frr`` user and ``frrvty`` group as shown above.

Newer versions of Address Sanitizers require a sysctl to be changed
to allow for the tests to be successfully run.  This is also true
for Undefined behavior Sanitizers as well as Memory Sanitizer.

.. code:: shell

   sysctl vm.mmap_rnd_bits=28

Debugging Topotest Failures
^^^^^^^^^^^^^^^^^^^^^^^^^^^

Install and run tests inside ``tmux`` or ``byobu`` for best results.

``XTerm`` is also fully supported. GNU ``screen`` can be used in most
situations; however, it does not work as well with launching ``vtysh`` or shell
on error.

For the below debugging options which launch programs or CLIs, topotest should
be run within ``tmux`` (or ``screen``)_, as ``gdb``, the shell or ``vtysh`` will
be launched using that windowing program, otherwise ``xterm`` will be attempted
to launch the given programs.

NOTE: you must run the topotest (pytest) such that your DISPLAY, STY or TMUX
environment variables are carried over. You can do this by passing the
``-E`` flag to ``sudo`` or you can modify your ``/etc/sudoers`` config to
automatically pass that environment variable through to the ``sudo``
environment.

.. _screen: https://www.gnu.org/software/screen/
.. _tmux: https://github.com/tmux/tmux/wiki

Capturing Packets
"""""""""""""""""

One can view and capture packets on any of the networks or interfaces defined by
the topotest by specifying the ``--pcap=NET|INTF|all[,NET|INTF,...]`` CLI option
as shown in the examples below.

.. code:: shell

   # Capture on all networks in isis_topo1 test
   sudo -E pytest isis_topo1 --pcap=all

   # Capture on `sw1` network
   sudo -E pytest isis_topo1 --pcap=sw1

   # Capture on `sw1` network and on interface `eth0` on router `r2`
   sudo -E pytest isis_topo1 --pcap=sw1,r2:r2-eth0

For each capture a window is opened displaying a live summary of the captured
packets. Additionally, the entire packet stream is captured in a pcap file in
the tests log directory e.g.,:

.. code:: console

   $ sudo -E pytest isis_topo1 --pcap=sw1,r2:r2-eth0
   ...
   $ ls -l /tmp/topotests/isis_topo1.test_isis_topo1/
   -rw------- 1 root root 45172 Apr 19 05:30 capture-r2-r2-eth0.pcap
   -rw------- 1 root root 48412 Apr 19 05:30 capture-sw1.pcap
   ...

Viewing Live Daemon Logs
""""""""""""""""""""""""

One can live view daemon or the frr logs in separate windows using the
``--logd`` CLI option as shown below.

.. code:: shell

   # View `ripd` logs on all routers in test
   sudo -E pytest rip_allow_ecmp --logd=ripd

   # View `ripd` logs on all routers and `mgmtd` log on `r1`
   sudo -E pytest rip_allow_ecmp --logd=ripd --logd=mgmtd,r1

For each capture a window is opened displaying a live summary of the captured
packets. Additionally, the entire packet stream is captured in a pcap file in
the tests log directory e.g.,

When using a unified log file ``frr.log`` one substitutes ``frr`` for the
daemon name in the ``--logd`` CLI option, e.g.,

.. code:: shell

   # View `frr` log on all routers in test
   sudo -E pytest some_test_suite --logd=frr

Spawning Debugging CLI, ``vtysh`` or Shells on Routers on Test Failure
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

One can have a debugging CLI invoked on test failures by specifying the
``--cli-on-error`` CLI option as shown in the example below.

.. code:: shell

   sudo -E pytest --cli-on-error all-protocol-startup

The debugging CLI can run shell or vtysh commands on any combination of routers
It can also open shells or vtysh in their own windows for any combination of
routers. This is usually the most useful option when debugging failures. Here is
the help command from within a CLI launched on error:

.. code:: shell

    test_bgp_multiview_topo1/test_bgp_routingTable> help

    Basic Commands:
      cli   :: open a secondary CLI window
      help  :: this help
      hosts :: list hosts
      quit  :: quit the cli

      HOST can be a host or one of the following:
        - '*' for all hosts
        - '.' for the parent munet
        - a regex specified between '/' (e.g., '/rtr.*/')

    New Window Commands:
      logd HOST [HOST ...] DAEMON   :: tail -f on the logfile of the given DAEMON for the given HOST[S]
      pcap NETWORK  :: capture packets from NETWORK into file capture-NETWORK.pcap the command is run within a new window which also shows packet summaries. NETWORK can also be an interface specified as HOST:INTF. To capture inside the host namespace.
      stderr HOST [HOST ...] DAEMON :: tail -f on the stderr of the given DAEMON for the given HOST[S]
      stdlog HOST [HOST ...]        :: tail -f on the `frr.log` for the given HOST[S]
      stdout HOST [HOST ...] DAEMON :: tail -f on the stdout of the given DAEMON for the given HOST[S]
      term HOST [HOST ...]  :: open terminal[s] (TMUX or XTerm) on HOST[S], * for all
      vtysh ROUTER [ROUTER ...]     ::
      xterm HOST [HOST ...] :: open XTerm[s] on HOST[S], * for all
    Inline Commands:
      [ROUTER ...] COMMAND  :: execute vtysh COMMAND on the router[s]
      [HOST ...] sh <SHELL-COMMAND> :: execute <SHELL-COMMAND> on hosts
      [HOST ...] shi <INTERACTIVE-COMMAND>  :: execute <INTERACTIVE-COMMAND> on HOST[s]

    test_bgp_multiview_topo1/test_bgp_routingTable> r1 show int br
    ------ Host: r1 ------
    Interface       Status  VRF             Addresses
    ---------       ------  ---             ---------
    erspan0         down    default
    gre0            down    default
    gretap0         down    default
    lo              up      default
    r1-eth0         up      default         172.16.1.254/24
    r1-stub         up      default         172.20.0.1/28

    ----------------------
    test_bgp_multiview_topo1/test_bgp_routingTable>

Additionally, one can have ``vtysh`` or a shell launched on all routers when a
test fails. To launch the given process on each router after a test failure
specify one of ``--shell-on-error`` or ``--vtysh-on-error``.

Spawning ``vtysh`` or Shells on Routers
"""""""""""""""""""""""""""""""""""""""

Topotest can automatically launch a shell or ``vtysh`` for any or all routers in
a test. This is enabled by specifying 1 of 2 CLI arguments ``--shell`` or
``--vtysh``. Both of these options can be set to a single router value, multiple
comma-seperated values, or ``all``.

When either of these options are specified topotest will pause after setup and
each test to allow for inspection of the router state.

Here's an example of launching ``vtysh`` on routers ``rt1`` and ``rt2``.

.. code:: shell

   sudo -E pytest --vtysh=rt1,rt2 all-protocol-startup

.. _debug_with_gdb:

Debugging with GDB
""""""""""""""""""

Topotest can automatically launch any daemon with ``gdb``, possibly setting
breakpoints for any test run. This is enabled by specifying 1 or 2 CLI arguments
``--gdb-routers`` and ``--gdb-daemons``. Additionally ``--gdb-breakpoints`` can
be used to automatically set breakpoints in the launched ``gdb`` processes.

Each of these options can be set to a single value, multiple comma-seperated
values, or ``all``. If ``--gdb-routers`` is empty but ``--gdb_daemons`` is set
then the given daemons will be launched in ``gdb`` on all routers in the test.
Likewise if ``--gdb_routers`` is set, but ``--gdb_daemons`` is empty then all
daemons on the given routers will be launched in ``gdb``.

Here's an example of launching ``zebra`` and ``bgpd`` inside ``gdb`` on router
``r1`` with a breakpoint set on ``nb_config_diff``

.. code:: shell

   sudo -E pytest --gdb-routers=r1 \
          --gdb-daemons=bgpd,zebra \
          --gdb-breakpoints=nb_config_diff \
          all-protocol-startup

Finally, for Emacs users, you can specify ``--gdb-use-emacs``. When specified
the first router and daemon to be launched in gdb will be launched and run with
Emacs gdb functionality by using `emacsclient --eval` commands. This provides an
IDE debugging experience for Emacs users. This functionality works best when
using password-less sudo.

Reporting Memleaks with FRR Memory Statistics
"""""""""""""""""""""""""""""""""""""""""""""

FRR reports all allocated FRR memory objects on exit to standard error.
Topotest can be run to report such output as errors in order to check for
memleaks in FRR memory allocations. Specifying the CLI argument
``--memleaks`` will enable reporting FRR-based memory allocations at exit as errors.

.. code:: shell

   sudo -E pytest --memleaks all-protocol-startup


StdErr log from daemos after exit
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When running with ``--memleaks``, to enable the reporting of other,
non-memory related, messages seen on StdErr after the daemons exit,
the following env variable can be set::

   export TOPOTESTS_CHECK_STDERR=Yes

(The value doesn't matter at this time. The check is whether the env
variable exists or not.) There is no pass/fail on this reporting; the
Output will be reported to the console.

Collect Memory Leak Information
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When running with ``--memleaks``, FRR processes report unfreed memory
allocations upon exit. To enable also reporting of memory leaks to a specific
location, define an environment variable ``TOPOTESTS_CHECK_MEMLEAK`` with the
file prefix, i.e.:

::

   export TOPOTESTS_CHECK_MEMLEAK="/home/mydir/memleak_"

For tests that support the TOPOTESTS_CHECK_MEMLEAK environment variable, this
will enable output to the information to files with the given prefix (followed
by testname), e.g.,:
file:`/home/mydir/memcheck_test_bgp_multiview_topo1.txt` in case
of a memory leak.

Detecting Memleaks with Valgrind
""""""""""""""""""""""""""""""""

Topotest can automatically launch all daemons with ``valgrind`` to check for
memleaks. This is enabled by specifying 1 to 3 CLI arguments.
``--valgrind-memleaks`` enables memleak detection. ``--valgrind-extra`` enables
extra functionality including generating a suppression file. The suppression
file ``tools/valgrind.supp`` is used when memleak detection is enabled. Finally,
``--valgrind-leak-kinds=KINDS`` can be used to modify what types of links are
reported. This corresponds to valgrind's ``--show-link-kinds`` arg. The value is
either ``all`` or a comma-separated list of types:
``definite,indirect,possible,reachable``. The default is ``definite,possible``.

.. code:: shell

   sudo -E pytest --valgrind-memleaks all-protocol-startup

.. note:: GDB can be used in conjection with valgrind.

   When you enable ``--valgrind-memleaks`` and you also launch various daemons
   under GDB (debug_with_gdb_) topotest will connect the two utilities using
   ``--vgdb-error=0`` and attaching to a ``vgdb`` process. This is very
   useful for debugging bugs with use of uninitialized errors, et al.

Collecting Performance Data using perf(1)
"""""""""""""""""""""""""""""""""""""""""

Topotest can automatically launch any daemon under ``perf(1)`` to collect
performance data. The daemon is run in non-daemon mode with ``perf record -g``.
The ``perf.data`` file will be saved in the router specific directory under the
tests run directoy.

Here's an example of collecting performance data from ``mgmtd`` on router ``r1``
during the config_timing test.

.. code:: console

   $ sudo -E pytest --perf=mgmtd,r1 config_timing
   ...
   $ find /tmp/topotests/ -name '*perf.data*'
   /tmp/topotests/config_timing.test_config_timing/r1/perf.data

To specify different arguments for ``perf record``, one can use the
``--perf-options`` this will replace the ``-g`` used by default.

Running Daemons under RR Debug (``rr record``)
""""""""""""""""""""""""""""""""""""""""""""""

Topotest can automatically launch any daemon under ``rr(1)`` to collect
execution state. The daemon is run in the foreground with ``rr record``.

The execution state will be saved in the router specific directory
(in a `rr` subdir that rr creates) under the test's run directoy.

Here's an example of collecting ``rr`` execution state from ``mgmtd`` on router
``r1`` during the ``config_timing`` test.

.. code:: console

   $ sudo -E pytest --rr-routers=r1 --rr-daemons=mgmtd config_timing
   ...
   $ find /tmp/topotests/ -name '*perf.data*'
   /tmp/topotests/config_timing.test_config_timing/r1/perf.data

To specify additional arguments for ``rr record``, one can use the
``--rr-options``.

.. _code_coverage:

Code coverage
"""""""""""""
Code coverage reporting requires installation of the ``gcov`` and ``lcov``
packages.

Code coverage can automatically be gathered for any topotest run. To support
this FRR must first be compiled with the ``--enable-gcov`` configure option.
This will cause \*.gnco files to be created during the build. When topotests are
run the statistics are generated and stored in \*.gcda files. Topotest
infrastructure will gather these files, capture the information into a
``coverage.info`` ``lcov`` file and also report the coverage summary.

To enable code coverage support pass the ``--cov-topotest`` argument to pytest.
If you build your FRR in a directory outside of the FRR source directory you
will also need to pass the ``--cov-frr-build-dir`` argument specifying the build
directory location.

During the topotest run the \*.gcda files are generated into a ``gcda``
sub-directory of the top-level run directory (i.e., normally
``/tmp/topotests/gcda``). These files will then be copied at the end of the
topotest run into the FRR build directory where the ``gcov`` and ``lcov``
utilities expect to find them. This is done to deal with the various different
file ownership and permissions.

At the end of the run ``lcov`` will be run to capture all of the coverage data
into a ``coverage.info`` file. This file will be located in the top-level run
directory (i.e., normally ``/tmp/topotests/coverage.info``).

The ``coverage.info`` file can then be used to generate coverage reports or file
markup (e.g., using the ``genhtml`` utility) or enable markup within your
IDE/editor if supported (e.g., the emacs ``cov-mode`` package)

NOTE: the \*.gcda files in ``/tmp/topotests/gcda`` are cumulative so if you do
not remove them they will aggregate data across multiple topotest runs.

How to reproduce failed Tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Generally tests fail but recreating the test failure reliably is not necessarily
easy, or it happens once every 10 runs locally.  Here are some generic strategies
that are employed to allow for the test to be reproduced reliably

.. code:: console

   cd <test directory>
   ln -s test_the_test_name.py test_a.py
   ln -s test_the_test_name.py test_b.py

This allows you to run multiple copies of the same test with one full test run.
Additionally if you need to modify the test you don't need to recopy everything
to make it work.  By adding multiple copies of the same occassionally failing test
you raise the odds of it failing again.  Additionally you have easily accessible
good and bad runs to compare.

.. code:: console

   sudo -E python3 -m pytest -n <some value> --dist=loadfile

Choose a n value that is greater than the number of cpu's avalaible on the system.
This changes the timing and may or may not make it more likely that the test fails.
Be aware, though, that this changes memory requirements as well as may make other
tests fail more often as well.  You should choose values that do not cause the system
to go into swap usage.

.. code:: console

   stress -n <number of cpu's to put at 100%>

By filling up cpu's with programs that do nothing you also change the timing again and
may cause the problem to happen more often.

There is no magic bullet here.  You as a developer might have to experiment with different
values and different combinations of the above to cause the problem to happen more often.
These are just the tools that we know of at this point in time.


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
   $ # Tests must be run as root, since micronet requires it.
   $ sudo -E pytest

In order to run a specific test, you can use the following command:

.. code:: shell

   $ # running a specific topology
   $ sudo -E pytest ospf-topo1/
   $ # or inside the test folder
   $ cd ospf-topo1
   $ sudo -E pytest # to run all tests inside the directory
   $ sudo -E pytest test_ospf_topo1.py # to run a specific test
   $ # or outside the test folder
   $ cd ..
   $ sudo -E pytest ospf-topo1/test_ospf_topo1.py # to run a specific one

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
   $ sudo -E env TOPOTESTS_CHECK_MEMLEAK="/tmp/memleak_report_" pytest ospf-topo1/test_ospf_topo1.py
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
- Format the new code using `black <https://github.com/psf/black>`_
- Create a Pull Request

Some things to keep in mind:

- BGP tests MUST use generous convergence timeouts - you must ensure
  that any test involving BGP uses a convergence timeout of at least
  130 seconds.
- Topotests are run on a range of Linux versions: if your test
  requires some OS-specific capability (like mpls support, or vrf
  support), there are test functions available in the libraries that
  will help you determine whether your test should run or be skipped.
- Avoid including unstable data in your test: don't rely on link-local
  addresses or ifindex values, for example, because these can change
  from run to run.
- Using sleep is almost never appropriate. As an example: if the test resets the
  peers in BGP, the test should look for the peers re-converging instead of just
  sleeping an arbitrary amount of time and continuing on. See
  ``verify_bgp_convergence`` as a good example of this. In particular look at
  it's use of the ``@retry`` decorator. If you are having troubles figuring out
  what to look for, please do not be afraid to ask.
- Don't duplicate effort. There exists many protocol utility functions that can
  be found in their eponymous module under ``tests/topotests/lib/`` (e.g.,
  ``ospf.py``)



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

    topodef = {
        "s1": "r1"
        "s2": ("r1", "r2")
    }

If more specialized topology definitions, or router initialization arguments are
required a build function can be used instead of a dictionary:

.. code:: py

    def build_topo(tgen):
        "Build function"

        # Create 2 routers
        for routern in range(1, 3):
            tgen.add_router("r{}".format(routern))

        # Create a switch with just one router connected to it to simulate a
        # empty network.
        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])

        # Create a connection between r1 and r2
        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

- Run the topology

Topogen allows us to run the topology without running any tests, you can do
that using the following example commands:

.. code:: shell

   $ # Running your bootstraped topology
   $ sudo -E pytest -s --topology-only new-topo/test_new_topo.py
   $ # Running the test_template.py topology
   $ sudo -E pytest -s --topology-only example-test/test_template.py
   $ # Running the ospf_topo1.py topology
   $ sudo -E pytest -s --topology-only ospf-topo1/test_ospf_topo1.py

Parameters explanation:

.. program:: pytest

.. option:: -s

   Actives input/output capture. If this is not specified a new window will be
   opened for the interactive CLI, otherwise it will be activated inline.

.. option:: --topology-only

   Don't run any tests, just build the topology.

After executing the commands above, you should get the following terminal
output:

.. code:: shell

    frr/tests/topotests# sudo -E pytest -s --topology-only ospf_topo1/test_ospf_topo1.py
    ============================= test session starts ==============================
    platform linux -- Python 3.9.2, pytest-6.2.4, py-1.10.0, pluggy-0.13.1
    rootdir: /home/chopps/w/frr/tests/topotests, configfile: pytest.ini
    plugins: forked-1.3.0, xdist-2.3.0
    collected 11 items

    [...]
    unet>

The last line shows us that we are now using the CLI (Command Line
Interface), from here you can call your router ``vtysh`` or even bash.

Here's the help text:

.. code:: shell

    unet> help

    Commands:
      help                       :: this help
      sh [hosts] <shell-command> :: execute <shell-command> on <host>
      term [hosts]               :: open shell terminals for hosts
      vtysh [hosts]              :: open vtysh terminals for hosts
      [hosts] <vtysh-command>    :: execute vtysh-command on hosts

Here are some commands example:

.. code:: shell

    unet> sh r1 ping 10.0.3.1
    PING 10.0.3.1 (10.0.3.1) 56(84) bytes of data.
    64 bytes from 10.0.3.1: icmp_seq=1 ttl=64 time=0.576 ms
    64 bytes from 10.0.3.1: icmp_seq=2 ttl=64 time=0.083 ms
    64 bytes from 10.0.3.1: icmp_seq=3 ttl=64 time=0.088 ms
    ^C
    --- 10.0.3.1 ping statistics ---
    3 packets transmitted, 3 received, 0% packet loss, time 1998ms
    rtt min/avg/max/mdev = 0.083/0.249/0.576/0.231 ms

    unet> r1 show run
    Building configuration...

    Current configuration:
    !
    frr version 8.1-dev-my-manual-build
    frr defaults traditional
    hostname r1
    log file /tmp/topotests/ospf_topo1.test_ospf_topo1/r1/zebra.log
    [...]
    end

    unet> show daemons
    ------ Host: r1 ------
     zebra ospfd ospf6d staticd
    ------- End: r1 ------
    ------ Host: r2 ------
     zebra ospfd ospf6d staticd
    ------- End: r2 ------
    ------ Host: r3 ------
     zebra ospfd ospf6d staticd
    ------- End: r3 ------
    ------ Host: r4 ------
     zebra ospfd ospf6d staticd
    ------- End: r4 ------

After you successfully configured your topology, you can obtain the
configuration files (per-daemon) using the following commands:

.. code:: shell

   unet> sh r3 vtysh -d ospfd

   Hello, this is FRRouting (version 3.1-devrzalamena-build).
   Copyright 1996-2005 Kunihiro Ishiguro, et al.

   r1# show running-config
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
   r1#

You can also login to the node specified by nsenter using bash, etc.
A pid file for each node will be created in the relevant test dir.
You can run scripts inside the node, or use vtysh's <tab> or <?> feature.

.. code:: shell

  [unet shell]
  # cd tests/topotests/srv6_locator
  # ./test_srv6_locator.py --topology-only
  unet> r1 show segment-routing srv6 locator
  Locator:
  Name                 ID      Prefix                   Status
  -------------------- ------- ------------------------ -------
  loc1                       1 2001:db8:1:1::/64        Up
  loc2                       2 2001:db8:2:2::/64        Up

  [Another shell]
  # nsenter -a -t $(cat /tmp/topotests/srv6_locator.test_srv6_locator/r1.pid) bash --norc
  # vtysh
  r1# r1 show segment-routing srv6 locator
  Locator:
  Name                 ID      Prefix                   Status
  -------------------- ------- ------------------------ -------
  loc1                       1 2001:db8:1:1::/64        Up
  loc2                       2 2001:db8:2:2::/64        Up

.. _writing-tests:

Writing Tests
"""""""""""""

Test topologies should always be bootstrapped from
:file:`tests/topotests/example_test/test_template.py` because it contains
important boilerplate code that can't be avoided, like:

Example:

.. code:: py

       # For all routers arrange for:
       # - starting zebra using config file from <rtrname>/zebra.conf
       # - starting ospfd using an empty config file.
       for rname, router in router_list.items():
           router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
           router.load_config(TopoRouter.RD_OSPF)

or using unified config (specifying which daemons to run is optional):

.. code:: py

      for _, (rname, router) in enumerate(router_list.items(), 1):
         router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)), [
            (TopoRouter.RD_ZEBRA, "-s 90000000"),
            (TopoRouter.RD_MGMTD, None),
            (TopoRouter.RD_BGP, None)]

- The topology definition or build function

.. code:: py

   topodef = {
       "s1": ("r1", "r2"),
       "s2": ("r2", "r3")
   }

   def build_topo(tgen):
       # topology build code
       ...

- pytest setup/teardown fixture to start the topology and supply ``tgen``
  argument to tests.

.. code:: py


   @pytest.fixture(scope="module")
   def tgen(request):
       "Setup/Teardown the environment and provide tgen argument to tests"

       tgen = Topogen(topodef, module.__name__)
       # or
       tgen = Topogen(build_topo, module.__name__)

       ...

       # Start and configure the router daemons
       tgen.start_router()

       # Provide tgen as argument to each test function
       yield tgen

       # Teardown after last test runs
       tgen.stop_topology()


Requirements:

- Directory name for a new topotest must not contain hyphen (``-``) characters.
  To separate words, use underscores (``_``). For example, ``tests/topotests/bgp_new_example``;
- Test code should always be declared inside functions that begin with the
  ``test_`` prefix. Functions beginning with different prefixes will not be run
  by pytest;
- Configuration files and long output commands should go into separated files
  inside folders named after the equipment;
- Tests must be able to run without any interaction. To make sure your test
  conforms with this, run it without the :option:`-s` parameter;
- Use `black <https://github.com/psf/black>`_ code formatter before creating
  a pull request. This ensures we have a unified code style;
- Mark test modules with pytest markers depending on the daemons used during the
  tests (see :ref:`topotests-markers`);
- Always use IPv4 :rfc:`5737` (``192.0.2.0/24``, ``198.51.100.0/24``,
  ``203.0.113.0/24``) and IPv6 :rfc:`3849` (``2001:db8::/32``) ranges reserved
  for documentation;
- Use unified config (``frr.conf``) for all new tests. See :ref:`writing-tests`.

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
    (Pdb) tgen.cli()
    unet>

To enable more debug messages in other Topogen subsystems, more
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

.. include:: topotests-markers.rst

.. include:: topotests-snippets.rst

License
-------

All the configs and scripts are licensed under a ISC-style license. See Python
scripts for details.
