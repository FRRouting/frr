.. _installation:

Installation
============

.. index:: How to install FRR
.. index:: Installation
.. index:: Installing FRR
.. index:: Building the system
.. index:: Making FRR

This section covers the basics of building, installing and setting up FRR.

From Packages
-------------

The project publishes packages for Red Hat, Centos, Debian and Ubuntu on the
`GitHub releases <https://github.com/FRRouting/frr/releases>`_. page. External
contributors offer packages for many other platforms including \*BSD, Alpine,
Gentoo, Docker, and others. There is currently no documentation on how to use
those but we hope to add it soon.

From Snapcraft
--------------

In addition to traditional packages the project also builds and publishes
universal Snap images, available at https://snapcraft.io/frr.

From Source
-----------

Building FRR from source is the best way to ensure you have the latest features
and bug fixes. Details for each supported platform, including dependency
package listings, permissions, and other gotchas, are in the developer's
documentation. This section provides a brief overview on the process.

Getting the Source
^^^^^^^^^^^^^^^^^^

FRR's source is available on the project
`GitHub page <https://github.com/FRRouting/frr>`_.

.. code-block:: shell

   git clone https://github.com/FRRouting/frr.git

When building from Git there are several branches to choose from. The
``master`` branch is the primary development branch. It should be considered
unstable. Each release has its own branch named ``stable/X.X``, where ``X.X``
is the release version.

In addition, release tarballs are published on the GitHub releases page
`here <https://github.com/FRRouting/frr/releases>`_.

Configuration
^^^^^^^^^^^^^

.. index:: Configuration options
.. index:: Options for configuring
.. index:: Build options
.. index:: Distribution configuration
.. index:: Options to `./configure`

FRR has an excellent configure script which automatically detects most host
configurations. There are several additional configure options to customize the
build to include or exclude specific features and dependencies.

First, update the build system. Change into your FRR source directory and issue:

.. code-block:: shell

   ./bootstrap.sh

This will install any missing build scripts and update the Autotools
configuration. Once this is done you can move on to choosing your configuration
options from the list below.

.. _frr-configuration:

.. program:: configure

.. option:: --enable-tcmalloc

   Enable the alternate malloc library.  In some cases this is faster and more efficient,
   in some cases it is not.

.. option:: --disable-doc

   Do not build any documentation, including this one.

.. option:: --enable-doc-html

   From the documentation build html docs as well in addition to the normal output.

.. option:: --disable-zebra

   Do not build zebra daemon.  This generally only be useful in a scenario where
   you are building bgp as a standalone server.

.. option:: --disable-ripd

   Do not build ripd.

.. option:: --disable-ripngd

   Do not build ripngd.

.. option:: --disable-ospfd

   Do not build ospfd.

.. option:: --disable-ospf6d

   Do not build ospf6d.

.. option:: --disable-bgpd

   Do not build bgpd.

.. option:: --disable-ldpd

   Do not build ldpd.

.. option:: --disable-nhrpd

   Do not build nhrpd.

.. option:: --disable-eigrpd

   Do not build eigrpd.

.. option:: --disable-babeld

   Do not build babeld.

.. option:: --disable-watchfrr

   Do not build watchfrr.  Watchfrr is used to integrate daemons into startup/shutdown
   software available on your machine.  This is needed for systemd integration, if you
   disable watchfrr you cannot have any systemd integration.

.. option:: --enable-systemd

   Build watchfrr with systemd integration, this will allow FRR to communicate with
   systemd to tell systemd if FRR has come up properly.

.. option:: --disable-pimd

   Turn off building of pimd.  On some BSD platforms pimd will not build properly due
   to lack of kernel support.

.. option:: --disable-vrrpd

   Turn off building of vrrpd. Linux is required for vrrpd support;
   other platforms are not supported.

.. option:: --disable-pbrd

   Turn off building of pbrd.  This daemon currently requires linux in order to function
   properly.

.. option:: --enable-sharpd

   Turn on building of sharpd.  This daemon facilitates testing of FRR and can also
   be used as a quick and easy route generator.

.. option:: --disable-staticd

   Do not build staticd.  This daemon is necessary if you want static routes.

.. option:: --disable-bfdd

   Do not build bfdd.

.. option:: --disable-bgp-announce

   Make *bgpd* which does not make bgp announcements at all.  This
   feature is good for using *bgpd* as a BGP announcement listener.

.. option:: --disable-bgp-vnc

   Turn off bgpd's ability to use VNC.

.. option:: --enable-datacenter

   Enable system defaults to work as if in a Data Center. See defaults.h
   for what is changed by this configure option.

.. option:: --enable-snmp

   Enable SNMP support.  By default, SNMP support is disabled.

.. option:: --disable-ospfapi

   Disable support for OSPF-API, an API to interface directly with ospfd.
   OSPF-API is enabled if --enable-opaque-lsa is set.

.. option:: --disable-ospfclient

   Disable building of the example OSPF-API client.

.. option:: --disable-isisd

   Do not build isisd.

.. option:: --disable-fabricd

   Do not build fabricd.

.. option:: --enable-isis-topology

   Enable IS-IS topology generator.

.. option:: --enable-realms

   Enable the support of Linux Realms. Convert tag values from 1-255 into a
   realm value when inserting into the Linux kernel. Then routing policy can be
   assigned to the realm. See the tc man page.

.. option:: --disable-rtadv

   Disable support IPV6 router advertisement in zebra.

.. option:: --enable-gcc-rdynamic

   Pass the ``-rdynamic`` option to the linker driver.  This is in most cases
   necessary for getting usable backtraces.  This option defaults to on if the
   compiler is detected as gcc, but giving an explicit enable/disable is
   suggested.

.. option:: --disable-backtrace

   Controls backtrace support for the crash handlers. This is autodetected by
   default. Using the switch will enforce the requested behaviour, failing with
   an error if support is requested but not available.  On BSD systems, this
   needs libexecinfo, while on glibc support for this is part of libc itself.

.. option:: --enable-dev-build

   Turn on some options for compiling FRR within a development environment in
   mind.  Specifically turn on -g3 -O0 for compiling options and add inclusion
   of grammar sandbox.

.. option:: --enable-fuzzing

   Turn on some compile options to allow you to run fuzzing tools against the
   system. This flag is intended as a developer only tool and should not be
   used for normal operations.

.. option:: --disable-snmp

   Build without SNMP support.

.. option:: --disable-vtysh

   Build without VTYSH.

.. option:: --enable-fpm

   Build with FPM module support.

.. option:: --enable-numeric-version

   Alpine Linux does not allow non-numeric characters in the version string.
   With this option, we provide a way to strip out these characters for APK dev
   package builds.

.. option:: --enable-multipath=X

   Compile FRR with up to X way ECMP supported.  This number can be from 0-999.
   For backwards compatibility with older configure options when setting X = 0,
   we will build FRR with 64 way ECMP.  This is needed because there are
   hardcoded arrays that FRR builds towards, so we need to know how big to
   make these arrays at build time.  Additionally if this parameter is
   not passed in FRR will default to 16 ECMP.

.. option:: --enable-shell-access

   Turn on the ability of FRR to access some shell options( telnet/ssh/bash/etc. )
   from vtysh itself.  This option is considered extremely unsecure and should only
   be considered for usage if you really really know what you are doing.

.. option:: --enable-gcov

   Code coverage reports from gcov require adjustments to the C and LD flags.
   With this option, gcov instrumentation is added to the build and coverage
   reports are created during execution.  The check-coverage make target is
   also created to ease report uploading to codecov.io.  The upload requires
   the COMMIT (git hash) and TOKEN (codecov upload token) environment variables
   be set.

.. option:: --enable-config-rollbacks

   Build with configuration rollback support. Requires SQLite3.

.. option:: --enable-confd=<dir>

   Build the ConfD northbound plugin. Look for the libconfd libs and headers
   in `dir`.

.. option:: --enable-sysrepo

   Build the Sysrepo northbound plugin.

.. option:: --enable-time-check XXX

   When this is enabled with a XXX value in microseconds, any thread that
   runs for over this value will cause a warning to be issued to the log.
   If you do not specify any value or don't include this option then
   the default time is 5 seconds.  If --disable-time-check is specified
   then no warning is issued for any thread run length.

.. option:: --disable-cpu-time

   Disable cpu process accounting, this command also disables the `show thread cpu`
   command.  If this option is disabled, --enable-time-check is ignored.  This
   disabling of cpu time effectively means that the getrusage call is skipped.
   Since this is a process switch into the kernel, systems with high FRR
   load might see improvement in behavior.  Be aware that `show thread cpu`
   is considered a good data gathering tool from the perspective of developers.

You may specify any combination of the above options to the configure
script. By default, the executables are placed in :file:`/usr/local/sbin`
and the configuration files in :file:`/usr/local/etc`. The :file:`/usr/local/`
installation prefix and other directories may be changed using the following
options to the configuration script.

.. option:: --prefix <prefix>

   Install architecture-independent files in `prefix` [/usr/local].

.. option:: --sysconfdir <dir>

   Look for configuration files in `dir` [`prefix`/etc]. Note that sample
   configuration files will be installed here.

.. option:: --localstatedir <dir>

   Configure zebra to use `dir` for local state files, such as pid files and
   unix sockets.

.. option:: --with-yangmodelsdir <dir>

   Look for YANG modules in `dir` [`prefix`/share/yang]. Note that the FRR
   YANG modules will be installed here.

Python dependency, documentation and tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

FRR's documentation and basic unit tests heavily use code written in Python.
Additionally, FRR ships Python extensions written in C which are used during
its build process.

To this extent, FRR needs the following:

* an installation of CPython, preferably version 3.2 or newer (2.7 works but
  is end of life and will stop working at some point.)
* development files (mostly headers) for that version of CPython
* an installation of `sphinx` for that version of CPython, to build the
  documentation
* an installation of `pytest` for that version of CPython, to run the unit
  tests

The `sphinx` and `pytest` dependencies can be avoided by not building
documentation / not running ``make check``, but the CPython dependency is a
hard dependency of the FRR build process (for the `clippy` tool.)

.. _least-privilege-support:

Least-Privilege Support
"""""""""""""""""""""""

.. index:: FRR Least-Privileges
.. index:: FRR Privileges

Additionally, you may configure zebra to drop its elevated privileges
shortly after startup and switch to another user. The configure script will
automatically try to configure this support. There are three configure
options to control the behaviour of FRR daemons.

.. option:: --enable-user <user>

   Switch to user `user shortly after startup, and run as user `user` in normal
   operation.

.. option:: --enable-group <user>

   Switch real and effective group to `group` shortly after startup.

.. option:: --enable-vty-group <group>

   Create Unix Vty sockets (for use with vtysh) with group ownership set to
   `group`. This allows one to create a separate group which is restricted to
   accessing only the vty sockets, hence allowing one to delegate this group to
   individual users, or to run vtysh setgid to this group.

The default user and group which will be configured is 'frr' if no user or
group is specified. Note that this user or group requires write access to the
local state directory (see :option:`--localstatedir`) and requires at least
read access, and write access if you wish to allow daemons to write out their
configuration, to the configuration directory (see :option:`--sysconfdir`).

On systems which have the 'libcap' capabilities manipulation library (currently
only Linux), FRR will retain only minimal capabilities required and will only
raise these capabilities for brief periods. On systems without libcap, FRR will
run as the user specified and only raise its UID to 0 for brief periods.

Linux Notes
"""""""""""

.. index:: Building on Linux boxes
.. index:: Linux configurations

There are several options available only to GNU/Linux systems.  If you use
GNU/Linux, make sure that the current kernel configuration is what you want.
FRR will run with any kernel configuration but some recommendations do exist.

:makevar:`CONFIG_NETLINK`
   Kernel/User Netlink socket. This enables an advanced interface between
   the Linux kernel and *zebra* (:ref:`kernel-interface`).

:makevar:`CONFIG_RTNETLINK`
   This makes it possible to receive Netlink routing messages.  If you specify
   this option, *zebra* can detect routing information updates directly from
   the kernel (:ref:`kernel-interface`).

:makevar:`CONFIG_IP_MULTICAST`
   This option enables IP multicast and should be specified when you use *ripd*
   (:ref:`rip`) or *ospfd* (:ref:`ospfv2`) because these protocols use
   multicast.

Linux sysctl settings and kernel modules
````````````````````````````````````````

There are several kernel parameters that impact overall operation of FRR when
using Linux as a router. Generally these parameters should be set in a
sysctl related configuration file, e.g., :file:`/etc/sysctl.conf` on
Ubuntu based systems and a new file
:file:`/etc/sysctl.d/90-routing-sysctl.conf` on Centos based systems.
Additional kernel modules are also needed to support MPLS forwarding.

:makevar:`IPv4 and IPv6 forwarding`
   The following are set to enable IP forwarding in the kernel:

   .. code-block:: shell

      net.ipv4.conf.all.forwarding=1
      net.ipv6.conf.all.forwarding=1

:makevar:`MPLS forwarding`
   Basic MPLS support was introduced in the kernel in version 4.1 and
   additional capability was introduced in 4.3 and 4.5.
   For some general information on Linux MPLS support, see
   https://www.netdevconf.org/1.1/proceedings/slides/prabhu-mpls-tutorial.pdf.
   The following modules should be loaded to support MPLS forwarding,
   and are generally added to a configuration file such as
   :file:`/etc/modules-load.d/modules.conf`:

   .. code-block:: shell

      # Load MPLS Kernel Modules
      mpls_router
      mpls_iptunnel

   The following is an example to enable MPLS forwarding in the
   kernel, typically by editing :file:`/etc/sysctl.conf`:

   .. code-block:: shell

      # Enable MPLS Label processing on all interfaces
      net.mpls.conf.eth0.input=1
      net.mpls.conf.eth1.input=1
      net.mpls.conf.eth2.input=1
      net.mpls.platform_labels=100000

   Make sure to add a line equal to :file:`net.mpls.conf.<if>.input` for
   each interface *'<if>'* used with MPLS and to set labels to an
   appropriate value.

:makevar:`VRF forwarding`
   General information on Linux VRF support can be found in
   https://www.kernel.org/doc/Documentation/networking/vrf.txt. Kernel
   support for VRFs was introduced in 4.3 and improved upon through
   4.13, which is the version most used in FRR testing (as of June
   2018).  Additional background on using Linux VRFs and kernel specific
   features can be found in
   http://schd.ws/hosted_files/ossna2017/fe/vrf-tutorial-oss.pdf.

   The following impacts how BGP TCP sockets are managed across VRFs:

   .. code-block:: shell

      net.ipv4.tcp_l3mdev_accept=0

   With this setting a BGP TCP socket is opened per VRF.  This setting
   ensures that other TCP services, such as SSH, provided for non-VRF
   purposes are blocked from VRF associated Linux interfaces.

   .. code-block:: shell

      net.ipv4.tcp_l3mdev_accept=1

   With this setting a single BGP TCP socket is shared across the
   system.  This setting exposes any TCP service running on the system,
   e.g., SSH, to all VRFs.  Generally this setting is not used in
   environments where VRFs are used to support multiple administrative
   groups.

   **Important note** as of June 2018, Kernel versions 4.14-4.18 have a
   known bug where VRF-specific TCP sockets are not properly handled. When
   running these kernel versions, if unable to establish any VRF BGP
   adjacencies, either downgrade to 4.13 or set
   'net.ipv4.tcp_l3mdev_accept=1'. The fix for this issue is planned to be
   included in future kernel versions. So upgrading your kernel may also
   address this issue.


Building
^^^^^^^^

Once you have chosen your configure options, run the configure script and pass
the options you chose:

.. code-block:: shell

   ./configure \
       --prefix=/usr \
       --enable-exampledir=/usr/share/doc/frr/examples/ \
       --localstatedir=/var/run/frr \
       --sbindir=/usr/lib/frr \
       --sysconfdir=/etc/frr \
       --enable-pimd \
       --enable-watchfrr \
       ...

After configuring the software, you are ready to build and install it in your
system.

.. code-block:: shell

   make && sudo make install

If everything finishes successfully, FRR should be installed. You should now
skip to the section on :ref:`basic-setup`.
