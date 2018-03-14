.. _overview:

********
Overview
********

`FRR`_ is a routing software package that provides TCP/IP based
routing services with routing protocols support such as RIPv1, RIPv2, RIPng,
OSPFv2, OSPFv3, IS-IS, BGP-4, and BGP-4+ (:ref:`supported-rfcs`). FRR also
supports special BGP Route Reflector and Route Server behavior.  In addition to
traditional IPv4 routing protocols, FRR also supports IPv6 routing protocols.
With SNMP daemon which supports SMUX and AgentX protocol, FRR provides routing
protocol MIBs (:ref:`snmp-support`).

FRR uses an advanced software architecture to provide you with a high
quality, multi server routing engine. FRR has an interactive user
interface for each routing protocol and supports common client commands.
Due to this design, you can add new protocol daemons to FRR easily.  You
can use FRR library as your program's client user interface.

FRR is distributed under the GNU General Public License.

.. _about-frr:

About FRR
=========

Today, TCP/IP networks are covering all of the world.  The Internet has
been deployed in many countries, companies, and to the home.  When you
connect to the Internet your packet will pass many routers which have TCP/IP
routing functionality.

A system with FRR installed acts as a dedicated router.  With FRR,
your machine exchanges routing information with other routers using routing
protocols.  FRR uses this information to update the kernel routing table
so that the right data goes to the right place.  You can dynamically change
the configuration and you may view routing table information from the FRR
terminal interface.

Adding to routing protocol support, FRR can setup interface's flags,
interface's address, static routes and so on.  If you have a small network,
or a stub network, or xDSL connection, configuring the FRR routing
software is very easy.  The only thing you have to do is to set up the
interfaces and put a few commands about static routes and/or default routes.
If the network is rather large, or if the network structure changes
frequently, you will want to take advantage of FRR's dynamic routing
protocol support for protocols such as RIP, OSPF, IS-IS or BGP.

Traditionally, UNIX based router configuration is done by
*ifconfig* and *route* commands.  Status of routing
table is displayed by *netstat* utility.  Almost of these commands
work only if the user has root privileges.  FRR has a different system
administration method.  There are two user modes in FRR.  One is normal
mode, the other is enable mode.  Normal mode user can only view system
status, enable mode user can change system configuration.  This UNIX account
independent feature will be great help to the router administrator.

Currently, FRR supports common unicast routing protocols, that is BGP,
OSPF, RIP and IS-IS.  Upcoming for MPLS support, an implementation of LDP is
currently being prepared for merging.  Implementations of BFD and PIM-SSM
(IPv4) also exist, but are not actively being worked on.

The ultimate goal of the FRR project is making a productive, quality, free
TCP/IP routing software package.


System Architecture
===================

.. index:: System architecture

.. index:: Software architecture

.. index:: Software internals

Traditional routing software is made as a one process program which
provides all of the routing protocol functionalities.  FRR takes a
different approach.  It is made from a collection of several daemons that
work together to build the routing table.  There may be several
protocol-specific routing daemons and zebra the kernel routing manager.

The *ripd* daemon handles the RIP protocol, while
*ospfd* is a daemon which supports OSPF version 2.
*bgpd* supports the BGP-4 protocol.  For changing the kernel
routing table and for redistribution of routes between different routing
protocols, there is a kernel routing table manager *zebra* daemon.
It is easy to add a new routing protocol daemons to the entire routing
system without affecting any other software.  You need to run only the
protocol daemon associated with routing protocols in use.  Thus, user may
run a specific daemon and send routing reports to a central routing console.

There is no need for these daemons to be running on the same machine. You
can even run several same protocol daemons on the same machine.  This
architecture creates new possibilities for the routing system.

::

  +----+  +----+  +-----+  +-----+
  |bgpd|  |ripd|  |ospfd|  |zebra|
  +----+  +----+  +-----+  +-----+
                              |
  +---------------------------|--+
  |                           v  |
  |  UNIX Kernel  routing table  |
  |                              |
  +------------------------------+

      FRR System Architecture


Multi-process architecture brings extensibility, modularity and
maintainability.  At the same time it also brings many configuration files
and terminal interfaces.  Each daemon has it's own configuration file and
terminal interface.  When you configure a static route, it must be done in
*zebra* configuration file.  When you configure BGP network it must
be done in *bgpd* configuration file.  This can be a very annoying
thing.  To resolve the problem, FRR provides integrated user interface
shell called *vtysh*.  *vtysh* connects to each daemon with
UNIX domain socket and then works as a proxy for user input.

FRR was planned to use multi-threaded mechanism when it runs with a
kernel that supports multi-threads.  But at the moment, the thread library
which comes with GNU/Linux or FreeBSD has some problems with running
reliable services such as routing software, so we don't use threads at all.
Instead we use the *select(2)* system call for multiplexing the
events.


Supported Platforms
===================

.. index:: Supported platforms

.. index:: FRR on other systems

.. index:: Compatibility with other systems

.. index:: Operating systems that support FRR

Currently FRR supports GNU/Linux and BSD. Porting FRR
to other platforms is not too difficult as platform dependent code should
most be limited to the *zebra* daemon.  Protocol daemons are mostly
platform independent. Please let us know when you find out FRR runs on a
platform which is not listed below.

The list of officially supported platforms are listed below. Note that
FRR may run correctly on other platforms, and may run with partial
functionality on further platforms.

- GNU/Linux
- FreeBSD
- NetBSD
- OpenBSD

Versions of these platforms that are older than around 2 years from the point
of their original release (in case of GNU/Linux, this is since the kernel's
release on https://kernel.org/) may need some work.  Similarly, the following platforms
may work with some effort:

- Solaris
- MacOS

Also note that, in particular regarding proprietary platforms, compiler
and C library choice will affect FRR.  Only recent versions of the
following C compilers are well-tested:

- GNU's GCC
- LLVM's clang
- Intel's ICC


.. _supported-rfcs:

Supported RFCs
==============

FRR implements the following RFCs:

- :rfc:`1058`
  :t:`Routing Information Protocol. C.L. Hedrick. Jun-01-1988.`
- :rfc:`2082`
  :t:`RIP-2 MD5 Authentication. F. Baker, R. Atkinson. January 1997.`
- :rfc:`2453`
  :t:`RIP Version 2. G. Malkin. November 1998.`
- :rfc:`2080`
  :t:`RIPng for IPv6. G. Malkin, R. Minnear. January 1997.`
- :rfc:`2328`
  :t:`OSPF Version 2. J. Moy. April 1998.`
- :rfc:`2370`
  :t:`The OSPF Opaque LSA Option R. Coltun. July 1998.`
- :rfc:`3101`
  :t:`The OSPF Not-So-Stubby Area (NSSA) Option P. Murphy. January 2003.`
- :rfc:`2740`
  :t:`OSPF for IPv6. R. Coltun, D. Ferguson, J. Moy. December 1999.`
- :rfc:`1771`
  :t:`A Border Gateway Protocol 4 (BGP-4). Y. Rekhter & T. Li. March 1995.`
- :rfc:`1965`
  :t:`Autonomous System Confederations for BGP. P. Traina. June 1996.`
- :rfc:`1997`
  :t:`BGP Communities Attribute. R. Chandra, P. Traina & T. Li. August 1996.`
- :rfc:`2545`
  :t:`Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing. P.
  Marques, F. Dupont. March 1999.`
- :rfc:`2796`
  :t:`BGP Route Reflection An alternative to full mesh IBGP. T. Bates & R.
  Chandrasekeran. June 1996.`
- :rfc:`2858`
  :t:`Multiprotocol Extensions for BGP-4. T. Bates, Y. Rekhter, R. Chandra, D.
  Katz. June 2000.`
- :rfc:`2842`
  :t:`Capabilities Advertisement with BGP-4. R. Chandra, J. Scudder. May 2000.`
- :rfc:`3137`
  :t:`OSPF Stub Router Advertisement, A. Retana, L. Nguyen, R. White, A. Zinin,
  D. McPherson. June 2001`

**When SNMP support is enabled, the following RFCs are also supported:**

- :rfc:`1227`
  :t:`SNMP MUX protocol and MIB. M.T. Rose. May-01-1991.`
- :rfc:`1657`
  :t:`Definitions of Managed Objects for the Fourth Version of the Border
  Gateway Protocol (BGP-4) using SMIv2. S. Willis, J. Burruss, J. Chu, Editor.
  July 1994.`
- :rfc:`1724`
  :t:`RIP Version 2 MIB Extension. G. Malkin & F. Baker. November 1994.`
- :rfc:`1850`
  :t:`OSPF Version 2 Management Information Base. F. Baker, R. Coltun.
  November 1995.`
- :rfc:`2741`
  :t:`Agent Extensibility (AgentX) Protocol. M. Daniele, B. Wijnen. January 2000.`

How to get FRR
==============

The official FRR website is located at |PACKAGE_URL| and contains further
information, as well as links to additional resources.

FRR is a fork of `Quagga <http://www.quagga.net/>`_.

Mailing Lists
=============

.. index:: How to get in touch with FRR
.. index:: Contact information
.. index:: Mailing lists


Italicized lists are private.

+--------------------------------+------------------------------+
| Topic                          | List                         |
+================================+==============================+
| Development                    | dev@lists.frrouting.org      |
+--------------------------------+------------------------------+
| Users & Operators              | frog@lists.frrouting.org     |
+--------------------------------+------------------------------+
| Announcements                  | announce@lists.frrouting.org |
+--------------------------------+------------------------------+
| *Security*                     | security@lists.frrouting.org |
+--------------------------------+------------------------------+
| *Technical Steering Committee* | tsc@lists.frrouting.org      |
+--------------------------------+------------------------------+

The Development list is used to discuss and document general issues related to
project development and governance. The public `Slack`_ instance and weekly
technical meetings provide a higher bandwidth channel for discussions. The
results of such discussions are reflected in updates, as appropriate, to code
(i.e., merges), `GitHub issues`_ tracked issues, and for governance or process
changes, updates to the Development list and either this file or information
posted at `FRR`_.

.. index:: Bug Reports
.. index:: Bug hunting
.. index:: Found a bug?
.. index:: Reporting bugs
.. index:: Reporting software errors
.. index:: Errors in the software

.. _bug-reports:

Bug Reports
===========

If you think you have found a bug, please file a bug report on our
`GitHub issues`_ page.

When you send a bug report, please be careful about the points below.

- Please note what kind of OS you are using.  If you use the IPv6 stack
  please note that as well.
- Please show us the results of `netstat -rn` and `ifconfig -a`.
  Information from zebra's VTY command `show ip route` will also be
  helpful.
- Please send your configuration file with the report.  If you specify
  arguments to the configure script please note that too.

Bug reports help us improve FRR and are very much appreciated.

.. _frr: |package-url|
.. _github: https://github.com/frrouting/frr/
.. _github issues: https://github.com/frrouting/frr/issues
.. _slack: https://frrouting.slack.com/
