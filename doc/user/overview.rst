.. _overview:

********
Overview
********

`FRR`_ is a routing software package that provides TCP/IP based routing
services with routing protocols support such as BGP, RIP, OSPF, IS-IS and more
(see :ref:`supported-protocols`). FRR also supports
special BGP Route Reflector and Route Server behavior.  In addition to
traditional IPv4 routing protocols, FRR also supports IPv6 routing protocols.
With an SNMP daemon that supports the AgentX protocol, FRR provides routing
protocol MIB read-only access (:ref:`snmp-support`).

FRR uses an advanced software architecture to provide you with a high quality,
multi server routing engine. FRR has an interactive user interface for each
routing protocol and supports common client commands.  Due to this design, you
can add new protocol daemons to FRR easily.  You can use FRR library as your
program's client user interface.

FRR is distributed under the GNU General Public License.

FRR is a fork of `Quagga <http://www.quagga.net/>`_.

.. _about-frr:

About FRR
=========

Today, TCP/IP networks are covering all of the world.  The Internet has been
deployed in many countries, companies, and to the home.  When you connect to
the Internet your packet will pass many routers which have TCP/IP routing
functionality.

A system with FRR installed acts as a dedicated router.  With FRR, your machine
exchanges routing information with other routers using routing protocols.  FRR
uses this information to update the kernel routing table so that the right data
goes to the right place.  You can dynamically change the configuration and you
may view routing table information from the FRR terminal interface.

Adding to routing protocol support, FRR can setup interface's flags,
interface's address, static routes and so on.  If you have a small network, or
a stub network, or xDSL connection, configuring the FRR routing software is
very easy.  The only thing you have to do is to set up the interfaces and put a
few commands about static routes and/or default routes.  If the network is
rather large, or if the network structure changes frequently, you will want to
take advantage of FRR's dynamic routing protocol support for protocols such as
RIP, OSPF, IS-IS or BGP.

Traditionally, UNIX based router configuration is done by *ifconfig* and
*route* commands.  Status of routing table is displayed by *netstat* utility.
Almost of these commands work only if the user has root privileges.  FRR has a
different system administration method.  There are two user modes in FRR.  One
is normal mode, the other is enable mode.  Normal mode user can only view
system status, enable mode user can change system configuration.  This UNIX
account independent feature will be great help to the router administrator.

Currently, FRR supports common unicast routing protocols, that is BGP, OSPF,
RIP and IS-IS.  Upcoming for MPLS support, an implementation of LDP is
currently being prepared for merging.  Implementations of BFD and PIM-SSM
(IPv4) also exist, but are not actively being worked on.

The ultimate goal of the FRR project is making a production-grade, high
quality, featureful and free IP routing software suite.


System Architecture
===================

.. index:: System architecture

.. index:: Software architecture

.. index:: Software internals

Traditional routing software is made as a one process program which provides
all of the routing protocol functionalities. FRR takes a different approach.
FRR is a suite of daemons that work together to build the routing table. There
is a daemon for each major supported protocol as well as a middleman daemon
(*Zebra*) which serves as the broker between these daemons and the kernel.

This architecture allows for high resiliency, since an error, crash or exploit
in one protocol daemon will generally not affect the others.  It is also
flexible and extensible since the modularity makes it easy to implement new
protocols and tie them into the suite.

An illustration of the large scale architecture is given below.

::

   +----+  +----+  +-----+  +----+  +----+  +----+  +-----+
   |bgpd|  |ripd|  |ospfd|  |ldpd|  |pbrd|  |pimd|  |.....|
   +----+  +----+  +-----+  +----+  +----+  +----+  +-----+
        |       |        |       |       |       |        |
   +----v-------v--------v-------v-------v-------v--------v
   |                                                      |
   |                         Zebra                        |
   |                                                      |
   +------------------------------------------------------+
          |                    |                   |
          |                    |                   |
   +------v------+   +---------v--------+   +------v------+
   |             |   |                  |   |             |
   | *NIX Kernel |   | Remote dataplane |   | ........... |
   |             |   |                  |   |             |
   +-------------+   +------------------+   +-------------+


The multi-process architecture brings extensibility, modularity and
maintainability.  All of the FRR daemons can be managed through a single
integrated user interface shell called *vtysh*.  *vtysh* connects to each
daemon through a UNIX domain socket and then works as a proxy for user input.
In addition to a unified frontend, *vtysh* also provides the ability to
configure all the daemons using a single configuration file through the
integrated configuration mode avoiding the problem of having to maintain a
separate configuration file for each daemon.

Supported Platforms
===================

.. index:: Supported platforms
.. index:: FRR on other systems
.. index:: Compatibility with other systems
.. index:: Operating systems that support FRR

Currently FRR supports GNU/Linux and BSD. Porting FRR to other platforms is not
too difficult as platform dependent code should be mostly limited to the
*Zebra* daemon. Protocol daemons are largely platform independent. Please let
us know if you can get FRR to run on a platform which is not listed below:

- GNU/Linux
- FreeBSD
- NetBSD
- OpenBSD

Versions of these platforms that are older than around 2 years from the point
of their original release (in case of GNU/Linux, this is since the kernel's
release on https://kernel.org/) may need some work.  Similarly, the following
platforms may work with some effort:

- Solaris
- MacOS

Recent versions of the following compilers are well tested:

- GNU's GCC
- LLVM's Clang
- Intel's ICC

.. _supported-protocols:

Supported Protocols vs. Platform
================================

The following table lists all protocols cross-refrenced to all operating
systems that have at least CI build tests.  Note that for features, only
features with system dependencies are included here.

.. role:: mark

.. comment - the :mark:`X` pieces mesh with a little bit of JavaScript and
   CSS in _static/overrides.{js,css} respectively.  The JS code looks at the
   presence of the 'Y' 'N' '≥' '†' or 'CP' strings.  This seemed to be the
   best / least intrusive way of getting a nice table in HTML.  The table
   will look somewhat shoddy on other sphinx targets like PDF or info (but
   should still be readable.)

+-----------------------------------+----------------+--------------+------------+------------+------------+
| Daemon / Feature                  | Linux          | OpenBSD      | FreeBSD    | NetBSD     | Solaris    |
+===================================+================+==============+============+============+============+
| **FRR Core**                      |                |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `zebra`                           | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    VRF                            | :mark:`≥4.8`   | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    MPLS                           | :mark:`≥4.5`   | :mark:`Y`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `pbrd` (Policy Routing)           | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| **WAN / Carrier protocols**       |                |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `bgpd` (BGP)                      | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    VRF / L3VPN                    | :mark:`≥4.8`   | :mark:`CP`   | :mark:`CP` | :mark:`CP` | :mark:`CP` |
|                                   | :mark:`†4.3`   |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    EVPN                           | :mark:`≥4.18`  | :mark:`CP`   | :mark:`CP` | :mark:`CP` | :mark:`CP` |
|                                   | :mark:`†4.9`   |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    VNC (Virtual Network Control)  | :mark:`CP`     | :mark:`CP`   | :mark:`CP` | :mark:`CP` | :mark:`CP` |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    Flowspec                       | :mark:`CP`     | :mark:`CP`   | :mark:`CP` | :mark:`CP` | :mark:`CP` |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `ldpd` (LDP)                      | :mark:`≥4.5`   | :mark:`Y`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    VPWS / PW                      | :mark:`N`      | :mark:`≥5.8` | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    VPLS                           | :mark:`N`      | :mark:`≥5.8` | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `nhrpd` (NHRP)                    | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| **Link-State Routing**            |                |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `ospfd` (OSPFv2)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    Segment Routing                | :mark:`≥4.12`  | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `ospf6d` (OSPFv3)                 | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `isisd` (IS-IS)                   | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| **Distance-Vector Routing**       |                |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `ripd` (RIPv2)                    | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `ripngd` (RIPng)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `babeld` (BABEL)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `eigrpd` (EIGRP)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| **Multicast Routing**             |                |              |            |            |            |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `pimd` (PIM)                      | :mark:`≥4.18`  | :mark:`N`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    SSM (Source Specific)          | :mark:`Y`      | :mark:`N`    | :mark:`Y`  | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    ASM (Any Source)               | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
|    EVPN BUM Forwarding            | :mark:`≥5.0`   | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+
| `vrrpd` (VRRP)                    | :mark:`≥5.1`   | :mark:`N`    | :mark:`N`  | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+------------+

The indicators have the following semantics:

* :mark:`Y` - daemon/feature fully functional
* :mark:`≥X.X` - fully functional with kernel version X.X or newer
* :mark:`†X.X` - restricted functionality or impaired performance with kernel version X.X or newer
* :mark:`CP` - control plane only (i.e. BGP route server / route reflector)
* :mark:`N` - daemon/feature not supported by operating system


Known Kernel Issues:
====================

- Linux
   v6 Route Replacement - Linux kernels before 4.11 can cause issues with v6 route deletion when you
   have ecmp routes installed into the kernel.  This especially becomes apparent if the route is being
   transformed from one ecmp path to another.

.. _supported-rfcs:

Supported RFCs
--------------

FRR implements the following RFCs:

.. note:: This list is incomplete.

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
- :rfc:`4447`
  :t:`Pseudowire Setup and Maintenance Using the Label Distribution Protocol
  (LDP), L. Martini, E. Rosen, N. El-Aawar, T. Smith, and G. Heron. April
  2006.`
- :rfc:`4762`
  :t:`Virtual Private LAN Service (VPLS) Using Label Distribution Protocol
  (LDP) Signaling, M. Lasserre and V. Kompella. January 2007.`
- :rfc:`5036`
  :t:`LDP Specification, L. Andersson, I. Minei, and B. Thomas. October 2007.`
- :rfc:`5561`
  :t:`LDP Capabilities, B. Thomas, K. Raza, S. Aggarwal, R. Aggarwal, and
  JL. Le Roux. July 2009.`
- :rfc:`5918`
  :t:`Label Distribution Protocol (LDP) 'Typed Wildcard' Forward Equivalence
  Class (FEC), R. Asati, I. Minei, and B. Thomas. August 2010.`
- :rfc:`5919`
  :t:`Signaling LDP Label Advertisement Completion, R. Asati, P. Mohapatra,
  E. Chen, and B. Thomas. August 2010.`
- :rfc:`6667`
  :t:`LDP 'Typed Wildcard' Forwarding Equivalence Class (FEC) for PWid and
  Generalized PWid FEC Elements, K. Raza, S. Boutros, and C. Pignataro. July
  2012.`
- :rfc:`6720`
  :t:`The Generalized TTL Security Mechanism (GTSM) for the Label Distribution
  Protocol (LDP), C. Pignataro and R. Asati. August 2012.`
- :rfc:`7552`
  :t:`Updates to LDP for IPv6, R. Asati, C. Pignataro, K. Raza, V. Manral,
  and R. Papneja. June 2015.`
- :rfc:`5880`
  :t:`Bidirectional Forwarding Detection (BFD), D. Katz, D. Ward. June 2010`
- :rfc:`5881`
  :t:`Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop),
  D. Katz, D. Ward. June 2010`
- :rfc:`5883`
  :t:`Bidirectional Forwarding Detection (BFD) for Multihop Paths, D. Katz,
  D. Ward. June 2010`

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

Several distributions provide packages for FRR. Check your distribution's
repositories to find out if a suitable version is available.

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

Bug Reports
===========

For information on reporting bugs, please see :ref:`bug-reports`.

.. _frr: |package-url|
.. _github: https://github.com/frrouting/frr/
.. _github issues: https://github.com/frrouting/frr/issues
.. _slack: https://frrouting.slack.com/
