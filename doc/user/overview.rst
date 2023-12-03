.. _overview:

********
Overview
********

`FRR`_ is a fully featured, high performance, free software IP routing suite.

FRR implements all standard routing protocols such as BGP, RIP, OSPF, IS-IS and
more (see :ref:`feature-matrix`), as well as many of their extensions.

FRR is a high performance suite written primarily in C. It can easily handle
full Internet routing tables and is suitable for use on hardware ranging from
cheap SBCs to commercial grade routers. It is actively used in production by
hundreds of companies, universities, research labs and governments.

FRR is distributed under GPLv2, with development modeled after the Linux
kernel. Anyone may contribute features, bug fixes, tools, documentation
updates, or anything else.

FRR is a fork of `Quagga <http://www.quagga.net/>`_.

.. _how-to-get-frr:

How to get FRR
==============

The official FRR website is located at |PACKAGE_URL| and contains further
information, as well as links to additional resources.

Several distributions provide packages for FRR. Check your distribution's
repositories to find out if a suitable version is available.

Up-to-date Debian & Redhat packages are available at https://deb.frrouting.org/
& https://rpm.frrouting.org/ respectively.

For instructions on installing from source, refer to the
`developer documentation <http://docs.frrouting.org/projects/dev-guide/en/latest/>`_.


.. _about-frr:

About FRR
=========

FRR provides IP routing services. Its role in a networking stack is to exchange
routing information with other routers, make routing and policy decisions, and
inform other layers of these decisions. In the most common scenario, FRR
installs routing decisions into the OS kernel, allowing the kernel networking
stack to make the corresponding forwarding decisions.

In addition to dynamic routing FRR supports the full range of L3 configuration,
including static routes, addresses, router advertisements etc. It has some
light L2 functionality as well, but this is mostly left to the platform. This
makes it suitable for deployments ranging from small home networks with static
routes to Internet exchanges running full Internet tables.

FRR runs on all modern \*NIX operating systems, including Linux and the BSDs.
Feature support varies by platform; see the :ref:`feature-matrix`.

System Requirements
-------------------

System resources needed by FRR are highly dependent on workload. Routing
software performance is particularly susceptible to external factors such as:

* Kernel networking stack
* Physical NIC
* Peer behavior
* Routing information scale

Because of these factors - especially the last one - it's difficult to lay out
resource requirements.

To put this in perspective, FRR can be run on very low resource systems such as
SBCs, provided it is not stressed too much. If you want to set up 4 Raspberry
Pis to play with BGP or OSPF, it should work fine. If you ask a FRR to process
a complete internet routing table on a Raspberry Pi, you will be disappointed.
However, given enough resources, FRR ought to be capable of acting as a core IX
router. Such a use case requires at least 4gb of memory and a recent quad-core
server processor at a minimum.

If you are new to networking, an important thing to remember is that FRR is
control plane software. It does not itself forward packets - it exchanges
information with peers about how to forward packets. Forwarding plane
performance largely depends on choice of NIC / ASIC.


System Architecture
-------------------

.. index::
   pair: architecture; FRR

Traditional routing software is made as a one process program which provides
all of the routing protocol functionalities. FRR takes a different approach.
FRR is a suite of daemons that work together to build the routing table. Each
major protocol is implemented in its own daemon, and these daemons talk to a
middleman daemon (*zebra*), which is responsible for coordinating routing
decisions and talking to the dataplane.

This architecture allows for high resiliency, since an error, crash or exploit
in one protocol daemon will generally not affect the others. It is also
flexible and extensible since the modularity makes it easy to implement new
protocols and tie them into the suite. Additionally, each daemon implements a
plugin system allowing new functionality to be loaded at runtime.

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


All of the FRR daemons can be managed through a single integrated user
interface shell called *vtysh*. *vtysh* connects to each daemon through a UNIX
domain socket and then works as a proxy for user input. In addition to a
unified frontend, *vtysh* also provides the ability to configure all the
daemons using a single configuration file through the integrated configuration
mode. This avoids the overhead of maintaining a separate configuration file for
each daemon.

FRR is currently implementing a new internal configuration system based on YANG
data models. When this work is completed, FRR will be a fully programmable
routing stack.


.. index::
   pair: platforms; FRR
   pair: operating systems; FRR

.. _supported-platforms:

Supported Platforms
-------------------


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
release on https://kernel.org/) may need some work. Similarly, the following
platforms may work with some effort:

- MacOS

Recent versions of the following compilers are well tested:

- GNU's GCC
- LLVM's Clang
- Intel's ICC

.. _unsupported-platforms:

Unsupported Platforms
---------------------

In General if the platform you are attempting to use is not listed above then
FRR does not support being run on that platform.  The only caveat here is that
version 7.5 and before Solaris was supported in a limited fashion.

.. _feature-matrix:

Feature Matrix
^^^^^^^^^^^^^^

The following table lists all protocols cross-referenced to all operating
systems that have at least CI build tests. Note that for features, only
features with system dependencies are included here; if you don't see the
feature you're interested in, it should be supported on your platform.

.. role:: mark

.. comment - the :mark:`X` pieces mesh with a little bit of JavaScript and
   CSS in _static/overrides.{js,css} respectively.  The JS code looks at the
   presence of the 'Y' 'N' '≥' '†' or 'CP' strings.  This seemed to be the
   best / least intrusive way of getting a nice table in HTML.  The table
   will look somewhat shoddy on other sphinx targets like PDF or info (but
   should still be readable.)

+-----------------------------------+----------------+--------------+------------+------------+
| Daemon / Feature                  | Linux          | OpenBSD      | FreeBSD    | NetBSD     |
+===================================+================+==============+============+============+
| **FRR Core**                      |                |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
| `zebra`                           | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    VRF                            | :mark:`≥4.8`   | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    MPLS                           | :mark:`≥4.5`   | :mark:`Y`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `pbrd` (Policy Routing)           | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| **WAN / Carrier protocols**       |                |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
| `bgpd` (BGP)                      | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    VRF / L3VPN                    | :mark:`≥4.8`   | :mark:`CP`   | :mark:`CP` | :mark:`CP` |
|                                   | :mark:`†4.3`   |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
|    EVPN                           | :mark:`≥4.18`  | :mark:`CP`   | :mark:`CP` | :mark:`CP` |
|                                   | :mark:`†4.9`   |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
|    VNC (Virtual Network Control)  | :mark:`CP`     | :mark:`CP`   | :mark:`CP` | :mark:`CP` |
+-----------------------------------+----------------+--------------+------------+------------+
|    Flowspec                       | :mark:`CP`     | :mark:`CP`   | :mark:`CP` | :mark:`CP` |
+-----------------------------------+----------------+--------------+------------+------------+
| `ldpd` (LDP)                      | :mark:`≥4.5`   | :mark:`Y`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    VPWS / PW                      | :mark:`N`      | :mark:`≥5.8` | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    VPLS                           | :mark:`N`      | :mark:`≥5.8` | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `nhrpd` (NHRP)                    | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| **Link-State Routing**            |                |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
| `ospfd` (OSPFv2)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    Segment Routing                | :mark:`≥4.12`  | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `ospf6d` (OSPFv3)                 | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `isisd` (IS-IS)                   | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| **Distance-Vector Routing**       |                |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
| `ripd` (RIPv2)                    | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `ripngd` (RIPng)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `babeld` (BABEL)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `eigrpd` (EIGRP)                  | :mark:`Y`      | :mark:`Y`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
| **Multicast Routing**             |                |              |            |            |
+-----------------------------------+----------------+--------------+------------+------------+
| `pimd` (PIM)                      | :mark:`≥4.19`  | :mark:`N`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    SSM (Source Specific)          | :mark:`Y`      | :mark:`N`    | :mark:`Y`  | :mark:`Y`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    ASM (Any Source)               | :mark:`Y`      | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
|    EVPN BUM Forwarding            | :mark:`≥5.0`   | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+
| `vrrpd` (VRRP)                    | :mark:`≥5.1`   | :mark:`N`    | :mark:`N`  | :mark:`N`  |
+-----------------------------------+----------------+--------------+------------+------------+

The indicators have the following semantics:

* :mark:`Y` - daemon/feature fully functional
* :mark:`≥X.X` - fully functional with kernel version X.X or newer
* :mark:`†X.X` - restricted functionality or impaired performance with kernel version X.X or newer
* :mark:`CP` - control plane only (i.e. BGP route server / route reflector)
* :mark:`N` - daemon/feature not supported by operating system


Known Kernel Issues
-------------------

- Linux < 4.11

  v6 Route Replacement - Linux kernels before 4.11 can cause issues with v6
  route deletion when you have ECMP routes installed into the kernel. This
  especially becomes apparent if the route is being transformed from one ECMP
  path to another.


.. index::
   pair: rfcs; FRR

.. _supported-rfcs:

Supported RFCs
--------------

FRR implements the following RFCs:

.. note:: This list is incomplete.

BGP
----

- :rfc:`1771`
  :t:`A Border Gateway Protocol 4 (BGP-4). Y. Rekhter & T. Li. March 1995.`
- :rfc:`1965`
  :t:`Autonomous System Confederations for BGP. P. Traina. June 1996.`
- :rfc:`1997`
  :t:`BGP Communities Attribute. R. Chandra, P. Traina & T. Li. August 1996.`
- :rfc:`1998`
  :t:`An Application of the BGP Community Attribute in Multi-home Routing. E. Chen, T. Bates. August 1996.`
- :rfc:`2385`
  :t:`Protection of BGP Sessions via the TCP MD5 Signature Option. A. Heffernan. August 1998.`
- :rfc:`2439`
  :t:`BGP Route Flap Damping. C. Villamizar, R. Chandra, R. Govindan. November 1998.`
- :rfc:`2545`
  :t:`Use of BGP-4 Multiprotocol Extensions for IPv6 Inter-Domain Routing. P. Marques, F. Dupont. March 1999.`
- :rfc:`2796`
  :t:`BGP Route Reflection An alternative to full mesh IBGP. T. Bates & R. Chandrasekeran. June 1996.`
- :rfc:`2842`
  :t:`Capabilities Advertisement with BGP-4. R. Chandra, J. Scudder. May 2000.`
- :rfc:`2858`
  :t:`Multiprotocol Extensions for BGP-4. T. Bates, Y. Rekhter, R. Chandra, D. Katz. June 2000.`
- :rfc:`2918`
  :t:`Route Refresh Capability for BGP-4. E. Chen, September 2000.`
- :rfc:`3107`
  :t:`Carrying Label Information in BGP-4. Y. Rekhter & E. Rosen. May 2001.`
- :rfc:`3765`
  :t:`NOPEER Community for Border Gateway Protocol (BGP) Route Scope Control. G.Huston. April 2001.`
- :rfc:`4271`
  :t:`A Border Gateway Protocol 4 (BGP-4). Updates RFC1771. Y. Rekhter, T. Li & S. Hares. January 2006.`
- :rfc:`4360`
  :t:`BGP Extended Communities Attribute. S. Sangli, D. Tappan, Y. Rekhter. February 2006.`
- :rfc:`4364`
  :t:`BGP/MPLS IP Virtual Private Networks (VPNs). Y. Rekhter. February 2006.`
- :rfc:`4456`
  :t:`BGP Route Reflection An alternative to full mesh IBGP. T. Bates, E. Chen, R. Chandra. April 2006.`
- :rfc:`4486`
  :t:`Subcodes for BGP Cease Notification Message. E. Chen, V. Gillet. April 2006.`
- :rfc:`4659`
  :t:`BGP-MPLS IP Virtual Private Network (VPN) Extension for IPv6 VPN. J. De Clercq, D. Ooms, M. Carugi, F. Le Faucheur. September 2006.`
- :rfc:`4724`
  :t:`Graceful Restart Mechanism for BGP. S. Sangli, E. Chen, R. Fernando, J. Scudder, Y. Rekhter. January 2007.`
- :rfc:`4760`
  :t:`Multiprotocol Extensions for BGP-4. T. Bates, R. Chandra, D. Katz, Y. Rekhter. January 2007.`
- :rfc:`4893`
  :t:`BGP Support for Four-octet AS Number Space. Q. Vohra, E. Chen May 2007.`
- :rfc:`5004`
  :t:`Avoid BGP Best Path Transitions from One External to Another. E. Chen & S. Sangli. September 2007 (Partial support).`
- :rfc:`5065`
  :t:`Autonomous System Confederations for BGP. P. Traina, D. McPherson, J. Scudder. August 2007.`
- :rfc:`5082`
  :t:`The Generalized TTL Security Mechanism (GTSM). V. Gill, J. Heasley, D. Meyer, P. Savola, C. Pingnataro. October 2007.`
- :rfc:`5291`
  :t:`Outbound Route Filtering Capability. E. Chen, Y. Rekhter. August 2008.`
- :rfc:`5292`
  :t:`Address-Prefix-Based Outbound Route Filter for BGP-4. E. Chen, S. Sangli. August 2008.`
- :rfc:`5396`
  :t:`Textual Representation of Autonomous System (AS) Numbers. G. Michaelson, G. Huston. December 2008.`
- :rfc:`5492`
  :t:`Capabilities Advertisement with BGP-4. J. Scudder, R. Chandra. February 2009.`
- :rfc:`5575`
  :t:`Dissemination of Flow Specification Rules. P. Marques, N. Sheth, R. Raszuk, B. Greene, J. Mauch, D. McPherson. August 2009.`
- :rfc:`5668`
  :t:`4-Octet AS Specific BGP Extended Community. Y. Rekhter, S. Sangli, D. Tappan October 2009.`
- :rfc:`6286`
  :t:`Autonomous-System-Wide Unique BGP Identifier for BGP-4. E. Chen, J. Yuan. June 2011.`
- :rfc:`6472`
  :t:`Recommendation for Not Using AS_SET and AS_CONFED_SET in BGP. W. Kumari, K. Sriram. December 2011.`
- :rfc:`6608`
  :t:`Subcodes for BGP Finite State Machine Error. J. Dong, M. Chen, Huawei Technologies, A. Suryanarayana, Cisco Systems. May 2012.`
- :rfc:`6810`
  :t:`The Resource Public Key Infrastructure (RPKI) to Router Protocol. R. Bush, R. Austein. January 2013.`
- :rfc:`6811`
  :t:`BGP Prefix Origin Validation. P. Mohapatra, J. Scudder, D. Ward, R. Bush, R. Austein. January 2013.`
- :rfc:`6938`
  :t:`Deprecation of BGP Path Attributes: DPA, ADVERTISER, and RCID_PATH / CLUSTER_ID. J. Scudder. May 2013.`
- :rfc:`6996`
  :t:`Autonomous System (AS) Reservation for Private Use. J. Mitchell. July 2013.`
- :rfc:`7196`
  :t:`Making Route Flap Damping Usable. C. Pelsser, R. Bush, K. Patel, P. Mohapatra, O. Maennel. May 2014.`
- :rfc:`7300`
  :t:`Reservation of Last Autonomous System (AS) Numbers. J. Haas, J. Mitchell. July 2014.`
- :rfc:`7313`
  :t:`Enhanced Route Refresh Capability for BGP-4. K. Patel, E. Chen, B. Venkatachalapathy. July 2014.`
- :rfc:`7606`
  :t:`Revised Error Handling for BGP UPDATE Messages. E. Chen, J. Scudder, P. Mohapatra, K. Patel. August 2015.`
- :rfc:`7607`
  :t:`Codification of AS 0 Processing. W. Kumari, R. Bush, H. Schiller, K. Patel. August 2015.`
- :rfc:`7611`
  :t:`BGP ACCEPT_OWN Community Attribute. J. Uttaro, P. Mohapatra, D. Smith, R. Raszuk, J. Scudder. August 2015.`
- :rfc:`7911`
  :t:`Advertisement of Multiple Paths in BGP. D. Walton, A. Retana, E. Chen, J. Scudder. July 2016.`
- :rfc:`7947`
  :t:`Internet Exchange BGP Route Server. E. Jasinska, N. Hilliard, R. Raszuk, N. Bakker. September 2016.`
- :rfc:`7999`
  :t:`BLACKHOLE Community. T. King, C. Dietzel, J. Snijders, G. Doering, G. Hankins. October 2016.`
- :rfc:`8050`
  :t:`Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format with BGP Additional Path Extensions. C. Petrie, T. King. May 2017.`
- :rfc:`8092`
  :t:`BGP Large Communities Attribute. J. Heitz, Ed., J. Snijders, Ed, K. Patel, I. Bagdonas, N. Hilliard. February 2017.`
- :rfc:`8093`
  :t:`Deprecation of BGP Path Attribute Values 30, 31, 129, 241, 242, and 243. J. Snijders. February 2017.`
- :rfc:`8097`
  :t:`BGP Prefix Origin Validation State Extended Community. P. Mohapatra, K. Patel, J. Scudder, D. Ward, R. Bush. March 2017.`
- :rfc:`8195`
  :t:`Use of BGP Large Communities. J. Snijders, J. Heasley, M. Schmidt. June 2017.`
- :rfc:`8203`
  :t:`BGP Administrative Shutdown Communication. J. Snijders, J. Heitz, J. Scudder. July 2017.`
- :rfc:`8212`
  :t:`Default External BGP (EBGP) Route Propagation Behavior without Policies. J. Mauch, J. Snijders, G. Hankins. July 2017.`
- :rfc:`8277`
  :t:`Using BGP to Bind MPLS Labels to Address Prefixes. E. Rosen. October 2017.`
- :rfc:`8538`
  :t:`Notification Message Support for BGP Graceful Restart. K. Patel, R. Fernando, J. Scudder, J. Haas. March 2019.`
- :rfc:`8654`
  :t:`Extended Message Support for BGP. R. Bush, K. Patel, D. Ward. October 2019.`
- :rfc:`9003`
  :t:`Extended BGP Administrative Shutdown Communication. J. Snijders, J. Heitz, J. Scudder, A. Azimov. January 2021.`
- :rfc:`9012`
  :t:`The BGP Tunnel Encapsulation Attribute. K. Patel, G. Van de Velde, S. Sangli, J. Scudder. April 2021.`
- :rfc:`9072`
  :t:`Extended Optional Parameters Length for BGP OPEN Message. E. Chen, J. Scudder. July 2021.`
- :rfc:`9234`
  :t:`Route Leak Prevention and Detection Using Roles in UPDATE and OPEN Messages. A. Azimov, E. Bogomazov, R. Bush, K. Patel, K. Sriram. May 2022.`
- :rfc:`9384`
  :t:`A BGP Cease NOTIFICATION Subcode for Bidirectional Forwarding Detection (BFD). J. Haas. March 2023.`
- :rfc:`9494`
  :t:`Long-Lived Graceful Restart for BGP. J. Uttaro, E. Chen, B. Decraene, J. Scudder. November 2023.`

OSPF
----

- :rfc:`2328`
  :t:`OSPF Version 2. J. Moy. April 1998.`
- :rfc:`2370`
  :t:`The OSPF Opaque LSA Option R. Coltun. July 1998.`
- :rfc:`3101`
  :t:`The OSPF Not-So-Stubby Area (NSSA) Option P. Murphy. January 2003.`
- :rfc:`2740`
  :t:`OSPF for IPv6. R. Coltun, D. Ferguson, J. Moy. December 1999.`
- :rfc:`3137`
  :t:`OSPF Stub Router Advertisement, A. Retana, L. Nguyen, R. White, A. Zinin, D. McPherson. June 2001`

ISIS
----

RIP
----

- :rfc:`1058`
  :t:`Routing Information Protocol. C.L. Hedrick. Jun-01-1988.`
- :rfc:`2082`
  :t:`RIP-2 MD5 Authentication. F. Baker, R. Atkinson. January 1997.`
- :rfc:`2453`
  :t:`RIP Version 2. G. Malkin. November 1998.`
- :rfc:`2080`
  :t:`RIPng for IPv6. G. Malkin, R. Minnear. January 1997.`

PIM
----

BFD
----
- :rfc:`5880`
  :t:`Bidirectional Forwarding Detection (BFD), D. Katz, D. Ward. June 2010`
- :rfc:`5881`
  :t:`Bidirectional Forwarding Detection (BFD) for IPv4 and IPv6 (Single Hop), D. Katz, D. Ward. June 2010`
- :rfc:`5882`
  :t:`Generic Application of Bidirectional Forwarding Detection (BFD), D. Katz, D. Ward. June 2010`
- :rfc:`5883`
  :t:`Bidirectional Forwarding Detection (BFD) for Multihop Paths, D. Katz, D. Ward. June 2010`

MPLS
----

- :rfc:`2858`
  :t:`Multiprotocol Extensions for BGP-4. T. Bates, Y. Rekhter, R. Chandra, D. Katz. June 2000.`
- :rfc:`4364`
  :t:`BGP/MPLS IP Virtual Private Networks (VPNs). Y. Rekhter. Feb 2006.`
- :rfc:`4447`
  :t:`Pseudowire Setup and Maintenance Using the Label Distribution Protocol (LDP), L. Martini, E. Rosen, N. El-Aawar, T. Smith, and G. Heron. April 2006.`
- :rfc:`4659`
  :t:`BGP-MPLS IP Virtual Private Network (VPN) Extension for IPv6 VPN. J. De Clercq, D. Ooms, M. Carugi, F. Le Faucheur. September 2006`
- :rfc:`4762`
  :t:`Virtual Private LAN Service (VPLS) Using Label Distribution Protocol (LDP) Signaling, M. Lasserre and V. Kompella. January 2007.`
- :rfc:`5036`
  :t:`LDP Specification, L. Andersson, I. Minei, and B. Thomas. October 2007.`
- :rfc:`5561`
  :t:`LDP Capabilities, B. Thomas, K. Raza, S. Aggarwal, R. Aggarwal, and JL. Le Roux. July 2009.`
- :rfc:`5918`
  :t:`Label Distribution Protocol (LDP) 'Typed Wildcard' Forward Equivalence Class (FEC), R. Asati, I. Minei, and B. Thomas. August 2010.`
- :rfc:`5919`
  :t:`Signaling LDP Label Advertisement Completion, R. Asati, P. Mohapatra, E. Chen, and B. Thomas. August 2010.`
- :rfc:`6667`
  :t:`LDP 'Typed Wildcard' Forwarding Equivalence Class (FEC) for PWid and Generalized PWid FEC Elements, K. Raza, S. Boutros, and C. Pignataro. July 2012.`
- :rfc:`6720`
  :t:`The Generalized TTL Security Mechanism (GTSM) for the Label Distribution Protocol (LDP), C. Pignataro and R. Asati. August 2012.`
- :rfc:`7552`
  :t:`Updates to LDP for IPv6, R. Asati, C. Pignataro, K. Raza, V. Manral, and R. Papneja. June 2015.`

VRRP
----

- :rfc:`3768`
  :t:`Virtual Router Redundancy Protocol (VRRP). R. Hinden. April 2004.`
- :rfc:`5798`
  :t:`Virtual Router Redundancy Protocol (VRRP) Version 3 for IPv4 and IPv6. S. Nadas. June 2000.`

SNMP
----

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


.. index::
   pair: mailing lists; contact

.. _mailing-lists:

Mailing Lists
=============

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

.. _frr: https://frrouting.org
.. _github: https://github.com/frrouting/frr/
.. _github issues: https://github.com/frrouting/frr/issues
.. _slack: https://frrouting.org/community
