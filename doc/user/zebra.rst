.. _zebra:

*****
Zebra
*****

*zebra* is an IP routing manager. It provides kernel routing
table updates, interface lookups, and redistribution of routes between
different routing protocols.

.. _invoking-zebra:

Invoking zebra
==============

Besides the common invocation options (:ref:`common-invocation-options`), the
*zebra* specific invocation options are listed below.

.. program:: zebra

.. option:: -b, --batch

   Runs in batch mode. *zebra* parses configuration file and terminates
   immediately.

.. option:: -K TIME, --graceful_restart TIME

   If this option is specified, the graceful restart time is TIME seconds.
   Zebra, when started, will read in routes.  Those routes that Zebra
   identifies that it was the originator of will be swept in TIME seconds.
   If no time is specified then we will sweep those routes immediately.

.. option:: -r, --retain

   When program terminates, do not flush routes installed by *zebra* from the
   kernel.

.. option:: -e X, --ecmp X

   Run zebra with a limited ecmp ability compared to what it is compiled to.
   If you are running zebra on hardware limited functionality you can
   force zebra to limit the maximum ecmp allowed to X.  This number
   is bounded by what you compiled FRR with as the maximum number.

.. option:: -n, --vrfwnetns

   When *Zebra* starts with this option, the VRF backend is based on Linux
   network namespaces. That implies that all network namespaces discovered by
   ZEBRA will create an associated VRF. The other daemons will operate on the VRF
   VRF defined by *Zebra*, as usual.

   .. seealso:: :ref:`zebra-vrf`

.. option:: -o, --vrfdefaultname

   When *Zebra* starts with this option, the default VRF name is changed to the
   parameter.

   .. seealso:: :ref:`zebra-vrf`

.. option:: -z <path_to_socket>, --socket <path_to_socket>

   If this option is supplied on the cli, the path to the zebra
   control socket(zapi), is used.  This option overrides a -N <namespace>
   option if handed to it on the cli.

.. option:: --v6-rr-semantics

   The linux kernel is receiving the ability to use the same route
   replacement semantics for v6 that v4 uses.  If you are using a
   kernel that supports this functionality then run *Zebra* with this
   option and we will use Route Replace Semantics instead of delete
   than add.

.. _interface-commands:

Configuration Addresses behaviour
=================================

At startup, *Zebra* will first discover the underlying networking objects
from the operating system. This includes interfaces, addresses of
interfaces, static routes, etc. Then, it will read the configuration
file, including its own interface addresses, static routes, etc. All this
information comprises the operational context from *Zebra*. But
configuration context from *Zebra* will remain the same as the one from
:file:`zebra.conf` config file. As an example, executing the following
:clicmd:`show running-config` will reflect what was in :file:`zebra.conf`.
In a similar way, networking objects that are configured outside of the
*Zebra* like *iproute2* will not impact the configuration context from
*Zebra*. This behaviour permits you to continue saving your own config
file, and decide what is really to be pushed on the config file, and what
is dependent on the underlying system.
Note that inversely, from *Zebra*, you will not be able to delete networking
objects that were previously configured outside of *Zebra*.


Interface Commands
==================

.. _standard-commands:

Standard Commands
-----------------

.. index:: interface IFNAME

.. clicmd:: interface IFNAME

.. index:: interface IFNAME vrf VRF

.. clicmd:: interface IFNAME vrf VRF

.. index:: shutdown

.. clicmd:: shutdown
.. index:: no shutdown

.. clicmd:: no shutdown

   Up or down the current interface.

.. index:: ip address ADDRESS/PREFIX

.. clicmd:: ip address ADDRESS/PREFIX
.. index:: ipv6 address ADDRESS/PREFIX

.. clicmd:: ipv6 address ADDRESS/PREFIX
.. index:: no ip address ADDRESS/PREFIX

.. clicmd:: no ip address ADDRESS/PREFIX
.. index:: no ipv6 address ADDRESS/PREFIX

.. clicmd:: no ipv6 address ADDRESS/PREFIX

   Set the IPv4 or IPv6 address/prefix for the interface.

.. index:: ip address LOCAL-ADDR peer PEER-ADDR/PREFIX

.. clicmd:: ip address LOCAL-ADDR peer PEER-ADDR/PREFIX
.. index:: no ip address LOCAL-ADDR peer PEER-ADDR/PREFIX

.. clicmd:: no ip address LOCAL-ADDR peer PEER-ADDR/PREFIX

   Configure an IPv4 Point-to-Point address on the interface. (The concept of
   PtP addressing does not exist for IPv6.)

   `local-addr` has no subnet mask since the local side in PtP addressing is
   always a single (/32) address. `peer-addr/prefix` can be an arbitrary subnet
   behind the other end of the link (or even on the link in Point-to-Multipoint
   setups), though generally /32s are used.

.. index:: description DESCRIPTION ...

.. clicmd:: description DESCRIPTION ...

   Set description for the interface.

.. index:: multicast

.. clicmd:: multicast
.. index:: no multicast

.. clicmd:: no multicast

   Enable or disables multicast flag for the interface.

.. index:: bandwidth (1-10000000)

.. clicmd:: bandwidth (1-10000000)
.. index:: no bandwidth (1-10000000)

.. clicmd:: no bandwidth (1-10000000)

   Set bandwidth value of the interface in kilobits/sec. This is for
   calculating OSPF cost. This command does not affect the actual device
   configuration.

.. index:: link-detect

.. clicmd:: link-detect
.. index:: no link-detect

.. clicmd:: no link-detect

   Enable/disable link-detect on platforms which support this. Currently only
   Linux and Solaris, and only where network interface drivers support
   reporting link-state via the ``IFF_RUNNING`` flag.

   In FRR, link-detect is on by default.

.. _link-parameters-commands:

Link Parameters Commands
------------------------

.. note::

   At this time, FRR offers partial support for some of the routing
   protocol extensions that can be used with MPLS-TE. FRR does not
   support a complete RSVP-TE solution currently.

.. index:: link-params
.. clicmd:: link-params

.. index:: no link-param
.. clicmd:: no link-param

   Enter into the link parameters sub node. At least 'enable' must be
   set to activate the link parameters, and consequently routing
   information that could be used as part of Traffic Engineering on
   this interface. MPLS-TE must be enable at the OSPF
   (:ref:`ospf-traffic-engineering`) or ISIS
   (:ref:`isis-traffic-engineering`) router level in complement to
   this.  Disable link parameters for this interface.

   Under link parameter statement, the following commands set the different TE values:

.. index:: link-params [enable]
.. clicmd:: link-params [enable]

   Enable link parameters for this interface.

.. index:: link-params [metric (0-4294967295)]
.. clicmd:: link-params [metric (0-4294967295)]

.. index:: link-params max-bw BANDWIDTH
.. clicmd:: link-params max-bw BANDWIDTH

.. index:: link-params max-rsv-bw BANDWIDTH
.. clicmd:: link-params max-rsv-bw BANDWIDTH

.. index:: link-params unrsv-bw (0-7) BANDWIDTH
.. clicmd:: link-params unrsv-bw (0-7) BANDWIDTH

.. index:: link-params admin-grp BANDWIDTH
.. clicmd:: link-params admin-grp BANDWIDTH

   These commands specifies the Traffic Engineering parameters of the interface
   in conformity to RFC3630 (OSPF) or RFC5305 (ISIS).  There are respectively
   the TE Metric (different from the OSPF or ISIS metric), Maximum Bandwidth
   (interface speed by default), Maximum Reservable Bandwidth, Unreserved
   Bandwidth for each 0-7 priority and Admin Group (ISIS) or Resource
   Class/Color (OSPF).

   Note that BANDIWDTH is specified in IEEE floating point format and express
   in Bytes/second.

.. index::  link-param delay (0-16777215) [min (0-16777215) | max (0-16777215)]
.. clicmd:: link-param delay (0-16777215) [min (0-16777215) | max (0-16777215)]

.. index::  link-param delay-variation (0-16777215)
.. clicmd:: link-param delay-variation (0-16777215)

.. index::  link-param packet-loss PERCENTAGE
.. clicmd:: link-param packet-loss PERCENTAGE

.. index::  link-param res-bw BANDWIDTH
.. clicmd:: link-param res-bw BANDWIDTH

.. index::  link-param ava-bw BANDWIDTH
.. clicmd:: link-param ava-bw BANDWIDTH

.. index::  link-param use-bw BANDWIDTH
.. clicmd:: link-param use-bw BANDWIDTH

   These command specifies additional Traffic Engineering parameters of the
   interface in conformity to draft-ietf-ospf-te-metrics-extension-05.txt and
   draft-ietf-isis-te-metrics-extension-03.txt. There are respectively the
   delay, jitter, loss, available bandwidth, reservable bandwidth and utilized
   bandwidth.

   Note that BANDWIDTH is specified in IEEE floating point format and express
   in Bytes/second.  Delays and delay variation are express in micro-second
   (µs). Loss is specified in PERCENTAGE ranging from 0 to 50.331642% by step
   of 0.000003.

.. index:: link-param neighbor <A.B.C.D> as (0-65535)
.. clicmd:: link-param neighbor <A.B.C.D> as (0-65535)

.. index:: link-param no neighbor
.. clicmd:: link-param no neighbor

   Specifies the remote ASBR IP address and Autonomous System (AS) number
   for InterASv2 link in OSPF (RFC5392).  Note that this option is not yet
   supported for ISIS (RFC5316).

.. index:: ip nht resolve-via-default
.. clicmd:: ip nht resolve-via-default

   Allows nexthop tracking to resolve via the default route. This is useful
   when e.g. you want to allow BGP to peer across the default route.

.. _zebra-vrf:

Administrative Distance
=======================

Administrative distance allows FRR to make decisions about what routes
should be installed in the rib based upon the originating protocol.
The lowest Admin Distance is the route selected.  This is purely a
subjective decision about ordering and care has been taken to choose
the same distances that other routing suites have choosen.

+------------+-----------+
| Protocol   | Distance  |
+------------+-----------+
| System     | 0         |
+------------+-----------+
| Kernel     | 0         |
+------------+-----------+
| Connect    | 0         |
+------------+-----------+
| Static     | 1         |
+------------+-----------+
| NHRP       | 10        |
+------------+-----------+
| EBGP       | 20        |
+------------+-----------+
| EIGRP      | 90        |
+------------+-----------+
| BABEL      | 100       |
+------------+-----------+
| OSPF       | 110       |
+------------+-----------+
| ISIS       | 115       |
+------------+-----------+
| OPENFABRIC | 115       |
+------------+-----------+
| RIP        | 120       |
+------------+-----------+
| Table      | 150       |
+------------+-----------+
| SHARP      | 150       |
+------------+-----------+
| IBGP       | 200       |
+------------+-----------+
| PBR        | 200       |
+------------+-----------+

An admin distance of 255 indicates to Zebra that the route should not be
installed into the Data Plane.  Additionally routes with an admin distance
of 255 will not be redistributed.

Zebra does treat Kernel routes as special case for the purposes of Admin
Distance.  Upon learning about a route that is not originated by FRR
we read the metric value as a uint32_t.  The top byte of the value
is interpreted as the Administrative Distance and the low three bytes
are read in as the metric.  This special case is to facilitate VRF
default routes.

Virtual Routing and Forwarding
==============================

FRR supports :abbr:`VRF (Virtual Routing and Forwarding)`. VRF is a way to
separate networking contexts on the same machine. Those networking contexts are
associated with separate interfaces, thus making it possible to associate one
interface with a specific VRF.

VRF can be used, for example, when instantiating per enterprise networking
services, without having to instantiate the physical host machine or the
routing management daemons for each enterprise. As a result, interfaces are
separate for each set of VRF, and routing daemons can have their own context
for each VRF.

This conceptual view introduces the *Default VRF* case. If the user does not
configure any specific VRF, then by default, FRR uses the *Default VRF*.

Configuring VRF networking contexts can be done in various ways on FRR. The VRF
interfaces can be configured by entering in interface configuration mode
:clicmd:`interface IFNAME vrf VRF`.

A VRF backend mode is chosen when running *Zebra*.

If no option is chosen, then the *Linux VRF* implementation as references in
https://www.kernel.org/doc/Documentation/networking/vrf.txt will be mapped over
the *Zebra* VRF. The routing table associated to that VRF is a Linux table
identifier located in the same *Linux network namespace* where *Zebra* started.

If the :option:`-n` option is chosen, then the *Linux network namespace* will
be mapped over the *Zebra* VRF. That implies that *Zebra* is able to configure
several *Linux network namespaces*.  The routing table associated to that VRF
is the whole routing tables located in that namespace. For instance, this mode
matches OpenStack Network Namespaces. It matches also OpenFastPath. The default
behavior remains Linux VRF which is supported by the Linux kernel community,
see https://www.kernel.org/doc/Documentation/networking/vrf.txt.

Because of that difference, there are some subtle differences when running some
commands in relationship to VRF. Here is an extract of some of those commands:

.. index:: vrf VRF
.. clicmd:: vrf VRF

   This command is available on configuration mode. By default, above command
   permits accessing the VRF configuration mode. This mode is available for
   both VRFs. It is to be noted that *Zebra* does not create Linux VRF.
   The network administrator can however decide to provision this command in
   configuration file to provide more clarity about the intended configuration.

.. index:: netns NAMESPACE
.. clicmd:: netns NAMESPACE

   This command is based on VRF configuration mode. This command is available
   when *Zebra* is run in :option:`-n` mode. This command reflects which *Linux
   network namespace* is to be mapped with *Zebra* VRF. It is to be noted that
   *Zebra* creates and detects added/suppressed VRFs from the Linux environment
   (in fact, those managed with iproute2). The network administrator can however
   decide to provision this command in configuration file to provide more clarity
   about the intended configuration.

.. index:: show ip route vrf VRF
.. clicmd:: show ip route vrf VRF

   The show command permits dumping the routing table associated to the VRF. If
   *Zebra* is launched with default settings, this will be the ``TABLENO`` of
   the VRF configured on the kernel, thanks to information provided in
   https://www.kernel.org/doc/Documentation/networking/vrf.txt. If *Zebra* is
   launched with :option:`-n` option, this will be the default routing table of
   the *Linux network namespace* ``VRF``.

.. index:: show ip route vrf VRF table TABLENO
.. clicmd:: show ip route vrf VRF table TABLENO

   The show command is only available with :option:`-n` option. This command
   will dump the routing table ``TABLENO`` of the *Linux network namespace*
   ``VRF``.

.. index:: show ip route vrf VRF tables
.. clicmd:: show ip route vrf VRF tables

   This command will dump the routing tables within the vrf scope. If `vrf all`
   is executed, all routing tables will be dumped.

.. index:: show <ip|ipv6> route summary [vrf VRF] [table TABLENO] [prefix]
.. clicmd:: show <ip|ipv6> route summary [vrf VRF] [table TABLENO] [prefix]

   This command will dump a summary output of the specified VRF and TABLENO
   combination.  If neither VRF or TABLENO is specified FRR defaults to
   the default vrf and default table.  If prefix is specified dump the
   number of prefix routes.

By using the :option:`-n` option, the *Linux network namespace* will be mapped
over the *Zebra* VRF. One nice feature that is possible by handling *Linux
network namespace* is the ability to name default VRF. At startup, *Zebra*
discovers the available *Linux network namespace* by parsing folder
`/var/run/netns`. Each file stands for a *Linux network namespace*, but not all
*Linux network namespaces* are available under that folder. This is the case for
default VRF. It is possible to name the default VRF, by creating a file, by
executing following commands.

.. code-block:: shell

   touch /var/run/netns/vrf0
   mount --bind /proc/self/ns/net /var/run/netns/vrf0

Above command illustrates what happens when the default VRF is visible under
`var/run/netns/`. Here, the default VRF file is `vrf0`.
At startup, FRR detects the presence of that file. It detects that the file
statistics information matches the same file statistics information as
`/proc/self/ns/net` ( through stat() function). As statistics information
matches, then `vrf0` stands for the new default namespace name.
Consequently, the VRF naming `Default` will be overridden by the new discovered
namespace name `vrf0`.

For those who don't use VRF backend with *Linux network namespace*, it is
possible to statically configure and recompile FRR. It is possible to choose an
alternate name for default VRF. Then, the default VRF naming will automatically
be updated with the new name. To illustrate, if you want to recompile with
`global` value, use the following command:

.. code-block:: shell

   ./configure --with-defaultvrfname=global

.. _zebra-mpls:

MPLS Commands
=============

You can configure static mpls entries in zebra. Basically, handling MPLS
consists of popping, swapping or pushing labels to IP packets.

MPLS Acronyms
-------------

:abbr:`LSR (Labeled Switch Router)`
   Networking devices handling labels used to forward traffic between and through
   them.

:abbr:`LER (Labeled Edge Router)`
   A Labeled edge router is located at the edge of an MPLS network, generally
   between an IP network and an MPLS network.

MPLS Push Action
----------------

The push action is generally used for LER devices, which want to encapsulate
all traffic for a wished destination into an MPLS label. This action is stored
in routing entry, and can be configured like a route:

.. index:: [no] ip route NETWORK MASK GATEWAY|INTERFACE label LABEL
.. clicmd:: [no] ip route NETWORK MASK GATEWAY|INTERFACE label LABEL

   NETWORK and MASK stand for the IP prefix entry to be added as static
   route entry.
   GATEWAY is the gateway IP address to reach, in order to reach the prefix.
   INTERFACE is the interface behind which the prefix is located.
   LABEL is the MPLS label to use to reach the prefix abovementioned.

   You can check that the static entry is stored in the zebra RIB database, by
   looking at the presence of the entry.

   ::

      zebra(configure)# ip route 1.1.1.1/32 10.0.1.1 label 777
      zebra# show ip route
      Codes: K - kernel route, C - connected, S - static, R - RIP,
      O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
      T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
      F - PBR,
      > - selected route, * - FIB route

      S>* 1.1.1.1/32 [1/0] via 10.0.1.1, r2-eth0, label 777, 00:39:42

MPLS Swap and Pop Action
------------------------

The swap action is generally used for LSR devices, which swap a packet with a
label, with an other label. The Pop action is used on LER devices, at the
termination of the MPLS traffic; this is used to remove MPLS header.

.. index:: [no] mpls lsp INCOMING_LABEL GATEWAY OUTGOING_LABEL|explicit-null|implicit-null
.. clicmd:: [no] mpls lsp INCOMING_LABEL GATEWAY OUTGOING_LABEL|explicit-null|implicit-null

   INCOMING_LABEL and OUTGOING_LABEL are MPLS labels with values ranging from 16
   to 1048575.
   GATEWAY is the gateway IP address where to send MPLS packet.
   The outgoing label can either be a value or have an explicit-null label header. This
   specific header can be read by IP devices. The incoming label can also be removed; in
   that case the implicit-null keyword is used, and the outgoing packet emitted is an IP
   packet without MPLS header.

You can check that the MPLS actions are stored in the zebra MPLS table, by looking at the
presence of the entry.

.. index:: show mpls table
.. clicmd:: show mpls table

::

   zebra(configure)# mpls lsp 18 10.125.0.2 implicit-null
   zebra(configure)# mpls lsp 19 10.125.0.2 20
   zebra(configure)# mpls lsp 21 10.125.0.2 explicit-null
   zebra# show mpls table
   Inbound                            Outbound
   Label     Type          Nexthop     Label
   --------  -------  ---------------  --------
   18     Static       10.125.0.2  implicit-null
   19     Static       10.125.0.2  20
   21     Static       10.125.0.2  IPv4 Explicit Null


.. _multicast-rib-commands:

Multicast RIB Commands
======================

The Multicast RIB provides a separate table of unicast destinations which
is used for Multicast Reverse Path Forwarding decisions. It is used with
a multicast source's IP address, hence contains not multicast group
addresses but unicast addresses.

This table is fully separate from the default unicast table. However,
RPF lookup can include the unicast table.

WARNING: RPF lookup results are non-responsive in this version of FRR,
i.e. multicast routing does not actively react to changes in underlying
unicast topology!

.. index:: ip multicast rpf-lookup-mode MODE
.. clicmd:: ip multicast rpf-lookup-mode MODE

.. index:: no ip multicast rpf-lookup-mode [MODE]
.. clicmd:: no ip multicast rpf-lookup-mode [MODE]

   MODE sets the method used to perform RPF lookups. Supported modes:

   urib-only
      Performs the lookup on the Unicast RIB. The Multicast RIB is never used.

   mrib-only
      Performs the lookup on the Multicast RIB. The Unicast RIB is never used.

   mrib-then-urib
      Tries to perform the lookup on the Multicast RIB. If any route is found,
      that route is used. Otherwise, the Unicast RIB is tried.

   lower-distance
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the lower administrative distance is used;  if they're equal, the
      Multicast RIB takes precedence.

   longer-prefix
      Performs a lookup on the Multicast RIB and Unicast RIB each. The result
      with the longer prefix length is used;  if they're equal, the
      Multicast RIB takes precedence.

      The `mrib-then-urib` setting is the default behavior if nothing is
      configured. If this is the desired behavior, it should be explicitly
      configured to make the configuration immune against possible changes in
      what the default behavior is.

.. warning::
   Unreachable routes do not receive special treatment and do not cause
   fallback to a second lookup.

.. index:: show ip rpf ADDR
.. clicmd:: show ip rpf ADDR

   Performs a Multicast RPF lookup, as configured with ``ip multicast
   rpf-lookup-mode MODE``. ADDR specifies the multicast source address to look
   up.

   ::

      > show ip rpf 192.0.2.1
      Routing entry for 192.0.2.0/24 using Unicast RIB

      Known via "kernel", distance 0, metric 0, best
      * 198.51.100.1, via eth0


   Indicates that a multicast source lookup for 192.0.2.1 would use an
   Unicast RIB entry for 192.0.2.0/24 with a gateway of 198.51.100.1.

.. index:: show ip rpf
.. clicmd:: show ip rpf

   Prints the entire Multicast RIB. Note that this is independent of the
   configured RPF lookup mode, the Multicast RIB may be printed yet not
   used at all.

.. index:: ip mroute PREFIX NEXTHOP [DISTANCE]
.. clicmd:: ip mroute PREFIX NEXTHOP [DISTANCE]

.. index:: no ip mroute PREFIX NEXTHOP [DISTANCE]
.. clicmd:: no ip mroute PREFIX NEXTHOP [DISTANCE]

   Adds a static route entry to the Multicast RIB. This performs exactly as the
   ``ip route`` command, except that it inserts the route in the Multicast RIB
   instead of the Unicast RIB.

.. _zebra-route-filtering:

zebra Route Filtering
=====================

Zebra supports :dfn:`prefix-list` s and :ref:`route-map` s to match routes
received from other FRR components. The permit/deny facilities provided by
these commands can be used to filter which routes zebra will install in the
kernel.

.. index:: ip protocol PROTOCOL route-map ROUTEMAP
.. clicmd:: ip protocol PROTOCOL route-map ROUTEMAP

   Apply a route-map filter to routes for the specified protocol. PROTOCOL can
   be: 

   - any,
   - babel,
   - bgp,
   - connected,
   - eigrp,
   - isis,
   - kernel,
   - nhrp,
   - openfabric,
   - ospf,
   - ospf6,
   - rip,
   - sharp,
   - static,
   - ripng,
   - table,
   - vnc.

   If you choose any as the option that will cause all protocols that are sending
   routes to zebra.  You can specify a :dfn:`ip protocol PROTOCOL route-map ROUTEMAP`
   on a per vrf basis, by entering this command under vrf mode for the vrf you
   want to apply the route-map against.

.. index:: set src ADDRESS
.. clicmd:: set src ADDRESS

   Within a route-map, set the preferred source address for matching routes
   when installing in the kernel.


The following creates a prefix-list that matches all addresses, a route-map
that sets the preferred source address, and applies the route-map to all
*rip* routes.

.. code-block:: frr

   ip prefix-list ANY permit 0.0.0.0/0 le 32
   route-map RM1 permit 10
        match ip address prefix-list ANY
        set src 10.0.0.1

   ip protocol rip route-map RM1


.. _zebra-fib-push-interface:

zebra FIB push interface
========================

Zebra supports a 'FIB push' interface that allows an external
component to learn the forwarding information computed by the FRR
routing suite. This is a loadable module that needs to be enabled
at startup as described in :ref:`loadable-module-support`.

In FRR, the Routing Information Base (RIB) resides inside
zebra. Routing protocols communicate their best routes to zebra, and
zebra computes the best route across protocols for each prefix. This
latter information makes up the Forwarding Information Base
(FIB). Zebra feeds the FIB to the kernel, which allows the IP stack in
the kernel to forward packets according to the routes computed by
FRR. The kernel FIB is updated in an OS-specific way. For example,
the `Netlink` interface is used on Linux, and route sockets are
used on FreeBSD.

The FIB push interface aims to provide a cross-platform mechanism to
support scenarios where the router has a forwarding path that is
distinct from the kernel, commonly a hardware-based fast path. In
these cases, the FIB needs to be maintained reliably in the fast path
as well. We refer to the component that programs the forwarding plane
(directly or indirectly) as the Forwarding Plane Manager or FPM.

The FIB push interface comprises of a TCP connection between zebra and
the FPM. The connection is initiated by zebra -- that is, the FPM acts
as the TCP server.

.. program:: configure

The relevant zebra code kicks in when zebra is configured with the
:option:`--enable-fpm` flag. Zebra periodically attempts to connect to
the well-known FPM port. Once the connection is up, zebra starts
sending messages containing routes over the socket to the FPM. Zebra
sends a complete copy of the forwarding table to the FPM, including
routes that it may have picked up from the kernel. The existing
interaction of zebra with the kernel remains unchanged -- that is, the
kernel continues to receive FIB updates as before.

The encapsulation header for the messages exchanged with the FPM is
defined by the file :file:`fpm/fpm.h` in the frr tree. The routes
themselves are encoded in Netlink or protobuf format, with Netlink
being the default.

Protobuf is one of a number of new serialization formats wherein the
message schema is expressed in a purpose-built language. Code for
encoding/decoding to/from the wire format is generated from the
schema. Protobuf messages can be extended easily while maintaining
backward-compatibility with older code. Protobuf has the following
advantages over Netlink:

- Code for serialization/deserialization is generated automatically. This
  reduces the likelihood of bugs, allows third-party programs to be integrated
  quickly, and makes it easy to add fields.
- The message format is not tied to an OS (Linux), and can be evolved
  independently.

As mentioned before, zebra encodes routes sent to the FPM in Netlink
format by default. The format can be controlled via the FPM module's
load-time option to zebra, which currently takes the values `Netlink`
and `protobuf`.

The zebra FPM interface uses replace semantics. That is, if a 'route
add' message for a prefix is followed by another 'route add' message,
the information in the second message is complete by itself, and
replaces the information sent in the first message.

If the connection to the FPM goes down for some reason, zebra sends
the FPM a complete copy of the forwarding table(s) when it reconnects.

.. _zebra-dplane:

Dataplane Commands
==================

The zebra dataplane subsystem provides a framework for FIB
programming. Zebra uses the dataplane to program the local kernel as
it makes changes to objects such as IP routes, MPLS LSPs, and
interface IP addresses. The dataplane runs in its own pthread, in
order to off-load work from the main zebra pthread.


.. index:: show zebra dplane [detailed]
.. clicmd:: show zebra dplane [detailed]

   Display statistics about the updates and events passing through the
   dataplane subsystem.


.. index:: show zebra dplane providers
.. clicmd:: show zebra dplane providers

   Display information about the running dataplane plugins that are
   providing updates to a FIB. By default, the local kernel plugin is
   present.


.. index:: zebra dplane limit [NUMBER]
.. clicmd:: zebra dplane limit [NUMBER]

   Configure the limit on the number of pending updates that are
   waiting to be processed by the dataplane pthread.


zebra Terminal Mode Commands
============================

.. index:: show ip route
.. clicmd:: show ip route

   Display current routes which zebra holds in its database.

::

    Router# show ip route
    Codes: K - kernel route, C - connected, S - static, R - RIP,
     B - BGP * - FIB route.

    K* 0.0.0.0/0        203.181.89.241
    S  0.0.0.0/0        203.181.89.1
    C* 127.0.0.0/8      lo
    C* 203.181.89.240/28      eth0


.. index:: show ipv6 route
.. clicmd:: show ipv6 route

.. index:: show [ip|ipv6] route [PREFIX] [nexthop-group]
.. clicmd:: show [ip|ipv6] route [PREFIX] [nexthop-group]

   Display detailed information about a route. If [nexthop-group] is
   included, it will display the nexthop group ID the route is using as well.

.. index:: show interface [NAME] [{vrf VRF|brief}] [nexthop-group]
.. clicmd:: show interface [NAME] [{vrf VRF|brief}] [nexthop-group]

.. index:: show interface [NAME] [{vrf all|brief}] [nexthop-group]
.. clicmd:: show interface [NAME] [{vrf all|brief}] [nexthop-group]

   Display interface information. If no extra information is added, it will
   dump information on all interfaces. If [NAME] is specified, it will display
   detailed information about that single interface. If [nexthop-group] is
   specified, it will display nexthop groups pointing out that interface.

.. index:: show ip prefix-list [NAME]
.. clicmd:: show ip prefix-list [NAME]

.. index:: show route-map [NAME]
.. clicmd:: show route-map [NAME]

.. index:: show ip protocol
.. clicmd:: show ip protocol

.. index:: show ipforward
.. clicmd:: show ipforward

   Display whether the host's IP forwarding function is enabled or not.
   Almost any UNIX kernel can be configured with IP forwarding disabled.
   If so, the box can't work as a router.

.. index:: show ipv6forward
.. clicmd:: show ipv6forward

   Display whether the host's IP v6 forwarding is enabled or not.

.. index:: show zebra
.. clicmd:: show zebra

   Display various statistics related to the installation and deletion
   of routes, neighbor updates, and LSP's into the kernel.

.. index:: show zebra client [summary]
.. clicmd:: show zebra client [summary]

   Display statistics about clients that are connected to zebra.  This is
   useful for debugging and seeing how much data is being passed between
   zebra and it's clients.  If the summary form of the command is choosen
   a table is displayed with shortened information.

.. index:: show zebra router table summary
.. clicmd:: show zebra router table summary

   Display summarized data about tables created, their afi/safi/tableid
   and how many routes each table contains.  Please note this is the
   total number of route nodes in the table.  Which will be higher than
   the actual number of routes that are held.

.. index:: show zebra fpm stats
.. clicmd:: show zebra fpm stats

   Display statistics related to the zebra code that interacts with the
   optional Forwarding Plane Manager (FPM) component.

.. index:: clear zebra fpm stats
.. clicmd:: clear zebra fpm stats

   Reset statistics related to the zebra code that interacts with the
   optional Forwarding Plane Manager (FPM) component.

.. index:: show nexthop-group [ID] [vrf NAME] [ip|ipv6]
.. clicmd:: show nexthop-group [ID] [vrf NAME] [ip|ipv6]

   Display nexthop groups created by zebra.

