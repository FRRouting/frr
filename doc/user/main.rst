.. _Zebra:

*****
Zebra
*****

*zebra* is an IP routing manager.  It provides kernel routing
table updates, interface lookups, and redistribution of routes between
different routing protocols.

.. _Invoking_zebra:

Invoking zebra
==============

Besides the common invocation options (:ref:`Common_Invocation_Options`), the
*zebra* specific invocation options are listed below.



*-b*

*--batch*
  Runs in batch mode.  *zebra* parses configuration file and terminates
  immediately.


*-k*

*--keep_kernel*
  When zebra starts up, don't delete old self inserted routes.


*-r*

*--retain*
  When program terminates, retain routes added by zebra.


.. _Interface_Commands:

Interface Commands
==================


.. _Standard_Commands:

Standard Commands
-----------------

.. index:: Command {interface `ifname`} {}

Command {interface `ifname`} {}

.. index:: {Interface Command} {shutdown} {}

{Interface Command} {shutdown} {}
.. index:: {Interface Command} {no shutdown} {}

{Interface Command} {no shutdown} {}
    Up or down the current interface.

.. index:: {Interface Command} {ip address `address/prefix`} {}

{Interface Command} {ip address `address/prefix`} {}
.. index:: {Interface Command} {ipv6 address `address/prefix`} {}

{Interface Command} {ipv6 address `address/prefix`} {}
.. index:: {Interface Command} {no ip address `address/prefix`} {}

{Interface Command} {no ip address `address/prefix`} {}
.. index:: {Interface Command} {no ipv6 address `address/prefix`} {}

{Interface Command} {no ipv6 address `address/prefix`} {}
          Set the IPv4 or IPv6 address/prefix for the interface.

.. index:: {Interface Command} {ip address `local-addr` peer `peer-addr/prefix`} {}

{Interface Command} {ip address `local-addr` peer `peer-addr/prefix`} {}
.. index:: {Interface Command} {no ip address `local-addr` peer `peer-addr/prefix`} {}

{Interface Command} {no ip address `local-addr` peer `peer-addr/prefix`} {}
            Configure an IPv4 Pointopoint address on the interface.
            (The concept of PtP addressing does not exist for IPv6.)

            `local-addr` has no subnet mask since the local side in PtP
            addressing is always a single (/32) address.  `peer-addr/prefix`
            can be an arbitrary subnet behind the other end of the link (or even on the
            link in Point-to-Multipoint setups), though generally /32s are used.

.. index:: {Interface Command} {ip address `address/prefix` secondary} {}

{Interface Command} {ip address `address/prefix` secondary} {}
.. index:: {Interface Command} {no ip address `address/prefix` secondary} {}

{Interface Command} {no ip address `address/prefix` secondary} {}
              Set the secondary flag for this address. This causes ospfd to not treat the
              address as a distinct subnet.

.. index:: {Interface Command} {description `description` ...} {}

{Interface Command} {description `description` ...} {}
              Set description for the interface.

.. index:: {Interface Command} {multicast} {}

{Interface Command} {multicast} {}
.. index:: {Interface Command} {no multicast} {}

{Interface Command} {no multicast} {}
                Enable or disables multicast flag for the interface.

.. index:: {Interface Command} {bandwidth <1-10000000>} {}

{Interface Command} {bandwidth <1-10000000>} {}
.. index:: {Interface Command} {no bandwidth <1-10000000>} {}

{Interface Command} {no bandwidth <1-10000000>} {}
                  Set bandwidth value of the interface in kilobits/sec.  This is for
                  calculating OSPF cost. This command does not affect the actual device
                  configuration.

.. index:: {Interface Command} {link-detect} {}

{Interface Command} {link-detect} {}
.. index:: {Interface Command} {no link-detect} {}

{Interface Command} {no link-detect} {}
                    Enable/disable link-detect on platforms which support this. Currently
                    only Linux and Solaris, and only where network interface drivers support reporting
                    link-state via the IFF_RUNNING flag.

.. _Link_Parameters_Commands:

Link Parameters Commands
------------------------

.. index:: {Interface Command} {link-params} {}

{Interface Command} {link-params} {}
.. index:: {Interface Command} {no link-param} {}

{Interface Command} {no link-param} {}
    Enter into the link parameters sub node. At least 'enable' must be set to activate the link parameters,
    and consequently Traffic Engineering on this interface. MPLS-TE must be enable at the OSPF (:ref:`OSPF_Traffic_Engineering`)
    or ISIS (:ref:`ISIS_Traffic_Engineering`) router level in complement to this.
    Disable link parameters for this interface.

  Under link parameter statement, the following commands set the different TE values:

.. index:: link-params {enable}

link-params {enable}
    Enable link parameters for this interface.

.. index:: link-params {metric <0-4294967295>} {}

link-params {metric <0-4294967295>} {}
.. index:: link-params {max-bw `bandwidth`} {}

link-params {max-bw `bandwidth`} {}
.. index:: link-params {max-rsv-bw `bandwidth`} {}

link-params {max-rsv-bw `bandwidth`} {}
.. index:: link-params {unrsv-bw <0-7> `bandwidth`} {}

link-params {unrsv-bw <0-7> `bandwidth`} {}
.. index:: link-params {admin-grp `bandwidth`} {}

link-params {admin-grp `bandwidth`} {}
            These commands specifies the Traffic Engineering parameters of the interface in conformity to RFC3630 (OSPF)
            or RFC5305 (ISIS).
            There are respectively the TE Metric (different from the OSPF or ISIS metric), Maximum Bandwidth (interface speed
            by default), Maximum Reservable Bandwidth, Unreserved Bandwidth for each 0-7 priority and Admin Group (ISIS) or
            Resource Class/Color (OSPF).

            Note that `bandwidth` are specified in IEEE floating point format and express in Bytes/second.

.. index::  link-param {delay <0-16777215> [min <0-16777215> | max <0-16777215>]} {}

link-param {delay <0-16777215> [min <0-16777215> | max <0-16777215>]} {}
.. index::  link-param {delay-variation <0-16777215>} {}

link-param {delay-variation <0-16777215>} {}
.. index::  link-param {packet-loss `percentage`} {}

link-param {packet-loss `percentage`} {}
.. index::  link-param {res-bw `bandwidth`} {}

link-param {res-bw `bandwidth`} {}
.. index::  link-param {ava-bw `bandwidth`} {}

link-param {ava-bw `bandwidth`} {}
.. index::  link-param {use-bw `bandwidth`} {}

link-param {use-bw `bandwidth`} {}
                      These command specifies additionnal Traffic Engineering parameters of the interface in conformity to
                      draft-ietf-ospf-te-metrics-extension-05.txt and draft-ietf-isis-te-metrics-extension-03.txt. There are
                      respectively the delay, jitter, loss, available bandwidth, reservable bandwidth and utilized bandwidth.

                      Note that `bandwidth` are specified in IEEE floating point format and express in Bytes/second.
                      Delays and delay variation are express in micro-second (µs). Loss is specified in `percentage` ranging
                      from 0 to 50.331642% by step of 0.000003.

.. index:: link-param {neighbor <A.B.C.D> as <0-65535>} {}

link-param {neighbor <A.B.C.D> as <0-65535>} {}
.. index:: link-param {no neighbor} {}

link-param {no neighbor} {}
                        Specifies the remote ASBR IP address and Autonomous System (AS) number for InterASv2 link in OSPF (RFC5392).
                        Note that this option is not yet supported for ISIS (RFC5316).

.. _Static_Route_Commands:

Static Route Commands
=====================

Static routing is a very fundamental feature of routing technology.  It
defines static prefix and gateway.

.. index:: Command {ip route `network` `gateway`} {}

Command {ip route `network` `gateway`} {}
  `network` is destination prefix with format of A.B.C.D/M.
  `gateway` is gateway for the prefix.  When `gateway` is
  A.B.C.D format.  It is taken as a IPv4 address gateway.  Otherwise it
  is treated as an interface name. If the interface name is `null0` then
  zebra installs a blackhole route.

::

    ip route 10.0.0.0/8 10.0.0.2
    ip route 10.0.0.0/8 ppp0
    ip route 10.0.0.0/8 null0
    

  First example defines 10.0.0.0/8 static route with gateway 10.0.0.2.
  Second one defines the same prefix but with gateway to interface ppp0. The
  third install a blackhole route.

.. index:: Command {ip route `network` `netmask` `gateway`} {}

Command {ip route `network` `netmask` `gateway`} {}
  This is alternate version of above command.  When `network` is
  A.B.C.D format, user must define `netmask` value with A.B.C.D
  format.  `gateway` is same option as above command

::

    ip route 10.0.0.0 255.255.255.0 10.0.0.2
    ip route 10.0.0.0 255.255.255.0 ppp0
    ip route 10.0.0.0 255.255.255.0 null0
    

  These statements are equivalent to those in the previous example.

.. index:: Command {ip route `network` `gateway` `distance`} {}

Command {ip route `network` `gateway` `distance`} {}
  Installs the route with the specified distance.

Multiple nexthop static route

::

  ip route 10.0.0.1/32 10.0.0.2
  ip route 10.0.0.1/32 10.0.0.3
  ip route 10.0.0.1/32 eth0
  

If there is no route to 10.0.0.2 and 10.0.0.3, and interface eth0
is reachable, then the last route is installed into the kernel.

If zebra has been compiled with multipath support, and both 10.0.0.2 and
10.0.0.3 are reachable, zebra will install a multipath route via both
nexthops, if the platform supports this.

::

  zebra> show ip route
  S>  10.0.0.1/32 [1/0] via 10.0.0.2 inactive
                        via 10.0.0.3 inactive
    *                   is directly connected, eth0
  

::

  ip route 10.0.0.0/8 10.0.0.2
  ip route 10.0.0.0/8 10.0.0.3
  ip route 10.0.0.0/8 null0 255
  

This will install a multihop route via the specified next-hops if they are
reachable, as well as a high-metric blackhole route, which can be useful to
prevent traffic destined for a prefix to match less-specific routes (eg
default) should the specified gateways not be reachable. Eg:

::

  zebra> show ip route 10.0.0.0/8
  Routing entry for 10.0.0.0/8
    Known via "static", distance 1, metric 0
      10.0.0.2 inactive
      10.0.0.3 inactive

  Routing entry for 10.0.0.0/8
    Known via "static", distance 255, metric 0
      directly connected, Null0
  

.. index:: Command {ipv6 route `network` `gateway`} {}

Command {ipv6 route `network` `gateway`} {}
.. index:: Command {ipv6 route `network` `gateway` `distance`} {}

Command {ipv6 route `network` `gateway` `distance`} {}
    These behave similarly to their ipv4 counterparts.

.. index:: Command {ipv6 route `network` from `srcprefix` `gateway`} {}

Command {ipv6 route `network` from `srcprefix` `gateway`} {}
.. index:: Command {ipv6 route `network` from `srcprefix` `gateway` `distance`} {}

Command {ipv6 route `network` from `srcprefix` `gateway` `distance`} {}
      Install a static source-specific route.  These routes are currently supported
      on Linux operating systems only, and perform AND matching on packet's
      destination and source addresses in the kernel's forwarding path.  Note that
      destination longest-prefix match is "more important" than source LPM, e.g.
      *"2001:db8:1::/64 from 2001:db8::/48"* will win over
      *"2001:db8::/48 from 2001:db8:1::/64"* if both match.

.. index:: Command {table `tableno`} {}

Command {table `tableno`} {}
      Select the primary kernel routing table to be used.  This only works
      for kernels supporting multiple routing tables (like GNU/Linux 2.2.x
      and later).  After setting `tableno` with this command,
      static routes defined after this are added to the specified table.

.. _Multicast_RIB_Commands:

Multicast RIB Commands
======================

The Multicast RIB provides a separate table of unicast destinations which
is used for Multicast Reverse Path Forwarding decisions.  It is used with
a multicast source's IP address, hence contains not multicast group
addresses but unicast addresses.

This table is fully separate from the default unicast table.  However,
RPF lookup can include the unicast table.

WARNING: RPF lookup results are non-responsive in this version of FRR,
i.e. multicast routing does not actively react to changes in underlying
unicast topology!

.. index:: Command {ip multicast rpf-lookup-mode `mode`} {}

Command {ip multicast rpf-lookup-mode `mode`} {}
.. index:: Command {no ip multicast rpf-lookup-mode [`mode`]} {}

Command {no ip multicast rpf-lookup-mode [`mode`]} {}
    `mode` sets the method used to perform RPF lookups.  Supported modes:



*urib-only*
      Performs the lookup on the Unicast RIB.  The Multicast RIB is never used.

*mrib-only*
      Performs the lookup on the Multicast RIB.  The Unicast RIB is never used.

*mrib-then-urib*
      Tries to perform the lookup on the Multicast RIB.  If any route is found,
      that route is used.  Otherwise, the Unicast RIB is tried.

*lower-distance*
      Performs a lookup on the Multicast RIB and Unicast RIB each.  The result
      with the lower administrative distance is used;  if they're equal, the
      Multicast RIB takes precedence.

*longer-prefix*
      Performs a lookup on the Multicast RIB and Unicast RIB each.  The result
      with the longer prefix length is used;  if they're equal, the
      Multicast RIB takes precedence.

    The `mrib-then-urib` setting is the default behavior if nothing is
    configured.  If this is the desired behavior, it should be explicitly
    configured to make the configuration immune against possible changes in
    what the default behavior is.

    WARNING: Unreachable routes do not receive special treatment and do not
    cause fallback to a second lookup.

.. index:: Command {show ip rpf `addr`} {}

Command {show ip rpf `addr`} {}
    Performs a Multicast RPF lookup, as configured with
    *ip multicast rpf-lookup-mode `mode*`.  `addr` specifies
    the multicast source address to look up.

::

      > show ip rpf 192.0.2.1
      Routing entry for 192.0.2.0/24 using Unicast RIB
        Known via "kernel", distance 0, metric 0, best
        * 198.51.100.1, via eth0
      

    Indicates that a multicast source lookup for 192.0.2.1 would use an
    Unicast RIB entry for 192.0.2.0/24 with a gateway of 198.51.100.1.

.. index:: Command {show ip rpf} {}

Command {show ip rpf} {}
    Prints the entire Multicast RIB.  Note that this is independent of the
    configured RPF lookup mode, the Multicast RIB may be printed yet not
    used at all.

.. index:: Command {ip mroute `prefix` `nexthop` [`distance`]} {}

Command {ip mroute `prefix` `nexthop` [`distance`]} {}
.. index:: Command {no ip mroute `prefix` `nexthop` [`distance`]} {}

Command {no ip mroute `prefix` `nexthop` [`distance`]} {}
      Adds a static route entry to the Multicast RIB.  This performs exactly as
      the *ip route* command, except that it inserts the route in the
      Multicast RIB instead of the Unicast RIB.

.. _zebra_Route_Filtering:

zebra Route Filtering
=====================

Zebra supports *prefix-list* and *route-map* to match
routes received from other frr components.  The
*permit*/*deny* facilities provided by these commands
can be used to filter which routes zebra will install in the kernel.

.. index:: Command {ip protocol `protocol` route-map `routemap`} {}

Command {ip protocol `protocol` route-map `routemap`} {}
  Apply a route-map filter to routes for the specified protocol. `protocol`
  can be **any** or one of
  **system**,
  **kernel**,
  **connected**,
  **static**,
  **rip**,
  **ripng**,
  **ospf**,
  **ospf6**,
  **isis**,
  **bgp**,
  **hsls**.

.. index:: {Route Map} {set src `address`}

{Route Map} {set src `address`}
  Within a route-map, set the preferred source address for matching routes
  when installing in the kernel.

::

  The following creates a prefix-list that matches all addresses, a route-map
  that sets the preferred source address, and applies the route-map to all
  *rip* routes.

  @group
  ip prefix-list ANY permit 0.0.0.0/0 le 32
  route-map RM1 permit 10
       match ip address prefix-list ANY
       set src 10.0.0.1

  ip protocol rip route-map RM1
  @end group
  

.. _zebra_FIB_push_interface:

zebra FIB push interface
========================

Zebra supports a 'FIB push' interface that allows an external
component to learn the forwarding information computed by the FRR
routing suite.  This is a loadable module that needs to be enabled
at startup as described in :ref:`Loadable_Module_Support`.

In FRR, the Routing Information Base (RIB) resides inside
zebra. Routing protocols communicate their best routes to zebra, and
zebra computes the best route across protocols for each prefix. This
latter information makes up the Forwarding Information Base
(FIB). Zebra feeds the FIB to the kernel, which allows the IP stack in
the kernel to forward packets according to the routes computed by
FRR. The kernel FIB is updated in an OS-specific way. For example,
the `netlink` interface is used on Linux, and route sockets are
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

The relevant zebra code kicks in when zebra is configured with the
`--enable-fpm` flag. Zebra periodically attempts to connect to
the well-known FPM port. Once the connection is up, zebra starts
sending messages containing routes over the socket to the FPM. Zebra
sends a complete copy of the forwarding table to the FPM, including
routes that it may have picked up from the kernel. The existing
interaction of zebra with the kernel remains unchanged -- that is, the
kernel continues to receive FIB updates as before.

The encapsulation header for the messages exchanged with the FPM is
defined by the file :file:`fpm/fpm.h` in the frr tree. The routes
themselves are encoded in netlink or protobuf format, with netlink
being the default.

Protobuf is one of a number of new serialization formats wherein the
message schema is expressed in a purpose-built language. Code for
encoding/decoding to/from the wire format is generated from the
schema. Protobuf messages can be extended easily while maintaining
backward-compatibility with older code. Protobuf has the following
advantages over netlink:

* 
  Code for serialization/deserialization is generated
  automatically. This reduces the likelihood of bugs, allows third-party
  programs to be integrated quickly, and makes it easy to add fields.
* 
  The message format is not tied to an OS (Linux), and can be evolved
  independently.

As mentioned before, zebra encodes routes sent to the FPM in netlink
format by default. The format can be controlled via the FPM module's
load-time option to zebra, which currently takes the values `netlink`
and `protobuf`.

The zebra FPM interface uses replace semantics. That is, if a 'route
add' message for a prefix is followed by another 'route add' message,
the information in the second message is complete by itself, and
replaces the information sent in the first message.

If the connection to the FPM goes down for some reason, zebra sends
the FPM a complete copy of the forwarding table(s) when it reconnects.

zebra Terminal Mode Commands
============================

.. index:: Command {show ip route} {}

Command {show ip route} {}
  Display current routes which zebra holds in its database.

::

    @group
    Router# show ip route
    Codes: K - kernel route, C - connected, S - static, R - RIP,
           B - BGP * - FIB route.

    K* 0.0.0.0/0              203.181.89.241
    S  0.0.0.0/0              203.181.89.1
    C* 127.0.0.0/8            lo
    C* 203.181.89.240/28      eth0
    @end group
    

.. index:: Command {show ipv6 route} {}

Command {show ipv6 route} {}
.. index:: Command {show interface} {}

Command {show interface} {}
.. index:: Command {show ip prefix-list [`name`]} {}

Command {show ip prefix-list [`name`]} {}
.. index:: Command {show route-map [`name`]} {}

Command {show route-map [`name`]} {}
.. index:: Command {show ip protocol} {}

Command {show ip protocol} {}
.. index:: Command {show ipforward} {}

Command {show ipforward} {}
  Display whether the host's IP forwarding function is enabled or not.
  Almost any UNIX kernel can be configured with IP forwarding disabled.
  If so, the box can't work as a router.

.. index:: Command {show ipv6forward} {}

Command {show ipv6forward} {}
  Display whether the host's IP v6 forwarding is enabled or not.

.. index:: Command {show zebra} {}

Command {show zebra} {}
  Display various statistics related to the installation and deletion
  of routes, neighbor updates, and LSP's into the kernel.

.. index:: Command {show zebra fpm stats} {}

Command {show zebra fpm stats} {}
  Display statistics related to the zebra code that interacts with the
  optional Forwarding Plane Manager (FPM) component.

.. index:: Command {clear zebra fpm stats} {}

Command {clear zebra fpm stats} {}
  Reset statistics related to the zebra code that interacts with the
  optional Forwarding Plane Manager (FPM) component.

