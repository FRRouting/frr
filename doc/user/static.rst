.. _static:

******
STATIC
******

:abbr:`STATIC` is a daemon that handles the installation and deletion
of static routes.

.. _starting-static:

Starting STATIC
===============

.. program:: staticd

:abbr:`STATIC` supports all the common FRR daemon start options which are
documented elsewhere.

.. include:: config-include.rst

.. _static-route-commands:

Static Route Commands
=====================

Static routing is a very fundamental feature of routing technology. It defines
a static prefix and gateway, with several possible forms.

.. clicmd:: ip route NETWORK GATEWAY [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK IFNAME [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK GATEWAY IFNAME [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [onlink] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK (Null0|blackhole|reject) [tag TAG] [DISTANCE] [metric METRIC] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] GATEWAY [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] IFNAME [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] GATEWAY IFNAME [tag TAG] [DISTANCE] [metric METRIC] [weight WEIGHT] [onlink] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] (Null0|blackhole|reject) [tag TAG] [DISTANCE] [metric METRIC] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

   NETWORK is destination prefix with a valid v4 or v6 network based upon
   initial form of the command.
   
   GATEWAY is the IP address to use as next-hop for the prefix. Routes of type v4 can use v4 and v6 next-hops,
   v6 routes only support v6 next-hops.

   IFNAME is the name of the interface to use as next-hop. If only IFNAME is specified
   (without GATEWAY), a connected route will be created. Note that
   some of the other keywords are not valid interface names: ``vrf``,
   ``table``, ``label``, ``tag``, ``color``, ``segments``, and ``nexthop-vrf``.

   When both IFNAME and GATEWAY are specified together, it binds the route to the specified
   interface. In this case, it is also possible to specify ``onlink`` to force the kernel
   to consider the next-hop as "on link" on the given interface.

   Alternatively, the gateway can be specified as ``Null0`` or ``blackhole`` to create a blackhole
   route that drops all traffic. It can also be specified as ``reject`` to create an unreachable
   route that rejects traffic with ICMP "Destination Unreachable" messages.

   TAG is an optional 32-bit unsigned integer (1–4294967295) that marks the
   route entry in the RIB. See :ref:`static-route-tag` for details and
   limitations.

   DISTANCE is an optional administrative distance (1–255; default 1). See
   :ref:`static-route-distance-metric` for details.

   METRIC is an optional route metric (0–4294967295; default 0). See
   :ref:`static-route-distance-metric` for details.

   WEIGHT is an optional parameter that specifies the weight attributed to a
   nexthop when multiple nexthops are configured for the same static route. The
   value must be between 1 and 65535. The Linux kernel only supports 8-bit
   weights for multipath static routes, but Zebra creates and uses
   nexthop-groups for this, for which the kernel supports 16-bit weights since
   version 6.12.

   TABLENO is an optional parameter for namespaces that allows you to create the
   route in a specified table associated with the vrf namespace. ``table`` will
   be rejected if you are not using namespace based vrfs.
   
   ``vrf`` VRFNAME allows you to create the route in a specified vrf.

   ``nexthop-vrf`` VRFNAME allows you to create a leaked route with a nexthop in the
   specified VRFNAME. ``nexthop-vrf`` cannot be currently used with namespace based vrfs.
   
   The IPv6 variant allows the installation of a static source-specific route
   with the SRCPREFIX sub command.  These routes are currently supported
   on Linux operating systems only, and perform AND matching on packet's
   destination and source addresses in the kernel's forwarding path. Note
   that destination longest-prefix match is "more important" than source
   LPM, e.g.  ``2001:db8:1::/64 from 2001:db8::/48`` will win over
   ``2001:db8::/48 from 2001:db8:1::/64`` if both match.

.. _multiple-route-command:

Multiple nexthop static route
=============================

To create multiple nexthops to the same NETWORK (also known as a multipath route), just reenter the same
network statement with different nexthop information.

.. code-block:: frr

   ip route 10.0.0.1/32 10.0.0.2
   ip route 10.0.0.1/32 10.0.0.3
   ip route 10.0.0.1/32 eth0


If there is no route to 10.0.0.2 and 10.0.0.3, and interface eth0
is reachable, then the last route is installed into the kernel.

If zebra has been compiled with multipath support, and both 10.0.0.2 and
10.0.0.3 are reachable, zebra will install a multipath route via both
nexthops, if the platform supports this.

::

   router> show ip route
   S>  10.0.0.1/32 [1/0] via 10.0.0.2 inactive
       via 10.0.0.3 inactive
     *       is directly connected, eth0


.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2
   ip route 10.0.0.0/8 10.0.0.3
   ip route 10.0.0.0/8 null0 255


This will install a multipath route via the specified next-hops if they are
reachable, as well as a high-distance blackhole route, which can be useful to
prevent traffic destined for a prefix to match less-specific routes (e.g.
default) should the specified gateways not be reachable. E.g.:

::

   router> show ip route 10.0.0.0/8
   Routing entry for 10.0.0.0/8
     Known via "static", distance 1, metric 0
       10.0.0.2 inactive
       10.0.0.3 inactive

   Routing entry for 10.0.0.0/8
     Known via "static", distance 255, metric 0
       directly connected, Null0


A weight can be associated with each nexthop to influence traffic distribution
across the paths. In this example, both nexthops are installed as a multipath
route, with traffic distributed proportionally according to the configured
weights:

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2 weight 10
   ip route 10.0.0.0/8 10.0.0.3 weight 100


Also, if the user wants to configure a static route for a specific VRF, then
a specific VRF configuration mode is available. After entering into that mode
with :clicmd:`vrf VRF` the user can enter the same route command as before,
but this time, the route command will apply to the VRF.

.. code-block:: frr

   # case with VRF
   configure
   vrf r1-cust1
    ip route 10.0.0.0/24 10.0.0.2
   exit-vrf


.. _static-route-distance-metric:

Administrative Distance and Metric
===================================

Static routes are grouped internally by ``(table-id, distance, metric)``.
Nexthops that share the same tuple belong to the same *path group* and are
installed in the RIB together as an ECMP set.  Nexthops in different path
groups for the same prefix are independent: all path groups are present in
the RIB, but only the group with the lowest distance (and, for the same
distance, the lowest metric) is selected at any time.

**ECMP** — Multiple nexthops with the same ``(distance, metric)`` form an
equal-cost multipath group and are active in the RIB together:

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2
   ip route 10.0.0.0/8 10.0.0.3

Both nexthops share ``(distance=1, metric=0)`` and are active in the RIB as ECMP.

**Floating static routes** — Nexthops with different ``(distance, metric)`` tuples
form separate path groups.  All groups are present in the RIB; the group with
the best preference (lowest distance, then lowest metric) is selected.  A
lower-preference group is promoted when the higher-preference group becomes
unreachable.

Floating by distance:

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2
   ip route 10.0.0.0/8 10.0.0.3 200

``10.0.0.2`` is the primary (distance 1); ``10.0.0.3`` is the fallback
(distance 200), promoted only when ``10.0.0.2`` is gone.

Floating by metric (same distance, different metric):

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2 metric 100
   ip route 10.0.0.0/8 10.0.0.3 metric 200

``10.0.0.2`` is the primary (metric 100); ``10.0.0.3`` is the fallback
(metric 200), promoted only when ``10.0.0.2`` is gone.

**Nexthop uniqueness and automatic move** — A given nexthop (identified by
its forwarding information: type, gateway address, and interface) may appear
in at most one path group under a prefix at a time.  If a nexthop is
reconfigured with a new distance or metric, FRR automatically removes it from
the old path group and installs it in the new one:

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2 10
   ! Reconfigure with a new distance — old entry is removed automatically:
   ip route 10.0.0.0/8 10.0.0.2 20

After the second command there is exactly one path group for ``10.0.0.2`` at
distance 20; no stale distance-10 entry remains.  The same applies when
metric is changed.

**Removing routes** — When neither distance nor metric is specified, FRR
searches all path groups for a matching nexthop and removes whichever it finds:

.. code-block:: frr

   no ip route 10.0.0.0/8 10.0.0.2

When distance or metric is specified, only the exact ``(distance, metric)``
path group is targeted, with unspecified parameters defaulting to their default
values (distance 1, metric 0).  For example, if
``10.0.0.2`` was configured at ``(distance=10, metric=50)``, then:

.. code-block:: frr

   no ip route 10.0.0.0/8 10.0.0.2 10

targets ``(distance=10, metric=0)`` and does **not** remove the ``metric=50``
entry.  To remove it, the metric must be specified explicitly:

.. code-block:: frr

   no ip route 10.0.0.0/8 10.0.0.2 10 metric 50


.. _static-route-tag:

Route Tag
=========

TAG is a 32-bit unsigned integer (1–4294967295) that marks a route entry in
the RIB.  It can be matched by routing policy (route-maps, prefix-lists) to
filter or modify routes based on their tag value.

The tag is a per-path-group attribute: it is shared by all nexthops in a path
group and carried into the RIB.  Unlike distance and metric, tag is **not**
part of the path group identity — two nexthops with the same ``(distance,
metric)`` always belong to the same path group regardless of their configured
tags.

**Per-path-group tag** — Assigning a distinct tag to each path group lets
routing policy distinguish primary from backup routes:

.. code-block:: frr

   ip route 10.0.0.0/8 10.0.0.2 tag 100 10
   ip route 10.0.0.0/8 10.0.0.3 tag 200 20

``10.0.0.2`` (distance 10) carries tag 100 and ``10.0.0.3`` (distance 20)
carries tag 200.  Both tags are visible in the RIB simultaneously.

.. note::

   **Limitation — same (distance, metric), different tag:** because tag is
   not part of the path group key, two nexthops with the same ``(distance,
   metric)`` belong to the same path group regardless of their tags.  When
   different tags are configured for nexthops in the same path group, the
   last-configured value applies to the entire group and the earlier value is
   silently overwritten:

   .. code-block:: frr

      ip route 10.0.0.0/8 10.0.0.2 tag 100 10
      ip route 10.0.0.0/8 10.0.0.3 tag 200 10

   Both nexthops are grouped at distance 10 and the path tag becomes 200
   (the last value configured).  ``show running-config`` reflects only the
   final value.  To assign independent tags to nexthops, use different
   distances or metrics.


SR-TE Route Commands
====================

It is possible to specify a route using a SR-TE policy configured in Zebra.

e.g. to use the SR-TE policy with endpoint 6.6.6.6 and color 123 to reach the
network 9.9.9.9/24:

.. code-block:: frr

  ip route 9.9.9.9/24 6.6.6.6 color 123

SRv6 Route Commands
====================

It is possible to specify a static route for ipv6 prefixes using an SRv6
`segments` instruction. The `/` separator can be used to specify
multiple segments instructions.

.. code-block:: frr

  ipv6 route X:X::X:X <X:X::X:X|nexthop> segments U:U::U:U/Y:Y::Y:Y/Z:Z::Z:Z


::

  router(config)# ipv6 route 2005::1/64 ens3 segments 2001:db8:aaaa::7/2002::4/2002::3/2002::2

  router# show ipv6 route
  [..]
  S>* 2005::/64 [1/0] is directly connected, ens3, seg6 2001:db8:aaaa::7,2002::4,2002::3,2002::2, weight 1, 00:00:06

STATIC also supports steering of IPv4 traffic over an SRv6 SID list, as shown in the example below.

.. code-block:: frr

  ip route A.B.C.D <A.B.C.D|nexthop> segments U:U::U:U/Y:Y::Y:Y/Z:Z::Z:Z

::

  router(config)# ip route 10.0.0.0/24 sr0 segments fcbb:bbbb:1:2:3:fe00::

  router# show ip route
  [..]
  S>* 10.0.0.0/24 [1/0] is directly connected, sr0, seg6 fcbb:bbbb:1:2:3:fe00::, weight 1, 00:00:06

  Optionally, the user can specify the SRv6 Headend Behavior to be used for encapsulation. Currently, STATIC supports the following behaviors:

  * H.Encaps
  * H.Encaps.Red

  When the behavior is not specified, STATIC defaults to using H.Encaps.

.. clicmd:: ipv6 route X:X::X:X <X:X::X:X|nexthop> segments U:U::U:U/Y:Y::Y:Y/Z:Z::Z:Z [encap-behavior BEHAVIOR]
.. clicmd:: ip route A.B.C.D <A.B.C.D|nexthop> segments U:U::U:U/Y:Y::Y:Y/Z:Z::Z:Z [encap-behavior BEHAVIOR]

::

  router(config)# ipv6 route 2001:db8:1:1::1/128 sr0 segments fcbb:bbbb:1:2:3:fe00:: encap-behavior H.Encaps
  router(config)# ipv6 route 2001:db8:1:1::2/128 sr0 segments fcbb:bbbb:1:2:3:fe00:: encap-behavior H.Encaps.Red

  router# show ipv6 route
  [..]
  S>* 2001:db8:1:1::1/128 [1/0] is directly connected, ens3, seg6 fcbb:bbbb:1:2:3:fe00:: encap behavior H.Encaps, weight 1, 00:00:06
  S>* 2001:db8:1:1::2/128 [1/0] is directly connected, ens3, seg6 fcbb:bbbb:1:2:3:fe00:: encap behavior H.Encaps.Red, weight 1, 00:00:06

  router(config)# ip route 10.0.0.1/32 sr0 segments fcbb:bbbb:1:2:3:fe00:: encap-behavior H.Encaps
  router(config)# ip route 10.0.0.2/32 sr0 segments fcbb:bbbb:1:2:3:fe00:: encap-behavior H.Encaps.Red

  router# show ip route
  [..]
  S>* 10.0.0.1/32 [1/0] is directly connected, sr0, seg6 fcbb:bbbb:1:2:3:fe00:: encap behavior H.Encaps, weight 1, 00:00:06
  S>* 10.0.0.2/32 [1/0] is directly connected, sr0, seg6 fcbb:bbbb:1:2:3:fe00:: encap behavior H.Encaps.Red, weight 1, 00:00:06

SRv6 Static SIDs Commands
=========================

.. clicmd:: segment-routing
   :daemon: staticd

   Move from configure mode to segment-routing node.

.. clicmd:: srv6

   Move from segment-routing node to srv6 node.

.. clicmd:: static-sids

   Move from srv6 node to static-sids node. In this static-sids node, user can
   configure static SRv6 SIDs.

.. clicmd:: sid X:X::X:X/M locator NAME behavior <uN|uA|uDT4|uDT6|uDT46> [vrf VRF] [interface IFNAME [nexthop X:X::X:X]]

   Specify the locator sid manually. Configuring a local sid in a purely static mode
   by specifying the sid value would generate a unique SID.
   This feature will support the configuration of static SRv6 decapsulation on the system.

   It supports the following behaviors: uN, uA, uDT4, uDT6, uDT46.

   When configuring the local sid, if the action is set to 'uN', no vrf should be set.
   For uDT4, uDT6 and uDT46, it is necessary to specify a specific vrf.
   The uA behavior requires the outgoing interface and optionally the IPv6 address of the Layer 3 adjacency
   to which the packet should be forwarded.

::

   router# configure terminal
   router(config)# segment-routing
   router(config-sr)# srv6
   router(config-srv6)# static-sids
   router(config-srv6-sids)# sid fcbb:bbbb:1:fe01::/64 locator LOC1 behavior uDT6 vrf Vrf1
   router(config-srv6-sids)# sid fcbb:bbbb:1:fe02::/64 locator LOC1 behavior uDT4 vrf Vrf1
   router(config-srv6-sids)# sid fcbb:bbbb:1:fe03::/64 locator LOC1 behavior uDT46 vrf Vrf2
   router(config-srv6-sids)# sid fcbb:bbbb:1:fe04::/64 locator LOC1 behavior uA interface eth0 nexthop 2001::2

   router(config-srv6-locator)# show run
   ...
   segment-routing
    srv6
     static-sids
      sid    fcbb:bbbb:1:fe01::/64 locator LOC1 behavior uDT6 vrf Vrf1
      sid    fcbb:bbbb:1:fe02::/64 locator LOC1 behavior uDT4 vrf Vrf1
      sid    fcbb:bbbb:1:fe03::/64 locator LOC1 behavior uDT46 vrf Vrf2
      sid    fcbb:bbbb:1:fe04::/64 locator LOC1 behavior uA interface eth0 nexthop 2001::2
       !
   ...
