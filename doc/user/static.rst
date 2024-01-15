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

.. clicmd:: ip route NETWORK GATEWAY [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK IFNAME [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK GATEWAY IFNAME [DISTANCE] [onlink] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ip route NETWORK (Null0|blackhole|reject) [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] GATEWAY [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] IFNAME [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] GATEWAY IFNAME [DISTANCE] [onlink] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

.. clicmd:: ipv6 route NETWORK [from SRCPREFIX] (Null0|blackhole|reject) [DISTANCE] [table TABLENO] [nexthop-vrf VRFNAME] [vrf VRFNAME]

   NETWORK is destination prefix with a valid v4 or v6 network based upon
   initial form of the command.
   
   GATEWAY is the IP address to use as next-hop for the prefix. Currently, it must match
   the v4 or v6 route type specified at the start of the command.

   IFNAME is the name of the interface to use as next-hop. If only IFNAME is specified
   (without GATEWAY), a connected route will be created.

   When both IFNAME and GATEWAY are specified together, it binds the route to the specified
   interface. In this case, it is also possible to specify ``onlink`` to force the kernel
   to consider the next-hop as "on link" on the given interface.

   Alternatively, the gateway can be specified as ``Null0`` or ``blackhole`` to create a blackhole
   route that drops all traffic. It can also be specified as ``reject`` to create an unreachable
   route that rejects traffic with ICMP "Destination Unreachable" messages.

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
