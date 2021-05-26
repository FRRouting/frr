.. _wecmp_linkbw:

Weighted ECMP using BGP link bandwidth
======================================

.. _features-of-wecmp-linkbw:

Overview
--------

In normal equal cost multipath (ECMP), the route to a destination has
multiple next hops and traffic is expected to be equally distributed
across these next hops. In practice, flow-based hashing is used so that
all traffic associated with a particular flow uses the same next hop,
and by extension, the same path across the network.

Weighted ECMP using BGP link bandwidth introduces support for network-wide
unequal cost multipathing (UCMP) to an IP destination. The unequal cost
load balancing is implemented by the forwarding plane based on the weights
associated with the next hops of the IP prefix. These weights are computed
based on the bandwidths of the corresponding multipaths which are encoded
in the ``BGP link bandwidth extended community`` as specified in
[Draft-IETF-idr-link-bandwidth]_. Exchange of an appropriate BGP link
bandwidth value for a prefix across the network results in network-wide
unequal cost multipathing.

One of the primary use cases of this capability is in the data center when
a service (represented by its anycast IP) has an unequal set of resources
across the regions (e.g., PODs) of the data center and the network itself
provides the load balancing function instead of an external load balancer.
Refer to [Draft-IETF-mohanty-bess-ebgp-dmz]_ and :rfc:`7938` for details
on this use case. This use case is applicable in a pure L3 network as
well as in a EVPN network.

The traditional use case for BGP link bandwidth to load balance traffic
to the exit routers in the AS based on the bandwidth of their external
eBGP peering links is also supported.


Design Principles
-----------------

Next hop weight computation and usage
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

As described, in UCMP, there is a weight associated with each next hop of an
IP prefix, and traffic is expected to be distributed across the next hops in
proportion to their weight. The weight of a next hop is a simple factoring
of the bandwidth of the corresponding path against the total bandwidth of
all multipaths, mapped to the range 1 to 100. What happens if not all the
paths in the multipath set have link bandwidth associated with them? In such
a case, in adherence to [Draft-IETF-idr-link-bandwidth]_, the behavior
reverts to standard ECMP among all the multipaths, with the link bandwidth
being effectively ignored.

Note that there is no change to either the BGP best path selection algorithm
or to the multipath computation algorithm; the mapping of link bandwidth to
weight happens at the time of installation of the route in the RIB.

If data forwarding is implemented by means of the Linux kernel, the next hop’s
weight is used in the hash calculation. The kernel uses the Hash threshold
algorithm and use of the next hop weight is built into it; next hops need
not be expanded to achieve UCMP. UCMP for IPv4 is available in older Linux
kernels too, while UCMP for IPv6 is available from the 4.16 kernel onwards.

If data forwarding is realized in hardware, common implementations expand
the next hops (i.e., they are repeated) in the ECMP container in proportion
to their weight. For example, if the weights associated with 3 next hops for
a particular route are 50, 25 and 25 and the ECMP container has a size of 16
next hops, the first next hop will be repeated 8 times and the other 2 next
hops repeated 4 times each. Other implementations are also possible.

Unequal cost multipath across a network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For the use cases listed above, it is not sufficient to support UCMP on just
one router (e.g., egress router), or individually, on multiple routers; UCMP
must be deployed across the entire network. This is achieved by employing the
BGP link-bandwidth extended community.

At the router which originates the BGP link bandwidth, there has to be user
configuration to trigger it, which is described below. Receiving routers
would use the received link bandwidth from their downstream routers to
determine the next hop weight as described in the earlier section. Further,
if the received link bandwidth is a transitive attribute, it would be
propagated to eBGP peers, with the additional change that if the next hop
is set to oneself, the cumulative link bandwidth of all downstream paths
is propagated to other routers. In this manner, the entire network will
know how to distribute traffic to an anycast service across the network.

The BGP link-bandwidth extended community is encoded in bytes-per-second.
In the use case where UCMP must be based on the number of paths, a reference
bandwidth of 1 Mbps is used. So, for example, if there are 4 equal cost paths
to an anycast IP, the encoded bandwidth in the extended community will be
500,000. The actual value itself doesn’t matter as long as all routers
originating the link-bandwidth are doing it in the same way.


Configuration Guide
-------------------

The configuration for weighted ECMP using BGP link bandwidth requires
one essential step - using a route-map to inject the link bandwidth
extended community. An additional option is provided to control the
processing of received link bandwidth.

Injecting link bandwidth into the network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

At the "entry point" router that is injecting the prefix to which weighted
load balancing must be performed, a route-map must be configured to
attach the link bandwidth extended community.

For the use case of providing weighted load balancing for an anycast service,
this configuration will typically need to be applied at the TOR or Leaf
router that is connected to servers which provide the anycast service and
the bandwidth would be based on the number of multipaths for the destination.

For the use case of load balancing to the exit router, the exit router should
be configured with the route map specifying the a bandwidth value that
corresponds to the bandwidth of the link connecting to its eBGP peer in the
adjoining AS. In addition, the link bandwidth extended community must be
explicitly configured to be non-transitive.

The complete syntax of the route-map set command can be found at
:ref:`bgp-extended-communities-in-route-map`

This route-map is supported only at two attachment points:
(a) the outbound route-map attached to a peer or peer-group, per address-family
(b) the EVPN advertise route-map used to inject IPv4 or IPv6 unicast routes
into EVPN as type-5 routes.

Since the link bandwidth origination is done by using a route-map, it can
be constrained to certain prefixes (e.g., only for anycast services) or it
can be generated for all prefixes. Further, when the route-map is used in
the neighbor context, the link bandwidth usage can be constrained to certain
peers only.

A sample configuration is shown below and illustrates link bandwidth
advertisement towards the "SPINE" peer-group for anycast IPs in the
range 192.168.x.x

.. code-block:: frr

   ip prefix-list anycast_ip seq 10 permit 192.168.0.0/16 le 32
   route-map anycast_ip permit 10
    match ip address prefix-list anycast_ip
    set extcommunity bandwidth num-multipaths
   route-map anycast_ip permit 20
   !
   router bgp 65001
    neighbor SPINE peer-group
    neighbor SPINE remote-as external
    neighbor 172.16.35.1 peer-group SPINE
    neighbor 172.16.36.1 peer-group SPINE
    !
    address-family ipv4 unicast
     network 110.0.0.1/32
     network 192.168.44.1/32
     neighbor SPINE route-map anycast_ip out
    exit-address-family
   !


Controlling link bandwidth processing on the receiver
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

There is no configuration necessary to process received link bandwidth and
translate it into the weight associated with the corresponding next hop;
that happens by default. If some of the multipaths do not have the link
bandwidth extended community, the default behavior is to revert to normal
ECMP as recommended in [Draft-IETF-idr-link-bandwidth]_.

The operator can change these behaviors with the following configuration:

.. clicmd:: bgp bestpath bandwidth <ignore | skip-missing | default-weight-for-missing>

The different options imply behavior as follows:

- ignore: Ignore link bandwidth completely for route installation
  (i.e.,  do regular ECMP,  not weighted)
- skip-missing: Skip paths without link bandwidth and do UCMP among
  the others (if at least some paths have link-bandwidth)
- default-weight-for-missing: Assign a low default weight (value 1)
  to paths not having link bandwidth

This configuration is per BGP instance similar to other BGP route-selection
controls; it operates on both IPv4-unicast and IPv6-unicast routes in that
instance. In an EVPN network, this configuration (if required) should be
implemented in the tenant VRF and is again applicable for IPv4-unicast and
IPv6-unicast, including the ones sourced from EVPN type-5 routes.

A sample snippet of FRR configuration on a receiver to skip paths without
link bandwidth and do weighted ECMP among the other paths (if some of them
have link bandwidth) is as shown below.

.. code-block:: frr

   router bgp 65021
    bgp bestpath as-path multipath-relax
    bgp bestpath bandwidth skip-missing
    neighbor LEAF peer-group
    neighbor LEAF remote-as external
    neighbor 172.16.35.2 peer-group LEAF
    neighbor 172.16.36.2 peer-group LEAF
    !
    address-family ipv4 unicast
     network 130.0.0.1/32
    exit-address-family
   !


Stopping the propagation of the link bandwidth outside a domain
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The link bandwidth extended community will get automatically propagated
with the prefix to EBGP peers, if it is encoded as a transitive attribute
by the originator. If this propagation has to be stopped outside of a
particular domain (e.g., stopped from being propagated to routers outside
of the data center core network), the mechanism available is to disable
the advertisement of all BGP extended communities on the specific peering/s.
In other words, the propagation cannot be blocked just for the link bandwidth
extended community. The configuration to disable all extended communities
can be applied to a peer or peer-group (per address-family).

Of course, the other common way to stop the propagation of the link bandwidth
outside the domain is to block the prefixes themselves from being advertised
and possibly, announce only an aggregate route. This would be quite common
in a EVPN network.

BGP link bandwidth and UCMP monitoring & troubleshooting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Existing operational commands to display the BGP routing table for a specific
prefix will show the link bandwidth extended community also, if present.

An example of an IPv4-unicast route received with the link bandwidth
attribute from two peers is shown below:

.. code-block:: frr

   CLI# show bgp ipv4 unicast 192.168.10.1/32
   BGP routing table entry for 192.168.10.1/32
   Paths: (2 available, best #2, table default)
     Advertised to non peer-group peers:
     l1(swp1) l2(swp2) l3(swp3) l4(swp4)
     65002
       fe80::202:ff:fe00:1b from l2(swp2) (110.0.0.2)
       (fe80::202:ff:fe00:1b) (used)
         Origin IGP, metric 0, valid, external, multipath, bestpath-from-AS 65002
         Extended Community: LB:65002:125000000 (1000.000 Mbps)
         Last update: Thu Feb 20 18:34:16 2020

     65001
       fe80::202:ff:fe00:15 from l1(swp1) (110.0.0.1)
       (fe80::202:ff:fe00:15) (used)
         Origin IGP, metric 0, valid, external, multipath, bestpath-from-AS 65001, best (Older Path)
         Extended Community: LB:65001:62500000 (500.000 Mbps)
         Last update: Thu Feb 20 18:22:34 2020

The weights associated with the next hops of a route can be seen by querying
the RIB for a specific route.

For example, the next hop weights corresponding to the link bandwidths in the
above example is illustrated below:

.. code-block:: frr

   spine1# show ip route 192.168.10.1/32
   Routing entry for 192.168.10.1/32
     Known via "bgp", distance 20, metric 0, best
     Last update 00:00:32 ago
     * fe80::202:ff:fe00:1b, via swp2, weight 66
     * fe80::202:ff:fe00:15, via swp1, weight 33

For troubleshooting, existing debug logs ``debug bgp updates``,
``debug bgp bestpath <prefix>``, ``debug bgp zebra`` and
``debug zebra kernel`` can be used.

A debug log snippet when ``debug bgp zebra`` is enabled and a route is
installed by BGP in the RIB with next hop weights is shown below:

.. code-block:: frr

   2020-02-29T06:26:19.927754+00:00 leaf1 bgpd[5459]: bgp_zebra_announce: p=192.168.150.1/32, bgp_is_valid_label: 0
   2020-02-29T06:26:19.928096+00:00 leaf1 bgpd[5459]: Tx route add VRF 33 192.168.150.1/32 metric 0 tag 0 count 2
   2020-02-29T06:26:19.928289+00:00 leaf1 bgpd[5459]:   nhop [1]: 110.0.0.6 if 35 VRF 33 wt 50   RMAC 0a:11:2f:7d:35:20
   2020-02-29T06:26:19.928479+00:00 leaf1 bgpd[5459]:   nhop [2]: 110.0.0.5 if 35 VRF 33 wt 50   RMAC 32:1e:32:a3:6c:bf
   2020-02-29T06:26:19.928668+00:00 leaf1 bgpd[5459]: bgp_zebra_announce: 192.168.150.1/32: announcing to zebra (recursion NOT set)


References
----------

.. [Draft-IETF-idr-link-bandwidth] <https://tools.ietf.org/html/draft-ietf-idr-link-bandwidth>
.. [Draft-IETF-mohanty-bess-ebgp-dmz] <https://tools.ietf.org/html/draft-mohanty-bess-ebgp-dmz>

