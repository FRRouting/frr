.. _bgp:

***
BGP
***

:abbr:`BGP` stands for Border Gateway Protocol. The latest BGP version is 4.
BGP-4 is one of the Exterior Gateway Protocols and the de facto standard
interdomain routing protocol. BGP-4 is described in :rfc:`1771` and updated by
:rfc:`4271`. :rfc:`2858` adds multiprotocol support to BGP-4.

.. _starting-bgp:

Starting BGP
============

The default configuration file of *bgpd* is :file:`bgpd.conf`. *bgpd* searches
the current directory first, followed by |INSTALL_PREFIX_ETC|/bgpd.conf. All of
*bgpd*'s commands must be configured in :file:`bgpd.conf` when the integrated
config is not being used.

*bgpd* specific invocation options are described below. Common options may also
be specified (:ref:`common-invocation-options`).

.. program:: bgpd

.. option:: -p, --bgp_port <port>

   Set the bgp protocol's port number. When port number is 0, that means do not
   listen bgp port.

.. option:: -l, --listenon

   Specify a specific IP address for bgpd to listen on, rather than its
   default of INADDR_ANY / IN6ADDR_ANY. This can be useful to constrain bgpd
   to an internal address, or to run multiple bgpd processes on one host.

.. _bgp-basic-concepts:

Basic Concepts
==============

.. _bgp-autonomous-systems:

Autonomous Systems
------------------

The :abbr:`AS (Autonomous System)` number is one of the essential element of
BGP. BGP is a distance vector routing protocol, and the AS-Path framework
provides distance vector metric and loop detection to BGP. :rfc:`1930` provides
some background on the concepts of an AS.

The AS number is a two octet value, ranging in value from 1 to 65535. The AS
numbers 64512 through 65535 are defined as private AS numbers. Private AS
numbers must not to be advertised in the global Internet.

.. _bgp-address-families:

Address Families
----------------

Multiprotocol BGP enables BGP to carry routing information for multiple Network
Layer protocols. BGP supports an Address Family Identifier (AFI) for IPv4 and
IPv6. Support is also provided for multiple sets of per-AFI information via the
BGP Subsequent Address Family Identifier (SAFI). FRR supports SAFIs for unicast
information, labeled information :rfc:`3107` and :rfc:`8277`, and Layer 3 VPN
information :rfc:`4364` and :rfc:`4659`.

.. _bgp-route-selection:

Route Selection
---------------

The route selection process used by FRR's BGP implementation uses the following
decision criterion, starting at the top of the list and going towards the
bottom until one of the factors can be used.

1. **Weight check**

   Prefer higher local weight routes to lower routes.

2. **Local preference check**

   Prefer higher local preference routes to lower.

3. **Local route check**

   Prefer local routes (statics, aggregates, redistributed) to received routes.

4. **AS path length check**

   Prefer shortest hop-count AS_PATHs.

5. **Origin check**

   Prefer the lowest origin type route. That is, prefer IGP origin routes to
   EGP, to Incomplete routes.

6. **MED check**

   Where routes with a MED were received from the same AS, prefer the route
   with the lowest MED. :ref:`bgp-med`.

7. **External check**

   Prefer the route received from an external, eBGP peer over routes received
   from other types of peers.

8. **IGP cost check**

   Prefer the route with the lower IGP cost.

9. **Multi-path check**

   If multi-pathing is enabled, then check whether the routes not yet
   distinguished in preference may be considered equal. If
   :clicmd:`bgp bestpath as-path multipath-relax` is set, all such routes are
   considered equal, otherwise routes received via iBGP with identical AS_PATHs
   or routes received from eBGP neighbours in the same AS are considered equal.

10. **Already-selected external check**

    Where both routes were received from eBGP peers, then prefer the route
    which is already selected. Note that this check is not applied if
    :clicmd:`bgp bestpath compare-routerid` is configured. This check can
    prevent some cases of oscillation.

11. **Router-ID check**

    Prefer the route with the lowest `router-ID`. If the route has an
    `ORIGINATOR_ID` attribute, through iBGP reflection, then that router ID is
    used, otherwise the `router-ID` of the peer the route was received from is
    used.

12. **Cluster-List length check**

    The route with the shortest cluster-list length is used. The cluster-list
    reflects the iBGP reflection path the route has taken.

13. **Peer address**

    Prefer the route received from the peer with the higher transport layer
    address, as a last-resort tie-breaker.

.. _bgp-capability-negotiation:

Capability Negotiation
----------------------

When adding IPv6 routing information exchange feature to BGP. There were some
proposals. :abbr:`IETF (Internet Engineering Task Force)`
:abbr:`IDR (Inter Domain Routing)` adopted a proposal called Multiprotocol
Extension for BGP. The specification is described in :rfc:`2283`. The protocol
does not define new protocols. It defines new attributes to existing BGP. When
it is used exchanging IPv6 routing information it is called BGP-4+. When it is
used for exchanging multicast routing information it is called MBGP.

*bgpd* supports Multiprotocol Extension for BGP. So if a remote peer supports
the protocol, *bgpd* can exchange IPv6 and/or multicast routing information.

Traditional BGP did not have the feature to detect a remote peer's
capabilities, e.g. whether it can handle prefix types other than IPv4 unicast
routes. This was a big problem using Multiprotocol Extension for BGP in an
operational network. :rfc:`2842` adopted a feature called Capability
Negotiation. *bgpd* use this Capability Negotiation to detect the remote peer's
capabilities. If a peer is only configured as an IPv4 unicast neighbor, *bgpd*
does not send these Capability Negotiation packets (at least not unless other
optional BGP features require capability negotiation).

By default, FRR will bring up peering with minimal common capability for the
both sides. For example, if the local router has unicast and multicast
capabilities and the remote router only has unicast capability the local router
will establish the connection with unicast only capability. When there are no
common capabilities, FRR sends Unsupported Capability error and then resets the
connection.

.. _bgp-concepts-vrfs:

VRFs: Virtual Routing and Forwarding
------------------------------------

*bgpd* supports :abbr:`L3VPN (Layer 3 Virtual Private Networks)` :abbr:`VRFs
(Virtual Routing and Forwarding tables)` for IPv4 :rfc:`4364` and IPv6
:rfc:`4659`.  L3VPN routes, and their associated VRF MPLS labels, can be
distributed to VPN SAFI neighbors in the *default*, i.e., non VRF, BGP
instance. VRF MPLS labels are reached using *core* MPLS labels which are
distributed using LDP or BGP labeled unicast.  *bgpd* also supports inter-VRF
route leaking.  General information on FRR's VRF support can be found in
:ref:`zebra-vrf`.

.. _bgp-router-configuration:

BGP Router Configuration
========================

ASN and Router ID
-----------------

First of all you must configure BGP router with the :clicmd:`router bgp ASN`
command. The AS number is an identifier for the autonomous system. The BGP
protocol uses the AS number for detecting whether the BGP connection is
internal or external.

.. index:: router bgp ASN
.. clicmd:: router bgp ASN

   Enable a BGP protocol process with the specified ASN. After
   this statement you can input any `BGP Commands`.

.. index:: no router bgp ASN
.. clicmd:: no router bgp ASN

   Destroy a BGP protocol process with the specified ASN.

.. index:: bgp router-id A.B.C.D
.. clicmd:: bgp router-id A.B.C.D

   This command specifies the router-ID. If *bgpd* connects to *zebra* it gets
   interface and address information. In that case default router ID value is
   selected as the largest IP Address of the interfaces. When `router zebra` is
   not enabled *bgpd* can't get interface information so `router-id` is set to
   0.0.0.0. So please set router-id by hand.

Route Selection
---------------

.. index:: bgp bestpath as-path confed
.. clicmd:: bgp bestpath as-path confed

   This command specifies that the length of confederation path sets and
   sequences should should be taken into account during the BGP best path
   decision process.

.. index:: bgp bestpath as-path multipath-relax
.. clicmd:: bgp bestpath as-path multipath-relax

   This command specifies that BGP decision process should consider paths
   of equal AS_PATH length candidates for multipath computation. Without
   the knob, the entire AS_PATH must match for multipath computation.

.. clicmd:: bgp bestpath compare-routerid

   Ensure that when comparing routes where both are equal on most metrics,
   including local-pref, AS_PATH length, IGP cost, MED, that the tie is broken
   based on router-ID.

   If this option is enabled, then the already-selected check, where
   already selected eBGP routes are preferred, is skipped.

   If a route has an `ORIGINATOR_ID` attribute because it has been reflected,
   that `ORIGINATOR_ID` will be used. Otherwise, the router-ID of the peer the
   route was received from will be used.

   The advantage of this is that the route-selection (at this point) will be
   more deterministic. The disadvantage is that a few or even one lowest-ID
   router may attract all traffic to otherwise-equal paths because of this
   check. It may increase the possibility of MED or IGP oscillation, unless
   other measures were taken to avoid these. The exact behaviour will be
   sensitive to the iBGP and reflection topology.

.. _bgp-distance:

Administrative Distance Metrics
-------------------------------

.. index:: distance bgp (1-255) (1-255) (1-255)
.. clicmd:: distance bgp (1-255) (1-255) (1-255)

   This command change distance value of BGP. The arguments are the distance
   values for for external routes, internal routes and local routes
   respectively.

.. index:: distance (1-255) A.B.C.D/M
.. clicmd:: distance (1-255) A.B.C.D/M

.. index:: distance (1-255) A.B.C.D/M WORD
.. clicmd:: distance (1-255) A.B.C.D/M WORD

   Sets the administrative distance for a particular route.

.. _bgp-route-flap-dampening:

Route Flap Dampening
--------------------

.. clicmd:: bgp dampening (1-45) (1-20000) (1-20000) (1-255)

   This command enables BGP route-flap dampening and specifies dampening parameters.

   half-life
      Half-life time for the penalty

   reuse-threshold
      Value to start reusing a route

   suppress-threshold
      Value to start suppressing a route

   max-suppress
      Maximum duration to suppress a stable route

   The route-flap damping algorithm is compatible with :rfc:`2439`. The use of
   this command is not recommended nowadays.

.. seealso::
   https://www.ripe.net/publications/docs/ripe-378

.. _bgp-med:

Multi-Exit Discriminator
------------------------

The BGP :abbr:`MED (Multi-Exit Discriminator)` attribute has properties which
can cause subtle convergence problems in BGP. These properties and problems
have proven to be hard to understand, at least historically, and may still not
be widely understood. The following attempts to collect together and present
what is known about MED, to help operators and FRR users in designing and
configuring their networks.

The BGP :abbr:`MED` attribute is intended to allow one AS to indicate its
preferences for its ingress points to another AS. The MED attribute will not be
propagated on to another AS by the receiving AS - it is 'non-transitive' in the
BGP sense.

E.g., if AS X and AS Y have 2 different BGP peering points, then AS X might set
a MED of 100 on routes advertised at one and a MED of 200 at the other. When AS
Y selects between otherwise equal routes to or via AS X, AS Y should prefer to
take the path via the lower MED peering of 100 with AS X. Setting the MED
allows an AS to influence the routing taken to it within another, neighbouring
AS.

In this use of MED it is not really meaningful to compare the MED value on
routes where the next AS on the paths differs. E.g., if AS Y also had a route
for some destination via AS Z in addition to the routes from AS X, and AS Z had
also set a MED, it wouldn't make sense for AS Y to compare AS Z's MED values to
those of AS X. The MED values have been set by different administrators, with
different frames of reference.

The default behaviour of BGP therefore is to not compare MED values across
routes received from different neighbouring ASes. In FRR this is done by
comparing the neighbouring, left-most AS in the received AS_PATHs of the routes
and only comparing MED if those are the same.

Unfortunately, this behaviour of MED, of sometimes being compared across routes
and sometimes not, depending on the properties of those other routes, means MED
can cause the order of preference over all the routes to be undefined. That is,
given routes A, B, and C, if A is preferred to B, and B is preferred to C, then
a well-defined order should mean the preference is transitive (in the sense of
orders [#med-transitivity-rant]_) and that A would be preferred to C.

However, when MED is involved this need not be the case. With MED it is
possible that C is actually preferred over A. So A is preferred to B, B is
preferred to C, but C is preferred to A. This can be true even where BGP
defines a deterministic 'most preferred' route out of the full set of A,B,C.
With MED, for any given set of routes there may be a deterministically
preferred route, but there need not be any way to arrange them into any order
of preference. With unmodified MED, the order of preference of routes literally
becomes undefined.

That MED can induce non-transitive preferences over routes can cause issues.
Firstly, it may be perceived to cause routing table churn locally at speakers;
secondly, and more seriously, it may cause routing instability in iBGP
topologies, where sets of speakers continually oscillate between different
paths.

The first issue arises from how speakers often implement routing decisions.
Though BGP defines a selection process that will deterministically select the
same route as best at any given speaker, even with MED, that process requires
evaluating all routes together. For performance and ease of implementation
reasons, many implementations evaluate route preferences in a pair-wise fashion
instead. Given there is no well-defined order when MED is involved, the best
route that will be chosen becomes subject to implementation details, such as
the order the routes are stored in. That may be (locally) non-deterministic,
e.g.: it may be the order the routes were received in.

This indeterminism may be considered undesirable, though it need not cause
problems. It may mean additional routing churn is perceived, as sometimes more
updates may be produced than at other times in reaction to some event .

This first issue can be fixed with a more deterministic route selection that
ensures routes are ordered by the neighbouring AS during selection.
:clicmd:`bgp deterministic-med`. This may reduce the number of updates as routes
are received, and may in some cases reduce routing churn. Though, it could
equally deterministically produce the largest possible set of updates in
response to the most common sequence of received updates.

A deterministic order of evaluation tends to imply an additional overhead of
sorting over any set of n routes to a destination. The implementation of
deterministic MED in FRR scales significantly worse than most sorting
algorithms at present, with the number of paths to a given destination.  That
number is often low enough to not cause any issues, but where there are many
paths, the deterministic comparison may quickly become increasingly expensive
in terms of CPU.

Deterministic local evaluation can *not* fix the second, more major, issue of
MED however. Which is that the non-transitive preference of routes MED can
cause may lead to routing instability or oscillation across multiple speakers
in iBGP topologies. This can occur with full-mesh iBGP, but is particularly
problematic in non-full-mesh iBGP topologies that further reduce the routing
information known to each speaker. This has primarily been documented with iBGP
route-reflection topologies. However, any route-hiding technologies potentially
could also exacerbate oscillation with MED.

This second issue occurs where speakers each have only a subset of routes, and
there are cycles in the preferences between different combinations of routes -
as the undefined order of preference of MED allows - and the routes are
distributed in a way that causes the BGP speakers to 'chase' those cycles. This
can occur even if all speakers use a deterministic order of evaluation in route
selection.

E.g., speaker 4 in AS A might receive a route from speaker 2 in AS X, and from
speaker 3 in AS Y; while speaker 5 in AS A might receive that route from
speaker 1 in AS Y. AS Y might set a MED of 200 at speaker 1, and 100 at speaker
3. I.e, using ASN:ID:MED to label the speakers:

::

   .
             /---------------\\
   X:2------|--A:4-------A:5--|-Y:1:200
               Y:3:100--|-/   |
             \\---------------/



Assuming all other metrics are equal (AS_PATH, ORIGIN, 0 IGP costs), then based
on the RFC4271 decision process speaker 4 will choose X:2 over Y:3:100, based
on the lower ID of 2. Speaker 4 advertises X:2 to speaker 5.  Speaker 5 will
continue to prefer Y:1:200 based on the ID, and advertise this to speaker 4.
Speaker 4 will now have the full set of routes, and the Y:1:200 it receives
from 5 will beat X:2, but when speaker 4 compares Y:1:200 to Y:3:100 the MED
check now becomes active as the ASes match, and now Y:3:100 is preferred.
Speaker 4 therefore now advertises Y:3:100 to 5, which will also agrees that
Y:3:100 is preferred to Y:1:200, and so withdraws the latter route from 4.
Speaker 4 now has only X:2 and Y:3:100, and X:2 beats Y:3:100, and so speaker 4
implicitly updates its route to speaker 5 to X:2. Speaker 5 sees that Y:1:200
beats X:2 based on the ID, and advertises Y:1:200 to speaker 4, and the cycle
continues.

The root cause is the lack of a clear order of preference caused by how MED
sometimes is and sometimes is not compared, leading to this cycle in the
preferences between the routes:

::

   .
    /---> X:2 ---beats---> Y:3:100 --\\
   |                                   |
   |                                   |
    \\---beats--- Y:1:200 <---beats---/



This particular type of oscillation in full-mesh iBGP topologies can  be
avoided by speakers preferring already selected, external routes rather than
choosing to update to new a route based on a post-MED metric (e.g.  router-ID),
at the cost of a non-deterministic selection process. FRR implements this, as
do many other implementations, so long as it is not overridden by setting
:clicmd:`bgp bestpath compare-routerid`, and see also
:ref:`bgp-route-selection`.

However, more complex and insidious cycles of oscillation are possible with
iBGP route-reflection, which are not so easily avoided. These have been
documented in various places. See, e.g.:

- [bgp-route-osci-cond]_
- [stable-flexible-ibgp]_
- [ibgp-correctness]_

for concrete examples and further references.

There is as of this writing *no* known way to use MED for its original purpose;
*and* reduce routing information in iBGP topologies; *and* be sure to avoid the
instability problems of MED due the non-transitive routing preferences it can
induce; in general on arbitrary networks.

There may be iBGP topology specific ways to reduce the instability risks, even
while using MED, e.g.: by constraining the reflection topology and by tuning
IGP costs between route-reflector clusters, see :rfc:`3345` for details.  In the
near future, the Add-Path extension to BGP may also solve MED oscillation while
still allowing MED to be used as intended, by distributing "best-paths per
neighbour AS". This would be at the cost of distributing at least as many
routes to all speakers as a full-mesh iBGP would, if not more, while also
imposing similar CPU overheads as the "Deterministic MED" feature at each
Add-Path reflector.

More generally, the instability problems that MED can introduce on more
complex, non-full-mesh, iBGP topologies may be avoided either by:

- Setting :clicmd:`bgp always-compare-med`, however this allows MED to be compared
  across values set by different neighbour ASes, which may not produce
  coherent desirable results, of itself.
- Effectively ignoring MED by setting MED to the same value (e.g.: 0) using
  :clicmd:`set metric METRIC` on all received routes, in combination with
  setting :clicmd:`bgp always-compare-med` on all speakers. This is the simplest
  and most performant way to avoid MED oscillation issues, where an AS is happy
  not to allow neighbours to inject this problematic metric.

As MED is evaluated after the AS_PATH length check, another possible use for
MED is for intra-AS steering of routes with equal AS_PATH length, as an
extension of the last case above. As MED is evaluated before IGP metric, this
can allow cold-potato routing to be implemented to send traffic to preferred
hand-offs with neighbours, rather than the closest hand-off according to the
IGP metric.

Note that even if action is taken to address the MED non-transitivity issues,
other oscillations may still be possible. E.g., on IGP cost if iBGP and IGP
topologies are at cross-purposes with each other - see the Flavel and Roughan
paper above for an example. Hence the guideline that the iBGP topology should
follow the IGP topology.

.. index:: bgp deterministic-med
.. clicmd:: bgp deterministic-med

   Carry out route-selection in way that produces deterministic answers
   locally, even in the face of MED and the lack of a well-defined order of
   preference it can induce on routes. Without this option the preferred route
   with MED may be determined largely by the order that routes were received
   in.

   Setting this option will have a performance cost that may be noticeable when
   there are many routes for each destination. Currently in FRR it is
   implemented in a way that scales poorly as the number of routes per
   destination increases.

   The default is that this option is not set.

Note that there are other sources of indeterminism in the route selection
process, specifically, the preference for older and already selected routes
from eBGP peers, :ref:`bgp-route-selection`.

.. index:: bgp always-compare-med
.. clicmd:: bgp always-compare-med

   Always compare the MED on routes, even when they were received from
   different neighbouring ASes. Setting this option makes the order of
   preference of routes more defined, and should eliminate MED induced
   oscillations.

   If using this option, it may also be desirable to use
   :clicmd:`set metric METRIC` to set MED to 0 on routes received from external
   neighbours.

   This option can be used, together with :clicmd:`set metric METRIC` to use
   MED as an intra-AS metric to steer equal-length AS_PATH routes to, e.g.,
   desired exit points.

.. _bgp-network:

Networks
--------

.. index:: network A.B.C.D/M
.. clicmd:: network A.B.C.D/M

   This command adds the announcement network.

   .. code-block:: frr

      router bgp 1
       address-family ipv4 unicast
        network 10.0.0.0/8
       exit-address-family

   This configuration example says that network 10.0.0.0/8 will be
   announced to all neighbors. Some vendors' routers don't advertise
   routes if they aren't present in their IGP routing tables; `bgpd`
   doesn't care about IGP routes when announcing its routes.

.. index:: no network A.B.C.D/M
.. clicmd:: no network A.B.C.D/M

.. _bgp-route-aggregation:

Route Aggregation
-----------------

.. index:: aggregate-address A.B.C.D/M
.. clicmd:: aggregate-address A.B.C.D/M

   This command specifies an aggregate address.

.. index:: aggregate-address A.B.C.D/M as-set
.. clicmd:: aggregate-address A.B.C.D/M as-set

   This command specifies an aggregate address. Resulting routes include
   AS set.

.. index:: aggregate-address A.B.C.D/M summary-only
.. clicmd:: aggregate-address A.B.C.D/M summary-only

   This command specifies an aggregate address. Aggregated routes will
   not be announce.

.. index:: no aggregate-address A.B.C.D/M
.. clicmd:: no aggregate-address A.B.C.D/M

.. _bgp-redistribute-to-bgp:

Redistribution
--------------

.. index:: redistribute kernel
.. clicmd:: redistribute kernel

   Redistribute kernel route to BGP process.

.. index:: redistribute static
.. clicmd:: redistribute static

   Redistribute static route to BGP process.

.. index:: redistribute connected
.. clicmd:: redistribute connected

   Redistribute connected route to BGP process.

.. index:: redistribute rip
.. clicmd:: redistribute rip

   Redistribute RIP route to BGP process.

.. index:: redistribute ospf
.. clicmd:: redistribute ospf

   Redistribute OSPF route to BGP process.

.. index:: redistribute vpn
.. clicmd:: redistribute vpn

   Redistribute VNC routes to BGP process.

.. index:: update-delay MAX-DELAY
.. clicmd:: update-delay MAX-DELAY

.. index:: update-delay MAX-DELAY ESTABLISH-WAIT
.. clicmd:: update-delay MAX-DELAY ESTABLISH-WAIT

   This feature is used to enable read-only mode on BGP process restart or when
   BGP process is cleared using 'clear ip bgp \*'. When applicable, read-only
   mode would begin as soon as the first peer reaches Established status and a
   timer for max-delay seconds is started.

   During this mode BGP doesn't run any best-path or generate any updates to its
   peers. This mode continues until:

   1. All the configured peers, except the shutdown peers, have sent explicit EOR
      (End-Of-RIB) or an implicit-EOR. The first keep-alive after BGP has reached
      Established is considered an implicit-EOR.
      If the establish-wait optional value is given, then BGP will wait for
      peers to reach established from the beginning of the update-delay till the
      establish-wait period is over, i.e. the minimum set of established peers for
      which EOR is expected would be peers established during the establish-wait
      window, not necessarily all the configured neighbors.
   2. max-delay period is over.

   On hitting any of the above two conditions, BGP resumes the decision process
   and generates updates to its peers.

   Default max-delay is 0, i.e. the feature is off by default.

.. index:: table-map ROUTE-MAP-NAME
.. clicmd:: table-map ROUTE-MAP-NAME

   This feature is used to apply a route-map on route updates from BGP to
   Zebra.  All the applicable match operations are allowed, such as match on
   prefix, next-hop, communities, etc. Set operations for this attach-point are
   limited to metric and next-hop only. Any operation of this feature does not
   affect BGPs internal RIB.

   Supported for ipv4 and ipv6 address families. It works on multi-paths as
   well, however, metric setting is based on the best-path only.

.. _bgp-peers:

Peers
-----

.. _bgp-defining-peers:

Defining Peers
^^^^^^^^^^^^^^

.. index:: neighbor PEER remote-as ASN
.. clicmd:: neighbor PEER remote-as ASN

   Creates a new neighbor whose remote-as is ASN. PEER can be an IPv4 address
   or an IPv6 address or an interface to use for the connection.

   .. code-block:: frr

       router bgp 1
        neighbor 10.0.0.1 remote-as 2

   In this case my router, in AS-1, is trying to peer with AS-2 at 10.0.0.1.

   This command must be the first command used when configuring a neighbor.  If
   the remote-as is not specified, *bgpd* will complain like this: ::

      can't find neighbor 10.0.0.1

.. index:: neighbor PEER remote-as internal
.. clicmd:: neighbor PEER remote-as internal

   Create a peer as you would when you specify an ASN, except that if the
   peers ASN is different than mine as specified under the :clicmd:`router bgp ASN`
   command the connection will be denied.

.. index:: neighbor PEER remote-as external
.. clicmd:: neighbor PEER remote-as external

   Create a peer as you would when you specify an ASN, except that if the
   peers ASN is the same as mine as specified under the :clicmd:`router bgp ASN`
   command the connection will be denied.

.. _bgp-configuring-peers:

Configuring Peers
^^^^^^^^^^^^^^^^^

.. index:: neighbor PEER shutdown
.. clicmd:: neighbor PEER shutdown

.. index:: no neighbor PEER shutdown
.. clicmd:: no neighbor PEER shutdown

   Shutdown the peer. We can delete the neighbor's configuration by
   ``no neighbor PEER remote-as ASN`` but all configuration of the neighbor
   will be deleted. When you want to preserve the configuration, but want to
   drop the BGP peer, use this syntax.

.. index:: neighbor PEER ebgp-multihop
.. clicmd:: neighbor PEER ebgp-multihop

.. index:: no neighbor PEER ebgp-multihop
.. clicmd:: no neighbor PEER ebgp-multihop


.. index:: neighbor PEER description ...
.. clicmd:: neighbor PEER description ...


.. index:: no neighbor PEER description ...
.. clicmd:: no neighbor PEER description ...

   Set description of the peer.

.. index:: neighbor PEER version VERSION
.. clicmd:: neighbor PEER version VERSION

   Set up the neighbor's BGP version. `version` can be `4`, `4+` or `4-`. BGP
   version `4` is the default value used for BGP peering. BGP version `4+`
   means that the neighbor supports Multiprotocol Extensions for BGP-4. BGP
   version `4-` is similar but the neighbor speaks the old Internet-Draft
   revision 00's Multiprotocol Extensions for BGP-4. Some routing software is
   still using this version.

.. index:: neighbor PEER interface IFNAME
.. clicmd:: neighbor PEER interface IFNAME


.. index:: no neighbor PEER interface IFNAME
.. clicmd:: no neighbor PEER interface IFNAME

   When you connect to a BGP peer over an IPv6 link-local address, you have to
   specify the IFNAME of the interface used for the connection. To specify
   IPv4 session addresses, see the ``neighbor PEER update-source`` command
   below.

   This command is deprecated and may be removed in a future release. Its use
   should be avoided.

.. index:: neighbor PEER next-hop-self [all]
.. clicmd:: neighbor PEER next-hop-self [all]


.. index:: no neighbor PEER next-hop-self [all]
.. clicmd:: no neighbor PEER next-hop-self [all]

   This command specifies an announced route's nexthop as being equivalent to
   the address of the bgp router if it is learned via eBGP.  If the optional
   keyword `all` is specified the modification is done also for routes learned
   via iBGP.

.. index:: neighbor PEER update-source <IFNAME|ADDRESS>
.. clicmd:: neighbor PEER update-source <IFNAME|ADDRESS>


.. index:: no neighbor PEER update-source
.. clicmd:: no neighbor PEER update-source

   Specify the IPv4 source address to use for the :abbr:`BGP` session to this
   neighbour, may be specified as either an IPv4 address directly or as an
   interface name (in which case the *zebra* daemon MUST be running in order
   for *bgpd* to be able to retrieve interface state).

   .. code-block:: frr

      router bgp 64555
       neighbor foo update-source 192.168.0.1
       neighbor bar update-source lo0


.. index:: neighbor PEER default-originate
.. clicmd:: neighbor PEER default-originate

.. index:: no neighbor PEER default-originate
.. clicmd:: no neighbor PEER default-originate

   *bgpd*'s default is to not announce the default route (0.0.0.0/0) even if it
   is in routing table. When you want to announce default routes to the peer,
   use this command.

.. index:: neighbor PEER port PORT
.. clicmd:: neighbor PEER port PORT

.. index:: neighbor PEER send-community
.. clicmd:: neighbor PEER send-community

.. index:: neighbor PEER weight WEIGHT
.. clicmd:: neighbor PEER weight WEIGHT


.. index:: no neighbor PEER weight WEIGHT
.. clicmd:: no neighbor PEER weight WEIGHT

   This command specifies a default `weight` value for the neighbor's routes.

.. index:: neighbor PEER maximum-prefix NUMBER
.. clicmd:: neighbor PEER maximum-prefix NUMBER


.. index:: no neighbor PEER maximum-prefix NUMBER
.. clicmd:: no neighbor PEER maximum-prefix NUMBER


.. index:: neighbor PEER local-as AS-NUMBER
.. clicmd:: neighbor PEER local-as AS-NUMBER


.. index:: neighbor PEER local-as AS-NUMBER no-prepend
.. clicmd:: neighbor PEER local-as AS-NUMBER no-prepend


.. index:: neighbor PEER local-as AS-NUMBER no-prepend replace-as
.. clicmd:: neighbor PEER local-as AS-NUMBER no-prepend replace-as


.. index:: no neighbor PEER local-as
.. clicmd:: no neighbor PEER local-as

   Specify an alternate AS for this BGP process when interacting with the
   specified peer. With no modifiers, the specified local-as is prepended to
   the received AS_PATH when receiving routing updates from the peer, and
   prepended to the outgoing AS_PATH (after the process local AS) when
   transmitting local routes to the peer.

   If the no-prepend attribute is specified, then the supplied local-as is not
   prepended to the received AS_PATH.

   If the replace-as attribute is specified, then only the supplied local-as is
   prepended to the AS_PATH when transmitting local-route updates to this peer.

   Note that replace-as can only be specified if no-prepend is.

   This command is only allowed for eBGP peers.

.. index:: neighbor PEER ttl-security hops NUMBER
.. clicmd:: neighbor PEER ttl-security hops NUMBER


.. index:: no neighbor PEER ttl-security hops NUMBER
.. clicmd:: no neighbor PEER ttl-security hops NUMBER

   This command enforces Generalized TTL Security Mechanism (GTSM), as
   specified in RFC 5082. With this command, only neighbors that are the
   specified number of hops away will be allowed to become neighbors. This
   command is mutually exclusive with *ebgp-multihop*.

.. _bgp-peer-filtering:

Peer Filtering
^^^^^^^^^^^^^^

.. index:: neighbor PEER distribute-list NAME [in|out]
.. clicmd:: neighbor PEER distribute-list NAME [in|out]

   This command specifies a distribute-list for the peer. `direct` is
   ``in`` or ``out``.

.. index:: neighbor PEER prefix-list NAME [in|out]
.. clicmd:: neighbor PEER prefix-list NAME [in|out]

.. index:: neighbor PEER filter-list NAME [in|out]
.. clicmd:: neighbor PEER filter-list NAME [in|out]

.. index:: neighbor PEER route-map NAME [in|out]
.. clicmd:: neighbor PEER route-map NAME [in|out]

   Apply a route-map on the neighbor. `direct` must be `in` or `out`.

.. index:: bgp route-reflector allow-outbound-policy
.. clicmd:: bgp route-reflector allow-outbound-policy

   By default, attribute modification via route-map policy out is not reflected
   on reflected routes. This option allows the modifications to be reflected as
   well. Once enabled, it affects all reflected routes.

.. _bgp-peer-group:

Peer Groups
^^^^^^^^^^^

.. index:: neighbor WORD peer-group
.. clicmd:: neighbor WORD peer-group

   This command defines a new peer group.

.. index:: neighbor PEER peer-group WORD
.. clicmd:: neighbor PEER peer-group WORD

   This command bind specific peer to peer group WORD.

Capability Negotiation
^^^^^^^^^^^^^^^^^^^^^^

.. index:: neighbor PEER strict-capability-match
.. clicmd:: neighbor PEER strict-capability-match

.. index:: no neighbor PEER strict-capability-match
.. clicmd:: no neighbor PEER strict-capability-match

   Strictly compares remote capabilities and local capabilities. If
   capabilities are different, send Unsupported Capability error then reset
   connection.

   You may want to disable sending Capability Negotiation OPEN message optional
   parameter to the peer when remote peer does not implement Capability
   Negotiation. Please use *dont-capability-negotiate* command to disable the
   feature.

.. index:: neighbor PEER dont-capability-negotiate
.. clicmd:: neighbor PEER dont-capability-negotiate

.. index:: no neighbor PEER dont-capability-negotiate
.. clicmd:: no neighbor PEER dont-capability-negotiate

   Suppress sending Capability Negotiation as OPEN message optional parameter
   to the peer. This command only affects the peer is configured other than
   IPv4 unicast configuration.

   When remote peer does not have capability negotiation feature, remote peer
   will not send any capabilities at all. In that case, bgp configures the peer
   with configured capabilities.

   You may prefer locally configured capabilities more than the negotiated
   capabilities even though remote peer sends capabilities. If the peer is
   configured by *override-capability*, *bgpd* ignores received capabilities
   then override negotiated capabilities with configured values.

.. index:: neighbor PEER override-capability
.. clicmd:: neighbor PEER override-capability

.. index:: no neighbor PEER override-capability
.. clicmd:: no neighbor PEER override-capability

   Override the result of Capability Negotiation with local configuration.
   Ignore remote peer's capability value.

.. _bgp-as-path-access-lists:

AS Path Access Lists
--------------------

AS path access list is user defined AS path.

.. index:: ip as-path access-list WORD permit|deny LINE
.. clicmd:: ip as-path access-list WORD permit|deny LINE

   This command defines a new AS path access list.

.. index:: no ip as-path access-list WORD
.. clicmd:: no ip as-path access-list WORD

.. index:: no ip as-path access-list WORD permit|deny LINE
.. clicmd:: no ip as-path access-list WORD permit|deny LINE

.. _bgp-using-as-path-in-route-map:

Using AS Path in Route Map
--------------------------

.. index:: match as-path WORD
.. clicmd:: match as-path WORD


.. index:: set as-path prepend AS-PATH
.. clicmd:: set as-path prepend AS-PATH

   Prepend the given string of AS numbers to the AS_PATH.

.. index:: set as-path prepend last-as NUM
.. clicmd:: set as-path prepend last-as NUM

   Prepend the existing last AS number (the leftmost ASN) to the AS_PATH.

.. _bgp-communities-attribute:

Communities Attribute
---------------------

The BGP communities attribute is widely used for implementing policy routing.
Network operators can manipulate BGP communities attribute based on their
network policy. BGP communities attribute is defined in :rfc:`1997` and
:rfc:`1998`. It is an optional transitive attribute, therefore local policy can
travel through different autonomous system.

The communities attribute is a set of communities values. Each community value
is 4 octet long. The following format is used to define the community value.

``AS:VAL``
   This format represents 4 octet communities value. ``AS`` is high order 2
   octet in digit format. ``VAL`` is low order 2 octet in digit format. This
   format is useful to define AS oriented policy value. For example,
   ``7675:80`` can be used when AS 7675 wants to pass local policy value 80 to
   neighboring peer.

``internet``
   ``internet`` represents well-known communities value 0.

``no-export``
   ``no-export`` represents well-known communities value ``NO_EXPORT``
   ``0xFFFFFF01``. All routes carry this value must not be advertised to
   outside a BGP confederation boundary. If neighboring BGP peer is part of BGP
   confederation, the peer is considered as inside a BGP confederation
   boundary, so the route will be announced to the peer.

``no-advertise``
   ``no-advertise`` represents well-known communities value ``NO_ADVERTISE``
   ``0xFFFFFF02``. All routes carry this value must not be advertise to other
   BGP peers.

``local-AS``
   ``local-AS`` represents well-known communities value ``NO_EXPORT_SUBCONFED``
   ``0xFFFFFF03``. All routes carry this value must not be advertised to
   external BGP peers. Even if the neighboring router is part of confederation,
   it is considered as external BGP peer, so the route will not be announced to
   the peer.

When the communities attribute is received duplicate community values in the
attribute are ignored and value is sorted in numerical order.

.. _bgp-community-lists:

Community Lists
^^^^^^^^^^^^^^^
Community lists are user defined lists of community attribute values. These
lists can be used for matching or manipulating the communities attribute in
UPDATE messages.

There are two types of community list:

standard
   This type accepts an explicit value for the atttribute.

expanded
   This type accepts a regular expression. Because the regex must be
   interpreted on each use expanded community lists are slower than standard
   lists.

.. index:: ip community-list standard NAME permit|deny COMMUNITY
.. clicmd:: ip community-list standard NAME permit|deny COMMUNITY

   This command defines a new standard community list. ``COMMUNITY`` is
   communities value. The ``COMMUNITY`` is compiled into community structure.
   We can define multiple community list under same name. In that case match
   will happen user defined order. Once the community list matches to
   communities attribute in BGP updates it return permit or deny by the
   community list definition. When there is no matched entry, deny will be
   returned. When ``COMMUNITY`` is empty it matches to any routes.

.. index:: ip community-list expanded NAME permit|deny COMMUNITY
.. clicmd:: ip community-list expanded NAME permit|deny COMMUNITY

   This command defines a new expanded community list. ``COMMUNITY`` is a
   string expression of communities attribute. ``COMMUNITY`` can be a regular
   expression (:ref:`bgp-regular-expressions`) to match the communities
   attribute in BGP updates.

.. deprecated:: 5.0
   It is recommended to use the more explicit versions of this command.

.. index:: ip community-list NAME permit|deny COMMUNITY
.. clicmd:: ip community-list NAME permit|deny COMMUNITY

   When the community list type is not specified, the community list type is
   automatically detected. If ``COMMUNITY`` can be compiled into communities
   attribute, the community list is defined as a standard community list.
   Otherwise it is defined as an expanded community list. This feature is left
   for backward compatibility. Use of this feature is not recommended.


.. index:: no ip community-list [standard|expanded] NAME
.. clicmd:: no ip community-list [standard|expanded] NAME

   Deletes the community list specified by ``NAME``. All community lists share
   the same namespace, so it's not necessary to specify ``standard`` or
   ``expanded``; these modifiers are purely aesthetic.

.. index:: show ip community-list [NAME]
.. clicmd:: show ip community-list [NAME]

   Displays community list information. When ``NAME`` is specified the
   specified community list's information is shown.

   ::

       # show ip community-list
       Named Community standard list CLIST
       permit 7675:80 7675:100 no-export
       deny internet
         Named Community expanded list EXPAND
       permit :

         # show ip community-list CLIST
         Named Community standard list CLIST
       permit 7675:80 7675:100 no-export
       deny internet


.. _bgp-numbered-community-lists:

Numbered Community Lists
^^^^^^^^^^^^^^^^^^^^^^^^

When number is used for BGP community list name, the number has
special meanings. Community list number in the range from 1 and 99 is
standard community list. Community list number in the range from 100
to 199 is expanded community list. These community lists are called
as numbered community lists. On the other hand normal community lists
is called as named community lists.

.. index:: ip community-list (1-99) permit|deny COMMUNITY
.. clicmd:: ip community-list (1-99) permit|deny COMMUNITY

   This command defines a new community list. The argument to (1-99) defines
   the list identifier.

.. index:: ip community-list (100-199) permit|deny COMMUNITY
.. clicmd:: ip community-list (100-199) permit|deny COMMUNITY

   This command defines a new expanded community list. The argument to
   (100-199) defines the list identifier.

.. _bgp-using-communities-in-route-map:

Using Communities in Route Maps
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In :ref:`route-map` we can match on or set the BGP communities attribute. Using
this feature network operator can implement their network policy based on BGP
communities attribute.

The ollowing commands can be used in route maps:

.. index:: match community WORD exact-match [exact-match]
.. clicmd:: match community WORD exact-match [exact-match]

   This command perform match to BGP updates using community list WORD. When
   the one of BGP communities value match to the one of communities value in
   community list, it is match. When `exact-match` keyword is specified, match
   happen only when BGP updates have completely same communities value
   specified in the community list.

.. index:: set community <none|COMMUNITY> additive
.. clicmd:: set community <none|COMMUNITY> additive

   This command sets the community value in BGP updates.  If the attribute is
   already configured, the newly provided value replaces the old one unless the
   ``additive`` keyword is specified, in which case the new value is appended
   to the existing value.

   If ``none`` is specified as the community value, the communities attribute
   is not sent.

.. index:: set comm-list WORD delete
.. clicmd:: set comm-list WORD delete

   This command remove communities value from BGP communities attribute.  The
   ``word`` is community list name. When BGP route's communities value matches
   to the community list ``word``, the communities value is removed. When all
   of communities value is removed eventually, the BGP update's communities
   attribute is completely removed.

.. _bgp-communities-example:

Example Configuration
^^^^^^^^^^^^^^^^^^^^^

The following configuration is exemplary of the most typical usage of BGP
communities attribute. In the example, AS 7675 provides an upstream Internet
connection to AS 100. When the following configuration exists in AS 7675, the
network operator of AS 100 can set local preference in AS 7675 network by
setting BGP communities attribute to the updates.

.. code-block:: frr

   router bgp 7675
    neighbor 192.168.0.1 remote-as 100
    address-family ipv4 unicast
     neighbor 192.168.0.1 route-map RMAP in
    exit-address-family
   !
   ip community-list 70 permit 7675:70
   ip community-list 70 deny
   ip community-list 80 permit 7675:80
   ip community-list 80 deny
   ip community-list 90 permit 7675:90
   ip community-list 90 deny
   !
   route-map RMAP permit 10
    match community 70
    set local-preference 70
   !
   route-map RMAP permit 20
    match community 80
    set local-preference 80
   !
   route-map RMAP permit 30
    match community 90
    set local-preference 90


The following configuration announces ``10.0.0.0/8`` from AS 100 to AS 7675.
The route has communities value ``7675:80`` so when above configuration exists
in AS 7675, the announced routes' local preference value will be set to 80.

.. code-block:: frr

   router bgp 100
    network 10.0.0.0/8
    neighbor 192.168.0.2 remote-as 7675
    address-family ipv4 unicast
     neighbor 192.168.0.2 route-map RMAP out
    exit-address-family
   !
   ip prefix-list PLIST permit 10.0.0.0/8
   !
   route-map RMAP permit 10
    match ip address prefix-list PLIST
    set community 7675:80


The following configuration is an example of BGP route filtering using
communities attribute. This configuration only permit BGP routes which has BGP
communities value ``0:80`` or ``0:90``. The network operator can set special
internal communities value at BGP border router, then limit the BGP route
announcements into the internal network.

.. code-block:: frr

   router bgp 7675
    neighbor 192.168.0.1 remote-as 100
    address-family ipv4 unicast
     neighbor 192.168.0.1 route-map RMAP in
    exit-address-family
   !
   ip community-list 1 permit 0:80 0:90
   !
   route-map RMAP permit in
    match community 1


The following example filters BGP routes which have a community value of
``1:1``. When there is no match community-list returns ``deny``. To avoid
filtering all routes, a ``permit`` line is set at the end of the
community-list.

.. code-block:: frr

   router bgp 7675
    neighbor 192.168.0.1 remote-as 100
    address-family ipv4 unicast
     neighbor 192.168.0.1 route-map RMAP in
    exit-address-family
   !
   ip community-list standard FILTER deny 1:1
   ip community-list standard FILTER permit
   !
   route-map RMAP permit 10
    match community FILTER


The communities value keyword ``internet`` has special meanings in standard
community lists. In the below example ``internet`` matches all BGP routes even
if the route does not have communities attribute at all. So community list
``INTERNET`` is the same as ``FILTER`` in the previous example.

.. code-block:: frr

   ip community-list standard INTERNET deny 1:1
   ip community-list standard INTERNET permit internet


The following configuration is an example of communities value deletion.  With
this configuration the community values ``100:1`` and ``100:2`` are removed
from BGP updates. For communities value deletion, only ``permit``
community-list is used. ``deny`` community-list is ignored.

.. code-block:: frr

   router bgp 7675
    neighbor 192.168.0.1 remote-as 100
    address-family ipv4 unicast
     neighbor 192.168.0.1 route-map RMAP in
    exit-address-family
   !
   ip community-list standard DEL permit 100:1 100:2
   !
   route-map RMAP permit 10
    set comm-list DEL delete


.. _bgp-extended-communities-attribute:

Extended Communities Attribute
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

BGP extended communities attribute is introduced with MPLS VPN/BGP technology.
MPLS VPN/BGP expands capability of network infrastructure to provide VPN
functionality. At the same time it requires a new framework for policy routing.
With BGP Extended Communities Attribute we can use Route Target or Site of
Origin for implementing network policy for MPLS VPN/BGP.

BGP Extended Communities Attribute is similar to BGP Communities Attribute. It
is an optional transitive attribute. BGP Extended Communities Attribute can
carry multiple Extended Community value.  Each Extended Community value is
eight octet length.

BGP Extended Communities Attribute provides an extended range compared with BGP
Communities Attribute. Adding to that there is a type field in each value to
provides community space structure.

There are two format to define Extended Community value. One is AS based format
the other is IP address based format.

``AS:VAL``
   This is a format to define AS based Extended Community value.  ``AS`` part
   is 2 octets Global Administrator subfield in Extended Community value.
   ``VAL`` part is 4 octets Local Administrator subfield. ``7675:100``
   represents AS 7675 policy value 100.

``IP-Address:VAL``
   This is a format to define IP address based Extended Community value.
   ``IP-Address`` part is 4 octets Global Administrator subfield.  ``VAL`` part
   is 2 octets Local Administrator subfield.

.. _bgp-extended-community-lists:

Extended Community Lists
^^^^^^^^^^^^^^^^^^^^^^^^

.. index:: ip extcommunity-list standard NAME permit|deny EXTCOMMUNITY
.. clicmd:: ip extcommunity-list standard NAME permit|deny EXTCOMMUNITY

   This command defines a new standard extcommunity-list. `extcommunity` is
   extended communities value. The `extcommunity` is compiled into extended
   community structure. We can define multiple extcommunity-list under same
   name. In that case match will happen user defined order. Once the
   extcommunity-list matches to extended communities attribute in BGP updates
   it return permit or deny based upon the extcommunity-list definition. When
   there is no matched entry, deny will be returned. When `extcommunity` is
   empty it matches to any routes.

.. index:: ip extcommunity-list expanded NAME permit|deny LINE
.. clicmd:: ip extcommunity-list expanded NAME permit|deny LINE

   This command defines a new expanded extcommunity-list. `line` is a string
   expression of extended communities attribute. `line` can be a regular
   expression (:ref:`bgp-regular-expressions`) to match an extended communities
   attribute in BGP updates.

.. index:: no ip extcommunity-list NAME
.. clicmd:: no ip extcommunity-list NAME

.. index:: no ip extcommunity-list standard NAME
.. clicmd:: no ip extcommunity-list standard NAME

.. index:: no ip extcommunity-list expanded NAME
.. clicmd:: no ip extcommunity-list expanded NAME

   These commands delete extended community lists specified by `name`. All of
   extended community lists shares a single name space. So extended community
   lists can be removed simply specifying the name.

.. index:: show ip extcommunity-list
.. clicmd:: show ip extcommunity-list

.. index:: show ip extcommunity-list NAME
.. clicmd:: show ip extcommunity-list NAME

   This command displays current extcommunity-list information. When `name` is
   specified the community list's information is shown.::

      # show ip extcommunity-list


.. _bgp-extended-communities-in-route-map:

BGP Extended Communities in Route Map
"""""""""""""""""""""""""""""""""""""

.. index:: match extcommunity WORD
.. clicmd:: match extcommunity WORD

.. index:: set extcommunity rt EXTCOMMUNITY
.. clicmd:: set extcommunity rt EXTCOMMUNITY

   This command set Route Target value.

.. index:: set extcommunity soo EXTCOMMUNITY
.. clicmd:: set extcommunity soo EXTCOMMUNITY

   This command set Site of Origin value.

.. _bgp-large-communities-attribute:

Large Communities Attribute
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The BGP Large Communities attribute was introduced in Feb 2017 with
:rfc:`8092`.

The BGP Large Communities Attribute is similar to the BGP Communities Attribute
except that it has 3 components instead of two and each of which are 4 octets
in length. Large Communities bring additional functionality and convenience
over traditional communities, specifically the fact that the ``GLOBAL`` part
below is now 4 octets wide allowing seamless use in networks using 4-byte ASNs.

``GLOBAL:LOCAL1:LOCAL2``
   This is the format to define Large Community values. Referencing :rfc:`8195`
   the values are commonly referred to as follows:

   - The ``GLOBAL`` part is a 4 octet Global Administrator field, commonly used
     as the operators AS number.
   - The ``LOCAL1`` part is a 4 octet Local Data Part 1 subfield referred to as
     a function.
   - The ``LOCAL2`` part is a 4 octet Local Data Part 2 field and referred to
     as the parameter subfield.

   As an example, ``65551:1:10`` represents AS 65551 function 1 and parameter
   10. The referenced RFC above gives some guidelines on recommended usage.

.. _bgp-large-community-lists:

Large Community Lists
"""""""""""""""""""""

Two types of large community lists are supported, namely `standard` and
`expanded`.

.. index:: ip large-community-list standard NAME permit|deny LARGE-COMMUNITY
.. clicmd:: ip large-community-list standard NAME permit|deny LARGE-COMMUNITY

   This command defines a new standard large-community-list.  `large-community`
   is the Large Community value. We can add multiple large communities under
   same name. In that case the match will happen in the user defined order.
   Once the large-community-list matches the Large Communities attribute in BGP
   updates it will return permit or deny based upon the large-community-list
   definition. When there is no matched entry, a deny will be returned. When
   `large-community` is empty it matches any routes.

.. index:: ip large-community-list expanded NAME permit|deny LINE
.. clicmd:: ip large-community-list expanded NAME permit|deny LINE

   This command defines a new expanded large-community-list. Where `line` is a
   string matching expression, it will be compared to the entire Large
   Communities attribute as a string, with each large-community in order from
   lowest to highest.  `line` can also be a regular expression which matches
   this Large Community attribute.

.. index:: no ip large-community-list NAME
.. clicmd:: no ip large-community-list NAME

.. index:: no ip large-community-list standard NAME
.. clicmd:: no ip large-community-list standard NAME

.. index:: no ip large-community-list expanded NAME
.. clicmd:: no ip large-community-list expanded NAME

   These commands delete Large Community lists specified by `name`. All Large
   Community lists share a single namespace.  This means Large Community lists
   can be removed by simply specifying the name.

.. index:: show ip large-community-list
.. clicmd:: show ip large-community-list

.. index:: show ip large-community-list NAME
.. clicmd:: show ip large-community-list NAME

   This command display current large-community-list information. When
   `name` is specified the community list information is shown.

.. index:: show ip bgp large-community-info
.. clicmd:: show ip bgp large-community-info

   This command displays the current large communities in use.

.. _bgp-large-communities-in-route-map:

Large Communities in Route Map
""""""""""""""""""""""""""""""

.. index:: match large-community LINE
.. clicmd:: match large-community LINE

   Where `line` can be a simple string to match, or a regular expression. It
   is very important to note that this match occurs on the entire
   large-community string as a whole, where each large-community is ordered
   from lowest to highest.

.. index:: set large-community LARGE-COMMUNITY
.. clicmd:: set large-community LARGE-COMMUNITY

.. index:: set large-community LARGE-COMMUNITY LARGE-COMMUNITY
.. clicmd:: set large-community LARGE-COMMUNITY LARGE-COMMUNITY

.. index:: set large-community LARGE-COMMUNITY additive
.. clicmd:: set large-community LARGE-COMMUNITY additive

   These commands are used for setting large-community values. The first
   command will overwrite any large-communities currently present.
   The second specifies two large-communities, which overwrites the current
   large-community list. The third will add a large-community value without
   overwriting other values. Multiple large-community values can be specified.


.. _bgp-vrfs:

VRFs
----

BGP supports multiple VRF instances with the following command:

.. index:: router bgp ASN vrf VRFNAME
.. clicmd:: router bgp ASN vrf VRFNAME

``VRFNAME`` is matched against VRFs configured in the kernel. When
``vrf VRFNAME`` is not specified, the BGP protocol process belongs to the
default VRF.

With VRF, you can isolate networking information. Having BGP VRF allows you to
have several BGP instances on the same system process. This solution solves
scalabiliy issues where the network administrator had previously to run
separately several BGP processes on each namespace. Now, not only BGP VRF
solves this, but also this method applies to both kind of VRFs backend: default
VRF from Linux kernel or network namespaces. Also, having separate BGP
instances does not imply that the AS number has to be different. For internal
purposes, it is possible to do iBGP peering from two differents network
namespaces.

VRF Route Leaking
^^^^^^^^^^^^^^^^^

BGP routes may be leaked (i.e. copied) between a unicast VRF RIB and the VPN
SAFI RIB of the default VRF for use in MPLS-based L3VPNs. Unicast routes may
also be leaked between any VRFs (including the unicast RIB of the default BGP
instanced). A shortcut syntax is also available for specifying leaking from one
VRF to another VRF using the default instance's VPN RIB as the intemediary. A
common application of the VRF-VRF feature is to connect a customer's private
routing domain to a provider's VPN service. Leaking is configured from the
point of view of an individual VRF: ``import`` refers to routes leaked from VPN
to a unicast VRF, whereas ``export`` refers to routes leaked from a unicast VRF
to VPN.

Required parameters
"""""""""""""""""""

Routes exported from a unicast VRF to the VPN RIB must be augmented by two
parameters:

- an :abbr:`RD (Route Distinguisher)`
- an :abbr:`RTLIST (Route-target List)`

Configuration for these exported routes must, at a minimum, specify these two
parameters.

Routes imported from the VPN RIB to a unicast VRF are selected according to
their RTLISTs.  Routes whose RTLIST contains at least one route-target in
common with the configured import RTLIST are leaked.  Configuration for these
imported routes must specify an RTLIST to be matched.

The RD, which carries no semantic value, is intended to make the route unique
in the VPN RIB among all routes of its prefix that originate from all the
customers and sites that are attached to the provider's VPN service.
Accordingly, each site of each customer is typically assigned an RD that is
unique across the entire provider network.

The RTLIST is a set of route-target extended community values whose purpose is
to specify route-leaking policy. Typically, a customer is assigned a single
route-target value for import and export to be used at all customer sites. This
configuration specifies a simple topology wherein a customer has a single
routing domain which is shared across all its sites. More complex routing
topologies are possible through use of additional route-targets to augment the
leaking of sets of routes in various ways.

When using the shortcut syntax for vrf-to-vrf leaking, the RD and RT are
auto-derived.

General configuration
"""""""""""""""""""""

Configuration of route leaking between a unicast VRF RIB and the VPN SAFI RIB
of the default VRF is accomplished via commands in the context of a VRF
address-family:

.. index:: rd vpn export AS:NN|IP:nn
.. clicmd:: rd vpn export AS:NN|IP:nn

   Specifies the route distinguisher to be added to a route exported from the
   current unicast VRF to VPN.

.. index:: no rd vpn export [AS:NN|IP:nn]
.. clicmd:: no rd vpn export [AS:NN|IP:nn]

   Deletes any previously-configured export route distinguisher.

.. index:: rt vpn import|export|both RTLIST...
.. clicmd:: rt vpn import|export|both RTLIST...

   Specifies the route-target list to be attached to a route (export) or the
   route-target list to match against (import) when exporting/importing between
   the current unicast VRF and VPN.

   The RTLIST is a space-separated list of route-targets, which are BGP
   extended community values as described in
   :ref:`bgp-extended-communities-attribute`.

.. index:: no rt vpn import|export|both [RTLIST...]
.. clicmd:: no rt vpn import|export|both [RTLIST...]

   Deletes any previously-configured import or export route-target list.

.. index:: label vpn export (0..1048575)|auto
.. clicmd:: label vpn export (0..1048575)|auto

   Specifies an optional MPLS label to be attached to a route exported from the
   current unicast VRF to VPN. If label is specified as ``auto``, the label
   value is automatically assigned from a pool maintained by the zebra
   daemon. If zebra is not running, automatic label assignment will not
   complete, which will block corresponding route export.

.. index:: no label vpn export [(0..1048575)|auto]
.. clicmd:: no label vpn export [(0..1048575)|auto]

   Deletes any previously-configured export label.

.. index:: nexthop vpn export A.B.C.D|X:X::X:X
.. clicmd:: nexthop vpn export A.B.C.D|X:X::X:X

   Specifies an optional nexthop value to be assigned to a route exported from
   the current unicast VRF to VPN. If left unspecified, the nexthop will be set
   to 0.0.0.0 or 0:0::0:0 (self).

.. index:: no nexthop vpn export [A.B.C.D|X:X::X:X]
.. clicmd:: no nexthop vpn export [A.B.C.D|X:X::X:X]

   Deletes any previously-configured export nexthop.

.. index:: route-map vpn import|export MAP
.. clicmd:: route-map vpn import|export MAP

   Specifies an optional route-map to be applied to routes imported or exported
   between the current unicast VRF and VPN.

.. index:: no route-map vpn import|export [MAP]
.. clicmd:: no route-map vpn import|export [MAP]

   Deletes any previously-configured import or export route-map.

.. index:: import|export vpn
.. clicmd:: import|export vpn

   Enables import or export of routes between the current unicast VRF and VPN.

.. index:: no import|export vpn
.. clicmd:: no import|export vpn

   Disables import or export of routes between the current unicast VRF and VPN.

.. index:: import vrf VRFNAME
.. clicmd:: import vrf VRFNAME

   Shortcut syntax for specifying automatic leaking from vrf VRFNAME to
   the current VRF using the VPN RIB as intermediary.  The RD and RT
   are auto derived and should not be specified explicitly for either the
   source or destination VRF's.

   This shortcut syntax mode is not compatible with the explicit
   `import vpn` and `export vpn` statements for the two VRF's involved.
   The CLI will disallow attempts to configure incompatible leaking
   modes.

.. index:: no import vrf VRFNAME
.. clicmd:: no import vrf VRFNAME

   Disables automatic leaking from vrf VRFNAME to the current VRF using
   the VPN RIB as intermediary.

.. _bgp-instances-and-views:

Instances and Views
-------------------

A BGP *instance* is a normal BGP process. Routes selected by BGP are installed
into the kernel routing table.

.. note::
   In previous versions of FRR, running multiple AS's from the same BGP process
   was not supported; in order to run multiple AS's it was necessary to run
   multiple BGP processes. This had to be explicitly configured with the
   ``bgp multiple-instance`` command. Recent versions of FRR support multiple
   BGP AS's within the same process by simply defining multiple
   ``router bgp X`` blocks, so the ``multiple-instance`` command is now
   unnecessary and deprecated.

.. index:: router bgp AS-NUMBER
.. clicmd:: router bgp AS-NUMBER

   Make a new BGP instance. You can use an arbitrary word for the `name`.

   .. code-block:: frr

      router bgp 1
       neighbor 10.0.0.1 remote-as 2
       neighbor 10.0.0.2 remote-as 3
      !
      router bgp 2
       neighbor 10.0.0.3 remote-as 4
       neighbor 10.0.0.4 remote-as 5

.. deprecated:: 5.0
   This command does nothing and can be safely removed.

.. index:: bgp multiple-instance
.. clicmd:: bgp multiple-instance

   Enable BGP multiple instance feature. Because this is now the default
   configuration this command will not be displayed in the running
   configuration.

.. deprecated:: 5.0
   This command does nothing and can be safely removed.

.. index:: no bgp multiple-instance
.. clicmd:: no bgp multiple-instance

   In previous versions of FRR, this command disabled the BGP multiple instance
   feature. This functionality is automatically turned on when BGP multiple
   instances or views exist so this command no longer does anything.

BGP views are almost same as normal BGP processes, except that routes selected
by BGP are not installed into the kernel routing table. The view functionality
allows the exchange of BGP routing information only without affecting the
kernel routing tables.

.. index:: router bgp AS-NUMBER view NAME
.. clicmd:: router bgp AS-NUMBER view NAME

   Make a new BGP view. You can use arbitrary word for the ``NAME``. Routes selected by the view are not installed into the kernel routing table.
   view's route selection result does not go to the kernel routing table.

   With this command, you can setup Route Server like below.

   .. code-block:: frr

      !
      router bgp 1 view 1
       neighbor 10.0.0.1 remote-as 2
       neighbor 10.0.0.2 remote-as 3
      !
      router bgp 2 view 2
       neighbor 10.0.0.3 remote-as 4
       neighbor 10.0.0.4 remote-as 5

.. index:: show ip bgp view NAME
.. clicmd:: show ip bgp view NAME

   Display the routing table of BGP view ``NAME``.

.. _bgp-cisco-compatibility:

Cisco Compatibility
-------------------

FRR has commands that change some configuration syntax and default behavior to
behave more closely to Cisco conventions. These are deprecated and will be
removed in a future version of FRR.

.. deprecated:: 5.0
   Please transition to using the FRR specific syntax for your configuration.

.. index:: bgp config-type cisco
.. clicmd:: bgp config-type cisco

   Cisco compatible BGP configuration output.

   When this configuration line is specified:

   - ``no synchronization`` is displayed.  This command does nothing and is for
     display purposes only.
   - ``no auto-summary`` is displayed.
   - The ``network`` and ``aggregate-address`` arguments are displayed as:

     ::

        A.B.C.D M.M.M.M

        FRR: network 10.0.0.0/8
        Cisco: network 10.0.0.0

        FRR: aggregate-address 192.168.0.0/24
        Cisco: aggregate-address 192.168.0.0 255.255.255.0

   Community attribute handling is also different. If no configuration is
   specified community attribute and extended community attribute are sent to
   the neighbor. If a user manually disables the feature, the community
   attribute is not sent to the neighbor. When ``bgp config-type cisco`` is
   specified, the community attribute is not sent to the neighbor by default.
   To send the community attribute user has to specify
   :clicmd:`neighbor A.B.C.D send-community` like so:

   .. code-block:: frr

      !
      router bgp 1
       neighbor 10.0.0.1 remote-as 1
       address-family ipv4 unicast
        no neighbor 10.0.0.1 send-community
       exit-address-family
      !
      router bgp 1
       neighbor 10.0.0.1 remote-as 1
       address-family ipv4 unicast
        neighbor 10.0.0.1 send-community
       exit-address-family
      !

.. deprecated:: 5.0
   Please transition to using the FRR specific syntax for your configuration.

.. index:: bgp config-type zebra
.. clicmd:: bgp config-type zebra

   FRR style BGP configuration. This is the default.

.. _bgp-debugging:

Debugging
---------

.. index:: show debug
.. clicmd:: show debug

   Show all enabled debugs.

.. index:: [no] debug bgp neighbor-events
.. clicmd:: [no] debug bgp neighbor-events

   Enable or disable debugging for neighbor events. This provides general
   information on BGP events such as peer connection / disconnection, session
   establishment / teardown, and capability negotiation.

.. index:: [no] debug bgp updates
.. clicmd:: [no] debug bgp updates

   Enable or disable debugging for BGP updates. This provides information on
   BGP UPDATE messages transmitted and received between local and remote
   instances.

.. index:: [no] debug bgp keepalives
.. clicmd:: [no] debug bgp keepalives

   Enable or disable debugging for BGP keepalives. This provides information on
   BGP KEEPALIVE messages transmitted and received between local and remote
   instances.

.. index:: [no] debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>
.. clicmd:: [no] debug bgp bestpath <A.B.C.D/M|X:X::X:X/M>

   Enable or disable debugging for bestpath selection on the specified prefix.

.. index:: [no] debug bgp nht
.. clicmd:: [no] debug bgp nht

   Enable or disable debugging of BGP nexthop tracking.

.. index:: [no] debug bgp update-groups
.. clicmd:: [no] debug bgp update-groups

   Enable or disable debugging of dynamic update groups. This provides general
   information on group creation, deletion, join and prune events.

.. index:: [no] debug bgp zebra
.. clicmd:: [no] debug bgp zebra

   Enable or disable debugging of communications between *bgpd* and *zebra*.

Dumping Messages and Routing Tables
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. index:: dump bgp all PATH [INTERVAL]
.. clicmd:: dump bgp all PATH [INTERVAL]

.. index:: dump bgp all-et PATH [INTERVAL]
.. clicmd:: dump bgp all-et PATH [INTERVAL]

.. index:: no dump bgp all [PATH] [INTERVAL]
.. clicmd:: no dump bgp all [PATH] [INTERVAL]

   Dump all BGP packet and events to `path` file.
   If `interval` is set, a new file will be created for echo `interval` of
   seconds.  The path `path` can be set with date and time formatting
   (strftime).  The type ‘all-et’ enables support for Extended Timestamp Header
   (:ref:`packet-binary-dump-format`).

.. index:: dump bgp updates PATH [INTERVAL]
.. clicmd:: dump bgp updates PATH [INTERVAL]

.. index:: dump bgp updates-et PATH [INTERVAL]
.. clicmd:: dump bgp updates-et PATH [INTERVAL]

.. index:: no dump bgp updates [PATH] [INTERVAL]
.. clicmd:: no dump bgp updates [PATH] [INTERVAL]

   Dump only BGP updates messages to `path` file.
   If `interval` is set, a new file will be created for echo `interval` of
   seconds.  The path `path` can be set with date and time formatting
   (strftime).  The type ‘updates-et’ enables support for Extended Timestamp
   Header (:ref:`packet-binary-dump-format`).

.. index:: dump bgp routes-mrt PATH
.. clicmd:: dump bgp routes-mrt PATH

.. index:: dump bgp routes-mrt PATH INTERVAL
.. clicmd:: dump bgp routes-mrt PATH INTERVAL

.. index:: no dump bgp route-mrt [PATH] [INTERVAL]
.. clicmd:: no dump bgp route-mrt [PATH] [INTERVAL]

   Dump whole BGP routing table to `path`. This is heavy process. The path
   `path` can be set with date and time formatting (strftime). If `interval` is
   set, a new file will be created for echo `interval` of seconds.

   Note: the interval variable can also be set using hours and minutes: 04h20m00.


.. _bgp-other-commands:

Other BGP Commands
------------------

.. index:: clear bgp ipv4|ipv6 \*
.. clicmd:: clear bgp ipv4|ipv6 \*

   Clear all address family peers.

.. index:: clear bgp ipv4|ipv6 PEER
.. clicmd:: clear bgp ipv4|ipv6 PEER

   Clear peers which have addresses of X.X.X.X

.. index:: clear bgp ipv4|ipv6 PEER soft in
.. clicmd:: clear bgp ipv4|ipv6 PEER soft in

   Clear peer using soft reconfiguration.


.. _bgp-displaying-bgp-information:

Displaying BGP Information
==========================

.. index:: show ip bgp
.. clicmd:: show ip bgp

.. index:: show ip bgp A.B.C.D
.. clicmd:: show ip bgp A.B.C.D

.. index:: show ip bgp X:X::X:X
.. clicmd:: show ip bgp X:X::X:X

   These commands display BGP routes. When no route is specified, the default
   is to display all IPv4 BGP routes.

   ::

      BGP table version is 0, local router ID is 10.1.1.1
         Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
         Origin codes: i - IGP, e - EGP, ? - incomplete

      Network    Next Hop      Metric LocPrf Weight Path
         \*> 1.1.1.1/32       0.0.0.0      0   32768 i

         Total number of prefixes 1

.. index:: show ip bgp regexp LINE
.. clicmd:: show ip bgp regexp LINE

   This command displays BGP routes using AS path regular expression
   (:ref:`bgp-regular-expressions`).

.. index:: show bgp <ipv4|ipv6> summary
.. clicmd:: show bgp <ipv4|ipv6> summary

   Show a bgp peer summary for the specified address family.

.. index:: show bgp <ipv4|ipv6> neighbor [PEER]
.. clicmd:: show bgp <ipv4|ipv6> neighbor [PEER]

   This command shows information on a specific BGP `peer`.

.. index:: show bgp <ipv4|ipv6> dampening dampened-paths
.. clicmd:: show bgp <ipv4|ipv6> dampening dampened-paths

   Display paths suppressed due to dampening.

.. index:: show bgp <ipv4|ipv6> dampening flap-statistics
.. clicmd:: show bgp <ipv4|ipv6> dampening flap-statistics

   Display flap statistics of routes.

.. _bgp-display-routes-by-community:

Displaying Routes by Community Attribute
----------------------------------------

The following commands allow displaying routes based on their community
attribute.

.. index:: show [ip] bgp <ipv4|ipv6> community
.. clicmd:: show [ip] bgp <ipv4|ipv6> community

.. index:: show [ip] bgp <ipv4|ipv6> community COMMUNITY
.. clicmd:: show [ip] bgp <ipv4|ipv6> community COMMUNITY

.. index:: show [ip] bgp <ipv4|ipv6> community COMMUNITY exact-match
.. clicmd:: show [ip] bgp <ipv4|ipv6> community COMMUNITY exact-match

   These commands display BGP routes which have the community attribute.
   attribute. When ``COMMUNITY`` is specified, BGP routes that match that
   community are displayed. When `exact-match` is specified, it display only
   routes that have an exact match.

.. index:: show [ip] bgp <ipv4|ipv6> community-list WORD
.. clicmd:: show [ip] bgp <ipv4|ipv6> community-list WORD

.. index:: show [ip] bgp <ipv4|ipv6> community-list WORD exact-match
.. clicmd:: show [ip] bgp <ipv4|ipv6> community-list WORD exact-match

   These commands display BGP routes for the address family specified that
   match the specified community list. When `exact-match` is specified, it
   displays only routes that have an exact match.

.. _bgp-display-routes-by-as-path:

Displaying Routes by AS Path
----------------------------

.. index:: show bgp ipv4|ipv6 regexp LINE
.. clicmd:: show bgp ipv4|ipv6 regexp LINE

   This commands displays BGP routes that matches a regular
   expression `line` (:ref:`bgp-regular-expressions`).

.. index:: show ip bgp ipv4 vpn
.. clicmd:: show ip bgp ipv4 vpn

.. index:: show ip bgp ipv6 vpn
.. clicmd:: show ip bgp ipv6 vpn

   Print active IPV4 or IPV6 routes advertised via the VPN SAFI.

.. index:: show bgp ipv4 vpn summary
.. clicmd:: show bgp ipv4 vpn summary

.. index:: show bgp ipv6 vpn summary
.. clicmd:: show bgp ipv6 vpn summary

   Print a summary of neighbor connections for the specified AFI/SAFI combination.


.. _bgp-route-reflector:

Route Reflector
===============

.. note:: This documentation is woefully incomplete.

.. index:: bgp cluster-id A.B.C.D
.. clicmd:: bgp cluster-id A.B.C.D

.. index:: neighbor PEER route-reflector-client
.. clicmd:: neighbor PEER route-reflector-client

.. index:: no neighbor PEER route-reflector-client
.. clicmd:: no neighbor PEER route-reflector-client


.. _routing-policy:

Routing Policy
==============

You can set different routing policy for a peer. For example, you can set
different filter for a peer.

.. code-block:: frr

   bgp multiple-instance
   !
   router bgp 1 view 1
    neighbor 10.0.0.1 remote-as 2
    address-family ipv4 unicast
     neighbor 10.0.0.1 distribute-list 1 in
    exit-address-family
   !
   router bgp 1 view 2
    neighbor 10.0.0.1 remote-as 2
    address-family ipv4 unicast
     neighbor 10.0.0.1 distribute-list 2 in
    exit-address-family

This means BGP update from a peer 10.0.0.1 goes to both BGP view 1 and view 2.
When the update is inserted into view 1, distribute-list 1 is applied. On the
other hand, when the update is inserted into view 2, distribute-list 2 is
applied.


.. _bgp-regular-expressions:

BGP Regular Expressions
=======================

BGP regular expressions are based on :t:`POSIX 1003.2` regular expressions. The
following description is just a quick subset of the POSIX regular expressions.


.\*
   Matches any single character.

\*
   Matches 0 or more occurrences of pattern.

\+
   Matches 1 or more occurrences of pattern.

?
   Match 0 or 1 occurrences of pattern.

^
   Matches the beginning of the line.

$
   Matches the end of the line.

_
   The ``_`` character has special meanings in BGP regular expressions.  It
   matches to space and comma , and AS set delimiter ``{`` and ``}`` and AS
   confederation delimiter ``(`` and ``)``. And it also matches to the
   beginning of the line and the end of the line. So ``_`` can be used for AS
   value boundaries match. This character technically evaluates to
   ``(^|[,{}()]|$)``.


.. _bgp-configuration-examples:

Miscellaneous Configuration Examples
====================================

Example of a session to an upstream, advertising only one prefix to it.

.. code-block:: frr

   router bgp 64512
    bgp router-id 10.236.87.1
    neighbor upstream peer-group
    neighbor upstream remote-as 64515
    neighbor upstream capability dynamic
    neighbor 10.1.1.1 peer-group upstream
    neighbor 10.1.1.1 description ACME ISP

    address-family ipv4 unicast
     network 10.236.87.0/24
     neighbor upstream prefix-list pl-allowed-adv out
    exit-address-family
   !
   ip prefix-list pl-allowed-adv seq 5 permit 82.195.133.0/25
   ip prefix-list pl-allowed-adv seq 10 deny any

A more complex example including upstream, peer and customer sessions
advertising global prefixes and NO_EXPORT prefixes and providing actions for
customer routes based on community values. Extensive use is made of route-maps
and the 'call' feature to support selective advertising of prefixes. This
example is intended as guidance only, it has NOT been tested and almost
certainly contains silly mistakes, if not serious flaws.

.. code-block:: frr

   router bgp 64512
    bgp router-id 10.236.87.1
    neighbor upstream capability dynamic
    neighbor cust capability dynamic
    neighbor peer capability dynamic
    neighbor 10.1.1.1 remote-as 64515
    neighbor 10.1.1.1 peer-group upstream
    neighbor 10.2.1.1 remote-as 64516
    neighbor 10.2.1.1 peer-group upstream
    neighbor 10.3.1.1 remote-as 64517
    neighbor 10.3.1.1 peer-group cust-default
    neighbor 10.3.1.1 description customer1
    neighbor 10.4.1.1 remote-as 64518
    neighbor 10.4.1.1 peer-group cust
    neighbor 10.4.1.1 description customer2
    neighbor 10.5.1.1 remote-as 64519
    neighbor 10.5.1.1 peer-group peer
    neighbor 10.5.1.1 description peer AS 1
    neighbor 10.6.1.1 remote-as 64520
    neighbor 10.6.1.1 peer-group peer
    neighbor 10.6.1.1 description peer AS 2

    address-family ipv4 unicast
     network 10.123.456.0/24
     network 10.123.456.128/25 route-map rm-no-export
     neighbor upstream route-map rm-upstream-out out
     neighbor cust route-map rm-cust-in in
     neighbor cust route-map rm-cust-out out
     neighbor cust send-community both
     neighbor peer route-map rm-peer-in in
     neighbor peer route-map rm-peer-out out
     neighbor peer send-community both
     neighbor 10.3.1.1 prefix-list pl-cust1-network in
     neighbor 10.4.1.1 prefix-list pl-cust2-network in
     neighbor 10.5.1.1 prefix-list pl-peer1-network in
     neighbor 10.6.1.1 prefix-list pl-peer2-network in
    exit-address-family
   !
   ip prefix-list pl-default permit 0.0.0.0/0
   !
   ip prefix-list pl-upstream-peers permit 10.1.1.1/32
   ip prefix-list pl-upstream-peers permit 10.2.1.1/32
   !
   ip prefix-list pl-cust1-network permit 10.3.1.0/24
   ip prefix-list pl-cust1-network permit 10.3.2.0/24
   !
   ip prefix-list pl-cust2-network permit 10.4.1.0/24
   !
   ip prefix-list pl-peer1-network permit 10.5.1.0/24
   ip prefix-list pl-peer1-network permit 10.5.2.0/24
   ip prefix-list pl-peer1-network permit 192.168.0.0/24
   !
   ip prefix-list pl-peer2-network permit 10.6.1.0/24
   ip prefix-list pl-peer2-network permit 10.6.2.0/24
   ip prefix-list pl-peer2-network permit 192.168.1.0/24
   ip prefix-list pl-peer2-network permit 192.168.2.0/24
   ip prefix-list pl-peer2-network permit 172.16.1/24
   !
   ip as-path access-list asp-own-as permit ^$
   ip as-path access-list asp-own-as permit _64512_
   !
   ! #################################################################
   ! Match communities we provide actions for, on routes receives from
   ! customers. Communities values of <our-ASN>:X, with X, have actions:
   !
   ! 100 - blackhole the prefix
   ! 200 - set no_export
   ! 300 - advertise only to other customers
   ! 400 - advertise only to upstreams
   ! 500 - set no_export when advertising to upstreams
   ! 2X00 - set local_preference to X00
   !
   ! blackhole the prefix of the route
   ip community-list standard cm-blackhole permit 64512:100
   !
   ! set no-export community before advertising
   ip community-list standard cm-set-no-export permit 64512:200
   !
   ! advertise only to other customers
   ip community-list standard cm-cust-only permit 64512:300
   !
   ! advertise only to upstreams
   ip community-list standard cm-upstream-only permit 64512:400
   !
   ! advertise to upstreams with no-export
   ip community-list standard cm-upstream-noexport permit 64512:500
   !
   ! set local-pref to least significant 3 digits of the community
   ip community-list standard cm-prefmod-100 permit 64512:2100
   ip community-list standard cm-prefmod-200 permit 64512:2200
   ip community-list standard cm-prefmod-300 permit 64512:2300
   ip community-list standard cm-prefmod-400 permit 64512:2400
   ip community-list expanded cme-prefmod-range permit 64512:2...
   !
   ! Informational communities
   !
   ! 3000 - learned from upstream
   ! 3100 - learned from customer
   ! 3200 - learned from peer
   !
   ip community-list standard cm-learnt-upstream permit 64512:3000
   ip community-list standard cm-learnt-cust permit 64512:3100
   ip community-list standard cm-learnt-peer permit 64512:3200
   !
   ! ###################################################################
   ! Utility route-maps
   !
   ! These utility route-maps generally should not used to permit/deny
   ! routes, i.e. they do not have meaning as filters, and hence probably
   ! should be used with 'on-match next'. These all finish with an empty
   ! permit entry so as not interfere with processing in the caller.
   !
   route-map rm-no-export permit 10
    set community additive no-export
   route-map rm-no-export permit 20
   !
   route-map rm-blackhole permit 10
    description blackhole, up-pref and ensure it cant escape this AS
    set ip next-hop 127.0.0.1
    set local-preference 10
    set community additive no-export
   route-map rm-blackhole permit 20
   !
   ! Set local-pref as requested
   route-map rm-prefmod permit 10
    match community cm-prefmod-100
    set local-preference 100
   route-map rm-prefmod permit 20
    match community cm-prefmod-200
    set local-preference 200
   route-map rm-prefmod permit 30
    match community cm-prefmod-300
    set local-preference 300
   route-map rm-prefmod permit 40
    match community cm-prefmod-400
    set local-preference 400
   route-map rm-prefmod permit 50
   !
   ! Community actions to take on receipt of route.
   route-map rm-community-in permit 10
    description check for blackholing, no point continuing if it matches.
    match community cm-blackhole
    call rm-blackhole
   route-map rm-community-in permit 20
    match community cm-set-no-export
    call rm-no-export
    on-match next
   route-map rm-community-in permit 30
    match community cme-prefmod-range
    call rm-prefmod
   route-map rm-community-in permit 40
   !
   ! #####################################################################
   ! Community actions to take when advertising a route.
   ! These are filtering route-maps,
   !
   ! Deny customer routes to upstream with cust-only set.
   route-map rm-community-filt-to-upstream deny 10
    match community cm-learnt-cust
    match community cm-cust-only
   route-map rm-community-filt-to-upstream permit 20
   !
   ! Deny customer routes to other customers with upstream-only set.
   route-map rm-community-filt-to-cust deny 10
    match community cm-learnt-cust
    match community cm-upstream-only
   route-map rm-community-filt-to-cust permit 20
   !
   ! ###################################################################
   ! The top-level route-maps applied to sessions. Further entries could
   ! be added obviously..
   !
   ! Customers
   route-map rm-cust-in permit 10
    call rm-community-in
    on-match next
   route-map rm-cust-in permit 20
    set community additive 64512:3100
   route-map rm-cust-in permit 30
   !
   route-map rm-cust-out permit 10
    call rm-community-filt-to-cust
    on-match next
   route-map rm-cust-out permit 20
   !
   ! Upstream transit ASes
   route-map rm-upstream-out permit 10
    description filter customer prefixes which are marked cust-only
    call rm-community-filt-to-upstream
    on-match next
   route-map rm-upstream-out permit 20
    description only customer routes are provided to upstreams/peers
    match community cm-learnt-cust
   !
   ! Peer ASes
   ! outbound policy is same as for upstream
   route-map rm-peer-out permit 10
    call rm-upstream-out
   !
   route-map rm-peer-in permit 10
    set community additive 64512:3200


Example of how to set up a 6-Bone connection.

.. code-block:: frr

   ! bgpd configuration
   ! ==================
   !
   ! MP-BGP configuration
   !
   router bgp 7675
    bgp router-id 10.0.0.1
    neighbor 3ffe:1cfa:0:2:2a0:c9ff:fe9e:f56 remote-as `as-number`
   !
    address-family ipv6
    network 3ffe:506::/32
    neighbor 3ffe:1cfa:0:2:2a0:c9ff:fe9e:f56 activate
    neighbor 3ffe:1cfa:0:2:2a0:c9ff:fe9e:f56 route-map set-nexthop out
    neighbor 3ffe:1cfa:0:2:2c0:4fff:fe68:a231 remote-as `as-number`
    neighbor 3ffe:1cfa:0:2:2c0:4fff:fe68:a231 route-map set-nexthop out
    exit-address-family
   !
   ipv6 access-list all permit any
   !
   ! Set output nexthop address.
   !
   route-map set-nexthop permit 10
    match ipv6 address all
    set ipv6 nexthop global 3ffe:1cfa:0:2:2c0:4fff:fe68:a225
    set ipv6 nexthop local fe80::2c0:4fff:fe68:a225
   !
   log file bgpd.log
   !


.. include:: routeserver.rst

.. include:: rpki.rst

.. include:: flowspec.rst

.. [#med-transitivity-rant] For some set of objects to have an order, there *must* be some binary ordering relation that is defined for *every* combination of those objects, and that relation *must* be transitive. I.e.:, if the relation operator is <, and if a < b and b < c then that relation must carry over and it *must* be that a < c for the objects to have an order. The ordering relation may allow for equality, i.e. a < b and b < a may both be true and imply that a and b are equal in the order and not distinguished by it, in which case the set has a partial order. Otherwise, if there is an order, all the objects have a distinct place in the order and the set has a total order)
.. [bgp-route-osci-cond] McPherson, D. and Gill, V. and Walton, D., "Border Gateway Protocol (BGP) Persistent Route Oscillation Condition", IETF RFC3345
.. [stable-flexible-ibgp] Flavel, A. and M. Roughan, "Stable and flexible iBGP", ACM SIGCOMM 2009
.. [ibgp-correctness] Griffin, T. and G. Wilfong, "On the correctness of IBGP configuration", ACM SIGCOMM 2002
