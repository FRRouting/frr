.. _isis:

****
ISIS
****

:abbr:`ISIS (Intermediate System to Intermediate System)` is a routing protocol
which is described in :t:`ISO10589`, :rfc:`1195`, :rfc:`5308`. ISIS is an
:abbr:`IGP (Interior Gateway Protocol)`. Compared with :abbr:`RIP`,
:abbr:`ISIS` can provide scalable network support and faster convergence times
like :abbr:`OSPF`. ISIS is widely used in large networks such as :abbr:`ISP
(Internet Service Provider)` and carrier backbone networks.

.. _configuring-isisd:

Configuring isisd
=================

There are no *isisd* specific options. Common options can be specified
(:ref:`common-invocation-options`) to *isisd*. *isisd* needs to acquire
interface information from *zebra* in order to function. Therefore *zebra* must
be running before invoking *isisd*. Also, if *zebra* is restarted then *isisd*
must be too.

.. include:: config-include.rst

.. _isis-router:

ISIS router
===========

To start the ISIS process you have to specify the ISIS router. As of this
writing, *isisd* does not support multiple ISIS processes.

.. clicmd:: router isis WORD [vrf NAME]

   Enable or disable the ISIS process by specifying the ISIS domain with
   'WORD'.  *isisd* does not yet support multiple ISIS processes but you must
   specify the name of ISIS process. The ISIS process name 'WORD' is then used
   for interface (see command :clicmd:`ip router isis WORD`).

.. clicmd:: net XX.XXXX. ... .XXX.XX
   :daemon: isisd

   Set/Unset network entity title (NET) provided in ISO format.

.. clicmd:: hostname dynamic

   Enable support for dynamic hostname.

.. clicmd:: area-password [clear | md5] <password>

.. clicmd:: domain-password [clear | md5] <password>
   :daemon: isisd

   Configure the authentication password for an area, respectively a domain, as
   clear text or md5 one.

.. clicmd:: attached-bit [receive ignore | send]
   :daemon: isisd

   Set attached bit for inter-area traffic:

   - receive
     If LSP received with attached bit set, create default route to neighbor
   - send
     If L1|L2 router, set attached bit in LSP sent to L1 router

.. clicmd:: log-adjacency-changes
   :daemon: isisd

   Log changes in adjacency state.

.. clicmd:: log-pdu-drops

   Log any dropped PDUs.

.. clicmd:: metric-style [narrow | transition | wide]

   Set old-style (ISO 10589) or new-style packet formats:

   - narrow
     Use old style of TLVs with narrow metric
   - transition
     Send and accept both styles of TLVs during transition
   - wide
     Use new style of TLVs to carry wider metric. FRR uses this as a default value

.. clicmd:: advertise-high-metrics

   Advertise high metric value on all interfaces to gracefully shift traffic off the router. Reference: :rfc:`3277`
   
   For narrow metrics, the high metric value is 63; for wide metrics, 16777215; for transition metrics, 62.

.. clicmd:: set-overload-bit
   :daemon: isisd

   Set overload bit to avoid any transit traffic.

.. clicmd:: set-overload-bit on-startup (0-86400)

   Set overload bit on startup for the specified duration, in seconds. Reference: :rfc:`3277`

.. clicmd:: purge-originator
   :daemon: isisd

   Enable or disable :rfc:`6232` purge originator identification.

.. clicmd:: lsp-mtu (128-4352)

   Configure the maximum size of generated LSPs, in bytes.

.. clicmd:: advertise-passive-only

   Advertise prefixes of passive interfaces only.

.. _isis-timer:

ISIS Timer
==========

.. clicmd:: lsp-gen-interval [level-1 | level-2] (1-120)

   Set minimum interval in seconds between regenerating same LSP,
   globally, for an area (level-1) or a domain (level-2).

.. clicmd:: lsp-refresh-interval [level-1 | level-2] (1-65235)

   Set LSP refresh interval in seconds, globally, for an area (level-1) or a
   domain (level-2).

.. clicmd:: max-lsp-lifetime [level-1 | level-2] (350-65535)

   Set LSP maximum LSP lifetime in seconds, globally, for an area (level-1) or
   a domain (level-2).

.. clicmd:: spf-interval [level-1 | level-2] (1-120)

   Set minimum interval between consecutive SPF calculations in seconds.

.. _isis-fast-reroute:

ISIS Fast-Reroute
=================

Unless stated otherwise, commands in this section apply to all LFA
flavors (local LFA, Remote LFA and TI-LFA).

.. clicmd:: spf prefix-priority [critical | high | medium] WORD

   Assign a priority to the prefixes that match the specified access-list.

   By default loopback prefixes have medium priority and non-loopback prefixes
   have low priority.

.. clicmd:: fast-reroute priority-limit [critical | high | medium] [level-1 | level-2]

   Limit LFA backup computation up to the specified prefix priority.

.. clicmd:: fast-reroute lfa tiebreaker [downstream | lowest-backup-metric | node-protecting] index (1-255) [level-1 | level-2]

   Configure a tie-breaker for multiple local LFA backups. Lower indexes are
   processed first.

.. clicmd:: fast-reroute load-sharing disable [level-1 | level-2]

   Disable load sharing across multiple LFA backups.

.. clicmd:: fast-reroute remote-lfa prefix-list [WORD] [level-1 | level-2]

   Configure a prefix-list to select eligible PQ nodes for remote LFA
   backups (valid for all protected interfaces).

.. clicmd:: redistribute <ipv4 | ipv6> table (1-65535) <level-1 | level-2> [metric (0-16777215)|route-map WORD]

   Redistribute routes from a given routing table into the given ISIS
   level database.  Any default route will be ignored unless the
   `default-information originate` command is specified.

.. clicmd:: default-information originate <ipv4 | ipv6> <level-1 | level-2> [always] [metric (0-16777214)|route-map WORD]

   Originate a default route into the given ISIS level datbase.
   The `always` command will turn it on by default even if there
   is no default route in the system.

.. _isis-region:

ISIS region
===========

.. clicmd:: is-type [level-1 | level-1-2 | level-2-only]

   Define the ISIS router behavior:

   - level-1
     Act as a station router only
   - level-1-2
     Act as both a station router and an area router
   - level-2-only
     Act as an area router only

.. _isis-interface:

ISIS interface
==============

.. _ip-router-isis-word:

.. clicmd:: <ip|ipv6> router isis WORD

   Activate ISIS adjacency on this interface. Note that the name of ISIS
   instance must be the same as the one used to configure the ISIS process (see
   command :clicmd:`router isis WORD`). To enable IPv4, issue ``ip router isis
   WORD``; to enable IPv6, issue ``ipv6 router isis WORD``.

.. clicmd:: isis circuit-type [level-1 | level-1-2 | level-2]

   Configure circuit type for interface:

   - level-1
     Level-1 only adjacencies are formed
   - level-1-2
     Level-1-2 adjacencies are formed
   - level-2-only
     Level-2 only adjacencies are formed

.. clicmd:: isis csnp-interval (1-600) [level-1 | level-2]

   Set CSNP interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. clicmd:: isis hello padding

   Add padding to IS-IS hello packets.

.. clicmd:: isis hello padding during-adjacency-formation

   Add padding to IS-IS hello packets during adjacency formation only.

.. clicmd:: isis hello-interval [level-1 | level-2] (1-600)

   Set Hello interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. clicmd:: isis hello-multiplier [level-1 | level-2] (2-100)

   Set multiplier for Hello holding time globally, for an area (level-1) or a
   domain (level-2).

.. clicmd:: isis metric [level-1 | level-2] [(0-63) | (0-16777215)]

   Set default metric value globally, for an area (level-1) or a domain
   (level-2).  Max value depend if metric support narrow or wide value (see
   command :clicmd:`metric-style [narrow | transition | wide]`).

.. clicmd:: isis network point-to-point

   Set network type to 'Point-to-Point' (broadcast by default).

.. clicmd:: isis passive

   Configure the passive mode for this interface.

.. clicmd:: isis password [clear | md5] <password>

   Configure the authentication password (clear or encoded text) for the
   interface.

.. clicmd:: isis priority (0-127) [level-1 | level-2]

   Set priority for Designated Router election, globally, for the area
   (level-1) or the domain (level-2).

.. clicmd:: isis psnp-interval (1-120) [level-1 | level-2]

   Set PSNP interval in seconds globally, for an area (level-1) or a domain
   (level-2).

.. clicmd:: isis three-way-handshake

   Enable or disable :rfc:`5303` Three-Way Handshake for P2P adjacencies.
   Three-Way Handshake is enabled by default.

.. clicmd:: isis fast-reroute lfa [level-1 | level-2]

   Enable per-prefix local LFA fast reroute link protection.

.. clicmd:: isis fast-reroute lfa [level-1 | level-2] exclude interface IFNAME

   Exclude an interface from the local LFA backup nexthop computation.

.. clicmd:: isis fast-reroute remote-lfa tunnel mpls-ldp [level-1 | level-2]

   Enable per-prefix Remote LFA fast reroute link protection. Note that other
   routers in the network need to be configured to accept LDP targeted hello
   messages in order for RLFA to work.

.. clicmd:: isis fast-reroute remote-lfa maximum-metric (1-16777215) [level-1 | level-2]

   Limit Remote LFA PQ node selection within the specified metric.

.. clicmd:: isis fast-reroute ti-lfa [level-1|level-2] [node-protection [link-fallback]]

   Enable per-prefix TI-LFA fast reroute link or node protection.
   When node protection is used, option link-fallback enables the computation and use of
   link-protecting LFAs for destinations unprotected by node protection.

.. _showing-isis-information:

Showing ISIS information
========================

.. clicmd:: show isis [vrf <NAME|all>] summary [json]

   Show summary information about ISIS.

.. clicmd:: show isis [vrf <NAME|all>] hostname

   Show information about ISIS node.

.. clicmd:: show isis [vrf <NAME|all>] interface [detail] [IFNAME] [json]

   Show state and configuration of ISIS specified interface, or all interfaces
   if no interface is given with or without details.

.. clicmd:: show isis [vrf <NAME|all>] neighbor [detail] [SYSTEMID] [json]

   Show state and information of ISIS specified neighbor, or all neighbors if
   no system id is given with or without details.

.. clicmd:: show isis [vrf <NAME|all>] database [detail] [LSPID] [json]

   Show the ISIS database globally, for a specific LSP id without or with
   details.

.. clicmd:: show isis [vrf <NAME|all>] topology [level-1|level-2] [algorithm [(128-255)]]

   Show topology IS-IS paths to Intermediate Systems, globally, in area
   (level-1) or domain (level-2).

.. clicmd:: show isis [vrf <NAME|all>] route [level-1|level-2] [prefix-sid] [backup] [algorithm [(128-255)]]

   Show the ISIS routing table, as determined by the most recent SPF
   calculation.

.. clicmd:: show isis [vrf <NAME|all>] fast-reroute summary [level-1|level-2]

   Show information about the number of prefixes having LFA protection,
   and network-wide LFA coverage.


.. _isis-traffic-engineering:

Traffic Engineering
===================

.. note::

   IS-IS-TE supports RFC 5305 (base TE), RFC 6119 (IPv6) and RFC 7810 / 8570
   (Extended Metric) with or without Multi-Topology. All Traffic Engineering
   information are stored in a database formally named TED. However, best
   acccuracy is provided without Multi-Topology due to inconsistency of Traffic
   Engineering Advertisement of 3rd party commercial routers when MT is enabled.
   At this time, FRR offers partial support for some of the routing protocol
   extensions that can be used with MPLS-TE. FRR does not currently support a
   complete RSVP-TE solution.

.. clicmd:: mpls-te on

   Enable Traffic Engineering LSP flooding.

.. clicmd:: mpls-te router-address <A.B.C.D>

   Configure stable IP address for MPLS-TE.

.. clicmd:: mpls-te router-address ipv6 <X:X::X:X>

   Configure stable IPv6 address for MPLS-TE.

.. clicmd:: mpls-te export

   Export Traffic Engineering DataBase to other daemons through the ZAPI
   Opaque Link State messages.

.. clicmd:: show isis mpls-te interface

.. clicmd:: show isis mpls-te interface INTERFACE

   Show MPLS Traffic Engineering parameters for all or specified interface.

.. clicmd:: show isis mpls-te router

   Show Traffic Engineering router parameters.

.. clicmd:: show isis [vrf <NAME|all>] mpls-te database [detail|json]

.. clicmd:: show isis [vrf <NAME|all>] mpls-te database vertex [WORD] [detail|json]

.. clicmd:: show isis [vrf <NAME|all>] mpls-te database edge [A.B.C.D|X:X::X:X] [detail|json]

.. clicmd:: show isis [vrf <NAME|all>] mpls-te database subnet [A.B.C.D/M|X:X::X:X/M] [detail|json]

   Show Traffic Engineering Database

.. seealso::

   :ref:`ospf-traffic-engineering`

.. _isis-segment-routing:

Segment Routing
===============

This is an EXPERIMENTAL support of Segment Routing as per RFC8667
for MPLS dataplane. It supports IPv4, IPv6 and ECMP and has been
tested against Cisco & Juniper routers.

Known limitations:
 - No support for level redistribution (L1 to L2 or L2 to L1)
 - No support for binding SID
 - No support for SRMS
 - No support for SRLB
 - Only one SRGB and default SPF Algorithm is supported

.. clicmd:: segment-routing on

   Enable Segment Routing.

.. clicmd:: segment-routing global-block (16-1048575) (16-1048575) [local-block (16-1048575) (16-1048575)]

   Set the Segment Routing Global Block i.e. the label range used by MPLS
   to store label in the MPLS FIB for Prefix SID. Note that the block size
   may not exceed 65535. Optionally sets also the Segment Routing Local Block.
   The negative command always unsets both.

.. clicmd:: segment-routing node-msd (1-16)

   Set the Maximum Stack Depth supported by the router. The value depend of the
   MPLS dataplane. E.g. for Linux kernel, since version 4.13 the maximum value
   is 32.

.. clicmd:: segment-routing prefix <A.B.C.D/M|X:X::X:X/M> [algorithm (128-255)] <absolute (16-1048575)|index (0-65535) [no-php-flag|explicit-null] [n-flag-clear]

   prefix. The 'no-php-flag' means NO Penultimate Hop Popping that allows SR
   node to request to its neighbor to not pop the label. The 'explicit-null'
   flag allows SR node to request to its neighbor to send IP packet with the
   EXPLICIT-NULL label. The 'n-flag-clear' option can be used to explicitly
   clear the Node flag that is set by default for Prefix-SIDs associated to
   loopback addresses. This option is necessary to configure Anycast-SIDs.

.. clicmd:: show isis segment-routing node [algorithm [(128-255)]]

   Show detailed information about all learned Segment Routing Nodes.

.. _isis-flex-algo:

Flex-Algos (Flex-Algo)
======================

*isisd* supports some features of
`RFC 9350 <https://tools.ietf.org/html/rfc9350>`_ on an MPLS Segment-Routing
dataplane. The compatibility has been tested against Cisco.

IS-IS uses by default the `Shortest-Path-First` algorithm that basically
calculates paths based on the shortest total metric to the destinations.
Flex-Algo allows new algorithms to run in parallel to compute paths in different
manners, based on metrics (IGP metric or a new type of metrics such as Traffic
Engineering (TE) metric and minimum delay...) and constraints. New metric types
are not yet implemented but constraints are already operational. Constraints can
restrict paths to links with specific affinities or avoid links with specific
affinities. Combinations of these are also possible.

The administrator can configure up to 128 Flex-Algos in an IS-IS area.
To do so, it defines a set of Flex-Algo Definitions (FAD) which
have the following characteristics:

- a numeric identifier (ID) between 128 and 255 inclusive

- a set of constraints (basically, include or exclude a certain given set of
	links, designated by a admin-group)

- the calculation type (only the `Shortest-Path-First` is currently supported)

- the metric type (only the IGP inherited metric type is currently supported)

- some additional flags (not supported for the moment).

A subset of routers advertises the Flex-Algo Definitions (FAD) to the other
routers within an area. In order to use a common set of FADs, each router runs a
FAD election process for each locally configured algorithm, using the following
rules:

- If a locally configured FAD is not advertised to the area, the router does not
	participate in the particular flex algorithm.

- If a given flex algorithm is running, the participation in this particular
	flex algorithm stops when its advertisements are over.

- A router includes its own FAD in the election process if and only if it is
	advertised to the other routers.

- If only one router advertises the FAD, the FAD is elected.

- If several FADs are advertised with different priorities, the one with the
	highest priority value is selected.

- If there are multiple advertisements of the FAD with the same highest
	priority, the FAD of the router with the highest IS-IS system-ID is
	selected.

Routers only use the specifications of the elected FAD regardless of the locally
configured definitions. If a router does not support one of the FAD
characteristics, it stops participating in the Flex-Algo.

For each running Flex-Algo, the Segment-Routing SIDs must be
configured with values unique to the algorithm. It allows routers to identify
which flex algorithm they must use for a given packet.

The following commands configure Flex-Algo at the 'router isis' configuration
level. Segment-Routing prefixes must be configured for the Flex-Algo.

.. clicmd:: flex-algo (128-255)

   Add a Flex-Algo Definition (FAD) and enter the FAD configuration
   level. The algorithm ID value is in the range of 128 to 255 inclusive.

.. clicmd:: affinity-map NAME bit-position (0-255)

   Add the specified 'affinity-map'. Affinity-map definitions are used in
   FADs and in interfaces admin-group definition.

   Affinity-maps format in advertisement TLVs use the extended admin-group
   format defined in the RFC7308 section 2.2. The extended admin-group uses a
   256 bits field. If an affinity-map is set, the bit at the extended
   admin-group 'bit-position' is set 1, else it is set to 0.

The following commands configure Flex-Algo at the 'router isis' and
'flex-algo (128-255)' configuration level.

.. clicmd:: advertise-definition

   Advertise the current FAD to other IS-IS routers by using specific IS-IS
   TLVs. By default, the definition is is not shared with other routers.

   A router can advertise a FAD without participating in the Flex-Algo.

.. clicmd:: priority (0-255)

   Set the specified 'priority' in the current FAD advertisements .

.. clicmd:: metric-type [igp|te|delay]

   Set the 'metric-type' for the current FAD. 'igp' is
   the default value and refers to the classic 'Shortest-Path-First' algorithm.
   If the 'te' or the 'delay' metric is selected, the value is advertised but
   the flex algorithm is disabled locally because these types are not currently
   supported.

.. clicmd:: no metric-type

   Reset the 'metric-type' to the default 'igp' metric.

.. clicmd:: affinity exclude-any NAME

   Add the specified affinity to the list of exclude-any affinities. The
   Flex-Algo will compute paths that exclude the segments with any of
   the specified affinities.

.. clicmd:: no affinity exclude-any NAME

   Remove the specified affinity to the list of exclude-any affinities.

.. clicmd:: affinity include-all NAME

   Add the specified affinity to the list of include-all affinities. The
   Flex-Algo will compute paths that include the segments with all
   the specified affinities.

.. clicmd:: no affinity include-all NAME

   Remove the specified affinity to the list of include-all affinities.

.. clicmd:: affinity include-any NAME

   Add the specified affinity to the list of include-any affinities. The
   Flex-Algo will compute paths that include the segments with any of
   the specified affinities.

.. clicmd:: no affinity include-any NAME

   Remove the specified affinity to the list of include-any affinities.

The following commands configure Flex-Algo at the 'interface' configuration
level.

.. clicmd:: isis affinity flex-algo NAME

	Add the specified affinity to the interface.

.. clicmd:: no isis affinity flex-algo NAME

	Remove the specified affinity from the interface.

The following command show Flex-Algo information:

.. clicmd:: show isis flex-algo [(128-255)]

	Show information about the elected FADs

'show isis route', 'show isis topology' and 'show isis segment-routing node'
includes an 'algorithm (128-255)' optional argument. See
:ref:`showing-isis-information` and :ref:`isis-segment-routing`.

.. _isis-srv6:

Segment Routing over IPv6 (SRv6)
================================

This feature enables extensions in IS-IS to support Segment Routing over IPv6
data plane (SRv6) as per RFC 9352.

.. clicmd:: segment-routing srv6
   :daemon: isisd

   Enable Segment Routing over IPv6 data plane (SRv6).

.. clicmd:: locator NAME
   :daemon: isisd

   Specify the SRv6 locator to use for SRv6. The locator must be configured in
   Zebra. Once the locator is configured, IS-IS automatically allocates prefix
   SID and adjacency SIDs, creates local SID entries in the data plane, and
   advertises them in the IGP domain.

.. clicmd:: interface NAME

   Specify the dummy interface used to install SRv6 SIDs in the Linux data plane.
   The interface must be created manually. By default, the interface is 'sr0'.
   The interface can be created using the iproute2 utility:

   .. code-block:: bash

      ip link add sr0 type dummy
      ip link set sr0 up

.. clicmd:: show isis segment-routing srv6 node

   Show detailed information about all learned SRv6 Nodes.

.. _isis-srv6-tilfa:

SRv6 TI-LFA
-----------

Topology Independent Loop-Free Alternate (TI-LFA) provides fast reroute
protection by pre-computing backup paths before failures occur. When a link
or node fails, traffic is immediately switched to the backup path, achieving
sub-50ms convergence. This is an implementation of
`RFC 8402 <https://tools.ietf.org/html/rfc8402>`_ TI-LFA with SRv6 dataplane
as specified in `RFC 9352 <https://tools.ietf.org/html/rfc9352>`_.

TI-LFA uses Segment Routing to encode backup paths as a list of segments
(SIDs). Unlike classic LFA which depends on favorable network topology,
TI-LFA can protect any destination in any topology by steering traffic
through intermediate nodes.

With MPLS dataplane, TI-LFA uses label stacks where each label requires
SRGB (Segment Routing Global Block) translation. With SRv6 dataplane,
TI-LFA uses IPv6 addresses directly as segment identifiers:

- End SID: identifies a node (similar to Prefix-SID in MPLS)

- End.X SID: identifies an adjacency to a specific neighbor (similar to Adj-SID)

A key difference is that SRv6 End.X SIDs are globally routable IPv6 addresses.
Once traffic reaches the Q-node (the node adjacent to the destination on the
post-convergence path), normal IPv6 routing delivers it to the destination.
This means SRv6 TI-LFA does not need to push a destination SID, resulting in
shorter segment lists compared to MPLS.

TI-LFA supports three protection types:

- Link protection
  Protects against link failures. The backup path avoids the failed link but
  may traverse the same next-hop node.

- Node protection
  Protects against node failures. The backup path avoids both the failed link
  and the next-hop node entirely.

- SRLG protection
  Protects against shared risk failures. The backup path avoids all links that
  share the same SRLG values as the protected link.

Configuration
^^^^^^^^^^^^^

To enable SRv6 TI-LFA, configure both the global setting under
``segment-routing srv6`` and per-interface settings.

The following commands configure SRv6 TI-LFA at the ``segment-routing srv6``
configuration level:

.. clicmd:: fast-reroute ti-lfa

   Enable TI-LFA computation with SRv6 dataplane. This must be configured
   in addition to per-interface TI-LFA settings.

.. clicmd:: node-msd

   Enter Maximum SID Depth (MSD) configuration mode. MSD values are advertised
   to neighbors and used during TI-LFA computation to ensure backup paths do
   not exceed the router's segment processing capabilities.

.. clicmd:: max-segs-left (0-255)

   Specifies the maximum number of SIDs that can remain in the Segment Routing
   Header (SRH) when a packet is received by this node. This limits the depth
   of SRv6 segment stacks the router can process.

.. clicmd:: max-end-pop (0-255)

   Specifies the maximum number of SIDs that can be popped by the End.Pop
   behavior at this node.

.. clicmd:: max-h-encaps (0-255)

   Specifies the maximum number of SIDs that can be pushed when this node
   acts as a headend performing H.Encaps (SRv6 encapsulation).

.. clicmd:: max-end-d (0-255)

   Specifies the maximum number of SIDs in an SRH when applying End.DX
   (decapsulation with cross-connect) or End.DT (decapsulation with table
   lookup) behaviors.

The following command configures TI-LFA at the interface level:

.. clicmd:: isis fast-reroute ti-lfa [level-1|level-2] [node-protection [link-fallback]] [srlg-protection]

   Enable TI-LFA on the interface for the specified level (or both if not
   specified).

   - Without protection options: enables link protection only

   - ``node-protection``: enables node protection, which computes backup paths
     that avoid the next-hop node entirely

   - ``link-fallback``: when used with node-protection, falls back to link
     protection for destinations where node protection is not achievable

   - ``srlg-protection``: enables SRLG-aware backup path computation (see
     :ref:`isis-srlg-protection`)

.. _isis-srlg-protection:

SRLG Protection
^^^^^^^^^^^^^^^

Shared Risk Link Group (SRLG) identifies links that share a common physical
resource and are likely to fail together. For example, two fiber links in the
same conduit, or links crossing the same bridge, share failure risk. When one
fails, the other is likely to fail simultaneously.

SRLG protection extends TI-LFA to compute backup paths that avoid not only the
failed link but also all other links sharing any SRLG value with it. This
prevents backup path failures during correlated failure events. SRLG is
specified in `RFC 5307 <https://tools.ietf.org/html/rfc5307>`_.

Each interface is configured with one or more SRLG values (32-bit integers).
These values are advertised in IS-IS LSPs using the SRLG sub-TLV. When
computing TI-LFA backup paths with srlg-protection enabled, the algorithm
excludes any link whose SRLG set intersects with the protected link's SRLG set.

Configuration
"""""""""""""

.. clicmd:: isis srlg (0-16777215)

   Assign an SRLG value to the interface. Multiple SRLG values can be assigned
   by repeating the command. Each value represents membership in a shared risk
   group.

   Example: Two links in the same fiber conduit should be assigned the same
   SRLG value so that TI-LFA avoids using one as backup for the other.

To enable SRLG-aware TI-LFA, add the ``srlg-protection`` option to the
interface TI-LFA configuration:

.. code-block:: frr

   interface eth0
    isis fast-reroute ti-lfa level-1 srlg-protection
    isis srlg 100
    isis srlg 200
   !
   interface eth1
    isis fast-reroute ti-lfa level-1 srlg-protection
    isis srlg 100
   !

In this example, eth0 and eth1 share SRLG 100. If eth0 fails, TI-LFA will not
use eth1 as part of the backup path because they share a common SRLG.

Flex-Algo SRLG Constraints
^^^^^^^^^^^^^^^^^^^^^^^^^^

SRLG constraints can also be applied to Flexible Algorithm definitions,
allowing Flex-Algo to exclude links with specific SRLG values from its
topology.

.. clicmd:: srlg exclude-any (0-16777215)

   Under flex-algo configuration mode, exclude links that have the specified
   SRLG value. Multiple values can be excluded by repeating the command.

Show Commands
^^^^^^^^^^^^^

Use ``show isis fast-reroute summary`` (see :ref:`showing-isis-information`) to
display FRR protection statistics. Example output with TI-LFA protection::

   IS-IS Level-1 IPv4 Fast ReRoute summary:

   Protection \ Priority  Critical  High      Medium    Low       Total
   -------------------------------------------------------------------------
   Classic LFA            0         0         0         0         0
   Remote LFA             0         0         0         0         0
   Topology Independent   0         0         1         8         9
   ECMP                   0         0         0         0         0
   Unprotected            0         0         0         0         0
   Protection coverage    0.00%     0.00%     100.00%   100.00%   100.00%

This output shows that TI-LFA is protecting 9 prefixes with 100% coverage.

Use ``show isis route backup`` (see :ref:`showing-isis-information`) to display
TI-LFA backup paths. For SRv6, backup paths display the segment stack as IPv6
addresses separated by slashes. Example output::

   IS-IS Level-1 IPv6 routing table:

   Prefix            Metric  Interface  Nexthop          Label(s)
   ----------------------------------------------------------------
   fc00:0:3::1/128   20      eth-sw1    fe80::1          fc00:0:2:1::/fc00:0:3:42::

The Label(s) column shows the SRv6 segment stack: first the End SID of the
P-node (fc00:0:2:1::), then the End.X SID to reach the destination
(fc00:0:3:42::).

.. clicmd:: show isis [vrf <NAME|all>] srlg [level-1|level-2] [json]

   Display SRLG information learned from the IS-IS link-state database.
   Shows which links have SRLG values assigned and what those values are.

   Example output::

      Area FOO:
        Level-1 SRLG information:
          0000.0000.0001.00-00 -> 0000.0000.0002: 100 200
          0000.0000.0002.00-00 -> 0000.0000.0001: 100 200
          0000.0000.0002.00-00 -> 0000.0000.0003: 300

   This shows that the link between nodes 0001 and 0002 has SRLG values 100
   and 200, while the link from 0002 to 0003 has SRLG value 300.

Configuration Example
^^^^^^^^^^^^^^^^^^^^^

Complete SRv6 TI-LFA configuration with node protection and SRLG:

.. code-block:: frr

   ! Create the SRv6 interface (run as root before starting FRR)
   ! # ip link add sr0 type dummy
   ! # ip link set sr0 up

   ! Zebra configuration for SRv6 locator
   segment-routing
    srv6
     locators
      locator loc1
       prefix fc00:0:1::/48 block-len 32 node-len 16 func-bits 16
       behavior usid
   !
   ! Interface configuration
   interface lo
    ip address 1.1.1.1/32
    ipv6 address fc00:0:1::1/128
    ip router isis FOO
    ipv6 router isis FOO
    isis passive
   !
   interface eth-sw1
    ip address 10.0.1.1/24
    ipv6 address 2001:db8:1::1/64
    ip router isis FOO
    ipv6 router isis FOO
    isis hello-interval 1
    isis hello-multiplier 10
    isis fast-reroute ti-lfa level-1 node-protection link-fallback srlg-protection
    isis srlg 100
   !
   interface eth-sw2
    ip address 10.0.2.1/24
    ipv6 address 2001:db8:2::1/64
    ip router isis FOO
    ipv6 router isis FOO
    isis hello-interval 1
    isis hello-multiplier 10
    isis fast-reroute ti-lfa level-1 node-protection link-fallback srlg-protection
    isis srlg 100
   !
   ! Router configuration
   router isis FOO
    net 49.0000.0000.0000.0001.00
    is-type level-1
    topology ipv6-unicast
    segment-routing srv6
     locator loc1
     node-msd
      max-segs-left 3
      max-end-pop 3
      max-h-encaps 2
      max-end-d 5
     fast-reroute ti-lfa

In this example:

- SRv6 is enabled with locator ``loc1`` using micro-SID (uSID) behavior
- Node MSD values are configured to advertise segment processing capabilities
- Both eth-sw1 and eth-sw2 have TI-LFA enabled with node protection, link
  fallback, and SRLG protection
- Both interfaces share SRLG 100, so neither will be used as backup for the
  other during SRLG-protected failover

Debugging ISIS
==============

.. clicmd:: debug isis adj-packets

   IS-IS Adjacency related packets.

.. clicmd:: debug isis events

   IS-IS Events.

.. clicmd:: debug isis packet-dump

   IS-IS packet dump.

.. clicmd:: debug isis route-events

   IS-IS Route related events.

.. clicmd:: debug isis snp-packets

   IS-IS CSNP/PSNP packets.

.. clicmd:: debug isis spf-events

   IS-IS Shortest Path First Events.

.. clicmd:: debug isis update-packets


   Update related packets.

.. clicmd:: debug isis te-events

   IS-IS Traffic Engineering events

.. clicmd:: debug isis sr-events


   IS-IS Segment Routing events.

.. clicmd:: debug isis lfa


   IS-IS LFA events.

.. clicmd:: debug isis flooding

.. clicmd:: debug isis bfd

.. clicmd:: debug isis ldp-sync

.. clicmd:: debug isis tx-queue

.. clicmd:: show debugging isis

   Print which ISIS debug level is activate.

.. _isis-config-examples:

ISIS Configuration Examples
===========================

A simple example, with MD5 authentication enabled:

.. code-block:: frr

   !
   interface eth0
    ip router isis FOO
    isis network point-to-point
    isis circuit-type level-2-only
   !
   router isis FOO
   net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
    metric-style wide
    is-type level-2-only


A Traffic Engineering configuration, with Inter-ASv2 support.

First, the :file:`zebra.conf` part:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/zebra.log
   !
   interface eth0
    ip address 10.2.2.2/24
    link-params
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
     admin-grp 0xab
   !
   interface eth1
    ip address 10.1.1.1/24
    link-params
     enable
     metric 100
     max-bw 1.25e+07
     max-rsv-bw 1.25e+06
     unrsv-bw 0 1.25e+06
     unrsv-bw 1 1.25e+06
     unrsv-bw 2 1.25e+06
     unrsv-bw 3 1.25e+06
     unrsv-bw 4 1.25e+06
     unrsv-bw 5 1.25e+06
     unrsv-bw 6 1.25e+06
     unrsv-bw 7 1.25e+06
     neighbor 10.1.1.2 as 65000


Then the :file:`isisd.conf` itself:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/isisd.log
   !
   !
   interface eth0
    ip router isis FOO
   !
   interface eth1
    ip router isis FOO
   !
   !
   router isis FOO
    isis net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
     mpls-te on
     mpls-te router-address 10.1.1.1
   !
   line vty

A Segment Routing configuration, with IPv4, IPv6, SRGB and MSD configuration.

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/isisd.log
   !
   !
   interface eth0
    ip router isis SR
    isis network point-to-point
   !
   interface eth1
    ip router isis SR
   !
   !
   router isis SR
    net 49.0000.0000.0000.0001.00
    is-type level-1
    topology ipv6-unicast
    lsp-gen-interval 2
    segment-routing on
    segment-routing node-msd 8
    segment-routing prefix 10.1.1.1/32 index 100 explicit-null
    segment-routing prefix 2001:db8:1000::1/128 index 101 explicit-null
   !

An SRv6 configuration:

.. code-block:: frr

   hostname HOSTNAME
   password PASSWORD
   log file /var/log/isisd.log
   !
   !
   interface eth0
    ipv6 router isis FOO
    ip router isis FOO
    isis hello-interval 5
   !
   interface eth1
    ip router isis FOO
   !
   !
   router isis FOO
    net 49.0001.1111.1111.1111.00
    is-type level-2-only
    metric-style wide
    segment-routing srv6
     locator loc1
   !
   line vty


.. _isis-vrf-config-examples:

ISIS Vrf Configuration Examples
===============================

A simple vrf example:

.. code-block:: frr

   !
   interface eth0 vrf RED
    ip router isis FOO
    isis network point-to-point
    isis circuit-type level-2-only
   !
   router isis FOO vrf RED
    net 47.0023.0000.0000.0000.0000.0000.0000.1900.0004.00
    metric-style wide
    is-type level-2-only
