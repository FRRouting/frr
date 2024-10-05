.. _route-map:

**********
Route Maps
**********

Route maps provide a means to both filter and/or apply actions to route, hence
allowing policy to be applied to routes.

For a route reflector to apply a ``route-map`` to reflected routes, be sure to
include ``bgp route-reflector allow-outbound-policy`` in ``router bgp`` mode.

Route maps are an ordered list of route map entries. Each entry may specify up
to four distinct sets of clauses:

.. glossary::

   Matching Conditions
      A route-map entry may, optionally, specify one or more conditions which
      must be matched if the entry is to be considered further, as governed by
      the Match Policy. If a route-map entry does not explicitly specify any
      matching conditions, then it always matches.

   Set Actions
      A route-map entry may, optionally, specify one or more Set Actions to set
      or modify attributes of the route.

   Matching Policy
      This specifies the policy implied if the :term:`Matching Conditions` are
      met or not met, and which actions of the route-map are to be taken, if
      any. The two possibilities are:

      - :dfn:`permit`: If the entry matches, then carry out the
        :term:`Set Actions`. Then finish processing the route-map, permitting
        the route, unless an :term:`Exit Policy` action indicates otherwise.

      - :dfn:`deny`: If the entry matches, then finish processing the route-map and
        deny the route (return `deny`).

      The `Matching Policy` is specified as part of the command which defines
      the ordered entry in the route-map. See below.

   Call Action
      Call to another route-map, after any :term:`Set Actions` have been
      carried out.  If the route-map called returns `deny` then processing of
      the route-map finishes and the route is denied, regardless of the
      :term:`Matching Policy` or the :term:`Exit Policy`. If the called
      route-map returns `permit`, then :term:`Matching Policy` and :term:`Exit
      Policy` govern further behaviour, as normal.

   Exit Policy
      An entry may, optionally, specify an alternative :dfn:`Exit Policy` to
      take if the entry matched, rather than the normal policy of exiting the
      route-map and permitting the route. The two possibilities are:

      - :dfn:`next`: Continue on with processing of the route-map entries.

      - :dfn:`goto N`: Jump ahead to the first route-map entry whose order in
        the route-map is >= N. Jumping to a previous entry is not permitted.

The default action of a route-map, if no entries match, is to deny.  I.e. a
route-map essentially has as its last entry an empty *deny* entry, which
matches all routes. To change this behaviour, one must specify an empty
*permit* entry as the last entry in the route-map.

To summarise the above:

+--------+--------+----------+
|        | Match  | No Match |
+========+========+==========+
| Permit | action | cont     |
+--------+--------+----------+
| Deny   | deny   | cont     |
+--------+--------+----------+

action
   - Apply *set* statements
   - If *call* is present, call given route-map. If that returns a ``deny``,
     finish processing and return ``deny``.
   - If *Exit Policy* is *next*, goto next route-map entry
   - If *Exit Policy* is *goto*, goto first entry whose order in the
     list is >= the given order.
   - Finish processing the route-map and permit the route.

deny
   The route is denied by the route-map (return ``deny``).

cont
   goto next route-map entry

.. _route-map-show-command:

.. clicmd:: show route-map [WORD] [json]

   Display data about each daemons knowledge of individual route-maps.
   If WORD is supplied narrow choice to that particular route-map.

   If the ``json`` option is specified, output is displayed in JSON format.

.. _route-map-clear-counter-command:

.. clicmd:: clear route-map counter [WORD]

   Clear counters that are being stored about the route-map utilization
   so that subsuquent show commands will indicate since the last clear.
   If WORD is specified clear just that particular route-map's counters.

.. _route-map-command:

Route Map Command
=================

.. clicmd:: route-map ROUTE-MAP-NAME (permit|deny) ORDER

   Configure the `order`'th entry in `route-map-name` with ``Match Policy`` of
   either *permit* or *deny*.

.. _route-map-match-command:

Route Map Match Command
=======================

.. clicmd:: match ip address ACCESS_LIST

   Matches the specified `access_list`

.. clicmd:: match ip address prefix-list PREFIX_LIST

   Matches the specified `PREFIX_LIST`

.. clicmd:: match ip address prefix-len 0-32

   Matches the specified `prefix-len`. This is a Zebra specific command.

.. clicmd:: match ipv6 address ACCESS_LIST

   Matches the specified `access_list`

.. clicmd:: match ipv6 address prefix-list PREFIX_LIST

   Matches the specified `PREFIX_LIST`

.. clicmd:: match ipv6 address prefix-len 0-128

   Matches the specified `prefix-len`. This is a Zebra specific command.

.. clicmd:: match ip next-hop ACCESS_LIST

   Match the next-hop according to the given access-list.

.. clicmd:: match ip next-hop address IPV4_ADDR

   This is a BGP specific match command. Matches the specified `ipv4_addr`.

.. clicmd:: match ip next-hop prefix-list PREFIX_LIST

   Match the next-hop according to the given prefix-list.

.. clicmd:: match ipv6 next-hop ACCESS_LIST

   Match the next-hop according to the given access-list.

.. clicmd:: match ipv6 next-hop address IPV6_ADDR

   This is a BGP specific match command. Matches the specified `ipv6_addr`.

.. clicmd:: match ipv6 next-hop prefix-list PREFIX_LIST

   Match the next-hop according to the given prefix-list.

.. clicmd:: match as-path AS_PATH

   Matches the specified `as_path`.

.. clicmd:: match metric METRIC

   Matches the specified `metric`.

.. clicmd:: match tag <untagged|(1-4294967295)>

   Matches the specified tag (or untagged) value associated with the route.

.. clicmd:: match local-preference METRIC

   Matches the specified `local-preference`.

.. clicmd:: match community COMMUNITY_LIST [<exact-match|any>]

   Matches the specified  `community_list`. ``exact-match`` specifies to
   do the exact matching of the communities, while ``any`` - can match any
   community specified in COMMUNITY_LIST.

.. clicmd:: match peer IPV4_ADDR

   This is a BGP specific match command. Matches the peer ip address
   if the neighbor was specified in this manner.

.. clicmd:: match peer IPV6_ADDR

   This is a BGP specific match command. Matches the peer ipv6
   address if the neighbor was specified in this manner.

.. clicmd:: match peer INTERFACE_NAME

  This is a BGP specific match command. Matches the peer
  interface name specified if the neighbor was specified
  in this manner.

.. clicmd:: match peer PEER_GROUP_NAME

  This is a BGP specific match command. Matches the peer
  group name specified for the peer in question.

.. clicmd:: match source-protocol PROTOCOL_NAME

  This is a ZEBRA and BGP specific match command.  Matches the
  originating protocol specified.

.. clicmd:: match source-instance NUMBER

  This is a ZEBRA specific match command.  The number is a range from (0-255).
  Matches the originating protocols instance specified.

.. clicmd:: match evpn route-type ROUTE_TYPE_NAME

  This is a BGP EVPN specific match command. It matches to EVPN route-type
  from type-1 (EAD route-type) to type-5 (Prefix route-type).
  User can provide in an integral form (1-5) or string form of route-type
  (i.e ead, macip, multicast, es, prefix).

.. clicmd:: match evpn vni NUMBER

  This is a BGP EVPN specific match command which matches to EVPN VNI id.
  The number is a range from (1-6777215).

.. _route-map-set-command:

Route Map Set Command
=====================

.. program:: configure

.. clicmd:: set tag <untagged|(1-4294967295)>

   Set a tag on the matched route.

   Additionally if you have compiled with the :option:`--enable-realms`
   configure option. Tag values from (1-255) are sent to the Linux kernel as a
   realm value. Then route policy can be applied. See the tc man page.  As
   a note realms cannot currently be used with the installation of nexthops
   as nexthop groups in the linux kernel.

.. clicmd:: set ip next-hop IPV4_ADDRESS

   Set the BGP nexthop address to the specified IPV4_ADDRESS.  For both
   incoming and outgoing route-maps.

.. clicmd:: set ip next-hop peer-address

   Set the BGP nexthop address to the address of the peer.  For an incoming
   route-map this means the ip address of our peer is used.  For an outgoing
   route-map this means the ip address of our self is used to establish the
   peering with our neighbor.

.. clicmd:: set ip next-hop unchanged

   Set the route-map as unchanged.  Pass the route-map through without
   changing it's value.

.. clicmd:: set ipv6 next-hop peer-address

   Set the BGP nexthop address to the address of the peer.  For an incoming
   route-map this means the ipv6 address of our peer is used.  For an outgoing
   route-map this means the ip address of our self is used to establish the
   peering with our neighbor.

.. clicmd:: set ipv6 next-hop prefer-global

   For Incoming and Import Route-maps if we receive a v6 global and v6 LL
   address for the route, then prefer to use the global address as the nexthop.

.. clicmd:: set ipv6 next-hop global IPV6_ADDRESS

   Set the next-hop to the specified IPV6_ADDRESS for both incoming and
   outgoing route-maps.

.. clicmd:: set local-preference LOCAL_PREF

   Set the BGP local preference to `local_pref`.

.. clicmd:: set local-preference +LOCAL_PREF

   Add the BGP local preference to an existing `local_pref`.

.. clicmd:: set local-preference -LOCAL_PREF

   Subtract the BGP local preference from an existing `local_pref`.

.. clicmd:: set distance (1-255)

   Set the Administrative distance to use for the route.
   This is only locally significant and will not be dispersed to peers.

.. clicmd:: set weight WEIGHT

   Set the route's weight.

.. clicmd:: set metric <[+|-](1-4294967295)|rtt|+rtt|-rtt>

   Set the route metric. When used with BGP, set the BGP attribute MED to a
   specific value. Use `+`/`-` to add or subtract the specified value to/from
   the existing/MED. Use `rtt` to set the MED to the round trip time or
   `+rtt`/`-rtt` to add/subtract the round trip time to/from the MED.

.. clicmd:: set min-metric <(0-4294967295)>

   Set the minimum meric for the route.

.. clicmd:: set max-metric <(0-4294967295)>

   Set the maximum meric for the route.

.. clicmd:: set aigp-metric <igp-metric|(1-4294967295)>

   Set the BGP attribute AIGP to a specific value. If ``igp-metric`` is specified,
   then the value is taken from the IGP protocol, otherwise an arbitrary value.

.. clicmd:: set as-path prepend AS_PATH

   Set the BGP AS path to prepend.

.. clicmd:: set as-path exclude AS-NUMBER...

   Drop AS-NUMBER from the BGP AS path.

.. clicmd:: set community COMMUNITY

   Set the BGP community attribute.

.. clicmd:: set extended-comm-list <EXTCOMMUNITY_LIST_NAME> delete

   Set BGP extended community list for deletion.

.. clicmd:: set ipv6 next-hop local IPV6_ADDRESS

   Set the BGP-4+ link local IPv6 nexthop address.

.. clicmd:: set origin ORIGIN <egp|igp|incomplete>

   Set BGP route origin.

.. clicmd:: set table (1-4294967295)

   Set the BGP table to a given table identifier

.. clicmd:: set sr-te color (1-4294967295)

   Set the color of a SR-TE Policy to be applied to a learned route. The SR-TE
   Policy is uniquely determined by the color and the BGP nexthop.

.. clicmd:: set l3vpn next-hop encapsulation gre

   Accept L3VPN traffic over GRE encapsulation.

.. _route-map-call-command:

Route Map Call Command
======================

.. clicmd:: call NAME

   Call route-map `name`. If it returns deny, deny the route and
   finish processing the route-map.


.. _route-map-exit-action-command:

Route Map Exit Action Command
=============================

.. clicmd:: on-match next

   Proceed on to the next entry in the route-map.

.. clicmd:: continue (1-65535)

   Proceed to the specified sequence in the route-map.

.. clicmd:: on-match goto N

   Proceed processing the route-map at the first entry whose order is >= N


.. _route-map-optimization-command:

Route Map Optimization Command
==============================

.. clicmd:: route-map ROUTE-MAP-NAME optimization

   Enable route-map processing optimization for `route-map-name`.
   The optimization is enabled by default.
   Instead of sequentially passing through all the route-map indexes
   until a match is found, the search for the best-match index will be
   based on a look-up in a prefix-tree. A per-route-map prefix-tree
   will be constructed for this purpose. The prefix-tree will compose
   of all the prefixes in all the prefix-lists that are included in the
   match rule of all the sequences of a route-map.


Route Map Examples
==================

A simple example of a route-map:

.. code-block:: frr

   route-map test permit 10
    match ip address 10
    set local-preference 200


This means that if a route matches ip access-list number 10 it's
local-preference value is set to 200.

See :ref:`bgp-configuration-examples` for examples of more sophisticated
usage of route-maps, including of the ``call`` action.

