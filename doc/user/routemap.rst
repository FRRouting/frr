.. _route-map:

**********
Route Maps
**********

Route maps provide a means to both filter and/or apply actions to route, hence
allowing policy to be applied to routes.

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

.. index:: show route-map [WORD]
.. clicmd:: show route-map [WORD]

   Display data about each daemons knowledge of individual route-maps.
   If WORD is supplied narrow choice to that particular route-map.

.. _route-map-clear-counter-command:

.. index:: clear route-map counter [WORD]
.. clicmd:: clear route-map counter [WORD]

   Clear counters that are being stored about the route-map utilization
   so that subsuquent show commands will indicate since the last clear.
   If WORD is specified clear just that particular route-map's counters.

.. _route-map-command:

Route Map Command
=================

.. index:: route-map ROUTE-MAP-NAME (permit|deny) ORDER
.. clicmd:: route-map ROUTE-MAP-NAME (permit|deny) ORDER

   Configure the `order`'th entry in `route-map-name` with ``Match Policy`` of
   either *permit* or *deny*.

.. _route-map-match-command:

Route Map Match Command
=======================

.. index:: match ip address ACCESS_LIST
.. clicmd:: match ip address ACCESS_LIST

   Matches the specified `access_list`

.. index:: match ip address prefix-list PREFIX_LIST
.. clicmd:: match ip address prefix-list PREFIX_LIST

   Matches the specified `PREFIX_LIST`

.. index:: match ip address prefix-len 0-32
.. clicmd:: match ip address prefix-len 0-32

   Matches the specified `prefix-len`. This is a Zebra specific command.

.. index:: match ipv6 address ACCESS_LIST
.. clicmd:: match ipv6 address ACCESS_LIST

   Matches the specified `access_list`

.. index:: match ipv6 address prefix-list PREFIX_LIST
.. clicmd:: match ipv6 address prefix-list PREFIX_LIST

   Matches the specified `PREFIX_LIST`

.. index:: match ipv6 address prefix-len 0-128
.. clicmd:: match ipv6 address prefix-len 0-128

   Matches the specified `prefix-len`. This is a Zebra specific command.

.. index:: match ip next-hop IPV4_ADDR
.. clicmd:: match ip next-hop IPV4_ADDR

   Matches the specified `ipv4_addr`.

.. index:: match as-path AS_PATH
.. clicmd:: match as-path AS_PATH

   Matches the specified `as_path`.

.. index:: match metric METRIC
.. clicmd:: match metric METRIC

   Matches the specified `metric`.

.. index:: match tag TAG
.. clicmd:: match tag TAG

   Matches the specified tag value associated with the route. This tag value
   can be in the range of (1-4294967295).

.. index:: match local-preference METRIC
.. clicmd:: match local-preference METRIC

   Matches the specified `local-preference`.

.. index:: match community COMMUNITY_LIST
.. clicmd:: match community COMMUNITY_LIST

   Matches the specified  `community_list`

.. index:: match peer IPV4_ADDR
.. clicmd:: match peer IPV4_ADDR

   This is a BGP specific match command. Matches the peer ip address
   if the neighbor was specified in this manner.

.. index:: match peer IPV6_ADDR
.. clicmd:: match peer IPV6_ADDR

   This is a BGP specific match command. Matches the peer ipv6
   address if the neighbor was specified in this manner.

.. index:: match peer INTERFACE_NAME
.. clicmd:: match peer INTERFACE_NAME

  This is a BGP specific match command. Matches the peer
  interface name specified if the neighbor was specified
  in this manner.

.. index:: match source-protocol PROTOCOL_NAME
.. clicmd:: match source-protocol PROTOCOL_NAME

  This is a ZEBRA specific match command.  Matches the
  originating protocol specified.

.. index:: match source-instance NUMBER
.. clicmd:: match source-instance NUMBER

  This is a ZEBRA specific match command.  The number is a range from (0-255).
  Matches the originating protocols instance specified.

.. _route-map-set-command:

Route Map Set Command
=====================

.. program:: configure

.. index:: set tag TAG
.. clicmd:: set tag TAG

   Set a tag on the matched route. This tag value can be from (1-4294967295).
   Additionally if you have compiled with the :option:`--enable-realms`
   configure option. Tag values from (1-255) are sent to the Linux kernel as a
   realm value. Then route policy can be applied. See the tc man page.

.. index:: set ip next-hop IPV4_ADDRESS
.. clicmd:: set ip next-hop IPV4_ADDRESS

   Set the BGP nexthop address to the specified IPV4_ADDRESS.  For both
   incoming and outgoing route-maps.

.. index:: set ip next-hop peer-address
.. clicmd:: set ip next-hop peer-address

   Set the BGP nexthop address to the address of the peer.  For an incoming
   route-map this means the ip address of our peer is used.  For an outgoing
   route-map this means the ip address of our self is used to establish the
   peering with our neighbor.

.. index:: set ip next-hop unchanged
.. clicmd:: set ip next-hop unchanged

   Set the route-map as unchanged.  Pass the route-map through without
   changing it's value.

.. index:: set ipv6 next-hop peer-address
.. clicmd:: set ipv6 next-hop peer-address

   Set the BGP nexthop address to the address of the peer.  For an incoming
   route-map this means the ipv6 address of our peer is used.  For an outgoing
   route-map this means the ip address of our self is used to establish the
   peering with our neighbor.

.. index:: set ipv6 next-hop prefer-global
.. clicmd:: set ipv6 next-hop prefer-global

   For Incoming and Import Route-maps if we receive a v6 global and v6 LL
   address for the route, then prefer to use the global address as the nexthop.

.. index:: set ipv6 next-hop global IPV6_ADDRESS
.. clicmd:: set ipv6 next-hop global IPV6_ADDRESS

   Set the next-hop to the specified IPV6_ADDRESS for both incoming and
   outgoing route-maps.

.. index:: set local-preference LOCAL_PREF
.. clicmd:: set local-preference LOCAL_PREF

   Set the BGP local preference to `local_pref`.

.. index:: [no] set distance DISTANCE
.. clicmd:: [no] set distance DISTANCE

   Set the Administrative distance to DISTANCE to use for the route.
   This is only locally significant and will not be dispersed to peers.

.. index:: set weight WEIGHT
.. clicmd:: set weight WEIGHT

   Set the route's weight.

.. index:: set metric METRIC
.. clicmd:: set metric METRIC

   Set the BGP attribute MED.

.. index:: set as-path prepend AS_PATH
.. clicmd:: set as-path prepend AS_PATH

   Set the BGP AS path to prepend.

.. index:: set community COMMUNITY
.. clicmd:: set community COMMUNITY

   Set the BGP community attribute.

.. index:: set ipv6 next-hop local IPV6_ADDRESS
.. clicmd:: set ipv6 next-hop local IPV6_ADDRESS

   Set the BGP-4+ link local IPv6 nexthop address.

.. index:: set origin ORIGIN <egp|igp|incomplete>
.. clicmd:: set origin ORIGIN <egp|igp|incomplete>

   Set BGP route origin.

.. index:: set table (1-4294967295)
.. clicmd:: set table (1-4294967295)

   Set the BGP table to a given table identifier

.. _route-map-call-command:

Route Map Call Command
======================

.. index:: call NAME
.. clicmd:: call NAME

   Call route-map `name`. If it returns deny, deny the route and
   finish processing the route-map.

.. _route-map-exit-action-command:

Route Map Exit Action Command
=============================

.. index:: on-match next
.. clicmd:: on-match next

.. index:: continue
.. clicmd:: continue

   Proceed on to the next entry in the route-map.

.. index:: on-match goto N
.. clicmd:: on-match goto N

.. index:: continue N
.. clicmd:: continue N

   Proceed processing the route-map at the first entry whose order is >= N


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

