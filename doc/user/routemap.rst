.. _Route_Map:

*********
Route Map
*********

Route maps provide a means to both filter and/or apply actions to
route, hence allowing policy to be applied to routes.

Route-maps are an ordered list of route-map entries. Each entry may
specify up to four distincts sets of clauses:



*Matching Policy*
  This specifies the policy implied if the @samp{Matching Conditions} are
  met or not met, and which actions of the route-map are to be taken, if
  any. The two possibilities are:


**
    @samp{permit}: If the entry matches, then carry out the @samp{Set
    Actions}. Then finish processing the route-map, permitting the route,
    unless an @samp{Exit Action} indicates otherwise.


**
    @samp{deny}: If the entry matches, then finish processing the route-map and
    deny the route (return @samp{deny}).

  The @samp{Matching Policy} is specified as part of the command which
  defines the ordered entry in the route-map. See below.


*Matching Conditions*
  A route-map entry may, optionally, specify one or more conditions which
  must be matched if the entry is to be considered further, as governed
  by the Match Policy. If a route-map entry does not explicitely specify
  any matching conditions, then it always matches.


*Set Actions*
  A route-map entry may, optionally, specify one or more @samp{Set
  Actions} to set or modify attributes of the route.


*Call Action*
  Call to another route-map, after any @samp{Set Actions} have been
  carried out. If the route-map called returns @samp{deny} then
  processing of the route-map finishes and the route is denied,
  regardless of the @samp{Matching Policy} or the @samp{Exit Policy}. If
  the called route-map returns @samp{permit}, then @samp{Matching Policy}
  and @samp{Exit Policy} govern further behaviour, as normal.


*Exit Policy*
  An entry may, optionally, specify an alternative @samp{Exit Policy} to
  take if the entry matched, rather than the normal policy of exiting the
  route-map and permitting the route. The two possibilities are:


**
    @samp{next}: Continue on with processing of the route-map entries.


**
    @samp{goto N}: Jump ahead to the first route-map entry whose order in
    the route-map is >= N. Jumping to a previous entry is not permitted.

The default action of a route-map, if no entries match, is to deny.
I.e. a route-map essentially has as its last entry an empty @samp{deny}
entry, which matches all routes. To change this behaviour, one must
specify an empty @samp{permit} entry as the last entry in the route-map.

To summarise the above:

@multitable {permit} {action} {No Match}
@headitem           @tab Match  @tab No Match
* *Permit* @tab action @tab cont
* *Deny*   @tab deny   @tab cont
@end multitable



*action*

**
    Apply *set* statements


**
    If *call* is present, call given route-map. If that returns a @samp{deny}, finish
    processing and return @samp{deny}.


**
    If @samp{Exit Policy} is *next*, goto next route-map entry


**
    If @samp{Exit Policy} is *goto*, goto first entry whose order in the list
    is >= the given order.


**
    Finish processing the route-map and permit the route.


*deny*

**
    The route is denied by the route-map (return @samp{deny}).


*cont*

**
    goto next route-map entry

.. _Route_Map_Command:

Route Map Command
=================

.. index:: {Command} {route-map `route-map-name` (permit|deny) `order`} {}

{Command} {route-map `route-map-name` (permit|deny) `order`} {}

  Configure the `order`'th entry in `route-map-name` with
  @samp{Match Policy} of either *permit* or *deny*.


.. _Route_Map_Match_Command:

Route Map Match Command
=======================

.. index:: {Route-map Command} {match ip address `access_list`} {}

{Route-map Command} {match ip address `access_list`} {}
  Matches the specified `access_list`

.. index:: {Route-map Command} {match ip address `prefix-list`} {}

{Route-map Command} {match ip address `prefix-list`} {}
  Matches the specified `prefix-list`

.. index:: {Route-map Command} {match ip address prefix-len `0-32`} {}

{Route-map Command} {match ip address prefix-len `0-32`} {}
  Matches the specified `prefix-len`.  This is a Zebra specific command.

.. index:: {Route-map Command} {match ipv6 address `access_list`} {}

{Route-map Command} {match ipv6 address `access_list`} {}
  Matches the specified `access_list`

.. index:: {Route-map Command} {match ipv6 address `prefix-list`} {}

{Route-map Command} {match ipv6 address `prefix-list`} {}
  Matches the specified `prefix-list`

.. index:: {Route-map Command} {match ipv6 address prefix-len `0-128`} {}

{Route-map Command} {match ipv6 address prefix-len `0-128`} {}
  Matches the specified `prefix-len`.  This is a Zebra specific command.

.. index:: {Route-map Command} {match ip next-hop `ipv4_addr`} {}

{Route-map Command} {match ip next-hop `ipv4_addr`} {}
  Matches the specified `ipv4_addr`.

.. index:: {Route-map Command} {match aspath `as_path`} {}

{Route-map Command} {match aspath `as_path`} {}
  Matches the specified `as_path`.

.. index:: {Route-map Command} {match metric `metric`} {}

{Route-map Command} {match metric `metric`} {}
  Matches the specified `metric`.

.. index:: {Route-map Command} {match local-preference `metric`} {}

{Route-map Command} {match local-preference `metric`} {}
  Matches the specified `local-preference`.

.. index:: {Route-map Command} {match community `community_list`} {}

{Route-map Command} {match community `community_list`} {}
  Matches the specified  `community_list`

.. index:: {Route-map Command} {match peer `ipv4_addr`} {}

{Route-map Command} {match peer `ipv4_addr`} {}
  This is a BGP specific match command.  Matches the peer ip address
  if the neighbor was specified in this manner.

.. index:: {Route-map Command} {match peer `ipv6_addr`} {}

{Route-map Command} {match peer `ipv6_addr`} {}
  This is a BGP specific match command.  Matches the peer ipv6
  address if the neighbor was specified in this manner.

.. index:: {Route-map Command} {match peer `interface_name`} {}

{Route-map Command} {match peer `interface_name`} {}
  This is a BGP specific match command.  Matches the peer
  interface name specified if the neighbor was specified
  in this manner.

.. _Route_Map_Set_Command:

Route Map Set Command
=====================

.. index:: {Route-map Command} {set ip next-hop `ipv4_address`} {}

{Route-map Command} {set ip next-hop `ipv4_address`} {}
  Set the BGP nexthop address.

.. index:: {Route-map Command} {set local-preference `local_pref`} {}

{Route-map Command} {set local-preference `local_pref`} {}
  Set the BGP local preference to `local_pref`. 

.. index:: {Route-map Command} {set weight `weight`} {}

{Route-map Command} {set weight `weight`} {}
  Set the route's weight.

.. index:: {Route-map Command} {set metric `metric`} {}

{Route-map Command} {set metric `metric`} {}
  .. _routemap_set_metric:

  Set the BGP attribute MED.

.. index:: {Route-map Command} {set as-path prepend `as_path`} {}

{Route-map Command} {set as-path prepend `as_path`} {}
  Set the BGP AS path to prepend.

.. index:: {Route-map Command} {set community `community`} {}

{Route-map Command} {set community `community`} {}
  Set the BGP community attribute.

.. index:: {Route-map Command} {set ipv6 next-hop global `ipv6_address`} {}

{Route-map Command} {set ipv6 next-hop global `ipv6_address`} {}
  Set the BGP-4+ global IPv6 nexthop address.

.. index:: {Route-map Command} {set ipv6 next-hop local `ipv6_address`} {}

{Route-map Command} {set ipv6 next-hop local `ipv6_address`} {}
  Set the BGP-4+ link local IPv6 nexthop address.

.. _Route_Map_Call_Command:

Route Map Call Command
======================

.. index:: {Route-map Command} {call `name`} {}

{Route-map Command} {call `name`} {}
  Call route-map `name`. If it returns deny, deny the route and
  finish processing the route-map.

.. _Route_Map_Exit_Action_Command:

Route Map Exit Action Command
=============================

.. index:: {Route-map Command} {on-match next} {}

{Route-map Command} {on-match next} {}
.. index:: {Route-map Command} {continue} {}

{Route-map Command} {continue} {}
    Proceed on to the next entry in the route-map.

.. index:: {Route-map Command} {on-match goto `N`} {}

{Route-map Command} {on-match goto `N`} {}
.. index:: {Route-map Command} {continue `N`} {}

{Route-map Command} {continue `N`} {}
      Proceed processing the route-map at the first entry whose order is >= N

Route Map Examples
==================

A simple example of a route-map:

::

  route-map test permit 10
   match ip address 10
   set local-preference 200
  

This means that if a route matches ip access-list number 10 it's
local-preference value is set to 200.

See :ref:`BGP_Configuration_Examples` for examples of more sophisticated
useage of route-maps, including of the @samp{call} action.

