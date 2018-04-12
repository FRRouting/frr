Next Hop Tracking
==================

Next hop tracking is an optimization feature that reduces the processing time
involved in the BGP bestpath algorithm by monitoring changes to the routing
table.

Background
-----------

Recursive routes are of the form:

::

    p/m --> n
    [Ex: 1.1.0.0/16 --> 2.2.2.2]

where 'n' itself is resolved through another route as follows:

::

    p2/m --> h, interface
    [Ex: 2.2.2.0/24 --> 3.3.3.3, eth0]

Usually, BGP routes are recursive in nature and BGP nexthops get resolved
through an IGP route. IGP usually adds its routes pointing to an interface
(these are called non-recursive routes).

When BGP receives a recursive route from a peer, it needs to validate the
nexthop. The path is marked valid or invalid based on the reachability status
of the nexthop. Nexthop validation is also important for BGP decision process
as the metric to reach the nexthop is a parameter to best path selection
process.

As it goes with routing, this is a dynamic process. Route to the nexthop can
change. The nexthop can become unreachable or reachable. In the current BGP
implementation, the nexthop validation is done periodically in the scanner run.
The default scanner run interval is one minute. Every minute, the scanner task
walks the entire BGP table. It checks the validity of each nexthop with Zebra
(the routing table manager) through a request and response message exchange
between BGP and Zebra process. BGP process is blocked for that duration. The
mechanism has two major drawbacks:

- The scanner task runs to completion. That can potentially starve the other
  tasks for long periods of time, based on the BGP table size and number of
  nexthops.

- Convergence around routing changes that affect the nexthops can be long
  (around a minute with the default intervals). The interval can be shortened
  to achieve faster reaction time, but it makes the first problem worse, with
  the scanner task consuming most of the CPU resources.

The next-hop tracking feature makes this process event-driven. It eliminates
periodic nexthop validation and introduces an asynchronous communication path
between BGP and Zebra for route change notifications that can then be acted
upon.

Goal
----

Stating the obvious, the main goal is to remove the two limitations we
discussed in the previous section. The goals, in a constructive tone,
are the following:

- **Fairness**: the scanner run should not consume an unjustly high amount of
  CPU time. This should give an overall good performance and response time to
  other events (route changes, session events, IO/user interface).

- **Convergence**: BGP must react to nexthop changes instantly and provide
  sub-second convergence. This may involve diverting the routes from one
  nexthop to another.

Overview of changes
------------------------

The changes are in both BGP and Zebra modules.  The short summary is
the following:

- Zebra implements a registration mechanism by which clients can
  register for next hop notification. Consequently, it maintains a
  separate table, per (VRF, AF) pair, of next hops and interested
  client-list per next hop.

- When the main routing table changes in Zebra, it evaluates the next
  hop table: for each next hop, it checks if the route table
  modifications have changed its state. If so, it notifies the
  interested clients.

- BGP is one such client. It registers the next hops corresponding to
  all of its received routes/paths. It also threads the paths against
  each nexthop structure.

- When BGP receives a next hop notification from Zebra, it walks the
  corresponding path list. It makes them valid or invalid depending
  on the next hop notification. It then re-computes best path for the
  corresponding destination. This may result in re-announcing those
  destinations to peers.

Design
------

Modules
^^^^^^^

The core design introduces an "nht" (next hop tracking) module in BGP
and "rnh" (recursive nexthop) module in Zebra. The "nht" module
provides the following APIs:

+----------------------------+--------------------------------------------------+
| Function                   | Action                                           |
+============================+==================================================+
| bgp_find_or_add_nexthop()  | find or add a nexthop in BGP nexthop table       |
+----------------------------+--------------------------------------------------+
| bgp_find_nexthop()         | find a nexthop in BGP nexthop table              |
+----------------------------+--------------------------------------------------+
| bgp_parse_nexthop_update() | parse a nexthop update message coming from zebra |
+----------------------------+--------------------------------------------------+

The "rnh" module provides the following APIs:

+----------------------------+----------------------------------------------------------------------------------------------------------+
| Function                   | Action                                                                                                   |
+============================+==========================================================================================================+
| zebra_add_rnh()            | add a recursive nexthop                                                                                  |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_delete_rnh()         | delete a recursive nexthop                                                                               |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_lookup_rnh()         | lookup a recursive nexthop                                                                               |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_add_rnh_client()     | register a client for nexthop notifications against a recursive nexthop                                  |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_remove_rnh_client()  | remove the client registration for a recursive nexthop                                                   |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_evaluate_rnh_table() | (re)evaluate the recursive nexthop table (most probably because the main routing table has changed).     |
+----------------------------+----------------------------------------------------------------------------------------------------------+
| zebra_cleanup_rnh_client() | Cleanup a client from the "rnh" module data structures (most probably because the client is going away). |
+----------------------------+----------------------------------------------------------------------------------------------------------+

4.2. Control flow

The next hop registration control flow is the following:

::

    <====      BGP Process       ====>|<====      Zebra Process      ====>
                                      |
    receive module     nht module     |  zserv module        rnh module
    ----------------------------------------------------------------------
                  |                   |                  |
    bgp_update_   |                   |                  |
          main()  | bgp_find_or_add_  |                  |
                  |        nexthop()  |                  |
                  |                   |                  |
                  |                   | zserv_nexthop_   |
                  |                   |       register() |
                  |                   |                  | zebra_add_rnh()
                  |                   |                  |


The next hop notification control flow is the following:

::

    <====     Zebra Process    ====>|<====      BGP Process       ====>
                                    |
    rib module         rnh module   |     zebra module        nht module
    ----------------------------------------------------------------------
                  |                 |                   |
    meta_queue_   |                 |                   |
        process() | zebra_evaluate_ |                   |
                  |     rnh_table() |                   |
                  |                 |                   |
                  |                 | bgp_read_nexthop_ |
                  |                 |          update() |
                  |                 |                   | bgp_parse_
                  |                 |                   | nexthop_update()
                  |                 |                   |


zclient message format
^^^^^^^^^^^^^^^^^^^^^^

ZEBRA_NEXTHOP_REGISTER and ZEBRA_NEXTHOP_UNREGISTER messages are
encoded in the following way:

::

    .   0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     AF                        |  prefix len   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .      Nexthop prefix                                           .
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .                                                               .
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     AF                        |  prefix len   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .      Nexthop prefix                                           .
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


``ZEBRA_NEXTHOP_UPDATE`` message is encoded as follows:

::

    .   0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |     AF                        |  prefix len   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .      Nexthop prefix getting resolved                          .
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        metric                                                 |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  #nexthops    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | nexthop type  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .      resolving Nexthop details                                .
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .                                                               .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | nexthop type  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    .      resolving Nexthop details                                .
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


BGP data structure
^^^^^^^^^^^^^^^^^^
Legend:

::

    /\   struct bgp_node: a BGP destination/route/prefix
    \/

    [ ]  struct bgp_info: a BGP path (e.g. route received from a peer)

     _
    (_)  struct bgp_nexthop_cache: a BGP nexthop

    /\         NULL
    \/--+        ^
        |        :
        +--[ ]--[ ]--[ ]--> NULL
    /\           :
    \/--+        :
        |        :
        +--[ ]--[ ]--> NULL
                 :
     _           :
    (_)...........


Zebra data structure
^^^^^^^^^^^^^^^^^^^^

RNH table::

   .  O
     / \
    O   O
       / \
      O   O
   
   struct rnh
   {
     uint8_t flags;
     struct route_entry *state;
     struct list *client_list;
     struct route_node *node;
   };

User interface changes
^^^^^^^^^^^^^^^^^^^^^^

::

    frr# show ip nht
    3.3.3.3
     resolved via kernel
     via 11.0.0.6, swp1
     Client list: bgp(fd 12)
    11.0.0.10
     resolved via connected
     is directly connected, swp2
     Client list: bgp(fd 12)
    11.0.0.18
     resolved via connected
     is directly connected, swp4
     Client list: bgp(fd 12)
    11.11.11.11
     resolved via kernel
     via 10.0.1.2, eth0
     Client list: bgp(fd 12)

    frr# show ip bgp nexthop
    Current BGP nexthop cache:
     3.3.3.3 valid [IGP metric 0], #paths 3
      Last update: Wed Oct 16 04:43:49 2013

     11.0.0.10 valid [IGP metric 1], #paths 1
      Last update: Wed Oct 16 04:43:51 2013

     11.0.0.18 valid [IGP metric 1], #paths 2
      Last update: Wed Oct 16 04:43:47 2013

     11.11.11.11 valid [IGP metric 0], #paths 1
      Last update: Wed Oct 16 04:43:47 2013

    frr# show ipv6 nht
    frr# show ip bgp nexthop detail

    frr# debug bgp nht
    frr# debug zebra nht

    6. Sample test cases

         r2----r3
        /  \  /
      r1----r4

    - Verify that a change in IGP cost triggers NHT
      + shutdown the r1-r4 and r2-r4 links
      + no shut the r1-r4 and r2-r4 links and wait for OSPF to come back
        up
      + We should be back to the original nexthop via r4 now
    - Verify that a NH becoming unreachable triggers NHT
      + Shutdown all links to r4
    - Verify that a NH becoming reachable triggers NHT
      + no shut all links to r4

Future work
^^^^^^^^^^^

- route-policy for next hop validation (e.g. ignore default route)
- damping for rapid next hop changes
- prioritized handling of nexthop changes ((un)reachability vs. metric
  changes)
- handling recursion loop, e.g::

   11.11.11.11/32 -> 12.12.12.12
   12.12.12.12/32 -> 11.11.11.11
   11.0.0.0/8 -> <interface>
- better statistics
