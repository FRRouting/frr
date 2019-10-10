.. _configuring-frr-as-a-route-server:

Configuring FRR as a Route Server
=================================

The purpose of a Route Server is to centralize the peerings between BGP
speakers. For example if we have an exchange point scenario with four BGP
speakers, each of which maintaining a BGP peering with the other three
(:ref:`fig-topologies-full`), we can convert it into a centralized scenario where
each of the four establishes a single BGP peering against the Route Server
(:ref:`fig-topologies-rs`).

We will first describe briefly the Route Server model implemented by FRR.
We will explain the commands that have been added for configuring that
model. And finally we will show a full example of FRR configured as Route
Server.

.. _description-of-the-route-server-model:

Description of the Route Server model
-------------------------------------

First we are going to describe the normal processing that BGP announcements
suffer inside a standard BGP speaker, as shown in :ref:`fig-normal-processing`,
it consists of three steps:

- When an announcement is received from some peer, the `In` filters configured
  for that peer are applied to the announcement. These filters can reject the
  announcement, accept it unmodified, or accept it with some of its attributes
  modified.

- The announcements that pass the `In` filters go into the Best Path Selection
  process, where they are compared to other announcements referred to the same
  destination that have been received from different peers (in case such other
  announcements exist). For each different destination, the announcement which
  is selected as the best is inserted into the BGP speaker's Loc-RIB.

- The routes which are inserted in the Loc-RIB are considered for announcement
  to all the peers (except the one from which the route came). This is done by
  passing the routes in the Loc-RIB through the `Out` filters corresponding to
  each peer. These filters can reject the route, accept it unmodified, or
  accept it with some of its attributes modified. Those routes which are
  accepted by the `Out` filters of a peer are announced to that peer.

.. _fig-normal-processing:

.. figure:: ../figures/fig-normal-processing.png
   :alt: Normal announcement processing
   :align: center

   Announcement processing inside a 'normal' BGP speaker

.. _fig-topologies-full:

.. figure:: ../figures/fig_topologies_full.png
   :alt: Full Mesh BGP Topology
   :align: center

   Full Mesh

.. _fig-topologies-rs:

.. figure:: ../figures/fig_topologies_rs.png
   :alt: Route Server BGP Topology
   :align: center

   Route server and clients

Of course we want that the routing tables obtained in each of the routers are
the same when using the route server than when not. But as a consequence of
having a single BGP peering (against the route server), the BGP speakers can no
longer distinguish from/to which peer each announce comes/goes.

.. _filter-delegation:

This means that the routers connected to the route server are not able to apply
by themselves the same input/output filters as in the full mesh scenario, so
they have to delegate those functions to the route server.

Even more, the 'best path' selection must be also performed inside the route
server on behalf of its clients. The reason is that if, after applying the
filters of the announcer and the (potential) receiver, the route server decides
to send to some client two or more different announcements referred to the same
destination, the client will only retain the last one, considering it as an
implicit withdrawal of the previous announcements for the same destination.
This is the expected behavior of a BGP speaker as defined in :rfc:`1771`,
and even though there are some proposals of mechanisms that permit multiple
paths for the same destination to be sent through a single BGP peering, none
are currently supported by most existing BGP implementations.

As a consequence a route server must maintain additional information and
perform additional tasks for a RS-client that those necessary for common BGP
peerings. Essentially a route server must:

.. _route-server-tasks:

- Maintain a separated Routing Information Base (Loc-RIB)
  for each peer configured as RS-client, containing the routes
  selected as a result of the 'Best Path Selection' process
  that is performed on behalf of that RS-client.

- Whenever it receives an announcement from a RS-client,
  it must consider it for the Loc-RIBs of the other RS-clients.

  - This means that for each of them the route server must pass the
    announcement through the appropriate `Out` filter of the
    announcer.

  - Then through the appropriate `In` filter of the potential receiver.

  - Only if the announcement is accepted by both filters it will be passed
    to the 'Best Path Selection' process.

  - Finally, it might go into the Loc-RIB of the receiver.

When we talk about the 'appropriate' filter, both the announcer and the
receiver of the route must be taken into account. Suppose that the route server
receives an announcement from client A, and the route server is considering it
for the Loc-RIB of client B. The filters that should be applied are the same
that would be used in the full mesh scenario, i.e., first the `Out` filter of
router A for announcements going to router B, and then the `In` filter of
router B for announcements coming from router A.

We call 'Export Policy' of a RS-client to the set of `Out` filters that the
client would use if there was no route server. The same applies for the 'Import
Policy' of a RS-client and the set of `In` filters of the client if there was
no route server.

It is also common to demand from a route server that it does not modify some
BGP attributes (next-hop, as-path and MED) that are usually modified by
standard BGP speakers before announcing a route.

The announcement processing model implemented by FRR is shown in
:ref:`fig-rs-processing`. The figure shows a mixture of RS-clients (B, C and D)
with normal BGP peers (A). There are some details that worth additional
comments:

- Announcements coming from a normal BGP peer are also considered for the
  Loc-RIBs of all the RS-clients. But logically they do not pass through any
  export policy.

- Those peers that are configured as RS-clients do not receive any announce
  from the `Main` Loc-RIB.

- Apart from import and export policies, `In` and `Out` filters can also be set
  for RS-clients. `In` filters might be useful when the route server has also
  normal BGP peers. On the other hand, `Out` filters for RS-clients are
  probably unnecessary, but we decided not to remove them as they do not hurt
  anybody (they can always be left empty).

.. _fig-rs-processing:
.. figure:: ../figures/fig-rs-processing.png
   :align: center
   :alt: Route Server Processing Model

   Announcement processing model implemented by the Route Server

.. _commands-for-configuring-a-route-server:

Commands for configuring a Route Server
---------------------------------------

Now we will describe the commands that have been added to frr
in order to support the route server features.

.. index:: neighbor PEER-GROUP route-server-client
.. clicmd:: neighbor PEER-GROUP route-server-client

.. index:: neighbor A.B.C.D route-server-client
.. clicmd:: neighbor A.B.C.D route-server-client

.. index:: neighbor X:X::X:X route-server-client
.. clicmd:: neighbor X:X::X:X route-server-client

   This command configures the peer given by `peer`, `A.B.C.D` or `X:X::X:X` as
   an RS-client.

   Actually this command is not new, it already existed in standard FRR. It
   enables the transparent mode for the specified peer. This means that some
   BGP attributes (as-path, next-hop and MED) of the routes announced to that
   peer are not modified.

   With the route server patch, this command, apart from setting the
   transparent mode, creates a new Loc-RIB dedicated to the specified peer
   (those named `Loc-RIB for X` in :ref:`fig-rs-processing`.). Starting from
   that moment, every announcement received by the route server will be also
   considered for the new Loc-RIB.

.. index:: neigbor A.B.C.D|X.X::X.X|peer-group route-map WORD import|export
.. clicmd:: neigbor A.B.C.D|X.X::X.X|peer-group route-map WORD import|export

   This set of commands can be used to specify the route-map that represents
   the Import or Export policy of a peer which is configured as a RS-client
   (with the previous command).

.. index:: match peer A.B.C.D|X:X::X:X
.. clicmd:: match peer A.B.C.D|X:X::X:X

   This is a new *match* statement for use in route-maps, enabling them to
   describe import/export policies. As we said before, an import/export policy
   represents a set of input/output filters of the RS-client. This statement
   makes possible that a single route-map represents the full set of filters
   that a BGP speaker would use for its different peers in a non-RS scenario.

   The *match peer* statement has different semantics whether it is used inside
   an import or an export route-map. In the first case the statement matches if
   the address of the peer who sends the announce is the same that the address
   specified by {A.B.C.D|X:X::X:X}. For export route-maps it matches when
   {A.B.C.D|X:X::X:X} is the address of the RS-Client into whose Loc-RIB the
   announce is going to be inserted (how the same export policy is applied
   before different Loc-RIBs is shown in :ref:`fig-rs-processing`.).

.. index:: call WORD
.. clicmd:: call WORD

   This command (also used inside a route-map) jumps into a different
   route-map, whose name is specified by `WORD`. When the called
   route-map finishes, depending on its result the original route-map
   continues or not. Apart from being useful for making import/export
   route-maps easier to write, this command can also be used inside
   any normal (in or out) route-map.

.. _example-of-route-server-configuration:

Example of Route Server Configuration
-------------------------------------

Finally we are going to show how to configure a FRR daemon to act as a
Route Server. For this purpose we are going to present a scenario without
route server, and then we will show how to use the configurations of the BGP
routers to generate the configuration of the route server.

All the configuration files shown in this section have been taken
from scenarios which were tested using the VNUML tool
`http://www.dit.upm.es/vnuml,VNUML <http://www.dit.upm.es/vnuml,VNUML>`_.

.. _configuration-of-the-bgp-routers-without-route-server:

Configuration of the BGP routers without Route Server
-----------------------------------------------------

We will suppose that our initial scenario is an exchange point with three
BGP capable routers, named RA, RB and RC. Each of the BGP speakers generates
some routes (with the `network` command), and establishes BGP peerings
against the other two routers. These peerings have In and Out route-maps
configured, named like 'PEER-X-IN' or 'PEER-X-OUT'. For example the
configuration file for router RA could be the following:

.. code-block:: frr

   #Configuration for router 'RA'
   !
   hostname RA
   password ****
   !
   router bgp 65001
     no bgp default ipv4-unicast
     neighbor 2001:0DB8::B remote-as 65002
     neighbor 2001:0DB8::C remote-as 65003
   !
     address-family ipv6
       network 2001:0DB8:AAAA:1::/64
       network 2001:0DB8:AAAA:2::/64
       network 2001:0DB8:0000:1::/64
       network 2001:0DB8:0000:2::/64
       neighbor 2001:0DB8::B activate
       neighbor 2001:0DB8::B soft-reconfiguration inbound
       neighbor 2001:0DB8::B route-map PEER-B-IN in
       neighbor 2001:0DB8::B route-map PEER-B-OUT out
       neighbor 2001:0DB8::C activate
       neighbor 2001:0DB8::C soft-reconfiguration inbound
       neighbor 2001:0DB8::C route-map PEER-C-IN in
       neighbor 2001:0DB8::C route-map PEER-C-OUT out
     exit-address-family
   !
   ipv6 prefix-list COMMON-PREFIXES seq  5 permit 2001:0DB8:0000::/48 ge 64 le 64
   ipv6 prefix-list COMMON-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-A-PREFIXES seq  5 permit 2001:0DB8:AAAA::/48 ge 64 le 64
   ipv6 prefix-list PEER-A-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-B-PREFIXES seq  5 permit 2001:0DB8:BBBB::/48 ge 64 le 64
   ipv6 prefix-list PEER-B-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-C-PREFIXES seq  5 permit 2001:0DB8:CCCC::/48 ge 64 le 64
   ipv6 prefix-list PEER-C-PREFIXES seq 10 deny any
   !
   route-map PEER-B-IN permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set metric 100
   route-map PEER-B-IN permit 20
     match ipv6 address prefix-list PEER-B-PREFIXES
     set community 65001:11111
   !
   route-map PEER-C-IN permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set metric 200
   route-map PEER-C-IN permit 20
     match ipv6 address prefix-list PEER-C-PREFIXES
     set community 65001:22222
   !
   route-map PEER-B-OUT permit 10
     match ipv6 address prefix-list PEER-A-PREFIXES
   !
   route-map PEER-C-OUT permit 10
     match ipv6 address prefix-list PEER-A-PREFIXES
   !
   line vty
   !


.. _configuration-of-the-bgp-routers-with-route-server:

Configuration of the BGP routers with Route Server
--------------------------------------------------

To convert the initial scenario into one with route server, first we must
modify the configuration of routers RA, RB and RC. Now they must not peer
between them, but only with the route server. For example, RA's
configuration would turn into:

.. code-block:: frr

   # Configuration for router 'RA'
   !
   hostname RA
   password ****
   !
   router bgp 65001
     no bgp default ipv4-unicast
     neighbor 2001:0DB8::FFFF remote-as 65000
   !
     address-family ipv6
       network 2001:0DB8:AAAA:1::/64
       network 2001:0DB8:AAAA:2::/64
       network 2001:0DB8:0000:1::/64
       network 2001:0DB8:0000:2::/64

       neighbor 2001:0DB8::FFFF activate
       neighbor 2001:0DB8::FFFF soft-reconfiguration inbound
     exit-address-family
   !
   line vty
   !


Which is logically much simpler than its initial configuration, as it now
maintains only one BGP peering and all the filters (route-maps) have
disappeared.

.. _configuration-of-the-route-server-itself:

Configuration of the Route Server itself
----------------------------------------

As we said when we described the functions of a route server
(:ref:`description-of-the-route-server-model`), it is in charge of all the
route filtering. To achieve that, the In and Out filters from the RA, RB and RC
configurations must be converted into Import and Export policies in the route
server.

This is a fragment of the route server configuration (we only show
the policies for client RA):

.. code-block:: frr

   # Configuration for Route Server ('RS')
   !
   hostname RS
   password ix
   !
   router bgp 65000 view RS
     no bgp default ipv4-unicast
     neighbor 2001:0DB8::A  remote-as 65001
     neighbor 2001:0DB8::B  remote-as 65002
     neighbor 2001:0DB8::C  remote-as 65003
   !
     address-family ipv6
       neighbor 2001:0DB8::A activate
       neighbor 2001:0DB8::A route-server-client
       neighbor 2001:0DB8::A route-map RSCLIENT-A-IMPORT import
       neighbor 2001:0DB8::A route-map RSCLIENT-A-EXPORT export
       neighbor 2001:0DB8::A soft-reconfiguration inbound

       neighbor 2001:0DB8::B activate
       neighbor 2001:0DB8::B route-server-client
       neighbor 2001:0DB8::B route-map RSCLIENT-B-IMPORT import
       neighbor 2001:0DB8::B route-map RSCLIENT-B-EXPORT export
       neighbor 2001:0DB8::B soft-reconfiguration inbound

       neighbor 2001:0DB8::C activate
       neighbor 2001:0DB8::C route-server-client
       neighbor 2001:0DB8::C route-map RSCLIENT-C-IMPORT import
       neighbor 2001:0DB8::C route-map RSCLIENT-C-EXPORT export
       neighbor 2001:0DB8::C soft-reconfiguration inbound
     exit-address-family
   !
   ipv6 prefix-list COMMON-PREFIXES seq  5 permit 2001:0DB8:0000::/48 ge 64 le 64
   ipv6 prefix-list COMMON-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-A-PREFIXES seq  5 permit 2001:0DB8:AAAA::/48 ge 64 le 64
   ipv6 prefix-list PEER-A-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-B-PREFIXES seq  5 permit 2001:0DB8:BBBB::/48 ge 64 le 64
   ipv6 prefix-list PEER-B-PREFIXES seq 10 deny any
   !
   ipv6 prefix-list PEER-C-PREFIXES seq  5 permit 2001:0DB8:CCCC::/48 ge 64 le 64
   ipv6 prefix-list PEER-C-PREFIXES seq 10 deny any
   !
   route-map RSCLIENT-A-IMPORT permit 10
     match peer 2001:0DB8::B
     call A-IMPORT-FROM-B
   route-map RSCLIENT-A-IMPORT permit 20
     match peer 2001:0DB8::C
     call A-IMPORT-FROM-C
   !
   route-map A-IMPORT-FROM-B permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set metric 100
   route-map A-IMPORT-FROM-B permit 20
     match ipv6 address prefix-list PEER-B-PREFIXES
     set community 65001:11111
   !
   route-map A-IMPORT-FROM-C permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set metric 200
   route-map A-IMPORT-FROM-C permit 20
     match ipv6 address prefix-list PEER-C-PREFIXES
     set community 65001:22222
   !
   route-map RSCLIENT-A-EXPORT permit 10
     match peer 2001:0DB8::B
     match ipv6 address prefix-list PEER-A-PREFIXES
   route-map RSCLIENT-A-EXPORT permit 20
     match peer 2001:0DB8::C
     match ipv6 address prefix-list PEER-A-PREFIXES
   !
   ...
   ...
   ...


If you compare the initial configuration of RA with the route server
configuration above, you can see how easy it is to generate the Import and
Export policies for RA from the In and Out route-maps of RA's original
configuration.

When there was no route server, RA maintained two peerings, one with RB and
another with RC. Each of this peerings had an In route-map configured. To
build the Import route-map for client RA in the route server, simply add
route-map entries following this scheme:

::

   route-map <NAME> permit 10
       match peer <Peer Address>
       call <In Route-Map for this Peer>
   route-map <NAME> permit 20
       match peer <Another Peer Address>
       call <In Route-Map for this Peer>


This is exactly the process that has been followed to generate the route-map
RSCLIENT-A-IMPORT. The route-maps that are called inside it (A-IMPORT-FROM-B
and A-IMPORT-FROM-C) are exactly the same than the In route-maps from the
original configuration of RA (PEER-B-IN and PEER-C-IN), only the name is
different.

The same could have been done to create the Export policy for RA (route-map
RSCLIENT-A-EXPORT), but in this case the original Out route-maps where so
simple that we decided not to use the `call WORD` commands, and we
integrated all in a single route-map (RSCLIENT-A-EXPORT).

The Import and Export policies for RB and RC are not shown, but
the process would be identical.

Further considerations about Import and Export route-maps
---------------------------------------------------------

The current version of the route server patch only allows to specify a
route-map for import and export policies, while in a standard BGP speaker
apart from route-maps there are other tools for performing input and output
filtering (access-lists, community-lists, ...). But this does not represent
any limitation, as all kinds of filters can be included in import/export
route-maps. For example suppose that in the non-route-server scenario peer
RA had the following filters configured for input from peer B:

.. code-block:: frr

   neighbor 2001:0DB8::B prefix-list LIST-1 in
   neighbor 2001:0DB8::B filter-list LIST-2 in
   neighbor 2001:0DB8::B route-map PEER-B-IN in
   ...
   ...
   route-map PEER-B-IN permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set local-preference 100
   route-map PEER-B-IN permit 20
     match ipv6 address prefix-list PEER-B-PREFIXES
     set community 65001:11111


It is possible to write a single route-map which is equivalent to the three
filters (the community-list, the prefix-list and the route-map). That route-map
can then be used inside the Import policy in the route server. Lets see how to
do it:

.. code-block:: frr

   neighbor 2001:0DB8::A route-map RSCLIENT-A-IMPORT import
   ...
   !
   ...
   route-map RSCLIENT-A-IMPORT permit 10
     match peer 2001:0DB8::B
     call A-IMPORT-FROM-B
   ...
   ...
   !
   route-map A-IMPORT-FROM-B permit 1
     match ipv6 address prefix-list LIST-1
     match as-path LIST-2
     on-match goto 10
   route-map A-IMPORT-FROM-B deny 2
   route-map A-IMPORT-FROM-B permit 10
     match ipv6 address prefix-list COMMON-PREFIXES
     set local-preference 100
   route-map A-IMPORT-FROM-B permit 20
     match ipv6 address prefix-list PEER-B-PREFIXES
     set community 65001:11111
   !
   ...
   ...


The route-map A-IMPORT-FROM-B is equivalent to the three filters (LIST-1,
LIST-2 and PEER-B-IN). The first entry of route-map A-IMPORT-FROM-B (sequence
number 1) matches if and only if both the prefix-list LIST-1 and the
filter-list LIST-2 match. If that happens, due to the 'on-match goto 10'
statement the next route-map entry to be processed will be number 10, and as of
that point route-map A-IMPORT-FROM-B is identical to PEER-B-IN. If the first
entry does not match, `on-match goto 10`' will be ignored and the next
processed entry will be number 2, which will deny the route.

Thus, the result is the same that with the three original filters, i.e., if
either LIST-1 or LIST-2 rejects the route, it does not reach the route-map
PEER-B-IN. In case both LIST-1 and LIST-2 accept the route, it passes to
PEER-B-IN, which can reject, accept or modify the route.
