.. _ospf-fundamentals:

OSPF Fundamentals
=================

.. index:: Link-state routing protocol
.. index:: Distance-vector routing protocol

:abbr:`OSPF` is, mostly, a link-state routing protocol. In contrast to
:term:`distance-vector` protocols, such as :abbr:`RIP` or :abbr:`BGP`, where
routers describe available `paths` (i.e. routes) to each other, in
:term:`link-state` protocols routers instead describe the state of their links
to their immediate neighbouring routers.

.. index:: Link State Announcement
.. index:: Link State Advertisement
.. index:: LSA flooding
.. index:: Link State Database

Each router describes their link-state information in a message known as an
:abbr:`LSA (Link State Advertisement)`, which is then propagated through to all
other routers in a link-state routing domain, by a process called `flooding`.
Each router thus builds up an :abbr:`LSDB (Link State Database)` of all the
link-state messages. From this collection of LSAs in the LSDB, each router can
then calculate the shortest path to any other router, based on some common
metric, by using an algorithm such as
`Edgar Djikstra's <http://www.cs.utexas.edu/users/EWD/>`_
:abbr:`SPF (Shortest Path First)` algorithm.

.. index:: Link-state routing protocol advantages

By describing connectivity of a network in this way, in terms of
routers and links rather than in terms of the paths through a network,
a link-state protocol can use less bandwidth and converge more quickly
than other protocols. A link-state protocol need distribute only one
link-state message throughout the link-state domain when a link on any
single given router changes state, in order for all routers to
reconverge on the best paths through the network. In contrast, distance
vector protocols can require a progression of different path update
messages from a series of different routers in order to converge.

.. index:: Link-state routing protocol disadvantages

The disadvantage to a link-state protocol is that the process of
computing the best paths can be relatively intensive when compared to
distance-vector protocols, in which near to no computation need be done
other than (potentially) select between multiple routes. This overhead
is mostly negligible for modern embedded CPUs, even for networks with
thousands of nodes. The primary scaling overhead lies more in coping
with the ever greater frequency of LSA updates as the size of a
link-state area increases, in managing the :abbr:`LSDB` and required
flooding.

This section aims to give a distilled, but accurate, description of the
more important workings of :abbr:`OSPF` which an administrator may need
to know to be able best configure and trouble-shoot :abbr:`OSPF`.

OSPF Mechanisms
---------------

:abbr:`OSPF` defines a range of mechanisms, concerned with detecting,
describing and propagating state through a network. These mechanisms
will nearly all be covered in greater detail further on. They may be
broadly classed as:


.. index:: OSPF Hello Protocol

The Hello Protocol
^^^^^^^^^^^^^^^^^^

The OSPF Hello protocol allows OSPF to quickly detect changes in two-way
reachability between routers on a link. OSPF can additionally avail of other
sources of reachability information, such as link-state information provided by
hardware, or through dedicated reachability protocols such as
:abbr:`BFD (Bidirectional Forwarding Detection)`.

OSPF also uses the Hello protocol to propagate certain state between routers
sharing a link, for example:

- Hello protocol configured state, such as the dead-interval.
- Router priority, for DR/BDR election.
- DR/BDR election results.
- Any optional capabilities supported by each router.

The Hello protocol is comparatively trivial and will not be explored in greater
detail than here.

.. index:: OSPF LSA overview
.. _ospf-lsas:

LSAs
^^^^

At the heart of :abbr:`OSPF` are :abbr:`LSA (Link State Advertisement)`
messages. Despite the name, some :abbr:`LSA` s do not, strictly speaking,
describe link-state information. Common :abbr:`LSA` s describe information
such as:

- Routers, in terms of their links.
- Networks, in terms of attached routers.
- Routes, external to a link-state domain:

  External Routes
     Routes entirely external to :abbr:`OSPF`. Routers originating such
     routes are known as :abbr:`ASBR (Autonomous-System Border Router)`
     routers.

  Summary Routes
     Routes which summarise routing information relating to OSPF areas
     external to the OSPF link-state area at hand, originated by
     :abbr:`ABR (Area Boundary Router)` routers.

.. _ospf-lsa-flooding:

LSA Flooding
""""""""""""

OSPF defines several related mechanisms, used to manage synchronisation of
:abbr:`LSDB` s between neighbours as neighbours form adjacencies and the
propagation, or `flooding` of new or updated :abbr:`LSA` s.

.. index:: OSPF Areas overview

.. _ospf-areas:

Areas
^^^^^

OSPF provides for the protocol to be broken up into multiple smaller and
independent link-state areas. Each area must be connected to a common backbone
area by an :abbr:`ABR (Area Boundary Router)`. These :abbr:`ABR` routers are
responsible for summarising the link-state routing information of an area into
`Summary LSAs`, possibly in a condensed (i.e. aggregated) form, and then
originating these summaries into all other areas the :abbr:`ABR` is connected
to.

Note that only summaries and external routes are passed between areas.  As
these describe *paths*, rather than any router link-states, routing between
areas hence is by :term:`distance-vector`, **not** link-state.

OSPF LSAs
---------

The core objects in OSPF are :abbr:`LSA` s. Everything else in OSPF revolves
around detecting what to describe in LSAs, when to update them, how to flood
them throughout a network and how to calculate routes from them.

There are a variety of different :abbr:`LSA` s, for purposes such as describing
actual link-state information, describing paths (i.e.  routes), describing
bandwidth usage of links for :abbr:`TE (Traffic Engineering)` purposes, and
even arbitrary data by way of *Opaque* :abbr:`LSA` s.

LSA Header
^^^^^^^^^^

All LSAs share a common header with the following information:

- Type

  Different types of :abbr:`LSA` s describe different things in
  :abbr:`OSPF`. Types include:

  - Router LSA
  - Network LSA
  - Network Summary LSA
  - Router Summary LSA
  - AS-External LSA

  The specifics of the different types of LSA are examined below.

- Advertising Router

  The Router ID of the router originating the LSA.

.. seealso::

   :clicmd:`ospf router-id A.B.C.D`.

- LSA ID

  The ID of the LSA, which is typically derived in some way from the
  information the LSA describes, e.g. a Router LSA uses the Router ID as
  the LSA ID, a Network LSA will have the IP address of the :abbr:`DR`
  as its LSA ID.

  The combination of the Type, ID and Advertising Router ID must uniquely
  identify the :abbr:`LSA`. There can however be multiple instances of
  an LSA with the same Type, LSA ID and Advertising Router ID, see
  :ref:`sequence number <ospf-lsa-sequence-number>`.

- Age

  A number to allow stale :abbr:`LSA` s to, eventually, be purged by routers
  from their :abbr:`LSDB` s.

  The value nominally is one of seconds. An age of 3600, i.e. 1 hour, is
  called the `MaxAge`. MaxAge LSAs are ignored in routing
  calculations. LSAs must be periodically refreshed by their Advertising
  Router before reaching MaxAge if they are to remain valid.

  Routers may deliberately flood LSAs with the age artificially set to
  3600 to indicate an LSA is no longer valid. This is called
  `flushing` of an LSA.

  It is not abnormal to see stale LSAs in the LSDB, this can occur where
  a router has shutdown without flushing its LSA(s), e.g. where it has
  become disconnected from the network. Such LSAs do little harm.

.. _ospf-lsa-sequence-number:

- Sequence Number

  A number used to distinguish newer instances of an LSA from older instances.

Link-State LSAs
^^^^^^^^^^^^^^^

Of all the various kinds of :abbr:`LSA` s, just two types comprise the
actual link-state part of :abbr:`OSPF`, Router :abbr:`LSA` s and
Network :abbr:`LSA` s. These LSA types are absolutely core to the
protocol.

Instances of these LSAs are specific to the link-state area in which
they are originated. Routes calculated from these two LSA types are
called `intra-area routes`.

- Router LSA

  Each OSPF Router must originate a router :abbr:`LSA` to describe
  itself. In it, the router lists each of its :abbr:`OSPF` enabled
  interfaces, for the given link-state area, in terms of:

  Cost
     The output cost of that interface, scaled inversely to some commonly known
     reference value, :clicmd:`auto-cost reference-bandwidth (1-4294967`.

  Link Type
     Transit Network

     A link to a multi-access network, on which the router has at least one
     Full adjacency with another router.

  :abbr:`PtP (Point-to-Point)`
     A link to a single remote router, with a Full adjacency. No
     :abbr:`DR (Designated Router)` is elected on such links; no network
     LSA is originated for such a link.

     Stub
        A link with no adjacent neighbours, or a host route.

  - Link ID and Data

    These values depend on the Link Type:

    +----------------+-----------------------------------+------------------------------------------+
    | Link Type      | Link ID                           | Link Data                                |
    +================+===================================+==========================================+
    | Transit        | Link IP address of the :abbr:`DR` | Interface IP address                     |
    +----------------+-----------------------------------+------------------------------------------+
    | Point-to-Point | Router ID of the remote router    | Local interface IP address, or the       |
    |                |                                   | :abbr:`ifindex (MIB-II interface index)` |
    |                |                                   | for unnumbered links                     |
    +----------------+-----------------------------------+------------------------------------------+
    | Stub           | IP address                        | Subnet Mask                              |
    +----------------+-----------------------------------+------------------------------------------+

    Links on a router may be listed multiple times in the Router LSA, e.g.  a
    :abbr:`PtP` interface on which OSPF is enabled must *always* be described
    by a Stub link in the Router :abbr:`LSA`, in addition to being listed as
    PtP link in the Router :abbr:`LSA` if the adjacency with the remote router
    is Full.

    Stub links may also be used as a way to describe links on which OSPF is
    *not* spoken, known as `passive interfaces`, see
    :clicmd:`passive-interface INTERFACE`.

- Network LSA

  On multi-access links (e.g. ethernets, certain kinds of ATM and X.25
  configurations), routers elect a :abbr:`DR`. The :abbr:`DR` is
  responsible for originating a Network :abbr:`LSA`, which helps reduce
  the information needed to describe multi-access networks with multiple
  routers attached. The :abbr:`DR` also acts as a hub for the flooding of
  :abbr:`LSA` s on that link, thus reducing flooding overheads.

  The contents of the Network LSA describes the:

  - Subnet Mask

    As the :abbr:`LSA` ID of a Network LSA must be the IP address of the
    :abbr:`DR`, the Subnet Mask together with the :abbr:`LSA` ID gives
    you the network address.

  - Attached Routers

    Each router fully-adjacent with the :abbr:`DR` is listed in the LSA,
    by their Router-ID. This allows the corresponding Router :abbr:`LSA` s to be
    easily retrieved from the :abbr:`LSDB`.

Summary of Link State LSAs:

+-------------+----------------------------+--------------------------------------------+
| LSA Type    | LSA ID                     | LSA Data Describes                         |
+=============+============================+============================================+
| Router LSA  | Router ID                  | The :abbr:`OSPF` enabled links of the      |
|             |                            | router, within a specific link-state area. |
+-------------+----------------------------+--------------------------------------------+
| Network LSA | The IP address of the      | The subnet mask of the network and the     |
|             | :abbr:`DR` for the network | Router IDs of all routers on the network   |
+-------------+----------------------------+--------------------------------------------+

With an LSDB composed of just these two types of :abbr:`LSA`, it is
possible to construct a directed graph of the connectivity between all
routers and networks in a given OSPF link-state area. So, not
surprisingly, when OSPF routers build updated routing tables, the first
stage of :abbr:`SPF` calculation concerns itself only with these two
LSA types.

.. _ospf-link-state-lsa-examples:

Link-State LSA Examples
^^^^^^^^^^^^^^^^^^^^^^^

The example below shows two :abbr:`LSA` s, both originated by the same router
(Router ID 192.168.0.49) and with the same :abbr:`LSA` ID (192.168.0.49), but
of different LSA types.

The first LSA being the router LSA describing 192.168.0.49's links: 2 links
to multi-access networks with fully-adjacent neighbours (i.e. Transit
links) and 1 being a Stub link (no adjacent neighbours).

The second LSA being a Network LSA, for which 192.168.0.49 is the
:abbr:`DR`, listing the Router IDs of 4 routers on that network which
are fully adjacent with 192.168.0.49.

::

   # show ip ospf database router 192.168.0.49

          OSPF Router with ID (192.168.0.53)

                   Router Link States (Area 0.0.0.0)

     LS age: 38
     Options: 0x2  : *|-|-|-|-|-|E|*
     LS Flags: 0x6
     Flags: 0x2 : ASBR
     LS Type: router-LSA
     Link State ID: 192.168.0.49
     Advertising Router: 192.168.0.49
     LS Seq Number: 80000f90
     Checksum: 0x518b
     Length: 60
      Number of Links: 3

       Link connected to: a Transit Network
        (Link ID) Designated Router address: 192.168.1.3
        (Link Data) Router Interface address: 192.168.1.3
         Number of TOS metrics: 0
          TOS 0 Metric: 10

       Link connected to: a Transit Network
        (Link ID) Designated Router address: 192.168.0.49
        (Link Data) Router Interface address: 192.168.0.49
         Number of TOS metrics: 0
          TOS 0 Metric: 10

       Link connected to: Stub Network
        (Link ID) Net: 192.168.3.190
        (Link Data) Network Mask: 255.255.255.255
         Number of TOS metrics: 0
          TOS 0 Metric: 39063
   # show ip ospf database network 192.168.0.49

          OSPF Router with ID (192.168.0.53)

                   Net Link States (Area 0.0.0.0)

     LS age: 285
     Options: 0x2  : *|-|-|-|-|-|E|*
     LS Flags: 0x6
     LS Type: network-LSA
     Link State ID: 192.168.0.49 (address of Designated Router)
     Advertising Router: 192.168.0.49
     LS Seq Number: 80000074
     Checksum: 0x0103
     Length: 40
     Network Mask: /29
           Attached Router: 192.168.0.49
           Attached Router: 192.168.0.52
           Attached Router: 192.168.0.53
           Attached Router: 192.168.0.54


Note that from one LSA, you can find the other. E.g. Given the
Network-LSA you have a list of Router IDs on that network, from which
you can then look up, in the local :abbr:`LSDB`, the matching Router
LSA. From that Router-LSA you may (potentially) find links to other
Transit networks and Routers IDs which can be used to lookup the
corresponding Router or Network LSA. And in that fashion, one can find
all the Routers and Networks reachable from that starting :abbr:`LSA`.

Given the Router LSA instead, you have the IP address of the
:abbr:`DR` of any attached transit links. Network LSAs will have that IP
as their LSA ID, so you can then look up that Network LSA and from that
find all the attached routers on that link, leading potentially to more
links and Network and Router LSAs, etc. etc.

From just the above two :abbr:`LSA` s, one can already see the
following partial topology:

::

   ------------------------ Network: ......
               |            Designated Router IP: 192.168.1.3
               |
         IP: 192.168.1.3
          (transit link)
           (cost: 10)
      Router ID: 192.168.0.49(stub)---------- IP: 192.168.3.190/32
           (cost: 10)        (cost: 39063)
          (transit link)
         IP: 192.168.0.49
               |
               |
   ------------------------------ Network: 192.168.0.48/29
     |        |           |       Designated Router IP: 192.168.0.49
     |        |           |
     |        |     Router ID: 192.168.0.54
     |        |
     |   Router ID: 192.168.0.53
     |
   Router ID: 192.168.0.52


Note the Router IDs, though they look like IP addresses and often are
IP addresses, are not strictly speaking IP addresses, nor need they be
reachable addresses (though, OSPF will calculate routes to Router IDs).

External LSAs
^^^^^^^^^^^^^

External, or "Type 5", :abbr:`LSA` s describe routing information which is
entirely external to :abbr:`OSPF`, and is "injected" into
:abbr:`OSPF`. Such routing information may have come from another
routing protocol, such as RIP or BGP, they may represent static routes
or they may represent a default route.

An :abbr:`OSPF` router which originates External :abbr:`LSA` s is known as an
:abbr:`ASBR (AS Boundary Router)`. Unlike the link-state :abbr:`LSA` s, and
most other :abbr:`LSA` s, which are flooded only within the area in
which they originate, External :abbr:`LSA` s are flooded through-out
the :abbr:`OSPF` network to all areas capable of carrying External
:abbr:`LSA` s (:ref:`ospf-areas`).

Routes internal to OSPF (intra-area or inter-area) are always preferred
over external routes.

The External :abbr:`LSA` describes the following:

IP Network number
   The IP Network number of the route is described by the :abbr:`LSA` ID field.

IP Network Mask
   The body of the External LSA describes the IP Network Mask of the route.
   This, together with the :abbr:`LSA` ID, describes the prefix of the IP route
   concerned.

Metric
   The cost of the External Route. This cost may be an OSPF cost (also known as
   a "Type 1" metric), i.e. equivalent to the normal OSPF costs, or an
   externally derived cost ("Type 2" metric) which is not comparable to OSPF
   costs and always considered larger than any OSPF cost. Where there are both
   Type 1 and 2 External routes for a route, the Type 1 is always preferred.

Forwarding Address
   The address of the router to forward packets to for the route. This may be,
   and usually is, left as 0 to specify that the ASBR originating the External
   :abbr:`LSA` should be used. There must be an internal OSPF route to the
   forwarding address, for the forwarding address to be usable.

Tag
   An arbitrary 4-bytes of data, not interpreted by OSPF, which may carry
   whatever information about the route which OSPF speakers desire.

AS External LSA Example
^^^^^^^^^^^^^^^^^^^^^^^

To illustrate, below is an example of an External :abbr:`LSA` in the
:abbr:`LSDB` of an OSPF router. It describes a route to the IP prefix of
192.168.165.0/24, originated by the ASBR with Router-ID 192.168.0.49. The
metric of 20 is external to OSPF. The forwarding address is 0, so the route
should forward to the originating ASBR if selected.

::

   # show ip ospf database external 192.168.165.0
     LS age: 995
     Options: 0x2  : *|-|-|-|-|-|E|*
     LS Flags: 0x9
     LS Type: AS-external-LSA
     Link State ID: 192.168.165.0 (External Network Number)
     Advertising Router: 192.168.0.49
     LS Seq Number: 800001d8
     Checksum: 0xea27
     Length: 36
     Network Mask: /24
           Metric Type: 2 (Larger than any link state path)
           TOS: 0
           Metric: 20
           Forward Address: 0.0.0.0
           External Route Tag: 0


We can add this to our partial topology from above, which now looks
like:::

   --------------------- Network: ......
            |            Designated Router IP: 192.168.1.3
            |
      IP: 192.168.1.3      /---- External route: 192.168.165.0/24
       (transit link)     /                Cost: 20 (External metric)
        (cost: 10)       /
   Router ID: 192.168.0.49(stub)---------- IP: 192.168.3.190/32
        (cost: 10)        (cost: 39063)
       (transit link)
      IP: 192.168.0.49
            |
            |
   ------------------------------ Network: 192.168.0.48/29
     |        |           |       Designated Router IP: 192.168.0.49
     |        |           |
     |        |     Router ID: 192.168.0.54
     |        |
     |   Router ID: 192.168.0.53
     |
   Router ID: 192.168.0.52


Summary LSAs
^^^^^^^^^^^^

Summary LSAs are created by :abbr:`ABR` s to summarise the destinations
available within one area to other areas. These LSAs may describe IP networks,
potentially in aggregated form, or :abbr:`ASBR` routers.
