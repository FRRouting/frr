BGP Next Hop Group
==================

BGP nexthop group is an optimization feature that splits the route message to send
in two, by dissociating the nexthop information with the prefix information. This
results in reducing the number of route messages to send when a failover happens.

Goal
----

The goal is the following:

- **Stability**: reduce the number of messages to send from *bgp* to *zebra* when a failover
  happens. Today, flapping interface triggers as many messages as there are prefixes to
  update. And the more the flapping happens, the more the memory taken will increase,
  and the most likely *bgp* or *zebra* process may make an `Out of Memory` issue.

- **Convergence**: improve the resilience by reducing the *zebra* time convergence when
  a next-hop becomes unreachable.

Example
-------

Let us imagine a BGP router with two devices at nexthop NH1 and NH2: peer1 and peer2.
BGP addpath feature is enabled. BGP receives BGP updates with different ADDPATH-ID
identifiers. The route structure looks like below:

  pDest = 192.0.2.1
    path_1_1, NH1 from peer1
    path_1_2, NH2 from peer2
  pDest = 192.0.2.2
    path_2_1, NH1 from peer1
    path_2_2, NH2 from peer2

To support the nexthop info, a 'bgp_nhg_cache' structure is used and hosts the nexthop information.
This nexthop information is based on the incoming BGP update + the BGP characteristics
(ebgp/ibgp, color community, ..). This is a zapi_nexthop structure. An unique 'nhg_id' identifier
is used.

  NEXTHOP_1 (bgp_nhg_cache) : TYPE_NEXTHOP
      -> struct zapi_nexthop znh;
      -> uint32_t nhg_id;
      -> list bgp_path_info

To support ECMP or WECMP cases, there is need to group the nexthops together. the 'bgp_nhg_cache'
structure hosts the nexthop group information. The below drawing illustrates an ECMP
nexthop with NH1 and NH2. Three 'bgp_nhg_cache' structures are used to represent it. Each strucure
owns an unique 'nhg_id' identifier.

  NHG_0 (bgp_nhg_cache) : TYPE_GROUP
          -> uint32_t nhg_id; --> NHG_0
          -> nhg_childs  ---> NEXTHOP_1 (bgp_nhg_cache) : TYPE_NEXTHOP
                                        nhg_parents ---> NHG_1
                         ---> NEXTHOP_2 (bgp_nhg_cache) : TYPE_NEXTHOP
                                        nhg_parents ---> NHG_2
          -> nhg_parents (NULL)
          -> list bgp_path_info

If the nexthop-group feature is enabled, the bgp_path_info structure owns 2 back-pointers:
bgp_nhg and bgp_nhg_nexthop. The referenced structures are 'bgp_nhg_cache' structures.
The `bgp_nhg_nexthop` pointer is used for all SELECTED and MULTIPATH paths.
The `bgp_nhg` pointer is used for all SELECTED paths.

 pDest = 192.0.2.1
    path_1_1, NH1 from peer1 -------> bgp_nhg_nexthop (bgp_nhg_cache) : NEXTHOP_1
                             -------> bgp_nhg (bgp_nhg_cache) : NHG_0

If we assume all the 4 paths are selected, and an ECMP group is formed with NH1 and NH2,
the internal structures are referenced like below:

  pDest = 192.0.2.1
    path_1_1, NH1 from peer1 -----+-----------------------------> bgp_nhg_nexthop (nhg) : NEXTHOP_1
                             -----|----+-+--+--> bgp_nhg (nhg) : NHG_0
    path_1_2, NH2 from peer2 -----|--+-|-|--|-------------------> bgp_nhg_nexthop (nhg) : NEXTHOP_2
                             -----|--|-+ |  |
  pDest = 192.0.2.2               |  |   |  |
    path_2_1, NH1 from peer1 -----+  |   |  |
                             --------|---+  |
    path_2_2, NH2 from peer2 --------+      |
                             ---------------+

nhg (NHG_0) has the {path_1_1, path_2_1} paths referenced.
nhg (NEXTHOP_1) has the {path_1_1, path_2_1} paths referenced.
nhg (NEXTHOP_2) has the {path_1_2, path_2_2} paths referenced.

BGP sends the following operations to ZEBRA.

  NHG_ADD(NHG_ID1)
  NHG_ADD(NHG_ID2)
  NHG_CHILD_ADD(NHG_0, {NHG_ID1, NHG_ID2})
  ROUTE_ADD(p1, NHG_0)
  ROUTE_ADD(p2, NHG_0)

Some events like peer2 becoming unreachable, or BGP BFD failure require a full flush of the ADJ-RIB-IN
of peer2. The BGP router will detect those events and will group the failover changes together, by
detaching all the bgp_nhg_nexthop from the concerned BGP updates.

- The NH2 nexthop represented by bgp_nhg_nexthop (NHG_ID2) is dereferenced from peer2 updates.
- If NHG_ID2 paths references is empty, then NHG_ID2 can be removed
- The NHG_0 can be detached from NHG_ID2, and updated to ZEBRA

Only the {path_1_1, path_2_1} paths are maintained as {path_2_1} and {path_2_2} will be removed.

  path_1_1(Prefix P1 = 192.0.2.1, NH1 from peer1) -> bgp_nhg_nexthop ------> nhg (NHG_ID1)
                                                     bgp_nhg  -------------> nhg (NHG_ID3)

  path_2_1(Prefix P2 = 192.0.2.2, NH1 from peer1) -> bgp_nhg_nexthop ------> nhg (NHG_ID1)
                                                     bgp_nhg  -------------> nhg (NHG_0)

BGP sends the following operations to ZEBRA:

  NHG_CHILD_ADD(NHG_0, {NHG_ID1})
  NHG_DEL(NHG_ID2)

Note that there is no need to send ROUTE_ADD messages, as only the nexthop changed.
