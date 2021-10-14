Link State API Documentation
============================

Introduction
------------

The Link State (LS) API aims to provide a set of structures and functions to
build and manage a Traffic Engineering Database for the various FRR daemons.
This API has been designed for several use cases:

- BGP Link State (BGP-LS): where BGP protocol need to collect the link state
  information from the routing daemons (IS-IS and/or OSPF) to implement RFC7572
- Path Computation Element (PCE): where path computation algorithms are based
  on Traffic Engineering Database
- ReSerVation Protocol (RSVP): where signaling need to know the Traffic
  Engineering topology of the network in order to determine the path of
  RSVP tunnels

Architecture
------------

The main requirements from the various uses cases are as follow:

- Provides a set of data model and function to ease Link State information
  manipulation (storage, serialize, parse ...)
- Ease and normalize Link State information exchange between FRR daemons
- Provides database structure for Traffic Engineering Database (TED)

To ease Link State understanding, FRR daemons have been classified into two
categories:

- **Consumer**: Daemons that consume Link State information e.g. BGPd
- **Producer**: Daemons that are able to collect Link State information and
  send them to consumer daemons e.g. OSPFd IS-ISd

Zebra daemon, and more precisely, the ZAPI message is used to convey the Link
State information between *producer* and *consumer*, but, Zebra acts as a
simple pass through and does not store any Link State information. A new ZAPI
**Opaque** message has been design for that purpose.

Each consumer and producer daemons are free to store or not Link State data and
organise the information following the Traffic Engineering Database model
provided by the API or any other data structure e.g. Hash, RB-tree ...

Link State API
--------------

This is the low level API that allows any daemons manipulate the Link State
elements that are stored in the Link State Database.

Data structures
^^^^^^^^^^^^^^^

3 types of Link State structure have been defined:

.. c:struct:: ls_node

   that groups all information related to a node

.. c:struct:: ls_attributes

   that groups all information related to a link

.. c:struct:: ls_prefix

   that groups all information related to a prefix

These 3 types of structures are those handled by BGP-LS (see RFC7752) and
suitable to describe a Traffic Engineering topology.

Each structure, in addition to the specific parameters, embed the node
identifier which advertises the Link State and a bit mask as flags to
indicates which parameters are valid i.e. for which the value is valid and
corresponds to a Link State information conveyed by the routing protocol.

.. c:struct:: ls_node_id

   defines the Node identifier as router ID IPv4 address plus the area ID for
   OSPF or the ISO System ID plus the IS-IS level for IS-IS.

Functions
^^^^^^^^^

A set of functions is provided to create, delete and compare Link State
Node, Atribute and Prefix:

.. c:function:: struct ls_node *ls_node_new(struct ls_node_id adv, struct in_addr router_id, struct in6_addr router6_id)
.. c:function:: struct ls_attributes *ls_attributes_new(struct ls_node_id adv, struct in_addr local, struct in6_addr local6, uint32_t local_id)
.. c:function:: struct ls_prefix *ls_prefix_new(struct ls_node_id adv, struct prefix p)

   Create respectively a new Link State Node, Attribute or Prefix.
   Structure is dynamically allocated. Link State Node ID (adv) is mandatory
   and:

   - at least one of IPv4 or IPv6 must be provided for the router ID
     (router_id or router6_id) for Node
   - at least one of local, local6 or local_id must be provided for Attribute
   - prefix is mandatory for Link State Prefix.

.. c:function:: void ls_node_del(struct ls_node *node)
.. c:function:: void ls_attributes_del(struct ls_attributes *attr)
.. c:function:: void ls_prefix_del(struct ls_prefix *pref)

   Remove, respectively Link State Node, Attributes or Prefix.
   Data structure is freed.

.. c:function:: void ls_attributes_srlg_del(struct ls_attributes *attr)

   Remove SRLGs attribute if defined. Data structure is freed.

.. c:function:: int ls_node_same(struct ls_node *n1, struct ls_node *n2)
.. c:function:: int ls_attributes_same(struct ls_attributes *a1, struct ls_attributes *a2)
.. c:function:: int ls_prefix_same(struct ls_prefix *p1, struct ls_prefix*p2)

   Check, respectively if two Link State Nodes, Attributes or Prefix are equal.
   Note that these routines have the same return value sense as '==' (which is
   different from a comparison).


Link State TED
--------------

This is the high level API that provides functions to create, update, delete a
Link State Database to build a Traffic Engineering Database (TED).

Data Structures
^^^^^^^^^^^^^^^

The Traffic Engineering is modeled as a Graph in order to ease Path Computation
algorithm implementation. Denoted **G(V, E)**, a graph is composed by a list of
**Vertices (V)** which represents the network Node and a list of **Edges (E)**
which represents Link. An additional list of **prefixes (P)** is also added and
also attached to the *Vertex (V)* which advertise it.

*Vertex (V)* contains the list of outgoing *Edges (E)* that connect this Vertex
with its direct neighbors and the list of incoming *Edges (E)* that connect
the direct neighbors to this Vertex. Indeed, the *Edge (E)* is unidirectional,
thus, it is necessary to add 2 Edges to model a bidirectional relation between
2 Vertices. Finally, the *Vertex (V)* contains a pointer to the corresponding
Link State Node.

*Edge (E)* contains the source and destination Vertex that this Edge
is connecting and a pointer to the corresponding Link State Attributes.

A unique Key is used to identify both Vertices and Edges within the Graph.


::

          --------------     ---------------------------    --------------
          | Connected  |---->| Connected Edge Va to Vb |--->| Connected  |
      --->|  Vertex    |     ---------------------------    |  Vertex    |---->
          |            |                                    |            |
          | - Key (Va) |                                    | - Key (Vb) |
      <---| - Vertex   |     ---------------------------    | - Vertex   |<----
          |            |<----| Connected Edge Vb to Va |<---|            |
          --------------     ---------------------------    --------------


4 data structures have been defined to implement the Graph model:

.. c:struct:: ls_vertex
.. c:struct:: ls_edge
.. c:struct:: ls_ted

 - :c:struct:`ls_prefix`

TED stores Vertex, Edge and Subnet elements with a RB Tree structure.
The Vertex key corresponds to the Router ID for OSPF and ISO System ID for
IS-IS. The Edge key corresponds to the IPv4 address, the lowest 64 bits of
the IPv6 address or the combination of the local & remote ID of the interface.
The Subnet key corresponds to the Prefix address (v4 or v6).

An additional status for Vertex, Edge and Subnet allows to determine the state
of the element in the TED: UNSET, NEW, UPDATE, DELETE, SYNC, ORPHAN. Normal
state is SYNC. NEW, UPDATE and DELETE are temporary state when element is
processed. UNSET is normally never used and ORPHAN serves to identify elements
that must be remove when TED is cleaning.

Vertex, Edges and Subnets management functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. c:function:: struct ls_vertex *ls_vertex_add(struct ls_ted *ted, struct ls_node *node)
.. c:function:: struct ls_edge *ls_edge_add(struct ls_ted *ted, struct ls_attributes *attributes)
.. c:function:: struct ls_subnet *ls_subnet_add(struct ls_ted *ted, struct ls_prefix *pref)

   Add, respectively new Vertex, Edge or Subnet to the Link State Datebase.
   Vertex, Edge or Subnet are created from, respectively the Link State Node,
   Attribute or Prefix structure. Data structure are dynamically allocated.

.. c:function:: struct ls_vertex *ls_vertex_update(struct ls_ted *ted, struct ls_node *node)
.. c:function:: struct ls_edge *ls_edge_update(struct ls_ted *ted, struct ls_attributes *attributes)
.. c:function:: struct ls_subnet *ls_subnet_update(struct ls_ted *ted, struct ls_prefix *pref)

   Update, respectively Vertex, Edge or Subnet with, respectively the Link
   State Node, Attribute or Prefix. A new data structure is created if no one
   corresponds to the Link State Node, Attribute or Prefix. If element already
   exists in the TED, its associated Link State information is replaced by the
   new one if there are different and the old associated Link State information
   is deleted and memory freed.

.. c:function:: void ls_vertex_del(struct ls_ted *ted, struct ls_vertex *vertex)
.. c:function:: void ls_vertex_del_all(struct ls_ted *ted, struct ls_vertex *vertex)
.. c:function:: void ls_edge_del(struct ls_ted *ted, struct ls_edge *edge)
.. c:function:: void ls_edge_del_all(struct ls_ted *ted, struct ls_edge *edge)
.. c:function:: void ls_subnet_del(struct ls_ted *ted, struct ls_subnet *subnet)
.. c:function:: void ls_subnet_del_all(struct ls_ted *ted, struct ls_subnet *subnet)

   Delete, respectively Link State Vertex, Edge or Subnet. Data structure are
   freed but not the associated Link State information with the simple `_del()`
   form of the function while the `_del_all()` version freed also associated
   Link State information. TED is not modified if Vertex, Edge or Subnet is
   NULL or not found in the Data Base. Note that references between Vertices,
   Edges and Subnets are removed first.

.. c:function:: struct ls_vertex *ls_find_vertex_by_key(struct ls_ted *ted, const uint64_t key)
.. c:function:: struct ls_vertex *ls_find_vertex_by_id(struct ls_ted *ted, struct ls_node_id id)

   Find Vertex in the TED by its unique key or its Link State Node ID.
   Return Vertex if found, NULL otherwise.

.. c:function:: struct ls_edge *ls_find_edge_by_key(struct ls_ted *ted, const uint64_t key)
.. c:function:: struct ls_edge *ls_find_edge_by_source(struct ls_ted *ted, struct ls_attributes *attributes);
.. c:function:: struct ls_edge *ls_find_edge_by_destination(struct ls_ted *ted, struct ls_attributes *attributes);

   Find Edge in the Link State Data Base by its key, source or distination
   (local IPv4 or IPv6 address or local ID) informations of the Link State
   Attributes. Return Edge if found, NULL otherwise.

.. c:function:: struct ls_subnet *ls_find_subnet(struct ls_ted *ted, const struct prefix prefix)

   Find Subnet in the Link State Data Base by its key, i.e. the associated
   prefix. Return Subnet if found, NULL otherwise.

.. c:function:: int ls_vertex_same(struct ls_vertex *v1, struct ls_vertex *v2)
.. c:function:: int ls_edge_same(struct ls_edge *e1, struct ls_edge *e2)
.. c:function:: int ls_subnet_same(struct ls_subnet *s1, struct ls_subnet *s2)

   Check, respectively if two Vertices, Edges or Subnets are equal.
   Note that these routines has the same return value sense as '=='
   (which is different from a comparison).


TED management functions
^^^^^^^^^^^^^^^^^^^^^^^^

Some helpers functions have been also provided to ease TED management:

.. c:function:: struct ls_ted *ls_ted_new(const uint32_t key, char *name, uint32_t asn)

   Create a new Link State Data Base. Key must be different from 0.
   Name could be NULL and AS number equal to 0 if unknown.

.. c:function:: void ls_ted_del(struct ls_ted *ted)
.. c:function:: void ls_ted_del_all(struct ls_ted *ted)

   Delete existing Link State Data Base. Vertices, Edges, and Subnets are not
   removed with ls_ted_del() function while they are with ls_ted_del_all().

.. c:function:: void ls_connect_vertices(struct ls_vertex *src, struct ls_vertex *dst, struct ls_edge *edge)

   Connect Source and Destination Vertices by given Edge. Only non NULL source
   and destination vertices are connected.

.. c:function:: void ls_connect(struct ls_vertex *vertex, struct ls_edge *edge, bool source)
.. c:function:: void ls_disconnect(struct ls_vertex *vertex, struct ls_edge *edge, bool source)

   Connect / Disconnect Link State Edge to the Link State Vertex which could be
   a Source (source = true) or a Destination (source = false) Vertex.

.. c:function:: void ls_disconnect_edge(struct ls_edge *edge)

   Disconnect Link State Edge from both Source and Destination Vertex.
   Note that Edge is not removed but its status is marked as ORPHAN.

.. c:function:: void ls_vertex_clean(struct ls_ted *ted, struct ls_vertex *vertex, struct zclient *zclient)

   Clean Vertex structure by removing all Edges and Subnets marked as ORPHAN
   from this vertex. Corresponding Link State Update message is sent if zclient
   parameter is not NULL. Note that associated Link State Attribute and Prefix
   are also removed and memory freed.

.. c:function:: void ls_ted_clean(struct ls_ted *ted)

   Clean Link State Data Base by removing all Vertices, Edges and SubNets
   marked as ORPHAN. Note that associated Link State Node, Attributes and
   Prefix are removed too.

.. c:function:: void ls_show_vertex(struct ls_vertex *vertex, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_edge(struct ls_edeg *edge, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_subnet(struct ls_subnet *subnet, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_vertices(struct ls_ted *ted, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_edges(struct ls_ted *ted, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_subnets(struct ls_ted *ted, struct vty *vty, struct json_object *json, bool verbose)
.. c:function:: void ls_show_ted(struct ls_ted *ted, struct vty *vty, struct json_object *json, bool verbose)

   Respectively, show Vertex, Edge, Subnet provided as parameter, all Vertices,
   all Edges, all Subnets and the whole TED if not specified. Output could be
   more detailed with verbose parameter for VTY output. If both JSON and VTY
   output are specified, JSON takes precedence over VTY.

.. c:function:: void ls_dump_ted(struct ls_ted *ted)

   Dump TED information to the current logging output.

Link State Messages
-------------------

This part of the API provides functions and data structure to ease the
communication between the *Producer* and *Consumer* daemons.

Communications principles
^^^^^^^^^^^^^^^^^^^^^^^^^

Recent ZAPI Opaque Message is used to exchange Link State data between daemons.
For that purpose, Link State API provides new functions to serialize and parse
Link State information through the ZAPI Opaque message. A dedicated flag,
named ZAPI_OPAQUE_FLAG_UNICAST, allows daemons to send a unicast or a multicast
Opaque message and is used as follow for the Link State exchange:

- Multicast: To send data update to all daemons that have subscribed to the
  Link State Update message
- Unicast: To send initial Link State information from a particular daemon. All
  data are send only to the daemon that request Link State Synchronisatio

Figure 1 below, illustrates the ZAPI Opaque message exchange between a
*Producer* (an IGP like OSPF or IS-IS) and a *Consumer* (e.g. BGP). The
message sequences are as follows:

- First, both *Producer* and *Consumer* must register to their respective ZAPI
  Opaque Message: **Link State Sync** for the *Producer* in order to receive
  Database synchronisation request from a *Consumer*, **Link State Update** for
  the *Consumer* in order to received any Link State update from a *Producer*.
  These register messages are stored by Zebra to determine to which daemon it
  should redistribute the ZAPI messages it receives.
- Then, the *Consumer* sends a **Link State Synchronistation** request with the
  Multicast method in order to receive the complete Link State Database from a
  *Producer*. ZEBRA daemon forwards this message to any *Producer* daemons that
  previously registered to this message. If no *Producer* has yet registered,
  the request is lost. Thus, if the *Consumer* receives no response whithin a
  given timer, it means that no *Producer* are available right now. So, the
  *Consumer* must send the same request until it receives a Link State Database
  Synchronistation message. This behaviour is necessary as we can't control in
  which order daemons are started. It is up to the *Consumer* daemon to fix the
  timeout and the number of retry.
- When a *Producer* receives a **Link State Synchronisation** request, it
  starts sending all elements of its own Link State Database through the
  **Link State Database Synchronisation** message. These messages are send with
  the Unicast method to avoid flooding other daemons with these elements. ZEBRA
  layer ensures to forward the message to the right daemon.
- When a *Producer* update its Link State Database, it automatically sends a
  **Link State Update** message with the Multicast method. In turn, ZEBRA
  daemon forwards the message to all *Consumer* daemons that previously
  registered to this message. if no daemon is registered, the message is lost.
- A daemon could unregister from the ZAPI Opaque message registry at any time.
  In this case, the ZEBRA daemon stops to forward any messages it receives to
  this daemon, even if it was previously converns.

::

       IGP                           ZEBRA                        Consumer
    (OSPF/IS-IS)               (ZAPI Opaque Thread)              (e.g. BGP)
        |                              |                             |           \
        |                              |      Register LS Update     |            |
        |                              |<----------------------------|   Register Phase
        |                              |                             |            |
        |                              |      Request LS Sync        |            |
        |                              |<----------------------------|            |
        :                              :                             :  A         |
        |    Register LS Sync          |                             |  |         |
        |----------------------------->|                             |  |        /
        :                              :                             :  |TimeOut
        :                              :                             :  |
        |                              |                             |  |
        |                              |      Request LS Sync        |  v        \
        |    Request LS Sync           |<----------------------------|            |
        |<-----------------------------|                             |   Synchronistation
        |    LS DB Update              |                             |           Phase
        |----------------------------->|      LS DB Update           |            |
        |                              |---------------------------->|            |
        |    LS DB Update (cont'd)     |                             |            |
        |----------------------------->|      LS DB Update (cont'd)  |            |
        |            .                 |---------------------------->|            |
        |            .                 |             .               |            |
        |            .                 |             .               |            |
        |    LS DB Update (end)        |             .               |            |
        |----------------------------->|      LS DB Update (end)     |            |
        |                              |---------------------------->|            |
        |                              |                             |           /
        :                              :                             :
        :                              :                             :
        |    LS DB Update              |                             |           \
        |----------------------------->|      LS DB Update           |            |
        |                              |---------------------------->|      Update Phase
        |                              |                             |            |
        :                              :                             :           /
        :                              :                             :
        |                              |                             |           \
        |                              |      Unregister LS Update   |            |
        |                              |<----------------------------|      Deregister Phase
        |                              |                             |            |
        |    LS DB Update              |                             |            |
        |----------------------------->|                             |            |
        |                              |                             |           /
        |                              |                             |

        Figure 1: Link State messages exchange


Data Structures
^^^^^^^^^^^^^^^

The Link State Message is defined to convey Link State parameters from
the routing protocol (OSPF or IS-IS) to other daemons e.g. BGP.

.. c:struct:: ls_message

The structure is composed of:

- Event of the message:

  - Sync: Send the whole LS DB following a request
  - Add: Send the a new Link State element
  - Update: Send an update of an existing Link State element
  - Delete: Indicate that the given Link State element is removed

- Type of Link State element: Node, Attribute or Prefix
- Remote node id when known
- Data: Node, Attributes or Prefix

A Link State Message can carry only one Link State Element (Node, Attributes
of Prefix) at once, and only one Link State Message is sent through ZAPI
Opaque Link State type at once.

Functions
^^^^^^^^^

.. c:function:: int ls_register(struct zclient *zclient, bool server)
.. c:function:: int ls_unregister(struct zclient *zclient, bool server)

   Register / Unregister daemon to received ZAPI Link State Opaque messages.
   Server must be set to true for *Producer* and to false for *Consumer*.

.. c:function:: int ls_request_sync(struct zclient *zclient)

   Request initial Synchronisation to collect the whole Link State Database.

.. c:function:: struct ls_message *ls_parse_msg(struct stream *s)

   Parse Link State Message from stream. Used this function once receiving a
   new ZAPI Opaque message of type Link State.

.. c:function:: void ls_delete_msg(struct ls_message *msg)

   Delete existing message. Data structure is freed.

.. c:function:: int ls_send_msg(struct zclient *zclient, struct ls_message *msg, struct zapi_opaque_reg_info *dst)

   Send Link State Message as new ZAPI Opaque message of type Link State.
   If destination is not NULL, message is sent as Unicast otherwise it is
   broadcast to all registered daemon.

.. c:function:: struct ls_message *ls_vertex2msg(struct ls_message *msg, struct ls_vertex *vertex)
.. c:function:: struct ls_message *ls_edge2msg(struct ls_message *msg, struct ls_edge *edge)
.. c:function:: struct ls_message *ls_subnet2msg(struct ls_message *msg, struct ls_subnet *subnet)

   Create respectively a new Link State Message from a Link State Vertex, Edge
   or Subnet. If Link State Message is NULL, a new data structure is
   dynamically allocated. Note that the Vertex, Edge and Subnet status is used
   to determine the corresponding Link State Message event: ADD, UPDATE,
   DELETE, SYNC.

.. c:function:: int ls_msg2vertex(struct ls_ted *ted, struct ls_message *msg)
.. c:function:: int ls_msg2edge(struct ls_ted *ted, struct ls_message *msg)
.. c:function:: int ls_msg2subnet(struct ls_ted *ted, struct ls_message *msg)

   Convert Link State Message respectively in Vertex, Edge or Subnet and
   update the Link State Database accordingly to the message event: SYNC, ADD,
   UPDATE or DELETE.

.. c:function:: struct ls_element *ls_msg2ted(struct ls_ted *ted, struct ls_message *msg, bool delete)
.. c:function:: struct ls_element *ls_stream2ted(struct ls_ted *ted, struct ls_message *msg, bool delete)

   Convert Link State Message or Stream Buffer in a Link State element (Vertex,
   Edge or Subnet) and update the Link State Database accordingly to the
   message event: SYNC, ADD, UPDATE or DELETE. The function return the generic
   structure ls_element that point to the Vertex, Edge or Subnet which has been
   added, updated or synchronous in the database. Note that the delete boolean
   parameter governs the action for the DELETE action: true, Link State Element
   is removed from the database and NULL is return. If set to false, database
   is not updated and the function sets the Link State Element status to
   Delete and return the element for futur deletion by the calling function.

.. c:function:: int ls_sync_ted(struct ls_ted *ted, struct zclient *zclient, struct zapi_opaque_reg_info *dst)

   Send all the content of the Link State Data Base to the given destination.
   Link State content is sent is this order: Vertices, Edges then Subnet.
   This function must be used when a daemon request a Link State Data Base
   Synchronization.
