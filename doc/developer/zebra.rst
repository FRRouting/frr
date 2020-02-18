.. _zebra:

*****
Zebra
*****

.. _zebra-protocol:

Overview of the Zebra Protocol
==============================

The Zebra protocol is used by protocol daemons to communicate with the
**zebra** daemon.

Each protocol daemon may request and send information to and from the **zebra**
daemon such as interface states, routing state, nexthop-validation, and so on.
Protocol daemons may also install routes with **zebra**. The **zebra** daemon
manages which routes are installed into the forwarding table with the kernel.

The Zebra protocol is a streaming protocol, with a common header. Version 0
lacks a version field and is implicitly versioned. Version 1 and all subsequent
versions have a version field.  Version 0 can be distinguished from all other
versions by examining the 3rd byte of the header, which contains a marker value
of 255 (in Quagga) or 254 (in FRR) for all versions except version 0. The
marker byte corresponds to the command field in version 0, and the marker value
is a reserved command in version 0.

Version History
---------------

- Version 0

  Used by all versions of GNU Zebra and all version of Quagga up to and
  including Quagga 0.98. This version has no ``version`` field, and so is
  implicitly versioned as version 0.

- Version 1

  Added ``marker`` and ``version`` fields, increased ``command`` field to 16
  bits. Used by Quagga versions 0.99.3 through 0.99.20.

- Version 2

  Used by Quagga versions 0.99.21 through 0.99.23.

- Version 3

  Added ``vrf_id`` field. Used by Quagga versions 0.99.23 until FRR fork.

- Version 4

  Change marker value to 254 to prevent people mixing and matching Quagga and
  FRR daemon binaries. Used by FRR versions 2.0 through 3.0.3.

- Version 5

  Increased VRF identifier field from 16 to 32 bits. Used by FRR versions 4.0
  through 5.0.1.

- Version 6

  Removed the following commands:

  * ZEBRA_IPV4_ROUTE_ADD
  * ZEBRA_IPV4_ROUTE_DELETE
  * ZEBRA_IPV6_ROUTE_ADD
  * ZEBRA_IPV6_ROUTE_DELETE

  Used since FRR version 6.0.


Zebra Protocol Definition
=========================

Zebra Protocol Header Field Definitions
---------------------------------------

Length
   Total packet length including this header.

Marker
   Static marker. The marker value, when it exists, is 255 in all versions of
   Quagga. It is 254 in all versions of FRR. This is to allow version 0 headers
   (which do not include version explicitly) to be distinguished from versioned
   headers.

Version
   Zebra protocol version number. Clients should not continue processing
   messages past the version field for versions they do not recognise.

Command
   The Zebra protocol command.


Current Version
^^^^^^^^^^^^^^^

::

   Version 5, 6

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Length            |     Marker    |    Version    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             VRF ID                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Command            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Past Versions
^^^^^^^^^^^^^

::

   Version 0

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Length            |    Command    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

::

   Version 1, 2

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Length            |     Marker    |    Version    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Command            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


::

   Version 3, 4

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Length            |     Marker    |    Version    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             VRF ID            |            Command            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


Zebra Protocol Commands
-----------------------

+------------------------------------+-------+
| Command                            | Value |
+====================================+=======+
| ZEBRA_INTERFACE_ADD                | 0     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_DELETE             | 1     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_ADDRESS_ADD        | 2     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_ADDRESS_DELETE     | 3     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_UP                 | 4     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_DOWN               | 5     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_SET_MASTER         | 6     |
+------------------------------------+-------+
| ZEBRA_INTERFACE_SET_PROTODOWN      | 7     |
+------------------------------------+-------+
| ZEBRA_ROUTE_ADD                    | 8     |
+------------------------------------+-------+
| ZEBRA_ROUTE_DELETE                 | 9     |
+------------------------------------+-------+
| ZEBRA_ROUTE_NOTIFY_OWNER           | 10    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ADD             | 11    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DELETE          | 12    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_ADD     | 13    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_DELETE  | 14    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_ADD                | 15    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_DELETE             | 16    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_UPDATE             | 17    |
+------------------------------------+-------+
| ZEBRA_HELLO                        | 18    |
+------------------------------------+-------+
| ZEBRA_CAPABILITIES                 | 19    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_REGISTER             | 20    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_UNREGISTER           | 21    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_UPDATE               | 22    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_NBR_ADDRESS_ADD    | 23    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_NBR_ADDRESS_DELETE | 24    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_BFD_DEST_UPDATE    | 25    |
+------------------------------------+-------+
| ZEBRA_IMPORT_ROUTE_REGISTER        | 26    |
+------------------------------------+-------+
| ZEBRA_IMPORT_ROUTE_UNREGISTER      | 27    |
+------------------------------------+-------+
| ZEBRA_IMPORT_CHECK_UPDATE          | 28    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_REGISTER            | 29    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_DEREGISTER          | 30    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_UPDATE              | 31    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_REPLAY              | 32    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ROUTE_ADD       | 33    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ROUTE_DEL       | 34    |
+------------------------------------+-------+
| ZEBRA_VRF_UNREGISTER               | 35    |
+------------------------------------+-------+
| ZEBRA_VRF_ADD                      | 36    |
+------------------------------------+-------+
| ZEBRA_VRF_DELETE                   | 37    |
+------------------------------------+-------+
| ZEBRA_VRF_LABEL                    | 38    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_VRF_UPDATE         | 39    |
+------------------------------------+-------+
| ZEBRA_BFD_CLIENT_REGISTER          | 40    |
+------------------------------------+-------+
| ZEBRA_BFD_CLIENT_DEREGISTER        | 41    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_ENABLE_RADV        | 42    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_DISABLE_RADV       | 43    |
+------------------------------------+-------+
| ZEBRA_IPV3_NEXTHOP_LOOKUP_MRIB     | 44    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_LINK_PARAMS        | 45    |
+------------------------------------+-------+
| ZEBRA_MPLS_LABELS_ADD              | 46    |
+------------------------------------+-------+
| ZEBRA_MPLS_LABELS_DELETE           | 47    |
+------------------------------------+-------+
| ZEBRA_MPLS_LABELS_REPLACE          | 48    |
+------------------------------------+-------+
| ZEBRA_IPMR_ROUTE_STATS             | 49    |
+------------------------------------+-------+
| ZEBRA_LABEL_MANAGER_CONNECT        | 50    |
+------------------------------------+-------+
| ZEBRA_LABEL_MANAGER_CONNECT_ASYNC  | 51    |
+------------------------------------+-------+
| ZEBRA_GET_LABEL_CHUNK              | 52    |
+------------------------------------+-------+
| ZEBRA_RELEASE_LABEL_CHUNK          | 53    |
+------------------------------------+-------+
| ZEBRA_FEC_REGISTER                 | 54    |
+------------------------------------+-------+
| ZEBRA_FEC_UNREGISTER               | 55    |
+------------------------------------+-------+
| ZEBRA_FEC_UPDATE                   | 56    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_DEFAULT_GW         | 57    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_SVI_MACIP          | 58    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_SUBNET             | 59    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_ALL_VNI            | 60    |
+------------------------------------+-------+
| ZEBRA_LOCAL_ES_ADD                 | 61    |
+------------------------------------+-------+
| ZEBRA_LOCAL_ES_DEL                 | 62    |
+------------------------------------+-------+
| ZEBRA_VNI_ADD                      | 63    |
+------------------------------------+-------+
| ZEBRA_VNI_DEL                      | 64    |
+------------------------------------+-------+
| ZEBRA_L3VNI_ADD                    | 65    |
+------------------------------------+-------+
| ZEBRA_L3VNI_DEL                    | 66    |
+------------------------------------+-------+
| ZEBRA_REMOTE_VTEP_ADD              | 67    |
+------------------------------------+-------+
| ZEBRA_REMOTE_VTEP_DEL              | 68    |
+------------------------------------+-------+
| ZEBRA_MACIP_ADD                    | 69    |
+------------------------------------+-------+
| ZEBRA_MACIP_DEL                    | 70    |
+------------------------------------+-------+
| ZEBRA_IP_PREFIX_ROUTE_ADD          | 71    |
+------------------------------------+-------+
| ZEBRA_IP_PREFIX_ROUTE_DEL          | 72    |
+------------------------------------+-------+
| ZEBRA_REMOTE_MACIP_ADD             | 73    |
+------------------------------------+-------+
| ZEBRA_REMOTE_MACIP_DEL             | 74    |
+------------------------------------+-------+
| ZEBRA_DUPLICATE_ADDR_DETECTION     | 75    |
+------------------------------------+-------+
| ZEBRA_PW_ADD                       | 76    |
+------------------------------------+-------+
| ZEBRA_PW_DELETE                    | 77    |
+------------------------------------+-------+
| ZEBRA_PW_SET                       | 78    |
+------------------------------------+-------+
| ZEBRA_PW_UNSET                     | 79    |
+------------------------------------+-------+
| ZEBRA_PW_STATUS_UPDATE             | 80    |
+------------------------------------+-------+
| ZEBRA_RULE_ADD                     | 81    |
+------------------------------------+-------+
| ZEBRA_RULE_DELETE                  | 82    |
+------------------------------------+-------+
| ZEBRA_RULE_NOTIFY_OWNER            | 83    |
+------------------------------------+-------+
| ZEBRA_TABLE_MANAGER_CONNECT        | 84    |
+------------------------------------+-------+
| ZEBRA_GET_TABLE_CHUNK              | 85    |
+------------------------------------+-------+
| ZEBRA_RELEASE_TABLE_CHUNK          | 86    |
+------------------------------------+-------+
| ZEBRA_IPSET_CREATE                 | 87    |
+------------------------------------+-------+
| ZEBRA_IPSET_DESTROY                | 88    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_ADD              | 89    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_DELETE           | 90    |
+------------------------------------+-------+
| ZEBRA_IPSET_NOTIFY_OWNER           | 91    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_NOTIFY_OWNER     | 92    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_ADD                  | 93    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_DELETE               | 94    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_NOTIFY_OWNER         | 95    |
+------------------------------------+-------+
| ZEBRA_VXLAN_FLOOD_CONTROL          | 96    |
+------------------------------------+-------+
| ZEBRA_VXLAN_SG_ADD                 | 97    |
+------------------------------------+-------+
| ZEBRA_VXLAN_SG_DEL                 | 98    |
+------------------------------------+-------+
| ZEBRA_VXLAN_SG_REPLAY              | 99    |
+------------------------------------+-------+
| ZEBRA_MLAG_PROCESS_UP              | 100   |
+------------------------------------+-------+
| ZEBRA_MLAG_PROCESS_DOWN            | 101   |
+------------------------------------+-------+
| ZEBRA_MLAG_CLIENT_REGISTER         | 102   |
+------------------------------------+-------+
| ZEBRA_MLAG_CLIENT_UNREGISTER       | 103   |
+------------------------------------+-------+
| ZEBRA_MLAG_FORWARD_MSG             | 104   |
+------------------------------------+-------+
| ZEBRA_CLIENT_CAPABILITIES          | 105   |
+------------------------------------+-------+

.. _zebra-nexthop-group:

Zebra Nexthop Group
==============================

code found in ``zebra/zebra_nhg.c[h]``


Zebra has its own heirarchical structure for nexthops in the form of 2 directed
graphs of nexthop objects. These objects, ``struct nhg_hash_entry (NHE)``
are given UUIDs assigned by zebra in the form of a ``uint32_t`` on ``->id``.

A route entry points to its nexthops via ``->nhe`` in ``struct route_entry``.

These NHEs are stored in two hash tables for lookup in ``zebra/zrouter.h``:
        - nhgs: key'd via a hash on the nexthops themselves
        - nhgs_id: key'd via the ``uint32_t`` ID assigned by zebra

We use the hash tables to to track nexthops and share them between routes via
lookup code and reference counting ``->refcnt``. Nexthops and nexthop groups
we receive from upper level protocols (and the dataplane) are hashed to find
or create a new NHE for them in the ``nhgs`` hash table. If new, we will also
allocate an ID for it and put it in the ``nhgs_id`` table for lookup via ID as
well. Sharing groups allows us to dramatically reduce memory in zebra and
create the heirarchical graph of NHEs.

Inside the NHEs themselves, there are two trees:
        - nhg_depends: NHE it resolves to or member NHEs if its a group
        - nhgs_dependents: backpointing tree to NHEs that depend on it

The ``depends``/``dependents`` tree is where the heirarchical tree of nexthops
is defined. A single NHE may have a tree in ``->nhg_depends`` that define the
children of its group. Those children NHEs may have their own trees in them
defining what NHEs they resolve to. Further, the original NHE may be part of a
larger group and reside in another NHE's ``depends`` tree.

Each of these ``depends`` relationships also create a back propogated tree of
``dependents`` so that any NHE can know what other NHE's ``depends`` trees
its a member of. ``struct zebra_if`` also has a similar list of NHEs that are
fully resolved and pointing out of its' interface.

Depends Tree
---------------
What exactly defines a ``depend``?

A ``depend`` is simply an NHE this NHE depends on. This can mean its recursively
resolved to that NHE or its a group and that NHE is a member of it. Abstracting
recursive resolution and groups into the same tree greatly simplifies the code
for tracking the heirarchical tree. We don't need two different paths to handle
creating/removing trees based on route resolution and group membership.

A couple examples of the ``depends`` tree:

*Nexthop Recursive Resolution:*
::

   A _____ B

   (A is resolved to B)

   NHE A would have a depends tree with one node NHE B.

*Nexthop Group (ECMP x3):*
::

   A _____ B
    \_____ C
    \_____ D

   (A is a nexthop group with members B,C,D)

   NHE A would have a depends tree with nodes NHE B, C, D.

*Nexthop Group (ECMP x3) & Recursive Resolution:*
::

   A _____ B
    \_____ C
    \_____ D _____ E

   (Same but D is recursively resolved to E)

   NHE A would have a depends tree with nodes NHE B, C, D and D would have
   a depends tree with node NHE E.


With the graph, we can do a lookup on an ID (via hashtable) to get any NHE and
then walk the entire subgraph starting at that given root NHE. This would
include itself as well as any fully resolved nexthops in recurses to and any
members of it if its a group and their ``depends``.

Dependents Tree
---------------
What exactly defines a ``dependent``?

A ``dependent`` is simply an NHE that has other NHEs depending on it. That is, 
it is a member of another NHE's ``depends`` tree either because it's recursively
resovled to it or it's a member of its group. When an NHE is added to another
NHE's ``depends`` tree, we add the latter NHE to the former's ``dependents``
tree at the same time.

The example from above:

*Nexthop Group (ECMP x3) && Recursive Resolution:*
::

   A _____ B
    \_____ C
    \_____ D _____ E

Would create the following ``dependents`` trees:

::

   B _____ A

   NHE B would have a dependents tree with node NHE A.

   C _____ A

   NHE C would have a dependents tree with node NHE A.

   D _____ A

   NHE D would have a dependents tree with node NHE A.

   E _____ D

   NHE E would have a dependents tree with node NHE D.


*Add Another NHE Resolution:*

Now, lets say we add another route with an NHE I and it resolves to NHE E
as well.

::

   I _____ E

This would modify NHE E's ``dependents`` tree to:

::

   E _____ D
    \_____ I

   NHE E would have a dependents tree with nodes NHE D and I.

*Overall:*

All these create an overall ``dependents`` tree that looks like this:

::

   E _____ D _____ A
    \_____ I      //
           C ____//
           B ____/


Macros:
==============

.. c:function:: zebra_nhg_nexthop(nhe)

   Accessor macro for the ``lib/nexthop.h`` nexthop.

   Returns ``struct nexthop *``:

   .. code-block:: c

      ->nexthop

Iteration Macros
----------------
Iterate over top-level (non-recursive) NHEs (singleton and groups):

ex)

::

   A _____ B
    \_____ C
    \_____ D _____ E


   for (B, C, D)

::

   A _____ B

   for (A)

.. c:function:: zebra_nhg_each(root, iter)

   If root is a singleton (recursive or not), it just iterates on that,
   otherwise it iterates on the group.

   .. code-block:: c

      if (root != GROUP)
              iter = root;
      else
              for (iter = root;
                      iter;
                      iter = nhg_connected_tree_next(&root->nhg_depends, iter)
              )

.. c:function:: zebra_nhg_each_nexthop(root, iter)

   Same as above but iterates on the ``struct nexthop *`` in an NHE.

   Equivalent to lib/nexthop iteration:

   .. code-block:: c

      for (iter = root; iter; iter = iter->next)


.. warning::

   These are non-safe macros (removing from list while iterating is undefined
   behavior).
