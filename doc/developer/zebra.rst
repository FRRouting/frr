.. _zebra:

*****
Zebra
*****

.. _zebra-protocol:

Overview of the Zebra Protocol
==============================

The Zebra protocol (or ``ZAPI``) is used by protocol daemons to
communicate with the **zebra** daemon.

Each protocol daemon may request and send information to and from the
**zebra** daemon such as interface states, routing state,
nexthop-validation, and so on.  Protocol daemons may also install
routes with **zebra**. The **zebra** daemon manages which routes are
installed into the forwarding table with the kernel. Some daemons use
more than one ZAPI connection. This is supported: each ZAPI session is
identified by a tuple of: ``{protocol, instance, session_id}``. LDPD
is an example: it uses a second, synchronous ZAPI session to manage
label blocks. The default value for ``session_id`` is zero; daemons
who use multiple ZAPI sessions must assign unique values to the
sessions' ids.

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
| ZEBRA_NEXTHOP_LOOKUP_MRIB          | 44    |
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
| ZEBRA_ERROR                        | 105   |
+------------------------------------+-------+
| ZEBRA_CLIENT_CAPABILITIES          | 106   |
+------------------------------------+-------+
| ZEBRA_OPAQUE_MESSAGE               | 107   |
+------------------------------------+-------+
| ZEBRA_OPAQUE_REGISTER              | 108   |
+------------------------------------+-------+
| ZEBRA_OPAQUE_UNREGISTER            | 109   |
+------------------------------------+-------+
| ZEBRA_NEIGH_DISCOVER               | 110   |
+------------------------------------+-------+

Dataplane batching
==================

Dataplane batching is an optimization feature that reduces the processing 
time involved in the user space to kernel space transition for every message we
want to send.

Design
-----------

With our dataplane abstraction, we create a queue of dataplane context objects
for the messages we want to send to the kernel. In a separate pthread, we
loop over this queue and send the context objects to the appropriate
dataplane. A batching enhancement tightly integrates with the dataplane
context objects so they are able to be batch sent to dataplanes that support
it. 

There is one main change in the dataplane code. It does not call
kernel-dependent functions one-by-one, but instead it hands a list of work down
to the kernel level for processing.

Netlink
^^^^^^^

At the moment, this is the only dataplane that allows for batch sending
messages to it.

When messages must be sent to the kernel, they are consecutively added
to the batch represented by the `struct nl_batch`. Context objects are firstly
encoded to their binary representation. All the encoding functions use the same
interface: take a context object, a buffer and a size of the buffer as an
argument. It is important that they should handle a situation in which a message
wouldn't fit in the buffer and return a proper error. To achieve a zero-copy
(in the user space only) messages are encoded to the same buffer which will
be passed to the kernel. Hence, we can theoretically hit the boundary of the
buffer.

Messages stored in the batch are sent if one of the conditions occurs:

- When an encoding function returns the buffer overflow error. The context
  object that caused this error is re-added to the new, empty batch.

- When the size of the batch hits certain limit.

- When the namespace of a currently being processed context object is
  different from all the previous ones. They have to be sent through
  distinct sockets, so the messages cannot share the same buffer.

- After the last message from the list is processed.

As mentioned earlier, there is a special threshold which is smaller than
the size of the underlying buffer. It prevents the overflow error and thus
eliminates the case, in which a message is encoded twice. 

The buffer used in the batching is global, since allocating that big amount of
memory every time wouldn't be most effective. However, its size can be changed
dynamically, using hidden vtysh command: 
``zebra kernel netlink batch-tx-buf (1-1048576) (1-1048576)``. This feature is
only used in tests and shouldn't be utilized in any other place.

For every failed message in the batch, the kernel responds with an error
message. Error messages are kept in the same order as they were sent, so parsing the
response is straightforward. We use the two pointer technique to match
requests with responses and then set appropriate status of dataplane context
objects. There is also a global receive buffer and it is assumed that whatever
the kernel sends it will fit in this buffer. The payload of netlink error messages
consists of a error code and the original netlink message of the request, so
the batch response won't be bigger than the batch request increased by 
some space for the headers.
