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
| ZEBRA_ROUTE_ADD                    | 7     |
+------------------------------------+-------+
| ZEBRA_ROUTE_DELETE                 | 8     |
+------------------------------------+-------+
| ZEBRA_ROUTE_NOTIFY_OWNER           | 9     |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ADD             | 10    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DELETE          | 11    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_ADD     | 12    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_DELETE  | 13    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_ADD                | 14    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_DELETE             | 15    |
+------------------------------------+-------+
| ZEBRA_ROUTER_ID_UPDATE             | 16    |
+------------------------------------+-------+
| ZEBRA_HELLO                        | 17    |
+------------------------------------+-------+
| ZEBRA_CAPABILITIES                 | 18    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_REGISTER             | 19    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_UNREGISTER           | 20    |
+------------------------------------+-------+
| ZEBRA_NEXTHOP_UPDATE               | 21    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_NBR_ADDRESS_ADD    | 22    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_NBR_ADDRESS_DELETE | 23    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_BFD_DEST_UPDATE    | 24    |
+------------------------------------+-------+
| ZEBRA_IMPORT_ROUTE_REGISTER        | 25    |
+------------------------------------+-------+
| ZEBRA_IMPORT_ROUTE_UNREGISTER      | 26    |
+------------------------------------+-------+
| ZEBRA_IMPORT_CHECK_UPDATE          | 27    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_REGISTER            | 28    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_DEREGISTER          | 29    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_UPDATE              | 30    |
+------------------------------------+-------+
| ZEBRA_BFD_DEST_REPLAY              | 31    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ROUTE_ADD       | 32    |
+------------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ROUTE_DEL       | 33    |
+------------------------------------+-------+
| ZEBRA_VRF_UNREGISTER               | 34    |
+------------------------------------+-------+
| ZEBRA_VRF_ADD                      | 35    |
+------------------------------------+-------+
| ZEBRA_VRF_DELETE                   | 36    |
+------------------------------------+-------+
| ZEBRA_VRF_LABEL                    | 37    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_VRF_UPDATE         | 38    |
+------------------------------------+-------+
| ZEBRA_BFD_CLIENT_REGISTER          | 39    |
+------------------------------------+-------+
| ZEBRA_BFD_CLIENT_DEREGISTER        | 40    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_ENABLE_RADV        | 41    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_DISABLE_RADV       | 42    |
+------------------------------------+-------+
| ZEBRA_IPV3_NEXTHOP_LOOKUP_MRIB     | 43    |
+------------------------------------+-------+
| ZEBRA_INTERFACE_LINK_PARAMS        | 44    |
+------------------------------------+-------+
| ZEBRA_MPLS_LABELS_ADD              | 45    |
+------------------------------------+-------+
| ZEBRA_MPLS_LABELS_DELETE           | 46    |
+------------------------------------+-------+
| ZEBRA_IPMR_ROUTE_STATS             | 47    |
+------------------------------------+-------+
| ZEBRA_LABEL_MANAGER_CONNECT        | 48    |
+------------------------------------+-------+
| ZEBRA_LABEL_MANAGER_CONNECT_ASYNC  | 49    |
+------------------------------------+-------+
| ZEBRA_GET_LABEL_CHUNK              | 50    |
+------------------------------------+-------+
| ZEBRA_RELEASE_LABEL_CHUNK          | 51    |
+------------------------------------+-------+
| ZEBRA_FEC_REGISTER                 | 52    |
+------------------------------------+-------+
| ZEBRA_FEC_UNREGISTER               | 53    |
+------------------------------------+-------+
| ZEBRA_FEC_UPDATE                   | 54    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_DEFAULT_GW         | 55    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_SUBNET             | 56    |
+------------------------------------+-------+
| ZEBRA_ADVERTISE_ALL_VNI            | 57    |
+------------------------------------+-------+
| ZEBRA_LOCAL_ES_ADD                 | 58    |
+------------------------------------+-------+
| ZEBRA_LOCAL_ES_DEL                 | 59    |
+------------------------------------+-------+
| ZEBRA_VNI_ADD                      | 60    |
+------------------------------------+-------+
| ZEBRA_VNI_DEL                      | 61    |
+------------------------------------+-------+
| ZEBRA_L3VNI_ADD                    | 62    |
+------------------------------------+-------+
| ZEBRA_L3VNI_DEL                    | 63    |
+------------------------------------+-------+
| ZEBRA_REMOTE_VTEP_ADD              | 64    |
+------------------------------------+-------+
| ZEBRA_REMOTE_VTEP_DEL              | 65    |
+------------------------------------+-------+
| ZEBRA_MACIP_ADD                    | 66    |
+------------------------------------+-------+
| ZEBRA_MACIP_DEL                    | 67    |
+------------------------------------+-------+
| ZEBRA_IP_PREFIX_ROUTE_ADD          | 68    |
+------------------------------------+-------+
| ZEBRA_IP_PREFIX_ROUTE_DEL          | 69    |
+------------------------------------+-------+
| ZEBRA_REMOTE_MACIP_ADD             | 70    |
+------------------------------------+-------+
| ZEBRA_REMOTE_MACIP_DEL             | 71    |
+------------------------------------+-------+
| ZEBRA_PW_ADD                       | 72    |
+------------------------------------+-------+
| ZEBRA_PW_DELETE                    | 73    |
+------------------------------------+-------+
| ZEBRA_PW_SET                       | 74    |
+------------------------------------+-------+
| ZEBRA_PW_UNSET                     | 75    |
+------------------------------------+-------+
| ZEBRA_PW_STATUS_UPDATE             | 76    |
+------------------------------------+-------+
| ZEBRA_RULE_ADD                     | 77    |
+------------------------------------+-------+
| ZEBRA_RULE_DELETE                  | 78    |
+------------------------------------+-------+
| ZEBRA_RULE_NOTIFY_OWNER            | 79    |
+------------------------------------+-------+
| ZEBRA_TABLE_MANAGER_CONNECT        | 80    |
+------------------------------------+-------+
| ZEBRA_GET_TABLE_CHUNK              | 81    |
+------------------------------------+-------+
| ZEBRA_RELEASE_TABLE_CHUNK          | 82    |
+------------------------------------+-------+
| ZEBRA_IPSET_CREATE                 | 83    |
+------------------------------------+-------+
| ZEBRA_IPSET_DESTROY                | 84    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_ADD              | 85    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_DELETE           | 86    |
+------------------------------------+-------+
| ZEBRA_IPSET_NOTIFY_OWNER           | 87    |
+------------------------------------+-------+
| ZEBRA_IPSET_ENTRY_NOTIFY_OWNER     | 88    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_ADD                  | 89    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_DELETE               | 90    |
+------------------------------------+-------+
| ZEBRA_IPTABLE_NOTIFY_OWNER         | 91    |
+------------------------------------+-------+
| ZEBRA_VXLAN_FLOOD_CONTROL          | 92    |
+------------------------------------+-------+
