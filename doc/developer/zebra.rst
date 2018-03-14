.. _zebra:

*****
Zebra
*****

.. _zebra-protocol:

Overview of the Zebra Protocol
==============================

Zebra Protocol is used by protocol daemons to communicate with the zebra
daemon.

Each protocol daemon may request and send information to and from the zebra
daemon such as interface states, routing state, nexthop-validation, and so on.
Protocol daemons may also install routes with zebra. The zebra daemon manages
which route is installed into the forwarding table with the kernel.

Zebra Protocol is a streaming protocol, with a common header. Two versions of
the header are in use. Version 0 is implicitely versioned. Version 1 has an
explicit version field. Version 0 can be distinguished from all other versions
by examining the 3rd byte of the header, which contains a marker value for all
versions bar version 0. The marker byte corresponds to the command field in
version 0, and the marker value is a reserved command in version 0.

We do not anticipate there will be further versions of the header for the
foreseeable future, as the command field in version 1 is wide enough to allow
for future extensions to done compatibly through seperate commands.

Version 0 is used by all versions of GNU Zebra as of this writing, and versions
of Quagga up to and including Quagga 0.98. Version 2 was created for 0.99.21 of
Quagga. Version 3 designates VRF compatibility and was released in 1.0.
Version 4 will be used as of FRR 2.0 to indicate that we are a different
Routing Suite now and to hopefully prevent accidental Quagga <-> FRR issues.

Zebra Protocol Definition
=========================

Zebra Protocol Header (version 0)
----------------------------------

::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------------------------------+---------------+
   |           Length (2)          |   Command (1) |
   +-------------------------------+---------------+


Zebra Protocol Common Header (version 1)
----------------------------------------

::

   0                   1                   2                   3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-------------------------------+---------------+-------------+
   |           Length (2)          |   Marker (1)  | Version (1) |
   +-------------------------------+---------------+-------------+
   |          Command (2)          |
   +-------------------------------+


Zebra Protocol Header Field Definitions
---------------------------------------

Length
   Total packet length including this header. The minimum length is 3 bytes for
   version 0 messages and 6 bytes for version 1 messages.

Marker
   Static marker with a value of 255 always. This is to allow version 0 Zserv
   headers (which do not include version explicitly) to be distinguished from
   versioned headers. Not present in version 0 messages.

Version
   Version number of the Zserv message. Clients should not continue processing
   messages past the version field for versions they do not recognise. Not
   present in version 0 messages.

Command
   The Zebra Protocol command.


Zebra Protocol Commands
-----------------------

+-----------------------------------+-------+
| Command                           | Value |
+===================================+=======+
| ZEBRA_INTERFACE_ADD               | 1     |
+-----------------------------------+-------+
| ZEBRA_INTERFACE_DELETE            | 2     |
+-----------------------------------+-------+
| ZEBRA_INTERFACE_ADDRESS_ADD       | 3     |
+-----------------------------------+-------+
| ZEBRA_INTERFACE_ADDRESS_DELETE    | 4     |
+-----------------------------------+-------+
| ZEBRA_INTERFACE_UP                | 5     |
+-----------------------------------+-------+
| ZEBRA_INTERFACE_DOWN              | 6     |
+-----------------------------------+-------+
| ZEBRA_IPV4_ROUTE_ADD              | 7     |
+-----------------------------------+-------+
| ZEBRA_IPV4_ROUTE_DELETE           | 8     |
+-----------------------------------+-------+
| ZEBRA_IPV6_ROUTE_ADD              | 9     |
+-----------------------------------+-------+
| ZEBRA_IPV6_ROUTE_DELETE           | 10    |
+-----------------------------------+-------+
| ZEBRA_REDISTRIBUTE_ADD            | 11    |
+-----------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DELETE         | 12    |
+-----------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_ADD    | 13    |
+-----------------------------------+-------+
| ZEBRA_REDISTRIBUTE_DEFAULT_DELETE | 14    |
+-----------------------------------+-------+
| ZEBRA_IPV4_NEXTHOP_LOOKUP         | 15    |
+-----------------------------------+-------+
| ZEBRA_IPV6_NEXTHOP_LOOKUP         | 16    |
+-----------------------------------+-------+
