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

The definitions of zebra protocol commands can be found at ``lib/zclient.h``.


Zebra Dataplane
===============

The zebra dataplane subsystem provides a framework for FIB
programming. Zebra uses the dataplane to program the local kernel as
it makes changes to objects such as IP routes, MPLS LSPs, and
interface IP addresses. The dataplane runs in its own pthread, in
order to off-load work from the main zebra pthread.

The zebra dataplane API is versioned; the version number must be
updated along with API changes. Plugins can test the current version
number and confirm that they are compatible with the current version.


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
