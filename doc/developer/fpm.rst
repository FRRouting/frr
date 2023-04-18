FPM
===

FPM stands for Forwarding Plane Manager and it's a module for use with Zebra.

The encapsulation header for the messages exchanged with the FPM is
defined by the file :file:`fpm/fpm.h` in the frr tree. The routes
themselves are encoded in Netlink or protobuf format, with Netlink
being the default.

Netlink is standard format for encoding messages to talk with kernel space
in Linux and it is also the name of the socket type used by it.
The FPM netlink usage differs from Linux's in:

- Linux netlink sockets use datagrams in a multicast fashion, FPM uses
  as a stream and it is unicast.
- FPM netlink messages might have more or less information than a normal
  Linux netlink socket message (example: RTM_NEWROUTE might add an extra
  route attribute to signalize VxLAN encapsulation).

Protobuf is one of a number of new serialization formats wherein the
message schema is expressed in a purpose-built language. Code for
encoding/decoding to/from the wire format is generated from the
schema. Protobuf messages can be extended easily while maintaining
backward-compatibility with older code. Protobuf has the following
advantages over Netlink:

- Code for serialization/deserialization is generated automatically. This
  reduces the likelihood of bugs, allows third-party programs to be integrated
  quickly, and makes it easy to add fields.
- The message format is not tied to an OS (Linux), and can be evolved
  independently.

.. note::

   Currently there are two FPM modules in ``zebra``:

   * ``fpm``
   * ``dplane_fpm_nl``

fpm
^^^

The first FPM implementation that was built using hooks in ``zebra`` route
handling functions. It uses its own netlink/protobuf encoding functions to
translate ``zebra`` route data structures into formatted binary data.


dplane_fpm_nl
^^^^^^^^^^^^^

The newer FPM implementation that was built using ``zebra``'s data plane
framework as a plugin. It only supports netlink and it shares ``zebra``'s
netlink functions to translate route event snapshots into formatted binary
data.


Protocol Specification
----------------------

FPM (in any mode) uses a TCP connection to talk with external applications.
It operates as TCP client and uses the CLI configured address/port to connect
to the FPM server (defaults to port ``2620``).

FPM frames all data with a header to help the external reader figure how
many bytes it has to read in order to read the full message (this helps
simulates datagrams like in the original netlink Linux kernel usage).

Frame header:

::

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +---------------+---------------+-------------------------------+
   | Version       | Message type  | Message length                |
   +---------------+---------------+-------------------------------+
   | Data...                                                       |
   +---------------------------------------------------------------+


Version
^^^^^^^

Currently there is only one version, so it should be always ``1``.


Message Type
^^^^^^^^^^^^

Defines what underlining protocol we are using: netlink (``1``) or protobuf (``2``).


Message Length
^^^^^^^^^^^^^^

Amount of data in this frame in network byte order.


Data
^^^^

The netlink or protobuf message payload.


Route Status Notification from ASIC
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The dplane_fpm_nl has the ability to read route netlink messages
from the underlying fpm implementation that can tell zebra
whether or not the route has been Offloaded/Failed or Trapped.
The end developer must send the data up the same socket that has
been created to listen for FPM messages from Zebra.  The data sent
must have a Frame Header with Version set to 1, Message Type set to 1
and an appropriate message Length.  The message data must contain
a RTM_NEWROUTE netlink message that sends the prefix and nexthops
associated with the route.  Finally rtm_flags must contain
RTM_F_OFFLOAD, RTM_F_TRAP and or RTM_F_OFFLOAD_FAILED to signify
what has happened to the route in the ASIC.
