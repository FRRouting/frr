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


EVPN Entries
^^^^^^^^^^^^

Besides the routes and next hop groups, ``dplane_fpm_nl`` sends the EVPN
entries ``zebra`` programs for the remote VTEPs, encoded like the kernel
neighbor and FDB netlink messages ``zebra`` sends:

- Remote MACs (EVPN type-2 routes) and router MACs (of the routes
  imported in an L3VNI VRF: type-5 routes, and type-2 routes with an IP
  address): ``RTM_NEWNEIGH`` / ``RTM_DELNEIGH`` of family ``AF_BRIDGE``
  on the vxlan interface, with ``NTF_SELF | NTF_MASTER``,
  ``NTF_EXT_LEARNED`` and the ``NUD_REACHABLE`` state or, for sticky MACs
  (and remote default gateway MACs), ``NTF_STICKY`` instead of
  ``NTF_EXT_LEARNED`` and ``NUD_NOARP`` added to the state, the MAC
  (``NDA_LLADDR``), the remote VTEP
  (``NDA_DST``), the VNI (``NDA_SRC_VNI``), the bridge (``NDA_MASTER``)
  and, on a VLAN-aware bridge, the access VLAN (``NDA_VLAN``). A MAC
  behind an EVPN-MH ethernet segment points to the segment's next hop
  group (``NDA_NH_ID``) instead of a VTEP. A remote MAC replacing an
  EVPN-MH sync (static) local one also carries ``NDA_FDB_EXT_ATTRS``. A
  removal carries the same entry, but always with ``NTF_EXT_LEARNED`` and
  the ``NUD_REACHABLE`` state. The removal of a MAC behind an ethernet
  segment carries an all-zero ``NDA_DST`` instead of its ``NDA_NH_ID``,
  but when only the FPM gets it (see below). Local MACs are not sent.
- Flood list entries (type-3 routes, remote VTEPs using head-end
  replication): ``RTM_NEWNEIGH`` / ``RTM_DELNEIGH`` of family
  ``AF_BRIDGE`` on the vxlan interface, with ``NTF_SELF`` and the
  ``NUD_NOARP | NUD_PERMANENT`` state, an all-zero MAC, the remote VTEP
  (``NDA_DST``), the VNI (``NDA_SRC_VNI``) and, on a VLAN-aware bridge,
  the access VLAN (``NDA_VLAN``).
- Remote neighbors (type-2 routes with an IP address) on the SVI of their
  VNI, and L3VNI next hops (the remote VTEPs with their router MAC) on the
  L3VNI SVI, or on the vxlan interface of a single vxlan device:
  ``RTM_NEWNEIGH`` / ``RTM_DELNEIGH`` of family ``AF_INET`` or
  ``AF_INET6`` with ``NTF_EXT_LEARNED``, and ``NTF_ROUTER`` for a
  neighbor advertised as a router, the ``NUD_NOARP`` state, the IP
  address (``NDA_DST``) and the MAC (``NDA_LLADDR``). A removal carries
  no state, no ``NTF_ROUTER`` and an all-zero MAC. A remote neighbor
  replacing an EVPN-MH sync (static) local one also carries
  ``NDA_EXT_FLAGS``.
- EVPN-MH next hops (the ethernet segment VTEPs) and their groups, only
  when the FPM uses next hop groups: ``RTM_NEWNEXTHOP`` with the next hop
  ID (``NHA_ID``), ``NHA_FDB``, and ``NHA_GATEWAY`` or ``NHA_GROUP``, and
  ``RTM_DELNEXTHOP`` with the next hop ID alone. An FPM that does not use
  them still gets the MACs behind an ethernet segment with their
  ``NDA_NH_ID``, but never the group it refers to.

The neighbor messages also carry the protocol that installed them
(``NDA_PROTOCOL``). The MACs and neighbors are added with
``NLM_F_REPLACE``, the flood list entries with ``NLM_F_APPEND`` (several
per VNI).

The removal of a remote MAC or router MAC is the removal of the whole
entry: an FPM server should key them by vxlan interface, MAC and VLAN
(the same MAC can be on several vxlan interfaces, e.g. the router MAC of
a VTEP with several L3VNIs, and there is no ``NDA_VLAN`` without VLAN
filtering), the flood list entries by vxlan interface, VNI, VTEP and
VLAN, and the neighbors by interface and IP address. Some removals only go
to the FPM, when the kernel already removed the entry by itself (e.g. an
SVI or a vxlan interface going down) or keeps it (e.g. a flood list entry
moving to another access VLAN, the kernel not keying them by VLAN), and
an entry moving to another access VLAN is removed with its old VLAN and
added with the new one. The entries of an interface that is deleted are
not always removed: the FPM server should remove them with it, as the
kernel does.

When ``zebra`` connects to the FPM it sends all these entries again, after
the routes.


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
