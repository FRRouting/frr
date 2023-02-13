.. _bmp:

***
BMP
***

:abbr:`BMP` (BGP Monitoring Protocol, :rfc:`7854`) is used to send monitoring
data from BGP routers to network management entities.

Implementation characteristics
==============================

The `BMP` implementation in FRR has the following properties:

- only the :rfc:`7854` features are currently implemented.  This means protocol
  version 3 without any extensions.  It is not possible to use an older draft
  protocol version of BMP.

- the following statistics codes are implemented:

  - 0: count of prefixes rejected
  - 2: count of duplicate prefix withdrawals
  - 3: count of **prefixes** with loop in cluster id
  - 4: count of **prefixes** with loop in AS-path
  - 5: count of **prefixes** with loop in originator
  - 7: count of **routes** in adj-rib-in
  - 8: count of **routes** in Loc-RIB
  - 11: count of updates subjected to :rfc:`7607` "treat as withdrawal"
    handling due to errors
  - 65531: *experimental* count of prefixes rejected due to invalid next-hop

  Note that stat items 3, 4 and 5 are specified to count updates, but FRR
  implements them as prefix-based counters.

- **route mirroring** is fully implemented, however BGP OPEN messages are not
  currently included in route mirroring messages.  Their contents can be
  extracted from the "peer up" notification for sessions that established
  successfully.  OPEN messages for failed sessions cannot currently be
  mirrored.

- **route monitoring** is available for IPv4 and IPv6 AFIs, unicast, multicast,
  EVPN and VPN SAFIs. Other SAFIs (VPN, Labeled-Unicast, Flowspec, etc.) are not
  currently supported.

- monitoring peers that have BGP **add-path** enabled on the session will
  result in somewhat unpredictable behaviour.  Currently, the outcome is:

  - route mirroring functions as intended, messages are copied verbatim
  - the add-path ID is never included in route monitoring messages
  - if multiple paths were received from a peer, an unpredictable path is
    picked and sent on the BMP session.  The selection will differ for
    pre-policy and post-policy monitoring sessions.
  - as long as any path is present, something will be advertised on BMP
    sessions.  Only after the last path is gone a withdrawal will be sent on
    BMP sessions.
  - updates to additional paths will trigger BMP route monitoring messages.
    There is no guarantee on consistency regarding which path is sent in these
    messages.

- monitoring peers with :rfc:`5549` extended next-hops has not been tested.

Starting BMP
============

BMP is implemented as a loadable module.  This means that to use BMP, ``bgpd``
must be started with the ``-M bmp`` option.  It is not possible to enable BMP
if ``bgpd`` was started without this option.

Configuring BMP
===============

All of FRR's BMP configuration options are located inside the
:clicmd:`router bgp ASN` block.  Configure BGP first before proceeding to BMP
setup.

There are two options that apply to the BGP instance as a whole:

.. clicmd:: bmp mirror buffer-limit(0-4294967294)

   This sets the maximum amount of memory used for buffering BGP messages
   (updates, keepalives, ...) for sending in BMP Route Mirroring.

   The buffer is for the entire BGP instance; if multiple BMP targets are
   configured they reference the same buffer and do not consume additional
   memory.  Queue overhead is included in accounting this memory, so the
   actual space available for BGP messages is slightly less than the value
   configured here.

   If the buffer fills up, the oldest messages are removed from the buffer and
   any BMP sessions where the now-removed messages were still pending have
   their **entire** queue flushed and a "Mirroring Messages Lost" BMP message
   is sent.

   BMP Route Monitoring is not affected by this option.

.. clicmd:: bmp startup-delay delay(0-4294967294)

   This sets the delay (in milliseconds) after module startup
   for BMP sessions to become active.

   This setting is useful for BMP Monitoring because it allows BMP
   to wait a bit for BGP to converge and the whole BGP state. It avoids
   sending empty RIB content during synchronization on startup followed
   by multiple incremental updates. It also avoids RIB-Out Pre-Policy Monitoring
   to send duplicated messages on startup triggered by the reconfiguration of peer
   policies.

   This setting applies to all sessions defined in the same BGP Instance.
   On module initialization (at BGP Startup), the time is recorded. Then,
   established sessions will wait "delay" after this recorded time to start
   sending BMP Mirroring, the initial BMP Monitoring synchronization and
   following BMP Monitoring Messages containing incremental updates.

   BMP Peer Up Messages are sent if the peer becomes available during this
   period of time.

   The startup delay is applied for BMP startup only. BMP Sessions configured
   while the daemon is running will only wait if this initial timer has not expired
   yet.

   BMP Session Establishment is not affected by this option.

All other configuration is managed per targets:

.. clicmd:: bmp targets NAME

   Create/delete a targets group.  As implied by the plural name, targets may
   cover multiple outbound active BMP sessions as well as inbound passive
   listeners.

   If BMP sessions have the same configuration, putting them in the same
   ``bmp targets`` will reduce overhead.

BMP session configuration
-------------------------

Inside a ``bmp targets`` block, the following commands control session
establishment:


.. clicmd:: bmp connect HOSTNAME port (1-65535) {min-retry MSEC|max-retry MSEC} [source-interface WORD]

   Add/remove an active outbound BMP session.  HOSTNAME is resolved via DNS,
   if multiple addresses are returned they are tried in nondeterministic
   order.  Only one connection will be established even if multiple addresses
   are returned.  ``min-retry`` and ``max-retry`` specify (in milliseconds)
   bounds for exponential backoff. ``source-interface`` is the local interface on
   which the connection has to bind.

.. warning::

   ``ip access-list`` and ``ipv6 access-list`` are checked for outbound
   connections resulting from ``bmp connect`` statements.

.. clicmd:: bmp listener <X:X::X:X|A.B.C.D> port (1-65535)

   Accept incoming BMP sessions on the specified address and port.  You can
   use ``0.0.0.0`` and ``::`` to listen on all IPv4/IPv6 addresses.

.. clicmd:: ip access-list NAME
.. clicmd:: ipv6 access-list NAME

   Restrict BMP sessions to the addresses allowed by the respective access
   lists.  The access lists are checked for both passive and active BMP
   sessions.  Changes do not affect currently established sessions.

BMP data feed configuration
---------------------------

The following commands configure what BMP messages are sent on sessions
associated with a particular ``bmp targets``:

.. clicmd:: bmp stats [interval (100-86400000)]

   Send BMP Statistics (counter) messages at the specified interval (in
   milliseconds.)

.. clicmd:: bmp stats send-experimental

   Send BMP Statistics (counter) messages whose code is defined as
   experimental (in the [65531-65534] range).

.. clicmd:: bmp monitor AFI SAFI <rib-in|loc-rib|rib-out> <pre-policy|post-policy>

   Perform Route Monitoring for the specified AFI, SAFI and RIB.  Only IPv4 and
   IPv6 are currently valid for AFI. SAFI valid values are currently
   unicast, multicast, evpn and vpn.
   Other AFI/SAFI combinations may be added in the future.

   All BGP neighbors are included in Route Monitoring.  Options to select
   a subset of BGP sessions may be added in the future.

   Pre-Policy and Post-Policy flags do not apply to Local-RIB monitoring.

   BMP Local-RIB Monitoring is defined in :rfc:`9069`
   BMP RIB-Out Monitoring is defined in :rfc:`8671`

.. clicmd:: bmp mirror

   Perform Route Mirroring for all BGP neighbors.  Since this provides a
   direct feed of BGP messages, there are no AFI/SAFI options to be
   configured.

   All BGP neighbors are included in Route Mirroring.  Options to select
   a subset of BGP sessions may be added in the future.

BMP Troubleshooting
-------------


When encountering problems with BMP, it may be interesting to know the current
state of the latter.

.. clicmd:: show bmp

   Displays information about the current state of BMP including targets, sessions,
   configured modes, global settings, ...

.. code-block:: frr
BMP Module started at Fri Feb 24 13:05:50 2023

BMP state for BGP VRF default:

  Route Mirroring         0 bytes (0 messages) pending
                          0 bytes maximum buffer used

  Startup delay : 10000ms

  Targets "my_targets":
    Route Mirroring disabled
    Route Monitoring IPv4 unicast rib-out pre-policy rib-out post-policy
    Listeners:

    Outbound connections:
 remote              state                       timer      local
 ----------------------------------------------------------------------
 99.99.99.99:12345   Up      99.99.99.99:12345   00:00:04   (unspec)

    1 connected clients:
 remote              uptime     state          MonSent   MirrSent   MirrLost   ByteSent   ByteQ   ByteQKernel
 ---------------------------------------------------------------------------------------------------------------
 99.99.99.99:12345   00:00:04   Startup-Wait   0         0          0          61         0       0
::

   Here we have a single BGP instance running on VRF default. No specific mirroring settings but a
   startup delay of 10000ms.
   This instance has a single target with rib-out pre-policy and post-policy monitoring, no mirroring.
   This target has a single session open with client 99.99.99.99 on port 12345 which is in state Startup-Wait.
   This session will start sending monitoring messages as soon as the current time is
   "Fri Feb 24 13:05:50 2023" + 10000ms = "Fri Feb 24 13:06:00 2023" which explains why it is in
   Startup-Wait mode and has not sent Monitoring Messages yet.
