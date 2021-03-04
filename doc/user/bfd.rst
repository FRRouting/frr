.. _bfd:

**********************************
Bidirectional Forwarding Detection
**********************************

:abbr:`BFD (Bidirectional Forwarding Detection)` stands for
Bidirectional Forwarding Detection and it is described and extended by
the following RFCs:

* :rfc:`5880`
* :rfc:`5881`
* :rfc:`5883`

Currently, there are two implementations of the BFD commands in FRR:

* :abbr:`PTM (Prescriptive Topology Manager)`: an external daemon which
  implements BFD;
* ``bfdd``: a BFD implementation that is able to talk with remote peers;

This document will focus on the later implementation: *bfdd*.


.. _bfd-starting:

Starting BFD
============

*bfdd* default configuration file is :file:`bfdd.conf`. *bfdd* searches
the current directory first then |INSTALL_PREFIX_ETC|/bfdd.conf. All of
*bfdd*'s command must be configured in :file:`bfdd.conf`.

*bfdd* specific invocation options are described below. Common options
may also be specified (:ref:`common-invocation-options`).

.. program:: bfdd

.. option:: --bfdctl <unix-socket>

   Set the BFD daemon control socket location. If using a non-default
   socket location::

      /usr/lib/frr/bfdd --bfdctl /tmp/bfdd.sock


   The default UNIX socket location is:

      #define BFDD_CONTROL_SOCKET "|INSTALL_PREFIX_STATE|/bfdd.sock"

   This option overrides the location addition that the -N option provides
   to the bfdd.sock


.. _bfd-commands:

BFDd Commands
=============

.. index:: bfd
.. clicmd:: bfd

   Opens the BFD daemon configuration node.

.. index:: peer <A.B.C.D|X:X::X:X> [{multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]
.. clicmd:: peer <A.B.C.D|X:X::X:X> [{multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]

   Creates and configures a new BFD peer to listen and talk to.

   `multihop` tells the BFD daemon that we should expect packets with
   TTL less than 254 (because it will take more than one hop) and to
   listen on the multihop port (4784). When using multi-hop mode
   `echo-mode` will not work (see :rfc:`5883` section 3).

   `local-address` provides a local address that we should bind our
   peer listener to and the address we should use to send the packets.
   This option is mandatory for IPv6.

   `interface` selects which interface we should use.

   `vrf` selects which domain we want to use.

.. index:: no peer <A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrf_name}]
.. clicmd:: no peer <A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrf_name}]

    Stops and removes the selected peer.


.. index:: profile WORD
.. clicmd:: profile WORD

   Creates a peer profile that can be configured in multiple peers.


.. index:: no profile WORD
.. clicmd:: no profile WORD

   Deletes a peer profile. Any peer using the profile will have their
   configurations reset to the default values.


.. index:: show bfd [vrf NAME] peers [json]
.. clicmd:: show bfd [vrf NAME] peers [json]

    Show all configured BFD peers information and current status.

.. index:: show bfd [vrf NAME$vrf_name] peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname}]> [json]
.. clicmd:: show bfd [vrf NAME$vrf_name] peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname}]> [json]

    Show status for a specific BFD peer.

.. index:: show bfd [vrf NAME] peers brief [json]
.. clicmd:: show bfd [vrf NAME] peers brief [json]

    Show all configured BFD peers information and current status in brief.

.. _bfd-peer-config:

Peer / Profile Configuration
----------------------------

BFD peers and profiles share the same BFD session configuration commands.

.. index:: detect-multiplier (2-255)
.. clicmd:: detect-multiplier (2-255)

   Configures the detection multiplier to determine packet loss. The
   remote transmission interval will be multiplied by this value to
   determine the connection loss detection timer. The default value is
   3.

   Example: when the local system has `detect-multiplier 3` and  the
   remote system has `transmission interval 300`, the local system will
   detect failures only after 900 milliseconds without receiving
   packets.

.. index:: receive-interval (10-60000)
.. clicmd:: receive-interval (10-60000)

   Configures the minimum interval that this system is capable of
   receiving control packets. The default value is 300 milliseconds.

.. index:: transmit-interval (10-60000)
.. clicmd:: transmit-interval (10-60000)

   The minimum transmission interval (less jitter) that this system
   wants to use to send BFD control packets. Defaults to 300ms.

.. index:: echo-interval (10-60000)
.. clicmd:: echo-interval (10-60000)

   Configures the minimal echo receive transmission interval that this
   system is capable of handling.

.. index:: [no] echo-mode
.. clicmd:: [no] echo-mode

   Enables or disables the echo transmission mode. This mode is disabled
   by default.

   It is recommended that the transmission interval of control packets
   to be increased after enabling echo-mode to reduce bandwidth usage.
   For example: `transmit-interval 2000`.

   Echo mode is not supported on multi-hop setups (see :rfc:`5883`
   section 3).

.. index:: [no] shutdown
.. clicmd:: [no] shutdown

   Enables or disables the peer. When the peer is disabled an
   'administrative down' message is sent to the remote peer.


.. index:: [no] passive-mode
.. clicmd:: [no] passive-mode

   Mark session as passive: a passive session will not attempt to start
   the connection and will wait for control packets from peer before it
   begins replying.

   This feature is useful when you have a router that acts as the
   central node of a star network and you want to avoid sending BFD
   control packets you don't need to.

   The default is active-mode (or ``no passive-mode``).

.. index:: [no] minimum-ttl (1-254)
.. clicmd:: [no] minimum-ttl (1-254)

   For multi hop sessions only: configure the minimum expected TTL for
   an incoming BFD control packet.

   This feature serves the purpose of thightening the packet validation
   requirements to avoid receiving BFD control packets from other
   sessions.

   The default value is 254 (which means we only expect one hop between
   this system and the peer).


BFD Peer Specific Commands
--------------------------

.. index:: label WORD
.. clicmd:: label WORD

   Labels a peer with the provided word. This word can be referenced
   later on other daemons to refer to a specific peer.


.. index:: profile BFDPROF
.. clicmd:: profile BFDPROF

   Configure peer to use the profile configurations.

   Notes:

   - Profile configurations can be overriden on a peer basis by specifying
     new parameters in peer configuration node.
   - Non existing profiles can be configured and they will only be applied
     once they start to exist.
   - If the profile gets updated the new configuration will be applied to all
     peers with the profile without interruptions.


.. _bfd-bgp-peer-config:

BGP BFD Configuration
---------------------

The following commands are available inside the BGP configuration node.

.. index:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd
.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd

   Listen for BFD events registered on the same target as this BGP
   neighbor. When BFD peer goes down it immediately asks BGP to shutdown
   the connection with its neighbor and, when it goes back up, notify
   BGP to try to connect to it.

.. index:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd
.. clicmd:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd

   Removes any notification registration for this neighbor.

.. index:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure
.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure

   Allow to write CBIT independence in BFD outgoing packets. Also allow to
   read both C-BIT value of BFD and lookup BGP peer status. This command is
   useful when a BFD down event is caught, while the BGP peer requested that
   local BGP keeps the remote BGP entries as staled if such issue is detected.
   This is the case when graceful restart is enabled, and it is wished to
   ignore the BD event while waiting for the remote router to restart.

.. index:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure
.. clicmd:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure

   Disallow to write CBIT independence in BFD outgoing packets. Also disallow
   to ignore BFD down notification. This is the default behaviour.


.. index:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF
.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF

   Same as command ``neighbor <A.B.C.D|X:X::X:X|WORD> bfd``, but applies the
   BFD profile to the sessions it creates or that already exist.


.. index:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF
.. clicmd:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF

   Removes the BFD profile configuration from peer session(s).


.. _bfd-isis-peer-config:

IS-IS BFD Configuration
-----------------------

The following commands are available inside the interface configuration node.

.. index:: isis bfd
.. clicmd:: isis bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

.. index:: no isis bfd
.. clicmd:: no isis bfd

   Removes any notification registration for this interface peers.

   Note that there will be just one BFD session per interface. In case both
   IPv4 and IPv6 support are configured then just a IPv6 based session is
   created.

.. index:: isis bfd profile BFDPROF
.. clicmd:: isis bfd profile BFDPROF

   Use a BFD profile BFDPROF as provided in the BFD configuration.

.. index:: no isis bfd profile BFDPROF
.. clicmd:: no isis bfd profile BFDPROF

   Removes any BFD profile if present.

.. _bfd-ospf-peer-config:

OSPF BFD Configuration
----------------------

The following commands are available inside the interface configuration node.

.. index:: ip ospf bfd
.. clicmd:: ip ospf bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

.. index:: no ip ospf bfd
.. clicmd:: no ip ospf bfd

   Removes any notification registration for this interface peers.


.. _bfd-ospf6-peer-config:

OSPF6 BFD Configuration
-----------------------

The following commands are available inside the interface configuration node.

.. index:: ipv6 ospf6 bfd
.. clicmd:: ipv6 ospf6 bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

.. index:: no ipv6 ospf6 bfd
.. clicmd:: no ipv6 ospf6 bfd

   Removes any notification registration for this interface peers.


.. _bfd-pim-peer-config:

PIM BFD Configuration
---------------------

The following commands are available inside the interface configuration node.

.. index:: ip pim bfd
.. clicmd:: ip pim bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

.. index:: no ip pim bfd
.. clicmd:: no ip pim bfd

   Removes any notification registration for this interface peers.


.. _bfd-configuration:

Configuration
=============

Before applying ``bfdd`` rules to integrated daemons (like BGPd), we must
create the corresponding peers inside the ``bfd`` configuration node.

Here is an example of BFD configuration:

::

    bfd
     peer 192.168.0.1
       label home-peer
       no shutdown
     !
    !
    router bgp 65530
     neighbor 192.168.0.1 remote-as 65531
     neighbor 192.168.0.1 bfd
     neighbor 192.168.0.2 remote-as 65530
     neighbor 192.168.0.2 bfd
     neighbor 192.168.0.3 remote-as 65532
     neighbor 192.168.0.3 bfd
    !

Peers can be identified by its address (use ``multihop`` when you need
to specify a multi hop peer) or can be specified manually by a label.

Here are the available peer configurations:

::

   bfd
    ! Configure a fast profile
    profile fast
     receive-interval 150
     transmit-interval 150
    !

    ! Configure peer with fast profile
    peer 192.168.0.6
     profile fast
     no shutdown
    !

   ! Configure peer with fast profile and override receive speed.
    peer 192.168.0.7
     profile fast
     receive-interval 500
     no shutdown
    !

    ! configure a peer on an specific interface
    peer 192.168.0.1 interface eth0
     no shutdown
    !

    ! configure a multihop peer
    peer 192.168.0.2 multihop local-address 192.168.0.3
      shutdown
    !

    ! configure a peer in a different vrf
    peer 192.168.0.3 vrf foo
     shutdown
    !

    ! configure a peer with every option possible
    peer 192.168.0.4
     label peer-label
     detect-multiplier 50
     receive-interval 60000
     transmit-interval 3000
     shutdown
    !

    ! configure a peer on an interface from a separate vrf
    peer 192.168.0.5 interface eth1 vrf vrf2
     no shutdown
    !

    ! remove a peer
    no peer 192.168.0.3 vrf foo


.. _bfd-status:

Status
======

You can inspect the current BFD peer status with the following commands:

::

   frr# show bfd peers
   BFD Peers:
           peer 192.168.0.1
                   ID: 1
                   Remote ID: 1
                   Status: up
                   Uptime: 1 minute(s), 51 second(s)
                   Diagnostics: ok
                   Remote diagnostics: ok
                   Peer Type: dynamic
                   Local timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: 50ms

           peer 192.168.1.1
                   label: router3-peer
                   ID: 2
                   Remote ID: 2
                   Status: up
                   Uptime: 1 minute(s), 53 second(s)
                   Diagnostics: ok
                   Remote diagnostics: ok
                   Peer Type: configured
                   Local timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: 50ms

   frr# show bfd peer 192.168.1.1
   BFD Peer:
               peer 192.168.1.1
                   label: router3-peer
                   ID: 2
                   Remote ID: 2
                   Status: up
                   Uptime: 3 minute(s), 4 second(s)
                   Diagnostics: ok
                   Remote diagnostics: ok
                   Peer Type: dynamic
                   Local timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo transmission interval: 50ms

   frr# show bfd peer 192.168.0.1 json
   {"multihop":false,"peer":"192.168.0.1","id":1,"remote-id":1,"status":"up","uptime":161,"diagnostic":"ok","remote-diagnostic":"ok","receive-interval":300,"transmit-interval":300,"echo-interval":50,"detect-multiplier":3,"remote-receive-interval":300,"remote-transmit-interval":300,"remote-echo-interval":50,"remote-detect-multiplier":3,"peer-type":"dynamic"}


You can inspect the current BFD peer status in brief with the following commands:

::

   frr# show bfd peers brief
   Session count: 1
   SessionId  LocalAddress         PeerAddress      Status
   =========  ============         ===========      ======
   1          192.168.0.1          192.168.0.2      up


You can also inspect peer session counters with the following commands:

::

   frr# show bfd peers counters
   BFD Peers:
        peer 192.168.2.1 interface r2-eth2
                Control packet input: 28 packets
                Control packet output: 28 packets
                Echo packet input: 0 packets
                Echo packet output: 0 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 2

        peer 192.168.0.1
                Control packet input: 54 packets
                Control packet output: 103 packets
                Echo packet input: 965 packets
                Echo packet output: 966 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 4

   frr# show bfd peer 192.168.0.1 counters
        peer 192.168.0.1
                Control packet input: 126 packets
                Control packet output: 247 packets
                Echo packet input: 2409 packets
                Echo packet output: 2410 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 4

   frr# show bfd peer 192.168.0.1 counters json
   {"multihop":false,"peer":"192.168.0.1","control-packet-input":348,"control-packet-output":685,"echo-packet-input":6815,"echo-packet-output":6816,"session-up":1,"session-down":0,"zebra-notifications":4}

You can also clear packet counters per session with the following commands, only the packet counters will be reset:

::

   frr# clear bfd peers counters

   frr# show bfd peers counters
   BFD Peers:
        peer 192.168.2.1 interface r2-eth2
                Control packet input: 0 packets
                Control packet output: 0 packets
                Echo packet input: 0 packets
                Echo packet output: 0 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 2

        peer 192.168.0.1
                Control packet input: 0 packets
                Control packet output: 0 packets
                Echo packet input: 0 packets
                Echo packet output: 0 packets
                Session up events: 1
                Session down events: 0
                Zebra notifications: 4

Debugging
=========

By default only informational, warning and errors messages are going to be
displayed. If you want to get debug messages and other diagnostics then make
sure you have `debugging` level enabled:

::

   config
   log file /var/log/frr/frr.log debugging
   log syslog debugging

You may also fine tune the debug messages by selecting one or more of the
debug levels:

.. index:: [no] debug bfd network
.. clicmd:: [no] debug bfd network

   Toggle network events: show messages about socket failures and unexpected
   BFD messages that may not belong to registered peers.

.. index:: [no] debug bfd peer
.. clicmd:: [no] debug bfd peer

   Toggle peer event log messages: show messages about peer creation/removal
   and state changes.

.. index:: [no] debug bfd zebra
.. clicmd:: [no] debug bfd zebra

   Toggle zebra message events: show messages about interfaces, local
   addresses, VRF and daemon peer registrations.
