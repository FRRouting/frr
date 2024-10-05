.. _bfd:

***
BFD
***

:abbr:`BFD (Bidirectional Forwarding Detection)` is:

  a protocol intended to detect faults in the bidirectional path between two
  forwarding engines, including interfaces, data link(s), and to the extent
  possible the forwarding engines themselves, with potentially very low
  latency.

  -- :rfc:`5880`

It is described and extended by the following RFCs:

* :rfc:`5880`
* :rfc:`5881`
* :rfc:`5882`
* :rfc:`5883`

Currently, there are two implementations of the BFD commands in FRR:

* :abbr:`PTM (Prescriptive Topology Manager)`: an external daemon which
  implements BFD;
* ``bfdd``: a BFD implementation that is able to talk with remote peers;

This document will focus on the later implementation: *bfdd*.


.. _bfd-starting:

Starting BFD
============

.. include:: config-include.rst

*bfdd* default configuration file is :file:`bfdd.conf`. *bfdd* searches
the current directory first then |INSTALL_PREFIX_ETC|/bfdd.conf. All of
*bfdd*'s command must be configured in :file:`bfdd.conf`.

*bfdd* specific invocation options are described below. Common options
may also be specified (:ref:`common-invocation-options`).

.. program:: bfdd

.. option:: --dplaneaddr <type>:<address>[<:port>]

   Configure the distributed BFD data plane listening socket bind address.

   One would expect the data plane to run in the same machine as FRR, so
   the suggested configuration would be:

      --dplaneaddr unix:/var/run/frr/bfdd_dplane.sock

   Or using IPv4:

      --dplaneaddr ipv4:127.0.0.1

   Or using IPv6:

      --dplaneaddr ipv6:[::1]

   It is also possible to specify a port (for IPv4/IPv6 only):

     --dplaneaddr ipv6:[::1]:50701

   (if omitted the default port is ``50700``).

   It is also possible to operate in client mode (instead of listening for
   connections). To connect to a data plane server append the letter 'c' to
   the protocol, example:

     --dplaneaddr ipv4c:127.0.0.1

.. note::

   When using UNIX sockets don't forget to check the file permissions
   before attempting to use it.


.. _bfd-commands:

BFDd Commands
=============

.. clicmd:: bfd

   Opens the BFD daemon configuration node.

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


.. clicmd:: profile WORD

   Creates a peer profile that can be configured in multiple peers.

   Deleting the profile will cause all peers using it to reset to the default
   values.


.. clicmd:: show bfd [vrf NAME] peers [json]

    Show all configured BFD peers information and current status.

.. clicmd:: show bfd [vrf NAME] peer <WORD|<A.B.C.D|X:X::X:X> [{multihop|local-address <A.B.C.D|X:X::X:X>|interface IFNAME}]> [json]

    Show status for a specific BFD peer.

.. clicmd:: show bfd [vrf NAME] peers brief [json]

    Show all configured BFD peers information and current status in brief.

.. clicmd:: show bfd distributed

   Show the BFD data plane (distributed BFD) statistics.


.. _bfd-peer-config:

Peer / Profile Configuration
----------------------------

BFD peers and profiles share the same BFD session configuration commands.

.. clicmd:: detect-multiplier (2-255)

   Configures the detection multiplier to determine packet loss. The
   remote transmission interval will be multiplied by this value to
   determine the connection loss detection timer. The default value is
   3.

   Example: when the local system has `detect-multiplier 3` and  the
   remote system has `transmission interval 300`, the local system will
   detect failures only after 900 milliseconds without receiving
   packets.

.. clicmd:: receive-interval (10-60000)

   Configures the minimum interval that this system is capable of
   receiving control packets. The default value is 300 milliseconds.

.. clicmd:: transmit-interval (10-60000)

   The minimum transmission interval (less jitter) that this system
   wants to use to send BFD control packets. Defaults to 300ms.

.. clicmd:: echo receive-interval <disabled|(10-60000)>

   Configures the minimum interval that this system is capable of
   receiving echo packets. Disabled means that this system doesn't want
   to receive echo packets. The default value is 50 milliseconds.

.. clicmd:: echo transmit-interval (10-60000)

   The minimum transmission interval (less jitter) that this system
   wants to use to send BFD echo packets. Defaults to 50ms.

.. clicmd:: echo-mode

   Enables or disables the echo transmission mode. This mode is disabled
   by default. If you are not using distributed BFD then echo mode works
   only when the peer is also FRR.

   It is recommended that the transmission interval of control packets
   to be increased after enabling echo-mode to reduce bandwidth usage.
   For example: `transmit-interval 2000`.

   Echo mode is not supported on multi-hop setups (see :rfc:`5883`
   section 3).

.. clicmd:: shutdown

   Enables or disables the peer. When the peer is disabled an
   'administrative down' message is sent to the remote peer.


.. clicmd:: passive-mode

   Mark session as passive: a passive session will not attempt to start
   the connection and will wait for control packets from peer before it
   begins replying.

   This feature is useful when you have a router that acts as the
   central node of a star network and you want to avoid sending BFD
   control packets you don't need to.

   The default is active-mode (or ``no passive-mode``).

.. clicmd:: minimum-ttl (1-254)

   For multi hop sessions only: configure the minimum expected TTL for
   an incoming BFD control packet.

   This feature serves the purpose of thightening the packet validation
   requirements to avoid receiving BFD control packets from other
   sessions.

   The default value is 254 (which means we only expect one hop between
   this system and the peer).


BFD Peer Specific Commands
--------------------------

.. clicmd:: profile BFDPROF

   Configure peer to use the profile configurations.

   Notes:

   - Profile configurations can be overridden on a peer basis by specifying
     non-default parameters in peer configuration node.
   - Non existing profiles can be configured and they will only be applied
     once they start to exist.
   - If the profile gets updated the new configuration will be applied to all
     peers with the profile without interruptions.


.. _bfd-bgp-peer-config:

BGP BFD Configuration
---------------------

The following commands are available inside the BGP configuration node.

.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd

   Listen for BFD events registered on the same target as this BGP
   neighbor. When BFD peer goes down it immediately asks BGP to shutdown
   the connection with its neighbor and, when it goes back up, notify
   BGP to try to connect to it.


.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd check-control-plane-failure

   Allow to write CBIT independence in BFD outgoing packets. Also allow to
   read both C-BIT value of BFD and lookup BGP peer status. This command is
   useful when a BFD down event is caught, while the BGP peer requested that
   local BGP keeps the remote BGP entries as staled if such issue is detected.
   This is the case when graceful restart is enabled, and it is wished to
   ignore the BD event while waiting for the remote router to restart.

   Disabling this disables presence of CBIT independence in BFD outgoing
   packets and pays attention to BFD down notifications. This is the default.


.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfd profile BFDPROF

   Same as command ``neighbor <A.B.C.D|X:X::X:X|WORD> bfd``, but applies the
   BFD profile to the sessions it creates or that already exist.


.. _bfd-isis-peer-config:

IS-IS BFD Configuration
-----------------------

The following commands are available inside the interface configuration node.

.. clicmd:: isis bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

   Note that there will be just one BFD session per interface. In case both
   IPv4 and IPv6 support are configured then just a IPv6 based session is
   created.

.. clicmd:: isis bfd profile BFDPROF

   Use a BFD profile BFDPROF as provided in the BFD configuration.


.. _bfd-ospf-peer-config:

OSPF BFD Configuration
----------------------

The following commands are available inside the interface configuration node.

.. clicmd:: ip ospf bfd

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

.. clicmd:: ip ospf bfd profile BFDPROF

   Same as command ``ip ospf bfd``, but applies the BFD profile to the sessions
   it creates or that already exist.


.. _bfd-ospf6-peer-config:

OSPF6 BFD Configuration
-----------------------

The following commands are available inside the interface configuration node.

.. clicmd:: ipv6 ospf6 bfd [profile BFDPROF]

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

   Optionally uses the BFD profile ``BFDPROF`` in the created sessions under
   that interface.


.. _bfd-pim-peer-config:

PIM BFD Configuration
---------------------

The following commands are available inside the interface configuration node.

.. clicmd:: ip pim bfd [profile BFDPROF]

   Listen for BFD events on peers created on the interface. Every time
   a new neighbor is found a BFD peer is created to monitor the link
   status for fast convergence.

   Optionally uses the BFD profile ``BFDPROF`` in the created sessions under
   that interface.


.. _bfd-rip-peer-config:

RIP BFD configuration
---------------------

The following commands are available inside the interface configuration node:

.. clicmd:: ip rip bfd

   Automatically create BFD session for each RIP peer discovered in this
   interface. When the BFD session monitor signalize that the link is down
   the RIP peer is removed and all the learned routes associated with that
   peer are removed.


.. clicmd:: ip rip bfd profile BFD_PROFILE_NAME

   Selects a BFD profile for the BFD sessions created in this interface.


The following command is available in the RIP router configuration node:

.. clicmd:: bfd default-profile BFD_PROFILE_NAME

   Selects a default BFD profile for all sessions without a profile specified.


.. _bfd-static-peer-config:

BFD Static Route Monitoring Configuration
-----------------------------------------

A monitored static route conditions the installation to the RIB on the
BFD session running state: when BFD session is up the route is installed
to RIB, but when the BFD session is down it is removed from the RIB.

The following commands are available inside the configuration node:

.. clicmd:: ip route A.B.C.D/M A.B.C.D bfd [{multi-hop|source A.B.C.D|profile BFDPROF}]

   Configure a static route for ``A.B.C.D/M`` using gateway ``A.B.C.D`` and use
   the gateway address as BFD peer destination address.

.. clicmd:: ipv6 route X:X::X:X/M [from X:X::X:X/M] X:X::X:X bfd [{multi-hop|source X:X::X:X|profile BFDPROF}]

   Configure a static route for ``X:X::X:X/M`` using gateway
   ``X:X::X:X`` and use the gateway address as BFD peer destination
   address.

The static routes when uninstalled will no longer show up in the output of
the command ``show ip route`` or ``show ipv6 route``, instead we must use the
BFD static route show command to see these monitored route status.

.. clicmd:: show bfd static route [json]

   Show all monitored static routes and their status.

   Example output:

   ::

      Showing BFD monitored static routes:

        Route groups:
          rtg1 peer 172.16.0.1 (status: uninstalled):
              2001:db8::100/128

      Next hops:
        VRF default IPv4 Unicast:
            192.168.100.0/24 peer 172.16.0.1 (status: uninstalled)

        VRF default IPv4 Multicast:

        VRF default IPv6 Unicast:

.. _bfd-configuration:

Configuration
=============

Before applying ``bfdd`` rules to integrated daemons (like BGPd), we must
create the corresponding peers inside the ``bfd`` configuration node.

Here is an example of BFD configuration:

::

    bfd
     peer 192.168.0.1
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
to specify a multi hop peer).

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
                           Echo receive interval: 50ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo receive interval: 50ms

           peer 192.168.1.1
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
                           Echo receive interval: 50ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo receive interval: 50ms

   frr# show bfd peer 192.168.1.1
   BFD Peer:
               peer 192.168.1.1
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
                           Echo receive interval: 50ms
                           Echo transmission interval: disabled
                   Remote timers:
                           Detect-multiplier: 3
                           Receive interval: 300ms
                           Transmission interval: 300ms
                           Echo receive interval: 50ms

   frr# show bfd peer 192.168.0.1 json
   {"multihop":false,"peer":"192.168.0.1","id":1,"remote-id":1,"status":"up","uptime":161,"diagnostic":"ok","remote-diagnostic":"ok","receive-interval":300,"transmit-interval":300,"echo-receive-interval":50,"echo-transmit-interval":0,"detect-multiplier":3,"remote-receive-interval":300,"remote-transmit-interval":300,"remote-echo-receive-interval":50,"remote-detect-multiplier":3,"peer-type":"dynamic"}

If you are running IPV4 BFD Echo, on a Linux platform, we also
calculate round trip time for the packets.  We display minimum,
average and maximum time it took to receive the looped Echo packets
in the RTT fields.

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


.. _bfd-distributed:

Distributed BFD
===============

The distributed BFD is the separation of the BFD protocol control plane from
the data plane. FRR implements its own BFD data plane protocol so vendors can
study and include it in their own software/hardware without having to modify
the FRR source code. The protocol definitions can be found at
``bfdd/bfddp_packet.h`` header (or the installed
``/usr/include/frr/bfdd/bfddp_packet.h``).

To use this feature the BFD daemon needs to be started using the command line
option :option:`--dplaneaddr`. When operating using this option the BFD daemon
will not attempt to establish BFD sessions, but it will offload all its work to
the data plane that is (or will be) connected. Data plane reconnection is also
supported.

The BFD data plane will be responsible for:

* Sending/receiving the BFD protocol control/echo packets

* Notifying BFD sessions state changes

* Keeping the number of packets/bytes received/transmitted per session


The FRR BFD daemon will be responsible for:

* Adding/updating BFD session settings

* Asking for BFD session counters

* Redistributing the state changes to the integrated protocols (``bgpd``,
  ``ospfd`` etc...)


BFD daemon will also keep record of data plane communication statistics with
the command :clicmd:`show bfd distributed`.

Sample output:

::

   frr# show bfd distributed
               Data plane
               ==========
          File descriptor: 16
              Input bytes: 1296
         Input bytes peak: 72
           Input messages: 42
      Input current usage: 0
             Output bytes: 568
        Output bytes peak: 136
          Output messages: 19
       Output full events: 0
     Output current usage: 0


.. _bfd-debugging:

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

.. clicmd:: debug bfd distributed

   Toggle BFD data plane (distributed BFD) debugging.

   Activates the following debug messages:

   * Data plane received / send messages
   * Connection events

.. clicmd:: debug bfd network

   Toggle network events: show messages about socket failures and unexpected
   BFD messages that may not belong to registered peers.

.. clicmd:: debug bfd peer

   Toggle peer event log messages: show messages about peer creation/removal
   and state changes.

.. clicmd:: debug bfd zebra

   Toggle zebra message events: show messages about interfaces, local
   addresses, VRF and daemon peer registrations.
