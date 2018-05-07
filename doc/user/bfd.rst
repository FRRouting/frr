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
* ``bfdd``: a BFD adapter which communicates with a external BFD daemon;

This document will focus on the later implementation: ``bfdd``.


.. _bfd-adapter:

BFD Adapter
===========

The current version of BFD daemon inside FRR is just an adapter that
communicates with an external daemon (also called ``bfdd`` which we
refer to as ``ebfdd`` to avoid confusion).

The current purpose of the BFD daemon inside the FRR tree is:

1. Keep the BFD daemon configuration (to display in
   ``show running-config``);
2. Install the vtysh commands;
3. Synchronize the external daemon when it restarts;

This daemon alone doesn't implement any BFD functionality, but it talks
with the real daemon which is does that.


.. _bfd-starting:

Starting the daemons
====================

The start order of the daemons ``ebfdd``/``bfdd`` doesn't matter,
because they will synchronize configuration on start-up, but it's
preferable to have them started before any other FRR daemon.

Make sure that the ``ebfdd`` UNIX socket is created and that it has FRR
permissions to talk with other daemons. When using a non-default socket
path, remember to feed this information to ``bfdd``/``bgpd`` or any
other daemons that may use it.

Here is how to run ``bfdd`` with a custom control socket path:

::

   ebfdd -C /var/run/frr/ebfdd.sock
   /usr/lib/frr/bfdd --bfdctl /var/run/frr/ebfdd.sock
   /usr/lib/frr/bgpd --bfdctl /var/run/frr/ebfdd.sock


The default UNIX socket location is defined in ``bfdctl.h``:

::

   #define BFD_CONTROL_SOCK_PATH "/var/run/bfdd.sock"


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

   `interface` selects which interface we should use. This option
   conflicts with `vrf`.

   `vrf` selects which domain we want to use.

.. index:: no peer <A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]
.. clicmd:: no peer <A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]

    Stops and removes the selected peer.

.. index:: show bfd peers
.. clicmd:: show bfd peers

    Show all configured BFD peers information and current status.

.. index:: show bfd peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]>
.. clicmd:: show bfd peer <WORD$label|<A.B.C.D|X:X::X:X>$peer [{multihop|local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]>

    Show status for a specific BFD peer.


.. _bfd-peer-config:

Peer Configurations
-------------------

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
   wants to use to send BFD control packets.

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
   For example: `transmission-interval 2000`.

   Echo mode is not supported on multi-hop setups (see :rfc:`5883`
   section 3).

.. index:: [no] shutdown
.. clicmd:: [no] shutdown

   Enables or disables the peer. When the peer is disabled an
   'administrative down' message is sent to the remote peer.

.. index:: label WORD
.. clicmd:: label WORD

   Labels a peer with the provided word. This word can be referenced
   later on other daemons to refer to a specific peer.


.. _bfd-bgp-peer-config:

BGP BFD Configuration
---------------------

.. index:: neighbor <A.B.C.D|X:X::X:X|WORD> bfdd [multihop]
.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfdd [multihop]

   Listen for BFD events registered on the same target as this BGP
   neighbor. When BFD peer goes down it immediately asks BGP to shutdown
   the connection with its neighbor and, when it goes back up, notify
   BGP to try to connect to it.

.. index:: neighbor <A.B.C.D|X:X::X:X|WORD> bfdd label WORD
.. clicmd:: neighbor <A.B.C.D|X:X::X:X|WORD> bfdd label WORD

   Same functionality as
   `neighbor <A.B.C.D|X:X::X:X|WORD> bfdd [multihop]`, but it will
   listen for events on the specified label instead of the neighbor's
   address.

.. index:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfdd
.. clicmd:: no neighbor <A.B.C.D|X:X::X:X|WORD> bfdd

   Removes any notification registration for this neighbor.


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
     neighbor 192.168.0.1 bfdd
     neighbor 192.168.0.2 remote-as 65530
     neighbor 192.168.0.2 bfdd label home-peer
     neighbor 192.168.0.3 remote-as 65532
     neighbor 192.168.0.3 bfdd multihop
    !

Peers can be identified by its address (use ``multihop`` when you need
to specify a multi-hop peer) or can be specified manually by a label.

Here are the available peer configurations:

::

   bfd

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
                   Local timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: disabled
                   Remote timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: 50

           peer 192.168.1.1
                   label: router3-peer
                   ID: 2
                   Remote ID: 2
                   Status: up
                   Uptime: 1 minute(s), 53 second(s)
                   Diagnostics: ok
                   Remote diagnostics: ok
                   Local timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: disabled
                   Remote timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: 50

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
                   Local timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: disabled
                   Remote timers:
                           Receive interval: 300
                           Transmission interval: 300
                           Echo transmission interval: 50
