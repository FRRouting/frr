.. _pm:

**
PM
**

:abbr:`PM (Path Monitoring)` is a daemon that provides path monitoring
functionality to track connectivity and performance measurements linked
with a remote IP address.

.. _starting-pm:

Starting PM
===========

Default configuration file for *pmd* is :file:`pmd.conf`.  The typical
location of :file:`pmd.conf` is |INSTALL_PREFIX_ETC|/pmd.conf.

If the user is using integrated config, then :file:`pmd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: pmd

:abbr:`PM` supports all the common FRR daemon start options which are
documented elsewhere.

.. _using-pm:

Using PM
========

All pm commands are under the enable node and preceeded by the ``pm``
keyword.

.. _pmd-commands:

PMd Commands
============

.. index:: pm
.. clicmd:: pm

   Opens the PM daemon configuration node.

.. index:: session <A.B.C.D|X:X::X:X> [{interface IFNAME|local-address <A.B.C.D|X:X::X:X>|vrf NAME}]
.. clicmd:: session <A.B.C.D|X:X::X:X> [{interface IFNAME|local-address <A.B.C.D|X:X::X:X>|vrf NAME}]

   Creates and configures a new PM session to send packets to and receive packets from.

   `local-address` provides a local address that we should bind our
   peer listener to and the address we should use to send the packets.

   `interface` selects which interface we should use.

   `vrf` selects which domain we want to use.

.. index:: no session <A.B.C.D|X:X::X:X>$session [{local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]
.. clicmd:: no session <A.B.C.D|X:X::X:X>$session [{local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]

    Stops and removes the selected session.

.. index:: show pm [vrf NAME] sessions [json]
.. clicmd:: show pm [vrf NAME] sessions [json]

    Show all configured PM sessions information and current status.

.. index:: show pm [vrf NAME$vrfname] session <A.B.C.D|X:X::X:X>$peer [json]
.. clicmd:: show pm [vrf NAME$vrfname] session <A.B.C.D|X:X::X:X>$peer [json]

    Show status for a specific PM session.


.. _pm-session-config:

Session Configurations
----------------------

.. index:: [no] packet-size (1-65535)
.. clicmd:: [no] packet-size (1-65535)

   Configures the packet size of packets to send within sessions.
   Default value is 80 bytes.

.. index:: [no] packet-tos (1-255)
.. clicmd:: [no] packet-tos (1-255)

   The type of service value to be written in the appropriate
   DSCP field of IP packet. Default value is 0xc0 which stands
   for Inter Network Control value.

.. index:: [no] interval (1-65535)
.. clicmd:: [no] interval (1-65535)

   Interval between each emission. This value is the interval
   in milliseconds between each emission of packet. Default
   interval value is set to 5000 ms.


.. index:: [no] timeout (1-65535)
.. clicmd:: [no] timeout (1-65535)

   Timeout value expressed in milliseconds. This is the time
   after emission, where one considers that the packet is not
   received in time. That value can not be greater than
   interval value. Default value is set to 5000 ms.


.. index:: [no] retries down-count (1-255) up-count (1-255)
.. clicmd:: [no] retries down-count (1-255) up-count (1-255)

   When packets are not received, or not received in time,
   the pm session is considered as lost. Reversely, the
   reception of one packet in time makes the pm session go up.
   However, it is possible to make more flexible the flip-
   flap algorithm by increasing the retry timers. Those timers
   permit to consider the session to go up or down, only after
   a defined amount of received or non received retries.


.. index:: [no] shutdown
.. clicmd:: [no] shutdown

   Enables or disables the peer. When the peer is disabled an
   'administrative down' message is sent to the remote peer.

.. _pm-static-config:

STATIC PM Configuration
------------------------

The following commands are available inside the configure or vrf configuration node.

.. index:: ip route [..] GATEWAY pm [..]
.. clicmd:: ip route [..] GATEWAY pm [..]

.. index:: ipv6 route [..] GATEWAY pm [..]
.. clicmd:: ipv6 route [..] GATEWAY pm [..]

   Listen for PM events on gateways mentioned in static route created. Every time the
   gateway is found thanks to nexthop tracking facility, a PM session is created to
   monitor the route entry. The route entry will be removed dynamically if remote PM
   session is not operational up.

.. index:: no ip route [..] GATEWAY pm [..]
.. clicmd:: no ip route [..] GATEWAY pm [..]

.. index:: no ipv6 route [..] GATEWAY pm [..]
.. clicmd:: no ipv6 route [..] GATEWAY pm [..]

   Removes route entry along with PM session context.

.. _pm-configuration:

Configuration
=============

Before applying ``pmd`` rules to integrated daemons, we must
create the corresponding sessions inside the ``pm`` configuration node.

Here is an example of PM configuration:

::

    pm
    session 192.168.0.2 local-address 192.168.0.1 interface r1-eth0
     interval 500
     timeout 500
     no shutdown
     !
    !
    interface r1-eth0
     ip address 192.168.0.1/24
    !
    ip route 192.168.2.0/24 192.168.0.2 pm vrf r1-cust1

.. _pm-status:

Status
======

You can inspect the current PM session status with the following commands:

::

   frr# show pm sessions
   session 192.168.0.2 local-address 192.168.0.1 interface r1-eth0
          packet-tos 192, packet-size 80, interval 500, timeout 500
          retries up-count 1 down-count 1
          status: (0x3e) session admin up, run active
                  up (echo timeout)

   frr# show pm session json
   [{"peer":"192.168.0.2","local":"192.168.0.1","vrf":"default","interface":"r1-eth0","id":4237984346,"diagnostic":"echo ok","status":"up","uptime":0,"type":"icmp_echo","interval":500,"timeout":500,"retries_up":1,"retries_down":1,"tos_val":192,"packet-size":300}]

You can also inspect peer session counters with the following commands:

::

   frr# show pm sessions
   Pm Sessions status:
        peer 192.168.0.2 interface r1-eth0
                packet-size 80, interval 500, timeout 500
                pkt 12 sent, 12 rcvd (timeout 0)
                last round trip time 0 sec, 0 usec
                rtt calculated total 12, min 0 ms, max 1000 msavg 83 ms
