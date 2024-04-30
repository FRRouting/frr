.. _ldp:

***
LDP
***

The *ldpd* daemon is a standardised protocol that permits exchanging MPLS label
information between MPLS devices. The LDP protocol creates peering between
devices, so as to exchange that label information. This information is stored in
MPLS table of *zebra*, and it injects that MPLS information in the underlying
system (Linux kernel or OpenBSD system for instance).
*ldpd* provides necessary options to create a Layer 2 VPN across MPLS network.
For instance, it is possible to interconnect several sites that share the same
broadcast domain.

FRR implements LDP as described in :rfc:`5036`; other LDP standard are the
following ones: :rfc:`6720`, :rfc:`6667`, :rfc:`5919`, :rfc:`5561`, :rfc:`7552`,
:rfc:`4447`.
Because MPLS is already available, FRR also supports :rfc:`3031`.

Running Ldpd
============

The *ldpd* daemon can be invoked with any of the common
options (:ref:`common-invocation-options`).

.. option:: --ctl_socket

   This option allows you to override the path to the ldpd.sock file
   used to control this daemon.  If specified this option overrides
   the -N option path addition.

The *zebra* daemon must be running before *ldpd* is invoked.

.. include:: config-include.rst

.. _understanding-ldp:

Understanding LDP principles
============================

Let's first introduce some definitions that permit understand better the LDP
protocol:

- `LSR` : Labeled Switch Router. Networking devices handling labels used to
  forward traffic between and through them.

- `LER` : Labeled Edge Router. A Labeled edge router is located at the edge of
   an MPLS network, generally between an IP network and an MPLS network.


``LDP`` aims at sharing label information across devices. It tries to establish
peering with remote LDP capable devices, first by discovering using UDP port 646
, then by peering using TCP port 646. Once the TCP session is established, the
label information is shared, through label advertisements.

There are different methods to send label advertisement modes. The
implementation actually supports the following : Liberal Label Retention +
Downstream Unsolicited + Independent Control.
The other advertising modes are depicted below, and compared with the current
implementation.

- Liberal label retention versus conservative mode
  In liberal mode, every label sent by every LSR is stored in the MPLS table.
  In conservative mode, only the label that was sent by the best next hop
  (determined by the IGP metric) for that particular FEC is stored in the MPLS
  table.

- Independent LSP Control versus ordered LSP Control
  MPLS has two ways of binding labels to FEC’s; either through ordered LSP
  control, or independent LSP control.
  Ordered LSP control only binds a label to a FEC if it is the egress LSR, or
  the router received a label binding for a FEC from the next hop router. In
  this mode, an MPLS router will create a label binding for each FEC and
  distribute it to its neighbors so long as he has a entry in the RIB for the
  destination.
  In the other mode, label bindings are made without any dependencies on another
  router advertising a label for a particular FEC. Each router makes it own
  independent decision to create a label for each FEC.
  By default IOS uses Independent LSP Control, while Juniper implements the
  Ordered Control. Both modes are interoperable, the difference is that Ordered
  Control prevent blackholing during the LDP convergence process, at cost of
  slowing down the convergence itself

- unsolicited downstream versus downstream on demand
  Downstream on demand label distribution is where an LSR must explicitly
  request that a label be sent from its downstream router for a particular FEC.
  Unsolicited label distribution is where a label is sent from the downstream
  router without the original router requesting it.

.. _configuring-ldpd:

.. _ldp-configuration:

LDP Configuration
===================

.. clicmd:: mpls ldp

   Enable or disable LDP daemon

.. clicmd:: router-id A.B.C.D

   The following command located under MPLS router node configures the MPLS
   router-id of the local device.

.. clicmd:: ordered-control

   Configure LDP Ordered Label Distribution Control.

.. clicmd:: address-family [ipv4 | ipv6]

   Configure LDP for IPv4 or IPv6 address-family. Located under MPLS route node,
   this subnode permits configuring the LDP neighbors.

.. clicmd:: interface IFACE

   Located under MPLS address-family node, use this command to enable or disable
   LDP discovery per interface. IFACE stands for the interface name where LDP is
   enabled. By default it is disabled. Once this command executed, the
   address-family interface node is configured.

.. clicmd:: discovery transport-address A.B.C.D | A:B::C:D

   Located under mpls address-family interface node, use this command to set
   the IPv4 or IPv6 transport-address used by the LDP protocol to talk on this
   interface.

.. clicmd:: ttl-security disable

   Located under the LDP address-family node, use this command to disable the
   GTSM procedures described in RFC 6720 (for the IPv4 address-family) and
   RFC 7552 (for the IPv6 address-family).

   Since GTSM is mandatory for LDPv6, the only effect of disabling GTSM for the
   IPv6 address-family is that *ldpd* will not discard packets with a hop limit
   below 255. This may be necessary to interoperate with older implementations.
   Outgoing packets will still be sent using a hop limit of 255 for maximum
   compatibility.

   If GTSM is enabled, multi-hop neighbors should have either GTSM disabled
   individually or configured with an appropriate ttl-security hops distance.

.. clicmd:: neighbor A.B.C.D password PASSWORD

   The following command located under MPLS router node configures the router
   of a LDP device. This device, if found, will have to comply with the
   configured password. PASSWORD is a clear text password wit its digest sent
   through the network.

.. clicmd:: neighbor A.B.C.D holdtime HOLDTIME

   The following command located under MPLS router node configures the holdtime
   value in seconds of the LDP neighbor ID. Configuring it triggers a keepalive
   mechanism. That value can be configured between 15 and 65535 seconds. After
   this time of non response, the LDP established session will be considered as
   set to down. By default, no holdtime is configured for the LDP devices.

.. clicmd:: neighbor A.B.C.D ttl-security disable

   Located under the MPLS LDP node, use this command to override the global
   configuration and enable/disable GTSM for the specified neighbor.

.. clicmd:: neighbor A.B.C.D ttl-security hops (1-254)

   Located under the MPLS LDP node, use this command to set the maximum number
   of hops the specified neighbor may be away. When GTSM is enabled for this
   neighbor, incoming packets are required to have a TTL/hop limit of 256
   minus this value, ensuring they have not passed through more than the
   expected number of hops. The default value is 1.

.. clicmd:: discovery hello holdtime HOLDTIME

.. clicmd:: discovery hello interval INTERVAL

   INTERVAL value ranges from 1 to 65535 seconds. Default value is 5 seconds.
   This is the value between each hello timer message sent.
   HOLDTIME value ranges from 1 to 65535 seconds. Default value is 15 seconds.
   That value is added as a TLV in the LDP messages.

.. clicmd:: dual-stack transport-connection prefer ipv4

   When *ldpd* is configured for dual-stack operation, the transport connection
   preference is IPv6 by default (as specified by :rfc:`7552`). On such
   circumstances, *ldpd* will refuse to establish TCP connections over IPv4.
   You can use above command to change the transport connection preference to
   IPv4. In this case, it will be possible to distribute label mappings for
   IPv6 FECs over TCPv4 connections.

.. _show-ldp-information:

Show LDP Information
====================

These commands dump various parts of *ldpd*.

.. clicmd:: show mpls ldp neighbor [A.B.C.D]

   This command dumps the various neighbors discovered. Below example shows that
   local machine has an operation neighbor with ID set to 1.1.1.1.

   ::

      west-vm# show mpls ldp neighbor
      AF   ID              State       Remote Address    Uptime
      ipv4 1.1.1.1         OPERATIONAL 1.1.1.1         00:01:37
      west-vm#

.. clicmd:: show mpls ldp neighbor [A.B.C.D] capabilities

.. clicmd:: show mpls ldp neighbor [A.B.C.D] detail

   Above commands dump other neighbor information.

.. clicmd:: show mpls ldp discovery [detail]

.. clicmd:: show mpls ldp ipv4 discovery [detail]

.. clicmd:: show mpls ldp ipv6 discovery [detail]

   Above commands dump discovery information.

.. clicmd:: show mpls ldp ipv4 interface

.. clicmd:: show mpls ldp ipv6 interface

   Above command dumps the IPv4 or IPv6 interface per where LDP is enabled.
   Below output illustrates what is dumped for IPv4.

   ::

      west-vm# show mpls ldp ipv4 interface
      AF   Interface   State  Uptime   Hello Timers  ac
      ipv4 eth1       ACTIVE 00:08:35 5/15           0
      ipv4 eth3       ACTIVE 00:08:35 5/15           1


.. clicmd:: show mpls ldp ipv4|ipv6 binding

   Above command dumps the binding obtained through MPLS exchanges with LDP.

   ::

      west-vm# show mpls ldp ipv4 binding
      AF   Destination          Nexthop         Local Label Remote Label  In Use
      ipv4 1.1.1.1/32           1.1.1.1         16          imp-null         yes
      ipv4 2.2.2.2/32           1.1.1.1         imp-null    16                no
      ipv4 10.0.2.0/24          1.1.1.1         imp-null    imp-null          no
      ipv4 10.115.0.0/24        1.1.1.1         imp-null    17                no
      ipv4 10.135.0.0/24        1.1.1.1         imp-null    imp-null          no
      ipv4 10.200.0.0/24        1.1.1.1         17          imp-null         yes
      west-vm#


LDP debugging commands
========================


.. clicmd:: debug mpls ldp KIND

   Enable or disable debugging messages of a given kind. ``KIND`` can
   be one of:

   - ``discovery``
   - ``errors``
   - ``event``
   - ``labels``
   - ``messages``
   - ``zebra``


Sample configuration
====================

Below configuration gives a typical MPLS configuration of a device located in a
MPLS backbone. LDP is enabled on two interfaces and will attempt to peer with
two neighbors with router-id set to either 1.1.1.1 or 3.3.3.3.

.. code-block:: frr

   mpls ldp
    router-id 2.2.2.2
    neighbor 1.1.1.1 password test
    neighbor 3.3.3.3 password test
    !
    address-family ipv4
     discovery transport-address 2.2.2.2
     !
     interface eth1
     !
     interface eth3
     !
    exit-address-family
    !


Deploying LDP across a backbone generally is done in a full mesh configuration
topology. LDP is typically deployed with an IGP like OSPF, that helps discover
the remote IPs. Below example is an OSPF configuration extract that goes with
LDP configuration

.. code-block:: frr

   router ospf
    ospf router-id 2.2.2.2
     network 0.0.0.0/0 area 0
    !


Below output shows the routing entry on the LER side. The OSPF routing entry
(10.200.0.0) is associated with Label entry (17), and shows that MPLS push action
that traffic to that destination will be applied.

::

   north-vm# show ip route
   Codes: K - kernel route, C - connected, S - static, R - RIP,
          O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
          T - Table, v - VNC, V - VNC-Direct, A - Babel, D - SHARP,
          F - PBR,
          > - selected route, * - FIB route

   O>* 1.1.1.1/32 [110/120] via 10.115.0.1, eth2, label 16, 00:00:15
   O>* 2.2.2.2/32 [110/20] via 10.115.0.1, eth2, label implicit-null, 00:00:15
   O   3.3.3.3/32 [110/10] via 0.0.0.0, loopback1 onlink, 00:01:19
   C>* 3.3.3.3/32 is directly connected, loopback1, 00:01:29
   O>* 10.0.2.0/24 [110/11] via 10.115.0.1, eth2, label implicit-null, 00:00:15
   O   10.100.0.0/24 [110/10] is directly connected, eth1, 00:00:32
   C>* 10.100.0.0/24 is directly connected, eth1, 00:00:32
   O   10.115.0.0/24 [110/10] is directly connected, eth2, 00:00:25
   C>* 10.115.0.0/24 is directly connected, eth2, 00:00:32
   O>* 10.135.0.0/24 [110/110] via 10.115.0.1, eth2, label implicit-null, 00:00:15
   O>* 10.200.0.0/24 [110/210] via 10.115.0.1, eth2, label 17, 00:00:15
   north-vm#


Additional example demonstrating use of some miscellaneous config options:

.. code-block:: frr

   interface eth0
   !
   interface eth1
   !
   interface lo
   !
   mpls ldp
    dual-stack cisco-interop
    neighbor 10.0.1.5 password opensourcerouting
    neighbor 172.16.0.1 password opensourcerouting
    !
    address-family ipv4
     discovery transport-address 10.0.1.1
     label local advertise explicit-null
     !
     interface eth0
     !
     interface eth1
     !
    !
    address-family ipv6
     discovery transport-address 2001:db8::1
     !
     interface eth1
     !
    !
   !
   l2vpn ENG type vpls
    bridge br0
    member interface eth2
    !
    member pseudowire mpw0
     neighbor lsr-id 1.1.1.1
     pw-id 100
    !
   !

