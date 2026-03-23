.. _l2vpn:

L2VPNs
======

This document details the software design and internal structures of the
FRR L2VPN subsystem. The design centers on the implementation of a common L2VPN
library—a unified abstraction layer that allows FRR to support multiple
L2VPN RFCs (both legacy Pseudowire and modern EVPN technologies) through a
single internal logic.

Protocol Suppport
-----------------
Currently, FRR fully or partially supports the following standars:

* RFC 4762: Virtual Private LAN Service Using Label Distrbution Protocal (LDP)
  Signaling -- LDP VPLS

* RFC 8214: Virtual Private Wire Service Support in Ethernet VPN -- BGP EVPN
  VPWS


Configuration
-------------

L2VPN configuration in FRR are fully northbound-based. However, the management
plane integration (mgmtd) is currently pending, as both BGP and LDP daemons
have not yet fully transitioned to a northbound-based.

To configure a Virtual Private Wire Service (VPWS) in EVPN, use the following
command:

.. code-block:: frr

   l2vpn test vpws
    member evpn vxlan1
     vni 1
     neighbor evpn evi 1 local-ac-id 1 remote-ac-id 2

These commands are dispatched by the ``VTYSH_L2VPN`` daemons, defined in
`vtysh.h`, which includes both the LDP and BGP daemons. This configures a EVPN
VPWS over VXLAN, future MPLS and SRv6 is under consideration. However, only BGP
currently supports EVPN VPWS, LDP just ignores this configuration.

.. note::

     The example above covers the L2VPN context for EVPN VPWS. For a fully
     example of BGP EVPN and EVPN VPWS configuration, please refer to the
     ``test_bgp_evpn_vpws.py`` topotest.


To configure a Virtual Private LAN Service using LDP, pleaser refer to
`ldpd-basic-test-setup.md`.


Internals
---------

L2VPN control plane
~~~~~~~~~~~~~~~~~~~

The L2VPN control plane subsystem relies on two primary data structures to
manage service state:

* `struct l2vpn`: The top-level container structure created to hold L2VPN
  instance data. This structure is instanciated globally on each running
  ``VTYSH_L2VPN`` daemons.
* `struct l2vpn_svc`: The generic service structure used to maintain and
  track the state of VPWS or VPLS instances. Multiple service structures can be
  present for each l2vpn global instance.

Both structures are defined in ``lib/l2vpn_svc.h`` header file.

L2VPN data plane
~~~~~~~~~~~~~~~~

While the L2VPN control plane is maintained by the protocol daemons, the
dataplane is managed by ZEBRA. Originally introduced as the ZEBRA Pseudowire
`struct zebra_pw`, it has been renamed to `struct zebra_l2vpn_svc` and expanded
into a generic `L2VPN Service`. This abstraction is designed to accommodate both
legacy Pseudowires and modern EVPN-based Services.

The ZEBRA L2VPN Service is responsible for the following functions:

* Validation: Ensuring the correct setup and parameter consistency for a given
  service.
* Dataplane: Managing the underlying dataplane installation, ensuring that the
  kernel or third-party dataplane program forwarding tables are correctly
  programmed for the specific L2VPN type.

ZEBRA API (ZAPI) Interaction
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following ZAPI messages are used to exchange information between the control
plane daemons and ``zebra``:

* ``L2VPN_SVC_ADD``: Informs zebra to register a new service instance.
* ``L2VPN_SVC_DEL``: Informs zebra to unregister an existing service instance.
* ``ZEBRA_L2VPN_SVC_STATUS_UPDATE``: Sent by zebra to notify the protocol daemon
  of changes in the operational status of a service.
* ``L2VPN_SVC_SET``: Instructs zebra to install the service into the dataplane.
* ``L2VPN_SVC_UNSET``: Instructs zebra to uninstall the service from the
  dataplane.

Service Operational Status
~~~~~~~~~~~~~~~~~~~~~~~~~~
In the context of EVPN, a service can exist in one of three states:

* ``EVPN_LOCAL_TX_FAULT``: Indicates the service setup is incorrect. This can
  occur for multiple reasons, such as the local attachment interface being down
  or not found.
* ``EVPN_NOT_FORWARDING``: Indicates that while the configuration may be valid,
  the control plane is not yet ready.
* ``EVPN_FORWARDING``: Indicates that both the control plane and the dataplane
  are fully operational and complete.

Service status is updated by `zebra`, which then informs the control plane
daemons.


.. note::

   Similar status values are defined for legacy Pseudowires but are more
   comprehensive in scope. For further details on Pseudowire-specific states,
   please refer to the LDP documentation.


Example
-------

.. note::

   This example assumes a solid understanding of current FRR EVPN concepts. For
   further clarification, please refer to the official FRR EVPN documentation.

The following example demonstrates EVPN VPWS VXLAN using BGP signaling step by
step. Below is the configuration of BGP EVPN VPWS VXLAN:

.. code-block:: frr

   router bgp 65000
    bgp router-id 10.10.10.10
    no bgp default ipv4-unicast
    neighbor 10.30.30.30 remote-as 65000
    neighbor 10.30.30.30 update-source lo
    address-family l2vpn evpn
     neighbor 10.30.30.30 activate
     advertise-all-vni
     vni 101
      rd 10.10.10.10:1
      route-target both 65000:1
    exit
   exit
   l2vpn test type vpws
    member evpn vxlan101
     vni 101
     neighbor evpn evi 100 local-ac-id 111 remote-ac-id 222

Let's now check the service status by `show l2vpn <l2vpn_name>`:

.. code-block:: frr

   PE1# show l2vpn test
   Virtual Private Wire Service
   EVI                 Local/Remote AC     IFNAME              Status              PROTO
   ------------------- ------------------- ------------------- ------------------- -------------------

The service remains unregistered because VNI 101 and the associated SVI have not
yet been configured in the system. Let's proceed with the Linux configuration:

.. code-block:: console

   ip link add vrf1 type vrf table 10
   ip link set up dev vrf1
   ip link add br101 type bridge
   ip link set br101 master vrf1 addrgenmode none
   ip link set dev br101 up
   ip link add vxlan102 type vxlan id 101 dstport 4789 local 10.10.10.10 nolearning
   ip link set dev vxlan101 master br101 addrgenmode none
   ip link set vxlan101 type bridge_slave neigh_suppress on learning off

Let's view more detailed information, use `show l2vpn <l2vpn_name> detail`:

.. code-block:: frr

   PE1# show l2vpn test detail
   Virtual Private Wire Service
   EVI 100
     AC: , state is Down
         AC-ID 111
         Status: evpn_local_tx_fault (4)
     EVPN: neighbor 0.0.0.0, AC-ID 222, state is Down
         Status: No Error
         MTU: 0
         Encapsulation VXLAN
         Ignore MTU mismatch: true
         Nexthop: 0.0.0.0

The output shows that local status is `evpn_local_tx_fault` indicating a setup
issue, as the local attachment remains undetected by the `zebra`.

Let's attach a physical interface to the bridge `br101`:

.. code-block:: console

   ip link add PE1-eth0 master br101
   ip link set up PE1-eth0

Let's check again the service status:

.. code-block:: frr

   PE1# show l2vpn test detail
   Virtual Private Wire Service
   EVI 100
     AC: PE1-eth0, state is Up
         AC-ID 111
         Status: evpn_not_forwarding (1)
     EVPN: neighbor 0.0.0.0, AC-ID 222, state is Down
         Status: missing remote EAD-per-EVI
         MTU: 0
         Encapsulation VXLAN
         Ignore MTU mismatch: true
         Nexthop: 0.0.0.0

System changes are detected by `zebra`, the bridge `br101` now includes
`vxlan101` and `PE1-eth0` slaves, the EVPN VPWS requirements are met. `zebra`
then transitions the instance status to `EVPN_NOT_FORWARDING`, which is
propagated to `bgpd`. This indicates taht BGP is ready to begin its signaling
process.

.. note::

   Attaching multiple local interfaces to the same service instance will trigger
   a configuration error. Currently, EVPN VPWS supports only a single local
   attachment per service instance. Support for multiple local attachments,
   often referred to as FXC VPWS (Flexible Cross-Connect), is currently under
   consideration for future updates.

BGP now is ready to originate EAD-per-EVI route to its peer:

.. code-block:: frr

   PE1# show bgp l2vpn evpn neighbors 10.30.30.30 advertised-routes
   ...
   Route Distinguisher: 10.10.10.10:1
    *> [1]:[100]:[00:00:00:00:00:00:00:00:00:00]:[128]:[::]:[0]
                                  100  32768 i

However, the service is not yet established, the remote peer status is down. As
indicated by the status ``missing remote EAD-per-EVI``, the remote peer has not
yet sent its EAD-per-EVI route.

Once the remote peer is configured to match the EVPN VPWS VXLAN:

.. code-block:: frr

   PE1# show bgp l2vpn evpn neighbors 10.30.30.30 routes
   ...
   Route Distinguisher: 10.30.30.30:1
    *>i [1]:[100]:[00:00:00:00:00:00:00:00:00:00]:[32]:[0.0.0.0]:[0]
                        10.30.30.30                   100      0 i
                    RT:65000:1 ET:8 L2: Cflags none, MTU 0

This complete the BGP signaling and informs `zebra` to install the dataplane
for this instance. The service should now transition to forwarding status:

.. code-block:: frr

   PE1# show l2vpn test detail
   Virtual Private Wire Service
   EVI 100
   AC: PE1-eth0, state is Up
      Status: evpn_forwarding (0)
   EVPN: neighbor 10.30.30.30, AC-ID 222, state is Up
       Status: No Error
       MTU: 0
       Encapsulation VXLAN
       Ignore MTU mismatch: true
       Nexthop: 10.30.30.30

The local status is in `EVPN_FORWARDING` status, which indicates that a
default FDB entry has been sucessfully installed by `zebra`, to steer traffic
from `PE1-eth0` to the VXLAN port:


.. code-block:: console

   bridge fdb show
   ...
   00:00:00:00:00:00 dev vxlan101 dst 10.30.30.30 self permanent

The service is now successfully established.
