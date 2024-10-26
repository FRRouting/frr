.. _evpn:

****
EVPN
****

:abbr:`EVPN` stands for Ethernet Virtual Private Network. This is an extension
of BGP that enables the signaling of bridged (L2) and routed (L3) VPNs over a
common network. EVPN is described in :rfc:`7432` and is updated by several
additional RFCs and IETF drafts including :rfc:`9135` (Integrated Routing
and Bridging in Ethernet VPN), :rfc:`9136` (IP Prefix Advertisement in Ethernet
VPN), :rfc:`8584` (Framework for Ethernet VPN Designated Forwarder Election
Extensibility), and :rfc:`8365` (A Network Virtualization Overlay Solution Using
Ethernet VPN). FRR supports All-Active Layer-2 Multihoming for devices (MHD) via
LACP Ethernet Segments as well as both Symmetric and Asymmetric IRB.
FRR implements MAC-VRFs using a "VLAN-Based Service Interface" (:rfc:`7432`)
and performs processing of Symmetric IRB routes following the
"Interface-less IP-VRF-to-IP-VRF Model" (:rfc:`9136`).

.. _evpn-concepts:

EVPN Concepts
=============
BGP-EVPN is the control plane for the transport of Ethernet frames, regardless
of whether those frames are bridged or routed. In the case of a VLAN-Based
Service Interface with VXLAN encap, a single VNI is used to represent an EVPN
Instance (EVI) and will have its own Route Distinguisher and set of
Import/Export Route-Targets.

A VNI is considered to be either Layer-2 (tied to a MAC-VRF) or Layer-3
(tied to an IP-VRF), which indicates what kind of information is represented by
the VRF. An IP-VRF represents a routing table (operating in much the same way as
a VRF traditionally operates in L3VPN), while a MAC-VRF represents a bridging
table i.e. MAC (fdb) and ARP/NDP entries.

A MAC-VRF can be thought of as a VLAN with or without an SVI associated with it.
An SVI is a Layer-3 interface bound to a bridging domain. In Linux an SVI can
either be a traditional bridge or a VLAN subinterface of a VLAN-aware bridge.
If there is an SVI for the VLAN, ARP/NDP entries can be bound to the MACs within
the broadcast domain. Without an SVI, the VLAN operates in traditional L2
fashion and MACs are the only type of host addresses known within the VLAN.

In the same way that there can be a many-to-one relationship of SVIs to a VRF,
there can also be a many-to-one relationship of MAC-VRFs (L2VNIs) to an IP-VRF
(L3VNI). In FRR the L3VNI association for an L2VNI is determined by the
presence of an SVI for the VLAN and the VRF membership of the SVI.
If an L2VNI does not have an SVI or its SVI is not enslaved to a VRF, the L2VNI
will be associated with the "default" VRF. If an L2VNI has an SVI whose master
device is a VRF, then that L2VNI will be associated with its master VRF.

.. _evpn-frr-configuration:

FRR Configuration
=================
FRR learns about the system's Linux network interface configuration from the
kernel via Netlink, however it does not manage network interfaces directly.
The following sections will include examples of Linux interface configurations
that are compatible with FRR's EVPN implementation. While there are multiple
interface managers that can set up a proper kernel config (e.g. ifupdown2),
these examples will use iproute2 to add/configure the interfaces.

All of the examples will follow the same basic setup but use different, yet
compatible, interface configurations.

In this example we will set up the following:

* An IP-VRF named vrf1, associated with L3VNI 100
* An IP-VRF named vrf2, associated with L3VNI 200
* An IP-VRF named vrf3, with no L3VNI associations
* A MAC-VRF using VLAN 10, associated with L2VNI 110 and IP-VRF vrf1
* A MAC-VRF using VLAN 20, associated with L2VNI 220 and IP-VRF vrf2
* A MAC-VRF using VLAN 30, associated with L2VNI 330 and IP-VRF vrf3
* A MAC-VRF using VLAN 40, associated with L2VNI 440 and IP-VRF default
* A MAC-VRF using VLAN 50, associated with L2VNI 550 and operating L2-Only

.. _evpn-sample-configuration:

Sample Configuration
--------------------
This is a sample FRR configuration that implements the above EVPN environment.
The first snippet will be the config in its entirety, then each config element
will be explained individually later in the document.

The following snippet will result in a functional EVPN control plane if the
corresponding Linux interface configuration is correct, compatible, and active:

.. code-block:: frr

   vrf vrf1
    vni 100
   exit-vrf
   !
   vrf vrf2
    vni 200
   exit-vrf
   !
   router bgp 4200000000
    neighbor 192.168.122.12 remote-as internal
    !
    address-family ipv4 unicast
     network 100.64.0.1/32
    exit-address-family
    !
    address-family l2vpn evpn
     neighbor 192.168.122.12 activate
     advertise-all-vni
     advertise-svi-ip
    exit-address-family
   exit
   !
   router bgp 4200000000 vrf vrf1
    !
    address-family ipv4 unicast
     redistribute static
    exit-address-family
    !
    address-family ipv6 unicast
     redistribute static
    exit-address-family
    !
    address-family l2vpn evpn
     advertise ipv4 unicast
     advertise ipv6 unicast
    exit-address-family
   exit
   !
   router bgp 4200000000 vrf vrf2
    !
    address-family ipv4 unicast
     redistribute static
    exit-address-family
    !
    address-family ipv6 unicast
     redistribute static
    exit-address-family
    !
    address-family l2vpn evpn
     advertise ipv4 unicast
     advertise ipv6 unicast
    exit-address-family
   exit

A VRF will get its L3VNI association as a result of the ``vni`` command under
the ``vrf`` stanza. Until this L3VNI association is made, zebra will discover
the VNI from netlink but will consider it to be an L2VNI. The current L2 vs L3
context of a VNI can be seen in the output of ``show evpn vni``.

In this configuration we are telling zebra to consider VXLAN-ID 100 to be the
L3VNI for vrf1 and VXLAN-ID 200 to be the L3VNI for vrf2.

.. code-block:: frr

   vrf vrf1
    vni 100
   exit-vrf
   !
   vrf vrf2
    vni 200
   exit-vrf

The VTEP-IP (100.64.0.1) needs to be reachable by other VTEPs in the EVPN
environment in order for VXLAN decapsulation to function. In this example we
will advertise our local VTEP-IP using BGP (via the ``network`` statement), but
static routes or other routing protocols like IS-IS or OSPF can also be used.

In order to enable EVPN for a BGP instance, we must use the command
``advertise-all-vni``. In this example we will be using the default VRF to
carry the l2vpn evpn address-family, so we will enable EVPN for the default VRF.

In this example, we plan to exchange EVPN routes with 192.168.122.12, so we
will activate the l2vpn evpn address-family for this peer in order to allow
EVPN NLRI to be advertised and received.

The ``advertise-svi-ip`` command also belongs in the BGP instance where EVPN is
enabled. This command tells FRR to originate "self" Type-2 routes for all the
MAC/IP pairs associated with the local SVI interfaces.

.. code-block:: frr

   router bgp 4200000000
    neighbor 192.168.122.12 remote-as internal
    !
    address-family ipv4 unicast
     network 100.64.0.1/32
    exit-address-family
    !
    address-family l2vpn evpn
     neighbor 192.168.122.12 activate
     advertise-all-vni
     advertise-svi-ip
    exit-address-family
   exit

IPv4 and IPv6 BGP Prefixes from an IP-VRF are not exported to EVPN as Type-5
routes until the respective ``advertise <afi> unicast`` command has been
configured in the BGP instance of the VRF in question. All routes in the BGP
RIB (locally originated, learned from a peer, or leaked from another VRF) will
be eligible to be exported to EVPN so long as they are valid and selected in
the VRF's unicast table.

In this example, the BGP instances for vrf1 and vrf2 will have their static
routes redistributed into the BGP loc-rib for the ipv4 unicast and ipv6 unicast
address-families via the ``redistribute static`` statements. These unicast
prefixes will then be exported into EVPN as Type-5 routes as a result of the
``advertise ipv4 unicast`` and ``advertise ipv6 unicast`` commands.

.. code-block:: frr

   router bgp 4200000000 vrf vrf1
    !
    address-family ipv4 unicast
     redistribute static
    exit-address-family
    !
    address-family ipv6 unicast
     redistribute static
    exit-address-family
    !
    address-family l2vpn evpn
     advertise ipv4 unicast
     advertise ipv6 unicast
    exit-address-family
   exit
   !
   router bgp 4200000000 vrf vrf2
    !
    address-family ipv4 unicast
     redistribute static
    exit-address-family
    !
    address-family ipv6 unicast
     redistribute static
    exit-address-family
    !
    address-family l2vpn evpn
     advertise ipv4 unicast
     advertise ipv6 unicast
    exit-address-family
   exit

.. _evpn-linux-interface-configuration:

Linux Interface Configuration
=============================
The Linux kernel offers several options for configuring netdevices for an
EVPN-VXLAN environment. The following section will include samples of a few
netdev configurations that are compatible with FRR which implement the
environment described above.

Some high-level config considerations:

* The local VTEP-IP should always be set to a reachable IP on the lo device.
* An L3VNI should always have an SVI (aka the L3-SVI).
* An L3-SVI should not be assigned an IP address, link-local or otherwise.

  * IPv6 address autoconfiguration can be disabled via ``addrgenmode none``.

* An SVI for an L2VNI is only needed for routing (IRB) or ARP/ND suppression.

  * ARP/ND suppression is a kernel function, it is not managed by FRR.
  * ARP/ND suppression is enabled per bridge_slave via ``neigh_suppress``.
  * ARP/ND suppression should only be enabled on vxlan interfaces.
  * IPv4/IPv6 forwarding should be disabled on SVIs not used for routing (IRB).

* Dynamic MAC/VTEP learning should be disabled on VXLAN interfaces used in EVPN.

  * Dynamic MAC learning is a function of the kernel bridge driver, not FRR.
  * Dynamic MAC learning is toggled per bridge_slave via ``learning {on|off}``.
  * Dynamic VTEP learning is a function of the kernel vxlan driver, not FRR.
  * Dynamic VTEP learning is toggled per vxlan interface via ``[no]learning``.

* The VXLAN interfaces should not have a ``remote`` VTEP defined.

  * Remote VTEPs are learned via EVPN, so static VTEPs are unnecessary.

.. _evpn-traditional-bridge-traditional-vxlan-devices:

Traditional Bridges and Traditional VXLAN Devices
-------------------------------------------------
In the traditional bridge model, we use a separate ``bridge`` interface per
MAC-VRF which acts as the SVI for that broadcast domain. A bridge is considered
"traditional" if ``vlan_filtering`` is set to ``0`` (disabled) which indicates
the bridge only has one broadcast domain which does not consider VLAN tags.
Similarly, only one VNI is carried by each "traditional" ``vxlan`` interface.
So in this deployment model, each VXLAN-enabled broadcast domain will have one
traditional vxlan interface enslaved to one traditional bridge.

Bridges created for an L3VNI broadcast domain should only have one member: the
L3VNI vxlan device. Bridges created for an L2VNI broadcast domain generally
have multiple members: the L2VNI vxlan device, plus any host/network ports
where the L2 domain will be carried.

To carry the broadcast domains of multiple traditional bridges over the same
host/network port, a tagged ``vlan`` sub-interface of the port must be created
per broadcast domain. The vlan sub-interfaces would then be enslaved to the
traditional bridge, ensuring that only packets tagged with the expected VID are
associated with the expected broadcast domain.

.. code-block:: shell

   ###################
   ## vxlan vtep-ip ##
   ###################
   ip addr add 100.64.0.1/32 dev lo

   #############################
   ## ip-vrf vrf1 / l3vni 100 ##
   #############################
   ip link add vrf1 type vrf table 1100
   ip link set vrf1 up
   ip link add br100 type bridge
   ip link set br100 master vrf1 addrgenmode none
   ip link set br100 addr aa:bb:cc:00:00:64
   ip link add vni100 type vxlan local 100.64.0.1 dstport 4789 id 100 nolearning
   ip link set vni100 master br100 addrgenmode none
   ip link set vni100 type bridge_slave neigh_suppress on learning off
   ip link set vni100 up
   ip link set br100 up

   #############################
   ## ip-vrf vrf2 / l3vni 200 ##
   #############################
   ip link add vrf2 type vrf table 1200
   ip link set vrf2 up
   ip link add br200 type bridge
   ip link set br200 master vrf2 addrgenmode none
   ip link set br200 addr aa:bb:cc:00:00:c8
   ip link add vni200 type vxlan local 100.64.0.1 dstport 4789 id 200 nolearning
   ip link set vni200 master br200 addrgenmode none
   ip link set vni200 type bridge_slave neigh_suppress on learning off
   ip link set vni200 up
   ip link set br200 up

   #################
   ## ip-vrf vrf3 ##
   #################
   ip link add vrf3 type vrf table 1300
   ip link set vrf3 up

   ###############
   ## l2vni 110 ##
   ###############
   ip link add br10 type bridge
   ip link set br10 master vrf1
   ip link set br10 addr aa:bb:cc:00:00:6e
   ip addr add 10.0.10.1/24 dev br10
   ip addr add 2001:db8:0:10::1/64 dev br10
   ip link add vni110 type vxlan local 100.64.0.1 dstport 4789 id 110 nolearning
   ip link set vni110 master br10 addrgenmode none
   ip link set vni110 type bridge_slave neigh_suppress on learning off
   ip link set vni110 up
   ip link set br10 up

   ###############
   ## l2vni 220 ##
   ###############
   ip link add br20 type bridge
   ip link set br20 master vrf2
   ip link set br20 addr aa:bb:cc:00:00:dc
   ip addr add 10.0.20.1/24 dev br20
   ip addr add 2001:db8:0:20::1/64 dev br20
   ip link add vni220 type vxlan local 100.64.0.1 dstport 4789 id 220 nolearning
   ip link set vni220 master br20 addrgenmode none
   ip link set vni220 type bridge_slave neigh_suppress on learning off
   ip link set vni220 up
   ip link set br20 up

   ###############
   ## l2vni 330 ##
   ###############
   ip link add br30 type bridge
   ip link set br30 master vrf3
   ip link set br30 addr aa:bb:cc:00:01:4a
   ip addr add 10.0.30.1/24 dev br30
   ip addr add 2001:db8:0:30::1/64 dev br30
   ip link add vni330 type vxlan local 100.64.0.1 dstport 4789 id 330 nolearning
   ip link set vni330 master br30 addrgenmode none
   ip link set vni330 type bridge_slave neigh_suppress on learning off
   ip link set vni330 up
   ip link set br30 up

   ###############
   ## l2vni 440 ##
   ###############
   ip link add br40 type bridge
   ip link set br40 addr aa:bb:cc:00:01:b8
   ip addr add 10.0.40.1/24 dev br40
   ip addr add 2001:db8:0:40::1/64 dev br40
   ip link add vni440 type vxlan local 100.64.0.1 dstport 4789 id 440 nolearning
   ip link set vni440 master br40 addrgenmode none
   ip link set vni440 type bridge_slave neigh_suppress on learning off
   ip link set vni440 up
   ip link set br40 up

   ###############
   ## l2vni 550 ##
   ###############
   ip link add br50 type bridge
   ip link set br50 addrgenmode none
   ip link set br50 addr aa:bb:cc:00:02:26
   ip link add vni550 type vxlan local 100.64.0.1 dstport 4789 id 550 nolearning
   ip link set vni550 master br50 addrgenmode none
   ip link set vni550 type bridge_slave neigh_suppress on learning off
   sysctl -w net.ipv4.conf.br50.forwarding=0
   sysctl -w net.ipv6.conf.br50.forwarding=0
   ip link set vni550 up
   ip link set br50 up

   ##################
   ## create vlan subinterface of eth0 for each l2vni vlan and enslave each
   ## subinterface to the corresponding bridge
   ##################
   ip link set eth0 up
   for i in 10 20 30 40 50; do
      ip link add link eth0 name eth0.$i type vlan id $i;
      ip link set eth0.$i master br$i;
      ip link set eth0.$i up;
   done


To begin with, it creates a ``vrf`` interface named "vrf1" that is bound to the
kernel routing table with ID 1100. This will represent the IP-VRF "vrf1" which
we will later allocate an L3VNI for.

.. code-block:: shell

   ip link add vrf1 type vrf table 1100

This block creates a traditional ``bridge`` interface named "br100", binds it to
the VRF named "vrf1", disables IPv6 address autoconfiguration, and statically
defines the MAC address of "br100". This traditional bridge is used for the
L3VNI broadcast domain mapping to VRF "vrf1", i.e. "br100" is vrf1's L3-SVI.

.. code-block:: shell

   ip link add br100 type bridge
   ip link set br100 master vrf1 addrgenmode none
   ip link set br100 addr aa:bb:cc:00:00:64

Here a traditional ``vxlan`` interface is created with the name "vni100" which
uses a VTEP-IP of 100.64.0.1, carries VNI 100, and has Dynamic VTEP learning
disabled. IPv6 address autoconfiguration is disabled for "vni100", then the
interface is enslaved to "br100", ARP/ND suppression is enabled, and Dynamic
MAC Learning is disabled.

.. code-block:: shell

   ip link add vni100 type vxlan local 100.64.0.1 dstport 4789 id 100 nolearning
   ip link set vni100 master br100 addrgenmode none
   ip link set vni100 type bridge_slave neigh_suppress on learning off

This completes the necessary configuration for a VRF and L3VNI.

Here a traditional bridge named "br10" is created. We add "br10" to "vrf1" by
setting "vrf1" as the ``master`` of "br10". It is not necessary to set the SVI
MAC statically, but it is done here for consistency's sake. Since "br10" will
be used for routing, IPv4 and IPv6 addresses are also added to the SVI.

.. code-block:: shell

   ip link add br10 type bridge
   ip link set br10 master vrf1
   ip link set br10 addr aa:bb:cc:00:00:6e
   ip addr add 10.0.10.1/24 dev br10
   ip addr add 2001:db8:0:10::1/64 dev br10

If the SVI will not be used for routing, IP addresses should not be assigned to
the SVI interface and IPv4/IPv6 "forwarding" should be disabled for the SVI via
the appropriate sysctl nodes.

.. code-block:: shell

   sysctl -w net.ipv4.conf.<ifname>.forwarding=0
   sysctl -w net.ipv6.conf.<ifname>.forwarding=0

The following commands create a ``vxlan`` interface for VNI 100. Other than the
VNI, The interface settings are the same for an L2VNI as they are for an L3VNI.

.. code-block:: shell

   ip link add vni110 type vxlan local 100.64.0.1 dstport 4789 id 110 nolearning
   ip link set vni110 master br10 addrgenmode none
   ip link set vni110 type bridge_slave neigh_suppress on learning off

Finally, to limit a traditional bridge's broadcast domain to traffic matching
specific VLAN-IDs, ``vlan`` subinterfaces of a host/network port need to be
set up. This example shows the creation of a VLAN subinterface of "eth0"
matching VID 10 with the name "eth0.10". By enslaving "eth0.10" to "br10"
(instead of "eth0") we ensure that only Ethernet frames ingressing "eth0"
tagged with VID 10 will be associated with the "br10" broadcast domain.

.. code-block:: shell

      ip link add link eth0 name eth0.10 type vlan id 10
      ip link set eth0.10 master br10

If you do not want to restrict the broadcast domain by VLAN-ID, you can skip
the creation of the VLAN subinterfaces and directly enslave "eth0" to "br10".

.. code-block:: shell

      ip link set eth0 master br10

This completes the necessary configuration for an L2VNI.

Displaying EVPN information
---------------------------

.. clicmd:: show evpn mac vni (1-16777215) detail [json]

   Display detailed information about MAC addresses for
   a specified VNI.

.. clicmd:: show vrf [<NAME$vrf_name|all$vrf_all>] vni [json]

   Displays VRF to L3VNI mapping. It also displays L3VNI associated
   router-mac, svi interface and vxlan interface.
   User can get that information as JSON format when ``json`` keyword
   at the end of cli is presented.

   .. code-block:: frr

      tor2# show vrf vni
      VRF                                   VNI        VxLAN IF             L3-SVI               State Rmac
      sym_1                                 9288       vxlan21              vlan210_l3           Up    21:31:36:ff:ff:20
      sym_2                                 9289       vxlan21              vlan210_l3           Up    21:31:36:ff:ff:20
      sym_3                                 9290       vxlan21              vlan210_l3           Up    21:31:36:ff:ff:20
      tor2# show vrf sym_1 vni
      VRF                                   VNI        VxLAN IF             L3-SVI               State Rmac
      sym_1                                 9288       vxlan21              vlan210_l3           Up    44:38:36:ff:ff:20
