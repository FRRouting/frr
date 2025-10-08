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
The VTEP-IP can be either an IPv4 or IPv6 address for Singlehomed deployments.
Only IPv4 is presently supported for Multihomed deployments.

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
* The local VTEP-IP can be either an IPv4 or IPv6 address.
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

.. _evpn-vlan-filtering-bridge-single-vxlan-device:

VLAN Filtering Bridge and Single VXLAN Device
---------------------------------------------

In contrast to traditional bridges, each with its own VXLAN device, an EVPN
deployment with a single VXLAN device (SVD) uses a single bridge and a single 
VXLAN interface with that bridge as its master. We'll use ``100.64.0.1`` as our 
local VTEP endpoint, so add that address to the ``lo`` device.

.. code-block:: shell

   ip addr replace 100.64.0.1 dev lo

Then create our root bridge and VXLAN device. These devices will service all 
VNIs, both L2VNIs and L3VNIs included. The bridge must be VLAN aware, i.e., 
``vlan_filtering 1``. It's best to set no default pvid to prevent accidentally
bridging two unrelated networks.

.. code-block:: shell

   ip link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0
   # the key setting for SVD configuration is "external"
   # "vnifilter" isn't strictly necessary but is correct
   ip link add vxlan0 type vxlan dstport 4789 local 100.64.0.1 nolearning external vnifilter
   ip link set br0 addrgenmode none
   ip link set vxlan0 addrgenmode none master br0

We will also choose a unique MAC address per VTEP which will be advertised along
with each Type-2 route advertising an IP address, and each Type-5 route. This 
is called the `routermac` and supports symmetric routing.

.. code-block:: shell

   ip link set br0 address 11:22:33:44:55:66
   ip link set vxlan0 address 11:22:33:44:55:66
   ip link set br0 up
   ip link set vxlan0 up

Lastly, the vlan_tunnel setting allows creation of a mapping between a VNI (global
identifier) and a VLAN (local identifier). To function, this requires the ``external``
setting when creating the VXLAN device.

.. code-block:: shell

   #and the last key setting for SVD here is "vlan_tunnel"
   bridge link set dev vxlan0 vlan_tunnel on neigh_suppress on learning off

And also create our vrfs.

.. code-block:: shell

   #############################
   ## ip-vrf vrf1 / l3vni 100 ##
   #############################
   ip link add vrf1 type vrf table 1100
   ip link set vrf1 up

   #############################
   ## ip-vrf vrf2 / l3vni 200 ##
   #############################
   ip link add vrf2 type vrf table 1200
   ip link set vrf2 up

   #############################
   ## ip-vrf vrf3 / no l3vni  ##
   #############################
   ip link add vrf3 type vrf table 1300
   ip link set vrf3 up

Now we perform the VLAN filtering, the VLAN-VNI binding, and L2VNI to L3VNI 
bindings. 

.. code-block:: shell

   #############################
   ## ip-vrf vrf1 / l3vni 100 ##
   #############################
   # Choose any arbitrary VLAN for L3VNIs, since it never leaves the device
   # as long as it doesn't collide with another VLAN. It's used solely to
   # bind into a routing table (VRF)
   bridge vlan add dev br0 vid 1100 self
   bridge vlan add dev vxlan0 vid 1100
   bridge vni add dev vxlan0 vni 100 # add vni if using vnifilter
   bridge vlan add dev vxlan0 vid 1100 tunnel_info id 100 # map vlan to vni
   ip link add vrf1br link br0 type vlan id 1100 # create vlan on top of bridge
   ip link set vrf1br address 11:22:33:44:55:66 addrgenmode none # set L3VNI devices to routermac and no address
   ip link set vrf1br master vrf1 # bind the device to the correct VRF, no address for L3VNI

   #############################
   ## ip-vrf vrf2 / l3vni 200 ##
   #############################
   bridge vlan add dev br0 vid 1200 self
   bridge vlan add dev vxlan0 vid 1200
   bridge vni add dev vxlan0 vni 200
   bridge vlan add dev vxlan0 vid 1200 tunnel_info id 200
   ip link add vrf2br link br0 type vlan id 1200
   ip link set vrf2br address 11:22:33:44:55:66 addrgenmode none
   ip link set vrf2br master vrf2

   ###############################
   ## ip-vrf vrf3 / no l3vni    ##
   ###############################
   # vrf3 has no L3VNI, so no bridge/vxlan configuration needed

   ip link set vrf1br up
   ip link set vrf2br up

   ###############
   ## l2vni 110 ##
   ###############
   bridge vlan add dev br0 vid 10 self
   bridge vlan add dev vxlan0 vid 10
   bridge vni add dev vxlan0 vni 110
   bridge vlan add dev vxlan0 vid 10 tunnel_info id 110
   ip link add vlan10 link br0 type vlan id 10
   ip link set vlan10 master vrf1 # bind L2VNI to L3VNI (vrf1)
   ip link set vlan10 addr aa:bb:cc:00:00:6e # unique MAC per L2VNI+VTEP combo (or use anycast MAC, see below)
   ip addr add 10.0.10.1/24 dev vlan10 # shared gateway IP per L2VNI, on all VTEPs
   ip addr add 2001:db8:0:10::1/64 dev vlan10
   ip link set vlan10 up

   ###############
   ## l2vni 220 ##
   ###############
   bridge vlan add dev br0 vid 20 self
   bridge vlan add dev vxlan0 vid 20
   bridge vni add dev vxlan0 vni 220
   bridge vlan add dev vxlan0 vid 20 tunnel_info id 220
   ip link add vlan20 link br0 type vlan id 20
   ip link set vlan20 master vrf2 # bind L2VNI to L3VNI (vrf2)
   ip link set vlan20 addr aa:bb:cc:00:00:dc
   ip addr add 10.0.20.1/24 dev vlan20
   ip addr add 2001:db8:0:20::1/64 dev vlan20
   ip link set vlan20 up

   ###############
   ## l2vni 330 ##
   ###############
   bridge vlan add dev br0 vid 30 self
   bridge vlan add dev vxlan0 vid 30
   bridge vni add dev vxlan0 vni 330
   bridge vlan add dev vxlan0 vid 30 tunnel_info id 330
   ip link add vlan30 link br0 type vlan id 30
   ip link set vlan30 master vrf3 # bind L2VNI to vrf3 (no L3VNI)
   ip link set vlan30 addr aa:bb:cc:00:01:4a
   ip addr add 10.0.30.1/24 dev vlan30
   ip addr add 2001:db8:0:30::1/64 dev vlan30
   ip link set vlan30 up

   ###############
   ## l2vni 440 ##
   ###############
   bridge vlan add dev br0 vid 40 self
   bridge vlan add dev vxlan0 vid 40
   bridge vni add dev vxlan0 vni 440
   bridge vlan add dev vxlan0 vid 40 tunnel_info id 440
   ip link add vlan40 link br0 type vlan id 40
   # vlan40 is not enslaved to any VRF, so it's in the default VRF
   ip link set vlan40 addr aa:bb:cc:00:01:b8
   ip addr add 10.0.40.1/24 dev vlan40
   ip addr add 2001:db8:0:40::1/64 dev vlan40
   ip link set vlan40 up

   ###############
   ## l2vni 550 ##
   ###############
   bridge vlan add dev br0 vid 50 self
   bridge vlan add dev vxlan0 vid 50
   bridge vni add dev vxlan0 vni 550
   bridge vlan add dev vxlan0 vid 50 tunnel_info id 550
   ip link add vlan50 link br0 type vlan id 50
   # vlan50 is L2-only (no routing)
   ip link set vlan50 addr aa:bb:cc:00:02:26
   # no IP address for unrouted L2VNI
   sysctl -w net.ipv4.conf.vlan50.forwarding=0
   sysctl -w net.ipv6.conf.vlan50.forwarding=0
   ip link set vlan50 up

Lastly, add your carrier device(s) to the bridge along with the needed
bridge settings. In our case, we will have one device per L2VNI which will
be akin to access ports.

.. code-block:: shell

   ###################################
   ## l2vni 110 / eth10 access port ##
   ###################################
   ip link set eth10 master br0
   bridge vlan add dev eth10 vid 10 pvid untagged

   ###################################
   ## l2vni 220 / eth20 access port ##
   ###################################
   ip link set eth20 master br0
   bridge vlan add dev eth20 vid 20 pvid untagged

   ###################################
   ## l2vni 330 / eth30 access port ##
   ###################################
   ip link set eth30 master br0
   bridge vlan add dev eth30 vid 30 pvid untagged

   ###################################
   ## l2vni 440 / eth40 access port ##
   ###################################
   ip link set eth40 master br0
   bridge vlan add dev eth40 vid 40 pvid untagged

   ###################################
   ## l2vni 550 / eth50 access port ##
   ###################################
   ip link set eth50 master br0
   bridge vlan add dev eth50 vid 50 pvid untagged

You can also use a trunk port if preferred, or any combination of trunk
and access ports.

.. code-block:: shell

   ip link set eth0 master br0
   bridge vlan add dev eth0 vid 10
   bridge vlan add dev eth0 vid 20
   bridge vlan add dev eth0 vid 30
   bridge vlan add dev eth0 vid 40
   bridge vlan add dev eth0 vid 50

This completes device configuration for a single vxlan device.

.. _evpn-anycast-gateways-single-vxlan-device:

Anycast Gateways with Single VXLAN Device
-----------------------------------------

When using anycast gateways, you can use the same MAC address across all VTEPs
for each L2VNI instead of unique MAC addresses. This simplifies configuration
and enables seamless host mobility between VTEPs. To implement anycast gateways:

1. Use the same MAC address for each L2VNI across all VTEPs in the cluster
2. Add a local FDB entry to ensure packets destined to the anycast MAC don't
   traverse the overlay

Here's how to configure L2VNIs with anycast gateways:

.. code-block:: shell

   # Create a macvlan device from L2VNI to serve as anycast gateway
   ip link add vlan10agw link vlan10 type macvlan mode private
   # Example for L2VNI 110 with anycast MAC aa:bb:cc:dd:ee:ff
   ip link set vlan10agw addr aa:bb:cc:dd:ee:ff  # same MAC on all VTEPs
   ip addr add 10.0.10.1/24 dev vlan10agw
   ip addr add 2001:db8:0:10::1/64 dev vlan10agw

   # You may set unique address(es) on the L2VNI if it needs to be reachable in the overlay
   ip addr add 10.0.0.10/32 dev vlan10
   
   # Critical: add local FDB entry to prevent anycast MAC from going over overlay
   bridge fdb add aa:bb:cc:dd:ee:ff dev br0 self local
   
   ip link set vlan10agw up

Repeat this pattern for all L2VNIs using anycast gateways. The key differences
from the non-anycast configuration are:

* For each L2VNI, create a macvlan device which uses the same MAC address across all VTEPs
* Each VTEP must have a local FDB entry for the anycast MAC
* No risk of duplicate address detection (DAD) issues

This approach is recommended for most EVPN deployments as it simplifies
configuration management and improves host mobility.

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
