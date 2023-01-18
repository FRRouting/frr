.. _bgp-link-state:

BGP Link-State
==============

Overview
--------

BGP Link-State (BGP-LS) is an extension of the BGP protocol designed to
redistribute information from an IGP database to a remote controller (most
likely a Path Computation Element - PCE). BGP-LS does nothing more than
transport IGP information. Therefore, it cannot be used to replace a Link State
routing protocol like OSPF and IS-IS.

Historically, the only way to get a network controller to collect an IGP
database was to have it participate in the IGP itself as if it were a standard
router. Since the controllers were usually located far from the IGP area,
tunnels such as GRE were used to connect the controllers to the IGP area. This
method was so impractical that an alternative solution was imagined: using the
the already deployed inter-domain BGP protocol to redistribute the various IGP
databases.

BGP Link-State as defined in `RFC7752
<https://www.rfc-editor.org/rfc/rfc7752.html>`_ uses the AFI 16388 and SAFI 71.
The BGP Link-State pseudo-prefixes distributed by the `NLRI (Network Layer
Reachability Information)` uniquely define the following
IGP information:

- Nodes
- Link
- IPv4 Prefix
- IPv6 Prefix

They are called descriptors. In addition, a new type of BGP Attributes called
"BGP-LS attributes" carries the other information related to a descriptor.

NLRI and attribute information for BGP-LS is organized using the TLV format
already used by IS-IS LSPs and OSPF opaque LSAs. The `list of TLV code points
<https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#node-descriptor-link-descriptor-prefix-descriptor-attribute-tlv>`_
is maintained by IANA

Current implementation
----------------------

The current version can participate in BGP Link-State AFI / SAFI with
third-party routers and forward the BGP Link-State descriptors and attributes to
other routers. However, it can not generate BGP Link-State data from OSPF and
IS-IS.

IANA maintains a `registry of BGP-LS NRLI descriptor types
<https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml#nlri-types>`_.
Only the following RFC7752 NRLI types are supported by the current version:

- Nodes
- Link
- IPv4 Prefix
- IPv6 Prefix

The BGP-LS attribute TLVs for these NLRI types are transmitted as is to other
routers which means that all the current and future version are already
supported.

Show commands
-------------

The following configuration enables the negotiation of the link-state AFI / SAFI
with the 192.0.2.2 eBGP peer.

.. code-block:: frr

	router bgp 65003
	 neighbor 192.0.2.2 remote-as 65002
	 neighbor 192.0.2.2 update-source 192.0.2.3
	 !
	 address-family link-state link-state
	  neighbor 192.0.2.2 activate
	  neighbor 192.0.2.2 route-map PERMIT-ALL in
	  neighbor 192.0.2.2 route-map PERMIT-ALL out
	 exit-address-family
	exit
	!
	route-map PERMIT-ALL permit 1

The BGP-LS table can be displayed.

.. code-block:: frr

	frr# show bgp link-state link-state
	BGP table version is 8, local router ID is 192.0.2.3, vrf id 0
	Default local pref 100, local AS 65003
	    Network          Next Hop            Metric LocPrf Weight Path
	 *> Node OSPFv2 ID:0x20 Local{AS:65001 ID:0 Area:0 Rtr:10.10.10.10:1.1.1.1}/48
	                                           0 65002 65001 i
	 *> IPv4-Prefix OSPFv2 ID:0x20 Local{AS:65001 ID:0 Area:0 Rtr:10.10.10.10:1.1.1.1} Prefix{IPv4:89.10.11.0/24}/64
	                                           0 65002 65001 i
	 *> IPv6-Prefix ISIS-L2 ID:0x20 Local{AS:65001 ID:0 Rtr:0000.0000.1003.00} Prefix{IPv6:12:12::12:12/128 MT:2}/74
	                                           0 65002 65001 i
	 *> IPv6-Prefix OSPFv3 ID:0x20 Local{AS:65001 ID:0 Area:0 Rtr:10.10.10.10} Prefix{OSPF-Route-Type:1 IPv6:12:12::12:12/128 MT:2}/74
	                                           0 65002 65001 i
	 *> Node OSPFv2 ID:0x20 Local{AS:65001 ID:0 Area:0 Rtr:10.10.10.10}/48
	                                           0 65002 65001 i
	 *> Node ISIS-L1 ID:0x20 Local{AS:65001 ID:0 Rtr:0000.0000.1003.00}/48
	                                           0 65002 65001 i
	 *> Link ISIS-L1 ID:0x20 Local{AS:65001 ID:0 Rtr:0000.0000.1001} Remote{AS:65001 ID:0 Rtr:0000.0000.1000} Link{IPv4:10.1.0.1 Neigh-IPv4:10.1.0.2 IPv6:2001::1 Neigh-IPv6:2001::2 MT:0,2}/132
	                                           0 65002 65001 i


