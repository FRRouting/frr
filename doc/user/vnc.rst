.. _VNC_and_VNC-GW:

**************
VNC and VNC-GW
**************

This chapter describes how to use
Virtual Network Control (@acronym{VNC}) services,
including Network Virtualization Authority (@acronym{NVA}) and 
VNC Gateway (@acronym{VNC-GW}) functions.
Background information on NVAs, 
Network Virtualization Edges (@acronym{NVE}s), underlay networks (@acronym{UN}s),
and virtual networks (@acronym{VN}s) is available from the  
`https://datatracker.ietf.org/wg/nvo3,IETF Network Virtualization Overlays (@acronym{NVO3 <https://datatracker.ietf.org/wg/nvo3,IETF Network Virtualization Overlays (@acronym{NVO3>`_) Working Group}.
VNC Gateways (@acronym{VNC-GW}s) support the import/export of routing
information between VNC and customer edge routers (@acronym{CE}s)
operating within a VN.  Both IP/Layer 3 (L3) VNs, and IP with
Ethernet/Layer 2 (L2) VNs are supported.

BGP, with IP VPNs and Tunnel Encapsulation, is used to distribute VN
information between NVAs. BGP based IP VPN support is defined in
:rfc:`4364`, and
@cite{RFC4659, BGP-MPLS IP Virtual Private Network (VPN) Extension for
IPv6 VPN }.  Both the Encapsulation Subsequent Address Family Identifier
(SAFI) and the Tunnel Encapsulation Attribute, @cite{RFC5512, The BGP
Encapsulation Subsequent Address Family Identifier (SAFI) and the BGP
Tunnel Encapsulation Attribute}, are supported.

The protocol that is used to communicate routing and Ethernet / Layer 2
(L2) forwarding information between NVAs and NVEs is referred to as the
Remote Forwarder Protocol (RFP). `OpenFlow` is an example
RFP.  Specific RFP implementations may choose to implement either a
`hard-state` or `soft-state` prefix and address registration
model.  To support a `soft-state` refresh model, a `lifetime`
in seconds is associated with all registrations and responses.

The chapter also provides sample configurations for basic example scenarios.

.. _Configuring_VNC:

Configuring VNC
===============

Virtual Network Control (@acronym{VNC}) service configuration commands
appear in the `router bgp` section of the BGPD configuration file
(:ref:`BGP_Configuration_Examples`). The commands are broken down into
the following areas:

`General VNC` configuration applies to general VNC operation and is
primarily used to control the method used to advertise tunnel
information.  

`Remote Forwarder Protocol (RFP)` configuration relates to the
protocol used between NVAs and NVEs.  

`VNC Defaults` provides default parameters for registered NVEs.

`VNC NVE Group` provides for configuration of a specific set of 
registered NVEs and overrides default parameters.

`Redistribution` and `Export` control VNC-GW operation, i.e.,
the  import/export of routing
information between VNC and customer edge routers (@acronym{CE}s)
operating within a VN.

.. _General_VNC_Configuration:

General VNC Configuration
-------------------------

.. index:: {VNC} {vnc advertise-un-method encap-safi|encap-attr} {}

{VNC} {vnc advertise-un-method encap-safi|encap-attr} {}
  Advertise NVE underlay-network IP addresses using the encapsulation SAFI
  (`encap-safi`) or the UN address sub-TLV of the Tunnel Encapsulation attribute
  (`encap-attr`). When `encap-safi` is used, neighbors under 
  `address-family encap` and/or `address-family encapv6` must be
  configured.  The default is `encap-attr`. 

.. _RFP_Related_Configuration:

RFP Related Configuration
-------------------------

The protocol that is used to communicate routing and Ethernet / L2
forwarding information between NVAs and NVEs is referred to as the
Remote Forwarder Protocol (RFP).  Currently, only a simple example RFP
is included in FRR.  Developers may use this example as a starting
point to integrate FRR with an RFP of their choosing, e.g.,
`OpenFlow`.  The example code includes the following sample
configuration: 

.. index:: {RFP} {rfp example-config-value `VALUE`} 

{RFP} {rfp example-config-value `VALUE`}
  This is a simple example configuration parameter included as part of the
  RFP example code.  `VALUE` must be in the range of 0 to 4294967295.

.. _VNC_Defaults_Configuration:

VNC Defaults Configuration
--------------------------

The VNC Defaults section allows the user to specify default values for
configuration parameters for all registered NVEs.
Default values are overridden by :ref:`VNC_NVE_Group_Configuration`. 

.. index:: {VNC} {vnc defaults} {}

{VNC} {vnc defaults} {}
  Enter VNC configuration mode for specifying VNC default behaviors.  Use
  `exit-vnc` to leave VNC configuration mode.  `vnc defaults` is optional.

::

    vnc defaults
      ... various VNC defaults
    exit-vnc
    

These are the statements that can appear between `vnc defaults`
and `exit-vnc`.

.. index:: {VNC} {rt import `rt-list`} {}

{VNC} {rt import `rt-list`} {}
.. index:: {VNC} {rt export `rt-list`} {}

{VNC} {rt export `rt-list`} {}
.. index:: {VNC} {rt both `rt-list`} {}

{VNC} {rt both `rt-list`} {}
      Specify default route target import and export lists.  `rt-list` is a
      space-separated list of route targets, each element of which is
      in one of the following forms:


`IPv4-address`:`two-byte-integer`

`four-byte-autonomous-system-number`:`two-byte-integer`

`two-byte-autonomous-system-number`:`four-byte-integer`

      If no default import RT list is specified, then the default import RT
      list is empty.
      If no default export RT list is specified, then the default export RT
      list is empty.

      A complete definition of these parameters is
      given below (:ref:`VNC_NVE_Group_Configuration`).

.. index:: {VNC} {rd `route-distinguisher`}

{VNC} {rd `route-distinguisher`}
      Specify the default route distinguisher (RD) for routes advertised via BGP
      VPNs.  The route distinguisher must be in one of four forms:


`IPv4-address`:`two-byte-integer`

`four-byte-autonomous-system-number`:`two-byte-integer`

`two-byte-autonomous-system-number`:`four-byte-integer`

auto:vn:`two-byte-integer`

      If RD is specified in the defaults section, the default RD
      value is `two-byte-autonomous-system-number=0`:`four-byte-integer=0`.

      A complete definition of this parameter is
      given below (:ref:`VNC_NVE_Group_Configuration`).

.. index:: {VNC} {l2rd `nve-id-value`}

{VNC} {l2rd `nve-id-value`}
      Set the value used to distinguish NVEs connected to the same logical
      Ethernet segment (i.e., L2VPN).

      A complete definition of this parameter is
      given below (:ref:`VNC_NVE_Group_Configuration`).

.. index:: {VNC} {response-lifetime `lifetime`|infinite} {}

{VNC} {response-lifetime `lifetime`|infinite} {}
      Specify the default lifetime to be included in RFP
      response messages sent to NVEs.

      A complete definition of this parameter is
      given below (:ref:`VNC_NVE_Group_Configuration`).

.. index:: {VNC} {export bgp|zebra route-map MAP-NAME}

{VNC} {export bgp|zebra route-map MAP-NAME}
      Specify that the named route-map should be applied to routes
      being exported to bgp or zebra.

.. index:: {VNC} {export bgp|zebra no route-map}

{VNC} {export bgp|zebra no route-map}
      Specify that no route-map should be applied to routes
      being exported to bgp or zebra.

.. index:: {VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}

{VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}
      Specify that the named prefix-list filter should be applied to
      routes being exported to bgp or zebra.
      Prefix-lists for ipv4 and ipv6 are independent of each other.

.. index:: {VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}

{VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}
      Specify that no prefix-list filter should be applied to
      routes being exported to bgp or zebra.

.. index:: {VNC} {exit-vnc} {}

{VNC} {exit-vnc} {}
      Exit VNC configuration mode.

.. _VNC_NVE_Group_Configuration:

VNC NVE Group Configuration
---------------------------

A NVE Group corresponds to a specific set of NVEs.  A Client NVE is
assigned to an NVE Group based on whether there is a match for either
its virtual or underlay network address against the VN and/or UN address
prefixes specified in the NVE Group definition.  When an NVE Group
definition specifies both VN and UN address prefixes, then an NVE must
match both prefixes in order to be assigned to the NVE Group.  In the
event that multiple NVE Groups match based on VN and/or UN addresses,
the NVE is assigned to the first NVE Group listed in the configuration.  
If an NVE is not assigned to an NVE Group, its messages will be ignored.

Configuration values specified for an NVE group apply to all
member NVEs and override configuration values specified in the VNC
Defaults section.

@strong{At least one `nve-group` is mandatory for useful VNC
operation.}

.. index:: {VNC} {vnc nve-group `name`} {}

{VNC} {vnc nve-group `name`} {}
  Enter VNC configuration mode for defining the NVE group `name`.  
  Use `exit` or `exit-vnc` to exit group configuration mode.

::

    vnc nve-group group1
      ... configuration commands
    exit-vnc
    

.. index:: {VNC} {no vnc nve-group `name`} {}

{VNC} {no vnc nve-group `name`} {}
  Delete the NVE group named `name`.

The following statements are valid in an NVE group definition:

.. index:: {VNC} {l2rd `nve-id-value`}

{VNC} {l2rd `nve-id-value`}
  Set the value used to distinguish NVEs connected to the same physical
  Ethernet segment (i.e., at the same location)@footnote{The nve-id is
  carried in the route
  distinguisher.  It is the second octet of the eight-octet route
  distinguisher generated for Ethernet / L2 advertisements.
  The first octet is a constant 0xFF, and the third through eighth
  octets are set to the L2 ethernet address being advertised.}

  The nve-id subfield may be specified as either a literal value
  in the range 1-255, or it may be specified as `auto:vn`, which
  means to use the least-significant octet of the originating
  NVE's VN address.

.. index:: {VNC} {prefix vn|un A.B.C.D/M|X:X::X:X/M} {}

{VNC} {prefix vn|un A.B.C.D/M|X:X::X:X/M} {}
  .. _prefix:

  Specify the matching prefix for this NVE group by either virtual-network address
  (`vn`) or underlay-network address (`un`). Either or both virtual-network
  and underlay-network prefixes may be specified.  Subsequent virtual-network or
  underlay-network values within a `vnc nve-group` `exit-vnc`
  block override their respective previous values.

  These prefixes are used only for determining assignments of NVEs
  to NVE Groups.

.. index:: {VNC} {rd `route-distinguisher`}

{VNC} {rd `route-distinguisher`}
  Specify the route distinguisher for routes advertised via BGP
  VPNs.  The route distinguisher must be in one of these forms:


`IPv4-address`:`two-byte-integer`

`four-byte-autonomous-system-number`:`two-byte-integer`

`two-byte-autonomous-system-number`:`four-byte-integer`

auto:vn:`two-byte-integer`

  Routes originated by NVEs in the NVE group will use
  the group's specified `route-distinguisher` when they are
  advertised via BGP. 
  If the `auto` form is specified, it means that a matching NVE has
  its RD set to
  `rd_type=IP=1`:`IPv4-address=VN-address`:`two-byte-integer`,
  for IPv4 VN addresses and
  `rd_type=IP=1`:`IPv4-address=Last-four-bytes-of-VN-address`:`two-byte-integer`,
  for IPv6 VN addresses.

  If the NVE group definition does not specify a `route-distinguisher`,
  then the default `route-distinguisher` is used.
  If neither a group nor a default `route-distinguisher` is
  configured, then the advertised RD is set to
  `two-byte-autonomous-system-number=0`:`four-byte-integer=0`.

.. index:: {VNC} {response-lifetime `lifetime`|infinite} {}

{VNC} {response-lifetime `lifetime`|infinite} {}
  Specify the response lifetime, in seconds, to be included in RFP
  response messages sent to NVEs.  If the value
  'infinite' is given, an infinite lifetime will be used.

  Note that this parameter is not the same as the lifetime supplied by
  NVEs in RFP registration messages. This parameter does not affect
  the lifetime value attached to routes sent by this server via BGP.

  If the NVE group definition does not specify a `response-lifetime`,
  the default `response-lifetime` will be used.
  If neither a group nor a default `response-lifetime` is configured,
  the value 3600 will be used.  The maximum response lifetime is 2147483647.

.. index:: {VNC} {rt export `rt-list`} {}

{VNC} {rt export `rt-list`} {}
.. index:: {VNC} {rt import `rt-list`} {}

{VNC} {rt import `rt-list`} {}
.. index:: {VNC} {rt both `rt-list`} {}

{VNC} {rt both `rt-list`} {}
      Specify route target import and export lists.  `rt-list` is a
      space-separated list of route targets, each element of which is
      in one of the following forms:


`IPv4-address`:`two-byte-integer`

`four-byte-autonomous-system-number`:`two-byte-integer`

`two-byte-autonomous-system-number`:`four-byte-integer`

      The first form, `rt export`, specifies an `export rt-list`.
      The `export rt-list` will be attached to routes originated by
      NVEs in the NVE group when they are advertised via BGP. 
      If the NVE group definition does not specify an `export rt-list`,
      then the default `export rt-list` is used.
      If neither a group nor a default `export rt-list` is configured,
      then no RT list will be sent; in turn, these routes will probably
      not be processed
      by receiving NVAs.

      The second form, `rt import` specifies an `import rt-list`,
      which is a filter for incoming routes.
      In order to be made available to NVEs in the group,
      incoming BGP VPN and @w{ENCAP} @w{SAFI} (when `vnc advertise-un-method encap-safi` is set) routes must have
      RT lists that have at least one route target in common with the
      group's `import rt-list`.

      If the NVE group definition does not specify an import filter,
      then the default `import rt-list` is used.
      If neither a group nor a default `import rt-list` is configured,
      there can be no RT intersections when receiving BGP routes and
      therefore no incoming BGP routes will be processed for the group.

      The third, `rt both`, is a shorthand way of specifying both
      lists simultaneously, and is equivalent to `rt export `rt-list``
      followed by `rt import `rt-list``.

.. index:: {VNC} {export bgp|zebra route-map MAP-NAME}

{VNC} {export bgp|zebra route-map MAP-NAME}
      Specify that the named route-map should be applied to routes
      being exported to bgp or zebra. 
      This paramter is used in conjunction with 
      :ref:`Configuring_Export_of_Routes_to_Other_Routing_Protocols`.
      This item is optional.

.. index:: {VNC} {export bgp|zebra no route-map}

{VNC} {export bgp|zebra no route-map}
      Specify that no route-map should be applied to routes
      being exported to bgp or zebra. 
      This paramter is used in conjunction with 
      :ref:`Configuring_Export_of_Routes_to_Other_Routing_Protocols`.
      This item is optional.

.. index:: {VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}

{VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}
      Specify that the named prefix-list filter should be applied to
      routes being exported to bgp or zebra.
      Prefix-lists for ipv4 and ipv6 are independent of each other. 
      This paramter is used in conjunction with 
      :ref:`Configuring_Export_of_Routes_to_Other_Routing_Protocols`.
      This item is optional.

.. index:: {VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}

{VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}
      Specify that no prefix-list filter should be applied to
      routes being exported to bgp or zebra. 
      This paramter is used in conjunction with 
      :ref:`Configuring_Export_of_Routes_to_Other_Routing_Protocols`.
      This item is optional.

.. _VNC_L2_Group_Configuration:

VNC L2 Group Configuration
--------------------------

The route targets advertised with prefixes and addresses registered by
an NVE are determined based on the NVE's associated VNC NVE Group
Configuration, :ref:`VNC_NVE_Group_Configuration`.  Layer 2 (L2) Groups
are used to override the route targets for an NVE's Ethernet
registrations based on the Logical Network Identifier and label value.
A Logical Network Identifier is used to uniquely identify a logical
Ethernet segment and is conceptually similar to the Ethernet Segment
Identifier defined in :rfc:`7432`.  Both
the Logical Network Identifier and Label are passed to VNC via RFP
prefix and address registration.

Note that a corresponding NVE group configuration must be present, and
that other NVE associated configuration information, notably RD, is
not impacted by L2 Group Configuration.

.. index:: {VNC} {vnc l2-group `name`} {}

{VNC} {vnc l2-group `name`} {}
  Enter VNC configuration mode for defining the L2 group `name`.  
  Use `exit` or `exit-vnc` to exit group configuration mode.

::

    vnc l2-group group1
      ... configuration commands
    exit-vnc
    

.. index:: {VNC} {no vnc l2-group `name`} {}

{VNC} {no vnc l2-group `name`} {}
  Delete the L2 group named `name`.

The following statements are valid in a L2 group definition:

.. index:: {VNC} {logical-network-id `VALUE`}

{VNC} {logical-network-id `VALUE`}
  Define the Logical Network Identifier with a value in the range of
  0-4294967295 that identifies the logical Ethernet segment. 

.. index:: {VNC} {labels `label-list`}

{VNC} {labels `label-list`}
.. index:: {VNC} {no labels `label-list`}

{VNC} {no labels `label-list`}
    Add or remove labels associated with the group.  `label-list` is a
    space separated list of label values in the range of 0-1048575.

.. index:: {VNC} {rt import `rt-target`} {}

{VNC} {rt import `rt-target`} {}
.. index:: {VNC} {rt export `rt-target`} {}

{VNC} {rt export `rt-target`} {}
.. index:: {VNC} {rt both `rt-target`} {}

{VNC} {rt both `rt-target`} {}
        Specify the route target import and export value associated with the
        group. A complete definition of these parameters is given above,
        :ref:`VNC_NVE_Group_Configuration`.

.. _Configuring_Redistribution_of_Routes_from_Other_Routing_Protocols:

Configuring Redistribution of Routes from Other Routing Protocols
-----------------------------------------------------------------

Routes from other protocols (including BGP) can be provided to VNC (both
for RFP and for redistribution via BGP)
from three sources: the zebra kernel routing process;
directly from the main (default) unicast BGP RIB; or directly
from a designated BGP unicast exterior routing RIB instance.

The protocol named in the `vnc redistribute` command indicates
the route source:
`bgp-direct` routes come directly from the main (default)
unicast BGP RIB and are available for RFP and are redistributed via BGP;
`bgp-direct-to-nve-groups` routes come directly from a designated
BGP unicast routing RIB and are made available only to RFP;
and routes from other protocols come from the zebra kernel
routing process.
Note that the zebra process does not need to be active if
only `bgp-direct` or `bgp-direct-to-nve-groups` routes are used.

`zebra` routes
^^^^^^^^^^^^^^

Routes originating from protocols other than BGP must be obtained
via the zebra routing process.
Redistribution of these routes into VNC does not support policy mechanisms
such as prefix-lists or route-maps.

`bgp-direct` routes
^^^^^^^^^^^^^^^^^^^

`bgp-direct` redistribution supports policy via
prefix lists and route-maps. This policy is applied to incoming
original unicast routes before the redistribution translations
(described below) are performed.

Redistribution of `bgp-direct` routes is performed in one of three
possible modes: `plain`, `nve-group`, or `resolve-nve`.
The default mode is `plain`.
These modes indicate the kind of translations applied to routes before
they are added to the VNC RIB.

In `plain` mode, the route's next hop is unchanged and the RD is set
based on the next hop.
For `bgp-direct` redistribution, the following translations are performed:

* 
  The VN address is set to the original unicast route's next hop address.
* 
  The UN address is NOT set. (VN->UN mapping will occur via
  ENCAP route or attribute, based on `vnc advertise-un-method`
  setting, generated by the RFP registration of the actual NVE) 
* 
  The RD is set to as if auto:vn:0 were specified (i.e.,
  `rd_type=IP=1`:`IPv4-address=VN-address`:`two-byte-integer=0`)
* 
  The RT list is included in the extended community list copied from the
  original unicast route (i.e., it must be set in the original unicast route).

In `nve-group` mode, routes are registered with VNC as
if they came from an NVE in the nve-group designated in the
`vnc redistribute nve-group` command. The following
translations are performed:

* 
  The next hop/VN address is set to the VN prefix configured for the
  redistribute nve-group.
* 
  The UN address is set to the UN prefix configured for the
  redistribute nve-group.
* 
  The RD is set to the RD configured for the redistribute nve-group.
* 
  The RT list is set to the RT list configured for the redistribute nve-group.
  If `bgp-direct` routes are being redistributed, 
  any extended communities present in the original unicast route
  will also be included.

In `resolve-nve` mode, the next hop of the original BGP route is
typically the address of an NVE connected router (CE) connected by one or
more NVEs.
Each of the connected NVEs will register, via RFP, a VNC host route
to the CE.
This mode may be though of as a mechanism to proxy RFP registrations
of BGP unicast routes on behalf of registering NVEs.

Multiple copies of the BGP route, one per matching NVE host route, will be
added to VNC.
In other words, for a given BGP unicast route, each instance of a
RFP-registered host route to the unicast route's next hop will result
in an instance of an imported VNC route.
Each such imported VNC route will have a prefix equal to the original
BGP unicast route's prefix, and a next hop equal to the next hop of the
matching RFP-registered host route.
If there is no RFP-registered host route to the next hop of the BGP unicast
route, no corresponding VNC route will be imported.

The following translations are applied:

* 
  The Next Hop is set to the next hop of the NVE route (i.e., the
  VN address of the NVE).

* 
  The extended community list in the new route is set to the 
  union of:

  * 
    Any extended communities in the original BGP route
  * 
    Any extended communities in the NVE route
  * 
    An added route-origin extended community with the next hop of the
    original BGP route
    is added to the new route.
    The value of the local administrator field defaults 5226 but may
    be configured by the user via the `roo-ec-local-admin` parameter.

* 
  The Tunnel Encapsulation attribute is set to the value of the Tunnel
  Encapsulation attribute of the NVE route, if any.


`bgp-direct-to-nve-groups` routes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Unicast routes from the main or a designated instance of BGP
may be redistributed to VNC as bgp-direct-to-nve-groups routes. These
routes are NOT announced via BGP,
but they are made available for local RFP lookup in response to
queries from NVEs.

A non-main/default BGP instance is configured using the
`bgp multiple-instance` and `router bgp AS view NAME`
commands as described elsewhere in this document.

In order for a route in the unicast BGP RIB to be made
available to a querying NVE, there must already be, available to
that NVE, an (interior) VNC route matching the next hop address
of the unicast route.
When the unicast route is provided to the NVE, its next hop 
is replaced by the next hop of the corresponding
NVE. If there are multiple longest-prefix-match VNC routes,
the unicast route will be replicated for each.

There is currently no policy (prefix-list or route-map) support
for `bgp-direct-to-nve-groups` routes.

Redistribution Command Syntax
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. index:: {VNC} {vnc redistribute ipv4|ipv6 bgp|bgp-direct|ipv6 bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static} {}

{VNC} {vnc redistribute ipv4|ipv6 bgp|bgp-direct|ipv6 bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static} {}
.. index:: {VNC} {vnc redistribute ipv4|ipv6 bgp-direct-to-nve-groups view `VIEWNAME`} {}

{VNC} {vnc redistribute ipv4|ipv6 bgp-direct-to-nve-groups view `VIEWNAME`} {}
.. index:: {VNC} {no vnc redistribute ipv4|ipv6 bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static} {}

{VNC} {no vnc redistribute ipv4|ipv6 bgp|bgp-direct|bgp-direct-to-nve-groups|connected|kernel|ospf|rip|static} {}
      Import (or do not import) prefixes from another routing
      protocols. Specify both the address family to import (`ipv4` or
      `ipv6`) and the protocol (`bgp`, `bgp-direct`,
      `bgp-direct-to-nve-groups`, `connected`,
      `kernel`, `ospf`, `rip`, or `static`).  Repeat
      this statement as needed for each combination of address family and
      routing protocol.
      Prefixes from protocol `bgp-direct` are imported from unicast BGP
      in the same bgpd process.
      Prefixes from all other protocols (including `bgp`) are imported
      via the `zebra` kernel routing process.

.. index:: {VNC} {vnc redistribute mode plain|nve-group|resolve-nve}

{VNC} {vnc redistribute mode plain|nve-group|resolve-nve}
      Redistribute routes from other protocols into VNC using the
      specified mode.
      Not all combinations of modes and protocols are supported.

.. index:: {VNC} {vnc redistribute nve-group `group-name`} {}

{VNC} {vnc redistribute nve-group `group-name`} {}
.. index:: {VNC} {no vnc redistribute nve-group `group-name`} {}

{VNC} {no vnc redistribute nve-group `group-name`} {}
        When using `nve-group` mode,
        assign (or do not assign) the NVE group `group-name` to routes
        redistributed from another routing protocol.  `group-name`
        must be configured using `vnc nve-group`.

        The VN and UN prefixes of the nve-group must both be configured,
        and each prefix must be specified as a full-length (/32 for IPv4,
        /128 for IPv6) prefix.

.. index:: {VNC} {vnc redistribute lifetime `lifetime`|infinite} {}

{VNC} {vnc redistribute lifetime `lifetime`|infinite} {}
        Assign a registration lifetime, either `lifetime` seconds or
        `infinite`, to prefixes redistributed from other routing
        protocols as if they had been received via RFP registration messages
        from an NVE.  `lifetime` can be any integer between 1 and
        4294967295, inclusive. 

.. index:: {VNC} {vnc redistribute resolve-nve roo-ec-local-admin `0-65536`}

{VNC} {vnc redistribute resolve-nve roo-ec-local-admin `0-65536`}
        Assign a value to the local-administrator subfield used in the
        Route Origin extended community that is assigned to routes exported 
        under the `resolve-nve` mode. The default value is `5226`.

      The following four `prefix-list` and `route-map` commands
      may be specified in the context of an nve-group or not.
      If they are specified in the context of an nve-group, they
      apply only if the redistribution mode is `nve-group`,
      and then only for routes being redistributed from
      `bgp-direct`.
      If they are specified outside the context of an nve-group, then
      they apply only for redistribution modes `plain` and `resolve-nve`,
      and then only for routes being redistributed from `bgp-direct`.

.. index:: {VNC} {vnc redistribute bgp-direct (ipv4|ipv6) prefix-list `LIST-NAME`}

{VNC} {vnc redistribute bgp-direct (ipv4|ipv6) prefix-list `LIST-NAME`}
        When redistributing `bgp-direct` routes,
        specifies that the named prefix-list should be applied.

.. index:: {VNC} {vnc redistribute bgp-direct no (ipv4|ipv6) prefix-list}

{VNC} {vnc redistribute bgp-direct no (ipv4|ipv6) prefix-list}
        When redistributing `bgp-direct` routes,
        specifies that no prefix-list should be applied.

.. index:: {VNC} {vnc redistribute bgp-direct route-map  `MAP-NAME`}

{VNC} {vnc redistribute bgp-direct route-map  `MAP-NAME`}
        When redistributing `bgp-direct` routes,
        specifies that the named route-map should be applied.

.. index:: {VNC} {vnc redistribute bgp-direct no route-map}

{VNC} {vnc redistribute bgp-direct no route-map}
        When redistributing `bgp-direct` routes,
        specifies that no route-map should be applied.

.. _Configuring_Export_of_Routes_to_Other_Routing_Protocols:

Configuring Export of Routes to Other Routing Protocols
-------------------------------------------------------

Routes from VNC (both for RFP and for redistribution via BGP) can be
provided to other protocols, either via zebra or directly to BGP.

It is important to note that when exporting routes to other protocols,
the downstream protocol must also be configured to import the routes.
For example, when VNC routes are exported to unicast BGP, the BGP
configuration must include a corresponding `redistribute vnc-direct`
statement.

.. index:: {VNC} {export bgp|zebra mode none|group-nve|registering-nve|ce}

{VNC} {export bgp|zebra mode none|group-nve|registering-nve|ce}
  Specify how routes should be exported to bgp or zebra.
  If the mode is `none`, routes are not exported.
  If the mode is `group-nve`, routes are exported according
  to nve-group or vrf-policy group configuration (:ref:`VNC_NVE_Group_Configuration`): if a group is configured to
  allow export, then each prefix visible to the group is exported
  with next hops set to the currently-registered NVEs.
  If the mode is `registering-nve`, then all VNC routes are
  exported with their original next hops.
  If the mode is `ce`, only VNC routes that have an NVE connected CE Router
  encoded in a Route Origin Extended Community are exported.
  This extended community must have an administrative value that
  matches the configured `roo-ec-local-admin` value.
  The next hop of the exported route is set to the encoded
  NVE connected CE Router.

  The default for both bgp and zebra is mode `none`.

.. index:: {VNC} {vnc export bgp|zebra group-nve group `group-name`}

{VNC} {vnc export bgp|zebra group-nve group `group-name`}
.. index:: {VNC} {vnc export bgp|zebra group-nve no group `group-name`}

{VNC} {vnc export bgp|zebra group-nve no group `group-name`}
    When export mode is `group-nve`,
    export (or do not export) prefixes from the specified nve-group or
    vrf-policy group
    to unicast BGP or to zebra.
    Repeat this statement as needed for each nve-group to be exported.
    Each VNC prefix that is exported will result in N exported routes to the
    prefix, each with a next hop corresponding to one of the N NVEs currently
    associated with the nve-group.

.. index:: {VNC} export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME

{VNC} export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME
    When export mode is `ce` or `registering-nve`,
    specifies that the named prefix-list should be applied to routes
    being exported to bgp or zebra.
    Prefix-lists for ipv4 and ipv6 are independent of each other.

.. index:: {VNC} export bgp|zebra no ipv4|ipv6 prefix-list

{VNC} export bgp|zebra no ipv4|ipv6 prefix-list
    When export mode is `ce` or `registering-nve`,
    specifies that no prefix-list should be applied to routes
    being exported to bgp or zebra.

.. index:: {VNC} export bgp|zebra route-map MAP-NAME

{VNC} export bgp|zebra route-map MAP-NAME
    When export mode is `ce` or `registering-nve`,
    specifies that the named route-map should be applied to routes
    being exported to bgp or zebra.

.. index:: {VNC} export bgp|zebra no route-map

{VNC} export bgp|zebra no route-map
    When export mode is `ce` or `registering-nve`,
    specifies that no route-map should be applied to routes
    being exported to bgp or zebra.

  When the export mode is `group-nve`, policy for exported
  routes is specified per-NVE-group or vrf-policy group inside a `nve-group` `RFG-NAME` block
  via the following commands(:ref:`VNC_NVE_Group_Configuration`):

.. index:: {VNC} {export bgp|zebra route-map MAP-NAME}

{VNC} {export bgp|zebra route-map MAP-NAME}
    This command is valid inside a `nve-group` `RFG-NAME` block.
    It specifies that the named route-map should be applied to routes
    being exported to bgp or zebra.

.. index:: {VNC} {export bgp|zebra no route-map}

{VNC} {export bgp|zebra no route-map}
    This command is valid inside a `nve-group` `RFG-NAME` block.
    It specifies that no route-map should be applied to routes
    being exported to bgp or zebra.

.. index:: {VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}

{VNC} {export bgp|zebra ipv4|ipv6 prefix-list LIST-NAME}
    This command is valid inside a `nve-group` `RFG-NAME` block.
    It specifies that the named prefix-list filter should be applied to
    routes being exported to bgp or zebra.
    Prefix-lists for ipv4 and ipv6 are independent of each other.

.. index:: {VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}

{VNC} {export bgp|zebra no ipv4|ipv6 prefix-list}
    This command is valid inside a `nve-group` `RFG-NAME` block.
    It specifies that no prefix-list filter should be applied to
    routes being exported to bgp or zebra.

.. _Manual_Address_Control:

Manual Address Control
======================

The commands in this section can be used to augment normal dynamic VNC.
The `add vnc` commands can be used to manually add IP prefix or
Ethernet MAC address forwarding information.  The `clear vnc`
commands can be used to remove manually and dynamically added
information.

.. index:: {Command} {add vnc prefix (A.B.C.D/M|X:X::X:X/M) vn (A.B.C.D|X:X::X:X) un (A.B.C.D|X:X::X:X) [cost (0-255)] [lifetime (infinite|(1-4294967295))] [local-next-hop (A.B.C.D|X:X::X:X) [local-cost (0-255)]]} {}

{Command} {add vnc prefix (A.B.C.D/M|X:X::X:X/M) vn (A.B.C.D|X:X::X:X) un (A.B.C.D|X:X::X:X) [cost (0-255)] [lifetime (infinite|(1-4294967295))] [local-next-hop (A.B.C.D|X:X::X:X) [local-cost (0-255)]]} {}
  Register an IP prefix on behalf of the NVE identified by the VN and UN
  addresses.  The `cost` parameter provides the administrative
  preference of the forwarding information for remote advertisement.  If
  omitted, it defaults to 255 (lowest preference).  The `lifetime`
  parameter identifies the period, in seconds, that the information
  remains valid.  If omitted, it defaults to `infinite`.  The optional
  `local-next-hop` parameter is used to configure a nexthop to be
  used by an NVE to reach the prefix via a locally connected CE router.
  This information remains local to the NVA, i.e., not passed to other
  NVAs, and is only passed to registered NVEs. When specified, it is also
  possible to provide a `local-cost` parameter to provide a
  forwarding preference.  If omitted, it defaults to 255 (lowest
  preference).

.. index:: {Command} {add vnc mac xx:xx:xx:xx:xx:xx virtual-network-identifier (1-4294967295) vn (A.B.C.D|X:X::X:X) un (A.B.C.D|X:X::X:X) [prefix (A.B.C.D/M|X:X::X:X/M)] [cost (0-255)] [lifetime (infinite|(1-4294967295))]} {}

{Command} {add vnc mac xx:xx:xx:xx:xx:xx virtual-network-identifier (1-4294967295) vn (A.B.C.D|X:X::X:X) un (A.B.C.D|X:X::X:X) [prefix (A.B.C.D/M|X:X::X:X/M)] [cost (0-255)] [lifetime (infinite|(1-4294967295))]} {}
  Register a MAC address for a logical Ethernet (L2VPN) on behalf of the
  NVE identified by the VN and UN addresses.
  The optional `prefix` parameter is to support enable IP address
  mediation for the given prefix.   The `cost` parameter provides the administrative
  preference of the forwarding information.  If omitted, it defaults to
  255.  The `lifetime` parameter identifies the period, in seconds,
  that the information remains valid.  If omitted, it defaults to
  `infinite`. 

.. index:: {Command} {clear vnc prefix (*|A.B.C.D/M|X:X::X:X/M) (*|[(vn|un) (A.B.C.D|X:X::X:X|*) [(un|vn) (A.B.C.D|X:X::X:X|*)] [mac xx:xx:xx:xx:xx:xx] [local-next-hop (A.B.C.D|X:X::X:X)])} {}

{Command} {clear vnc prefix (*|A.B.C.D/M|X:X::X:X/M) (*|[(vn|un) (A.B.C.D|X:X::X:X|*) [(un|vn) (A.B.C.D|X:X::X:X|*)] [mac xx:xx:xx:xx:xx:xx] [local-next-hop (A.B.C.D|X:X::X:X)])} {}
  Delete the information identified by prefix, VN address, and UN address.
  Any or all of these parameters may be wilcarded to (potentially) match
  more than one registration.
  The optional `mac` parameter specifies a layer-2 MAC address
  that must match the registration(s) to be deleted.
  The optional `local-next-hop` parameter is used to
  delete specific local nexthop information.

.. index:: {Command} {clear vnc mac (*|xx:xx:xx:xx:xx:xx) virtual-network-identifier (*|(1-4294967295)) (*|[(vn|un) (A.B.C.D|X:X::X:X|*) [(un|vn) (A.B.C.D|X:X::X:X|*)] [prefix (*|A.B.C.D/M|X:X::X:X/M)])} {}

{Command} {clear vnc mac (*|xx:xx:xx:xx:xx:xx) virtual-network-identifier (*|(1-4294967295)) (*|[(vn|un) (A.B.C.D|X:X::X:X|*) [(un|vn) (A.B.C.D|X:X::X:X|*)] [prefix (*|A.B.C.D/M|X:X::X:X/M)])} {}
  Delete mac forwarding information.
  Any or all of these parameters may be wilcarded to (potentially) match
  more than one registration.
  The default value for the `prefix` parameter is the wildcard value `*`.

.. index:: {Command} {clear vnc nve (*|((vn|un) (A.B.C.D|X:X::X:X) [(un|vn) (A.B.C.D|X:X::X:X)])) } {}

{Command} {clear vnc nve (*|((vn|un) (A.B.C.D|X:X::X:X) [(un|vn) (A.B.C.D|X:X::X:X)])) } {}
  Delete prefixes associated with the NVE specified by the given VN and UN
  addresses.
  It is permissible to specify only one of VN or UN, in which case
  any matching registration will be deleted.
  It is also permissible to specify `*` in lieu of any VN or UN
  address, in which case all registrations will match.

.. _Other_VNC-Related_Commands:

Other VNC-Related Commands
==========================

Note: VNC-Related configuration can be obtained via the `show running-configuration` command when in `enable` mode.

The following commands are used to clear and display 
Virtual Network Control related information:

.. index:: {COMMAND} {clear vnc counters} {}

{COMMAND} {clear vnc counters} {}
  Reset the counter values stored by the NVA. Counter
  values can be seen using the `show vnc` commands listed above. This
  command is only available in `enable` mode.

.. index:: {Command} {show vnc summary} {}

{Command} {show vnc summary} {}
  Print counter values and other general information 
  about the NVA. Counter values can be reset 
  using the `clear vnc counters` command listed below.

.. index:: {Command} {show vnc nves} {}

{Command} {show vnc nves} {}
.. index:: {Command} {show vnc nves vn|un `address`} {}

{Command} {show vnc nves vn|un `address`} {}
    Display the NVA's current clients. Specifying `address`
    limits the output to the NVEs whose addresses match `address`.
    The time since the NVA last communicated with the NVE, per-NVE
    summary counters and each NVE's addresses will be displayed.

.. index:: {Command} {show vnc queries} {}

{Command} {show vnc queries} {}
.. index:: {Command} {show vnc queries `prefix`} {}

{Command} {show vnc queries `prefix`} {}
      Display active Query information.  Queries remain valid for the default
      Response Lifetime (:ref:`VNC_Defaults_Configuration`) or NVE-group
      Response Lifetime (:ref:`VNC_NVE_Group_Configuration`).  Specifying
      `prefix` limits the output to Query Targets that fall within
      `prefix`.

      Query information is provided for each querying NVE, and includes the
      Query Target and the time remaining before the information is removed.

.. index:: {Command} {show vnc registrations [all|local|remote|holddown|imported]} {}

{Command} {show vnc registrations [all|local|remote|holddown|imported]} {}
.. index:: {Command} {show vnc registrations [all|local|remote|holddown|imported] `prefix`} {}

{Command} {show vnc registrations [all|local|remote|holddown|imported] `prefix`} {}
        Display local, remote, holddown, and/or imported registration information.
        Local registrations are routes received via RFP, which are present in the
        NVA Registrations Cache.
        Remote registrations are routes received via BGP (VPN SAFIs), which
        are present in the NVE-group import tables.
        Holddown registrations are local and remote routes that have been
        withdrawn but whose holddown timeouts have not yet elapsed.
        Imported information represents routes that are imported into NVA and
        are made available to querying NVEs.  Depending on configuration,
        imported routes may also be advertised via BGP.
        Specifying `prefix` limits the output to the registered prefixes that
        fall within `prefix`.

        Registration information includes the registered prefix, the registering
        NVE addresses, the registered administrative cost, the registration
        lifetime and the time since the information was registered or, in the
        case of Holddown registrations, the amount of time remaining before the
        information is removed.

.. index:: {Command} {show vnc responses [active|removed]} {}

{Command} {show vnc responses [active|removed]} {}
.. index:: {Command} {show vnc responses [active|removed] `prefix`} {}

{Command} {show vnc responses [active|removed] `prefix`} {}
          Display all, active and/or removed response information which are
          present in the NVA Responses Cache. Responses remain valid for the
          default Response Lifetime (:ref:`VNC_Defaults_Configuration`) or
          NVE-group Response Lifetime (:ref:`VNC_NVE_Group_Configuration`.)
          When Removal Responses are enabled (:ref:`General_VNC_Configuration`),
          such responses are listed for the Response Lifetime.  Specifying
          `prefix` limits the output to the addresses that fall within
          `prefix`.

          Response information is provided for each querying NVE, and includes
          the response prefix, the prefix-associated registering NVE addresses,
          the administrative cost, the provided response lifetime and the time
          remaining before the information is to be removed or will become inactive.

.. index:: {Command} {show memory vnc} {}

{Command} {show memory vnc} {}
          Print the number of memory items allocated by the NVA.

.. _Example_VNC_and_VNC-GW_Configurations:

Example VNC and VNC-GW Configurations
=====================================


