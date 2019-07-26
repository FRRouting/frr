IS-IS Segment Routing
=====================

This is an EXPERIMENTAL support of draft
`draft-ietf-isis-segment-routing-extensions-25`.
DON'T use it for production network.

Supported Features
------------------

* Automatic computation of Primary and Backup Adjacency SID
* SRGB configuration
* Prefix configuration for Node SID with optional NO-PHP and EXPLICIT-NULL flag
  (Linux kernel support both mode)
* Support of both IPv4 and IPv6 with ECMP
* Node MSD configuration (with Linux Kernel >= 4.10 a maximum of 32 labels
  could be stack)
* Automatic provisioning of MPLS table
* Static route configuration with label stack up to 32 labels

Interoperability
----------------

* Tested on various topology including point-to-point and LAN interfaces
  in a mix of Free Range Routing instance and Cisco IOS-XR 6.0.x
* Check ISIS LSP conformity with latest wireshark

Implementation overview
-----------------------

History
^^^^^^^

First code about Segment Routing was introduced in FRR for OSPF protocol in
Feb’2018. Then, development of Segment Routing for IS-IS start end of 2018,
trying to share the same code base with OSPF version (see ospf-sr.rst document).
But no real progress during several months. New requests from different persons
come in April 2019 telling that it is time to restart IS-IS-SR coding.
But, IS-IS code has evolved during this period that impose to rewrite part of
the original code, in particular the Traffic Engineering stuff.

Principles
^^^^^^^^^^

This code try to share the same principles as OSPF-SR, with in mind to possibly
share some part of the code (lib/mpls_sr.[c,h] ?) in library. If this seems
feasible, the few amount of code is not in favor of that, living 2 differents
code based, but sharing same spirit and Segment Routing DataBase structure.
Some enhancement has been added for ECMP and improve performance compared to the
OSPF version.

The code is archectured to use ZAPI interface as less as possible to avoid too
many sollicitation for performance. It avoids to update MPLS entry when it is
not necessary (no modification) and don’t remove MPLS entry if it breaks data
plane to avoid unnecessary packets loss if it is not needed. E.g. in ECMP,
the code remove only the MPLS entry that disappears instead of removing all
entries and then adding remaining valid ones.

The code parse IS-IS LSP when it arrives instead of parsing the whole LSPDB each
time a modification take place for better performance, update MPLS entry when
SPF change a nexthop for a prefix which is attached to a Segment Prefix. It also
prepare future development by keeping in SRDB all received information E.g.
Adjacency SID for TI-LFA. It is also possibile to add new algorithm to compute
different nexthop for Flexible Algorithm.

Segment Routing main functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Add Segment Routing subTLVs in advertised LSP
  Adjacency SID as subTLV of TLV 22 with other Extended link parameters (i.e. TE)
  Prefix SID as subTLV of TLV 135 for IPv4 Prefix and of TLV 235 for IPv6 Prefix
  SRGB, Algorithms & MSD as subTLV of TLV 242 - Router Capabilities 

* Create MPLS entries for its own configuration
  Adjacency (P2P) & LAN Adjacency (Broadcast) per interface when IS-IS
  neighbor is up and Prefix SID per definition found in isisd.conf. Note that
  pnly Prefix attached to loopback interface are supported and advertised as
  Node SID

* When an LSP is received
  Parse Segment Routing information and store them into SR Data Base, then Add
  / Remove MPLS entry for each Prefix SID taking into account flags (PHP,
  Explicit NULL …) and SRGB, Ignore Adjacency (global Adjacency are not
  supported) and Update impacted MPLS entries when a direct neighbor router
  change its SRGB

* When SPF update table
  Update corresponding MPLS entries if there is a SID associated to the prefix,
  avoiding disrupting data plane when removing a single entry for ECMP. This
  modification is triggered only when nexthop change

New ZAPI message
----------------

A new ZAPI message was introduces to configure MPLS entry. In fact, LDP and
OSPF-SR don’t share the same code for the same purpose and ISIS-SR will do the
same. By adding this new ZAPI message we share code and thus reduce problem. The
new zebra_send_mpls_label() function allows to manage both FTN & MPLS table in
consistent manner. The data preparation is also simplified through the new
zapi_labels structure.

Consequently, LDP and OSPF-SR code were updated to use the new ZAPI message. As
a consequence of new CLI ‘show mpls table’ output format, topology test for LDP
and BGP were also updated.

File modifications are as follow:

* lib/zclient.[c,h]: Add new zapi_labels structure, ZAPI message and update
  zebra_send_mpls_labels() accordingly
* lib/mpls.h: Change ZEBRA_LSP_SR to ZEBRA_LSP_OSPF_SR to prepare ISIS-SR
* zebra/zapi_mpls.[c,h] & zebra/zapi_msg.c: update to new ZAPI message
  and add new functions to remove all labels
* zebra/zebra_rnh.c: remove call to old mpls_ldp_ftn_uninstallXXX() functions
* ldpd & ospf_sr.c: update to new ZAPI message
* tests/topotests/ldp-topo1: update to new 'show mpls table' CLI output format
* tests/topotests/bgp_l3vpn_to_bgp_vrf/scripts/check_routes.py: update parser 
  to new 'show mpls table' CLI output format

Update IS-IS Traffic Engineering
--------------------------------

Segment Routing Adjacency SID are convey in TLV 22 with Traffic Engineering
parameters. However, IS-IS-TE code was not updated when Christian introduced new
TLVs parser / builder. But isis_tlvs.[c.h] is already able to handle Segment
Routing Prefix SID. For Segment Routing, it was necessary to introduce Router
Capability TLV as well as Adjacency SID subTLVs. If the first one did not cause
any difficulties, the second one could not be process by the new TLV parser.
In addition, mixing old TE parsing and new TLVs parsing quickly became a
nightmare. So, a rewriting of Traffic Engineering parser became mandatory prior
to the implementation of Segment Routing itself. The modifications are as bellow:

* Remove old parser from isis_te.[c,h] and keep only link parameter update and
  TE management
* Add all Traffic Engineering subTLVs parser / builder in isis_tlvs.|c,h]

A new extended structure `isis_ext_subtlvs` and associated subTLVs type were
defined in isis_tlv.h. This structure embeded all subTLVs value recognize by
the new parser. Status field within this structure is used to determine if a
subTLVs value is valid or not avoiding using too much dynamic memory allocation.
The TLV enum type was augmented with new subTLVs type value and a new enum type
was defined for the subTLVs size. In addition, Router Capability TLV 242
structure was added in preparation of Segment Routing.

New parser / builder were introduced in `isis_tlv.c` as follow:

* `isis_alloc_ext_subtlvs()`: create new extended subTLVs structure
* `copy_item_ext_subtlvs()`: copy extended subTLVs struture
* `format_item_ext_subtlvs()`: format extended subTLVs struture used mainly by
  CLI command `show isis database detail`
* `free_item_ext_subtlvs()`: to dealloc extended subTLVs structure
* `pack_item_ext_subtlvs()`: to prepare subTLVs for latter inclusion in LSP
* `unpack_item_ext_subtlvs()`: the extended subTLVs parser

* `copy_tlv_router_cap()`: copy TLV router capability structure
* `format_tlv_router_cap()`: format router capability TLV for `show` CLI
* `free_tlv_router_cap()`: free router capability TLV structure
* `pack_tlv_router_cap()`: router capability TLV preparation
* `unpack_tlv_router_cap()`: router capability TLV parser

* `delete_items()`: remove an item in an item_list

A new hook call was introduced in `isis_circuit.c` to trigger functions when
circuit state change. This gives the possibility in `isis_te.c` to update
correctly the remote IP parameters. Indeed, this value is only valid for P2P
when the circuit comes up. This correct a previous bug where remote IP address
was never correctly set. Another new hook call was introduced in `isis_lsp.c`
to trigger function when an LSP is added, deleted, incremented or updated. This
is for preparation of Segment Routing.

As new parser where introduce, the isis_tlv fuzzing test was updated.

File modifications are as follow:

* isis_tlvs.h: add new structure to manage TE subTLVs
* isis_tlvs.c: add new functions (pack, copy, free, unpack & print) to process
  Traffic Engineering subTLVs
* isis_circuit.[c,h] & isis_lsp.[c,h]: update to new subTLVs processing
* isis_te.[c,h]: remove all old TE structures and managment functions and
  update how local and remote IP addresses are computed
* isis_mt.[c,h], isis_pdu.c & isis_northbound.c: adjust to new TE subTLVs


Segment Routing implementation
------------------------------

The heart of Segment Routing code is located in `isis_sr.h` for new structure
definition and in `isis_sr.c` for the new functions.

Segment Routing Data Base
^^^^^^^^^^^^^^^^^^^^^^^^^

New subTLV definition and parser / builder for Adjacency SID were introduced
and Segment Routing Prefix SID was updated in `isis_tlvs.[c,h]`.

Segment Routing Data Base similar to the OSPF-SRDB was defined in `isis_sr.h`.
Compared to OSPF, hash hash been replaced by by RB_TREE for better performance.
SR-DB contains all Segment Routing Nodes (sr_node structure) found in the ISIS
topology. Each SR-Node structure contains the list of Adjacency SID and Segment
Prefix SID. For each Segment Prefix SID contains the list of Nexthop Label
Forwarding Entry (NHLFE) associated to this prefix. This list is synchronous
with the ECMP nexthop list computed by the ISIS SPF algorithm and serves to
manage corresponding MPLS entries.

The contains of the SR-DB could be seen with the new CLI command
`show isis database segment-routing`. No json output is available.

All definition take place in isis_sr.h and associated functions to manage the
SR-DB are located in isis_sr.c (lines 74 – 275):

* `sr_node_cmp() and sr_prefix_cmp()`: comparison function for RB_TREE
* `del_sr_adj()`: list helper to remove Adjacency SID
* `sr_nhlfe_new()`: NHLFE structure creation for a given Segment Prefix
* `sr_prefix_new()`: creation of a new Segment Prefix for a given SR Node
* `sr_prefix_del()`: deletion of Segment Prefix and associated NFLFE
* `sr_node_new()`: creation of a new SR Node identified by its ISIS SysID
* `sr_node_del()`: deletion of an SR Node and all associated Segment Prefix
  and Adjacency SID
* `get_self_by_area() and get_self_by_node()`: function to get the self SR Node

MPLS entry management
^^^^^^^^^^^^^^^^^^^^^

Nexthop Forwarding Label Entry are store in SRDB to avoid unnecessary MPLS
reconfiguration and thus too much ZEBRA sollicitation. This allows to minimize
ZAPI call in particular when a neighbor router change its SRGB. MPLS entry is
added / removed in Linux MPLS table through the newly introduced ZAPI msg.

Functions are defined in isis_sr.c (lines 276 – 511):

* `sr_op2str()`: pretty print function of MPLS operation
* `index2label()`: commputed label from index in a given SRGB
* `sr_zebra_send_mpls_labels()`: Add / Delete NHLFE to ZEBRA though new ZAPI
  message `zebra_send_mpls_labeles()` function.
* `add_sid_nhlfe() del_sid_nhlfe() and update_sid_nhlfe()`: convenient functions
* `sr_prefix_in_label()`: compute incoming label for a given SR prefix
* `sr_prefix_out_label()`: compute outgoing label for a given SR prefix
* `update_mpls_labels()`: update in and out label for a given NHLFE and prefix


Segment Routing Adjacency SID Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adjacency & LAN Adjacency SID are created when isis_adjacency is up
Used adjacency hook for that purpose is not fully working
Hook is call only once despite if the adjacency is both IPv4 & IPv6
Usable only when adjacency become down
Used ISIS TLV builder to add Adjacency information and re-advertise LSP

Functions are defined in isis_sr.c (lines 512 – 762):

* `sr_get_local_label()`: request new label from the Label Manager
* `sr_adj_add()`: create new Adjacency SID for the given circuit
* `sr_lan_adj_add()`: create new LAN Adjacency SID for the given circuit
* `sr_circuit_update_sid_adjs()`: update Adjacency SID based on circuit type
* `sr_remove_adj()`: remove Adjacency SID
* `isis_sr_update_adj()`: master function to install / uninstall Adjacency SID
* `sr_add_adj()`: call by isis_sr_start() to add Adjacency SID

Segment Routing Prefix SID Management
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Segment Routing Prefix is created when new CLI command `segment-routing prefix`
is used. It creates corresponding MPLS entry and re-generate LSP to advertise
the new Segment Prefix SID: subTLVs builder is done in `isis_tlvs.c` and call
in isis_lsp.c by `lsp_build()`.

Functions are defined in isis_sr.c (lines 825 – 920):

* `sr_if_new_hook()`: call when interface is attached to the isis area to
  associate Segment Prefix with Loopback interface to build Node SID
* `isis_sr_prefix_add()`: add Segment Prefix SID to the self SR Node
* `isis_sr_prefix_commit()`: commit the new Segment Prefix SID. Call by
   northboud / yang function
* `isis_sr_prefix_del()`: remove Segment Prefix SID from the self SR Node
* `isis_sr_prefix_find()`: find SID associated to a given prefix

NHLFE management
^^^^^^^^^^^^^^^^

This part manages MPLS entry when new Segment Routing Prefix SID is received by
computing and setup MPLS labels for the nexthops including ECMP support. It also
updates MPLS labels (in / out) when SRGB of a direct neighbor changes.

When a new MPLS entry or new Forwarding Equivalent Class (FEC) must be added or
deleted in the data plane, `add_sid_nhlfe()` respectively `del_sid_nhlfe()` are
called. Once check the validity of labels, they are send to ZEBRA layer through
`ZEBRA_MPLS_LABELS_ADD` command, respectively `ZEBRA_MPLS_LABELS_DELETE`
command for deletion using the new ZAPI_MSG zebra_send_mpls_labels().

Functions are defined in isis_sr.c (lines 921 – 1191):

* `nhlfe_merge_nexthop()`: build list of NHLFE per nexthops
* `nhlfe_merge_nexthop6()`: same for IPv6
* `get_nexthop_by_prefix()`: get list of nexthops for a given prefix
* `update_prefix_nhlfe()`: update list of NHLFE for a given prefix
* `update_in_nhlfe()`: update Input label of NHLFE when SRGB changes
* `update_out_nhlfe()`: update Output label of NHLFE when SRGB

ISIS LSP parser & route update
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

When an LSP is received, following functions extract Segment Routing subTLVs
and update SR-DB accordingly. This will trigger previous Segment Prefix functions
to manage corresponding NHLFE. SR-Node is added or removed based on Router
Capability parsing i.e. if Segment Routing information is found or not. Update
of input and/or output NHLFE is also triggered when parser detect a modification
on SRGB of a direct heighbor. NHLFE is also updated for a given prefix when a
new SPF run change the corresponding nexthop. New hook has been defined in
isis_spf.c for that purpose.

Functions are defined in isis_sr.c (lines 1192 – 1525):

* `sr_cap_update()`: parse and update SR-Node from Router Capabilities TLV
* `sr_prefix_update()`: parse and update Segment Routing prefix from subTLVs
* `srdb_commit_prefix()`: update corresponding NHLFE for an update SR prefix.
  This function is called after LSP parsing to detect when an SR prefix is
  removed or updated.
* `srdb_parse_lsp()`: global LSP parser
* `srdb_del_srnode_by_lsp()`: remove SR-Node if Router Capability disappear
* `srdb_lsp_event()`: hook call when an LSP is Add Delete or Update. Note that
  INC state is not process as own LSP are process directly and TICK state is 
  not of interest for Segment Routing.
* `isis_sr_route_update()`: call when SPF change a nexthop for a given prefix.
  Update NHLFE accordingly. 

Segment Routing Management
^^^^^^^^^^^^^^^^^^^^^^^^^^

To manage Segmnet Routing, new CLI and Yang model (yang/frr/frr_isisd.yang) have
been added. The Yang model follow the IETF draft. Corresponding code is located
in `isis_northbound.c` and CLI in `isis_cli.c`. New management functions were
introduced to initialize and configure Segment Routing. A new CLI command was
added to print the contain of the SR-DB: ‘show isis database segment-routing’.

Functions are defined in isis_sr.c (lines 1526 – end):

* `show_sr_prefix() show_sr_node() and show_isis_srdb()`: print the content of
  the Segment Routing Data base (SR-DB) 
* `isis_sr_srgb_update()`: call by northbound to update self SRGB
* `isis_sr_msd_update()`: same for the Maximum Stack Depth
* `isis_sr_create()`: create SR-DB and initialise Segment Routing processing
* `isis_sr_destroy()`: remove SR-DB and stop Segment Routing processing
* `isis_sr_start()`: start Segment Routing for the given area
* `isis_sr_stop()`: stop Segment Routing for the given area
* `isis_sr_init()`: register hook functions and install new CLI show command
* `isis_sr_term()`: unregister hook functions

Configuration
-------------

Linux Kernel
^^^^^^^^^^^^

In order to use IS-IS Segment Routing, you must setup MPLS data plane. Up to
know, only Linux Kernel version >= 4.5 is supported.

First, the MPLS modules aren't loaded by default, so you'll need to load them
yourself:

::

   modprobe mpls_router
   modprobe mpls_gso
   modprobe mpls_iptunnel

Then, you must activate MPLS on the interface you would used:

::

   sysctl -w net.mpls.conf.enp0s9.input=1
   sysctl -w net.mpls.conf.lo.input=1
   sysctl -w net.mpls.platform_labels=1048575

The last line fix the maximum MPLS label value.

Once IS-ISd start with Segment Routing, you could check that MPLS routes are
enable with:

::

   ip -M route
   ip route

The first command show the MPLS LFIB table while the second show the FIB
table which contains route with MPLS label encapsulation.

If you disable Penultimate Hop Popping with the `no-php-flag` (see below), you
MUST check that RP filter is not enable for the interface you intend to use,
especially the `lo` one. For that purpose, disable RP filtering with:

::

   systcl -w net.ipv4.conf.all.rp_filter=0
   sysctl -w net.ipv4.conf.lo.rp_filter=0

isisd
^^^^^

Here it is a simple example of configuration to enable Segment Routing.

::

   router isis SR
     net 49.0000.0000.0000.0001.00
     is-type level-1
     lsp-gen-interval 2
     topology ipv6-unicast

     segment-routing on
     segment-routing node-msd 8
     segment-routing prefix 10.1.1.1/32 index 100
     segment-routing prefix 2001:db8:1000::1/128 index 101


The first segment-routing statement enable it. The Second one set the SRGB,
third line the MSD and finally, set the Prefix SID index for a given prefix,
ipv4 then ipv6. Note that only prefix associated to Loopback interface could be
configured with a Prefix SID. It is possible to add the `no-php-flag` or
`explicit-null` flag at the end of the prefix command to disable Penultimate
Hop Popping, respectively set Explicit NULL label. This advertises to peers
that they MUST NOT pop the MPLS label, respectively swapt to the Excplit NULL
label prior to sending the packet.

Known limitations
-----------------

* Runs only within Level-1 or Level-2
* Only single level is supported. Level-1-2 redistribution is not yet supported
* Only SPF algorithm is supported
* SRMS is not supported
* MPLS table are not flush at startup. Thus, restarting zebra process is
  mandatory to remove old MPLS entries in the data plane after a crash of
  isisd daemon
* With NO Penultimate Hop Popping, it is not possible to express a Segment
  Path with an Adjacency SID due to the impossibility for the Linux Kernel to
  perform double POP instruction.

Credits
-------

* Author: Olivier Dugeon <olivier.dugeon@orange.com>
* Co-Authored-By: Renato Westphal <renato@opensourcerouting.org> 
* Copyright (C) 2019 Orange Labs http://www.orange.com

Thanks to Christian Franke for his excellent advices

