OSPF Segment Routing
====================

This is an EXPERIMENTAL support of `RFC 8665`.
DON'T use it for production network.

Supported Features
------------------

* Automatic computation of Primary and Backup Adjacency SID with
  Cisco experimental remote IP address
* SRGB & SRLB configuration
* Prefix configuration for Node SID with optional NO-PHP flag (Linux
  kernel support both mode)
* Node MSD configuration (with Linux Kernel >= 4.10 a maximum of 32 labels
  could be stack)
* Automatic provisioning of MPLS table
* Equal Cost Multi-Path (ECMP)
* Static route configuration with label stack up to 32 labels
* TI-LFA (for P2P interfaces only)

Interoperability
----------------

* Tested on various topology including point-to-point and LAN interfaces
  in a mix of FRRouting instance and Cisco IOS-XR 6.0.x
* Check OSPF LSA conformity with latest wireshark release 2.5.0-rc

Implementation details
----------------------

Concepts
^^^^^^^^

Segment Routing used 3 different OPAQUE LSA in OSPF to carry the various
information:

* **Router Information:** flood the Segment Routing capabilities of the node.
  This include the supported algorithms, the Segment Routing Global Block
  (SRGB) and the Maximum Stack Depth (MSD).
* **Extended Link:** flood the Adjaceny and Lan Adjacency Segment Identifier
* **Extended Prefix:** flood the Prefix Segment Identifier

The implementation follows previous TE and Router Information codes. It used the
OPAQUE LSA functions defined in ospf_opaque.[c,h] as well as the OSPF API. This
latter is mandatory for the implementation as it provides the Callback to
Segment Routing functions (see below) when an Extended Link / Prefix or Router
Information LSA s are received.

Overview
^^^^^^^^

Following files where modified or added:

* ospd_ri.[c,h] have been modified to add the new TLVs for Segment Routing.
* ospf_ext.[c,h] implement RFC7684 as base support of Extended Link and Prefix
  Opaque LSA.
* ospf_sr.[c,h] implement the earth of Segment Routing. It adds a new Segment
  Routing database to manage Segment Identifiers per Link and Prefix and
  Segment Routing enable node, Callback functions to process incoming LSA and
  install MPLS FIB entry through Zebra.

The figure below shows the relation between the various files:

* ospf_sr.c centralized all the Segment Routing processing. It receives Opaque
  LSA Router Information (4.0.0.0) from ospf_ri.c and Extended Prefix
  (7.0.0.X) Link (8.0.0.X) from ospf_ext.c. Once received, it parse TLVs and
  SubTLVs and store information in SRDB (which is defined in ospf_sr.h). For
  each received LSA, NHLFE is computed and send to Zebra to add/remove new
  MPLS labels entries and FEC. New CLI configurations are also centralized in
  ospf_sr.c. This CLI will trigger the flooding of new LSA Router Information
  (4.0.0.0), Extended Prefix (7.0.0.X) and Link (8.0.0.X) by ospf_ri.c,
  respectively ospf_ext.c.
* ospf_ri.c send back to ospf_sr.c received Router Information LSA and update
  Self Router Information LSA with parameters provided by ospf_sr.c i.e. SRGB
  and MSD. It use ospf_opaque.c functions to send/received these Opaque LSAs.
* ospf_ext.c send back to ospf_sr.c received Extended Prefix and Link Opaque
  LSA and send self Extended Prefix and Link Opaque LSA through ospf_opaque.c
  functions.

::

                    +-----------+     +-------+
                    |           |     |       |
                    | ospf_sr.c +-----+  SRDB |
        +-----------+           +--+  |       |
        |           +-^-------^-+  |  +-------+
        |             |   |   |    |
        |             |   |   |    |
        |             |   |   |    +--------+
        |             |   |   |             |
    +---v----------+  |   |   |       +-----v-------+
    |              |  |   |   |       |             |
    | ospf_ri.c    +--+   |   +-------+ ospf_ext.c  |
    | LSA 4.0.0.0  |      |           | LSA 7.0.0.X |
    |              |      |           | LSA 8.0.0.X |
    +---^----------+      |           |             |
        |                 |           +-----^-------+
        |                 |                 |
        |                 |                 |
        |        +--------v------------+    |
        |        |                     |    |
        |        | ZEBRA: Labels + FEC |    |
        |        |                     |    |
        |        +---------------------+    |
        |                                   |
        |                                   |
        |         +---------------+         |
        |         |               |         |
        +---------> ospf_opaque.c <---------+
                  |               |
                  +---------------+

      Figure 1: Overview of Segment Routing interaction

Module interactions
^^^^^^^^^^^^^^^^^^^

To process incoming LSA, the code is based on the capability to call `hook()`
functions when LSA are inserted or delete to / from the LSDB and the
possibility to register particular treatment for Opaque LSA. The first point
is provided by the OSPF API feature and the second by the Opaque implementation
itself. Indeed, it is possible to register callback function for a given Opaque
LSA ID (see `ospf_register_opaque_functab()` function defined in
`ospf_opaque.c`). Each time a new LSA is added to the LSDB, the
`new_lsa_hook()` function previously register for this LSA type is called. For
Opaque LSA it is the `ospf_opaque_lsa_install_hook()`.  For deletion, it is
`ospf_opaque_lsa_delete_hook()`.

Note that incoming LSA which is already present in the LSDB will be inserted
after the old instance of this LSA remove from the LSDB. Thus, after the first
time, each incoming LSA will trigger a `delete` following by an `install`. This
is not very helpful to handle real LSA deletion. In fact, LSA deletion is done
by Flushing LSA i.e. flood LSA after setting its age to MAX_AGE. Then, a garbage
function has the role to remove all LSA with `age == MAX_AGE` in the LSDB. So,
to handle LSA Flush, the best is to look to the LSA age to determine if it is
an installation or a future deletion i.e. the flushed LSA is first store in the
LSDB with MAX_AGE waiting for the garbage collector function.

Router Information LSAs
^^^^^^^^^^^^^^^^^^^^^^^

To activate Segment Routing, new CLI command `segment-routing on` has been
introduced. When this command is activated, function
`ospf_router_info_update_sr()` is called to indicate to Router Information
process that Segment Routing TLVs must be flood. Same function is called to
modify the Segment Routing Global Block (SRGB) and Maximum Stack Depth (MSD)
TLV. Only Shortest Path First (SPF) Algorithm is supported, so no possibility
to modify this TLV is offer by the code.

When Opaque LSA Type 4 i.e. Router Information are stored in LSDB, function
`ospf_opaque_lsa_install_hook()` will call the previously registered function
`ospf_router_info_lsa_update()`. In turn, the function will simply trigger
`ospf_sr_ri_lsa_update()` or `ospf_sr_ri_lsa_delete` in function of the LSA
age. Before, it verifies that the LSA Opaque Type is 4 (Router Information).
Self Opaque LSA are not send back to the Segment Routing functions as
information are already stored.

Extended Link Prefix LSAs
^^^^^^^^^^^^^^^^^^^^^^^^^

Like for Router Information, Segment Routing is activate at the Extended
Link/Prefix level with new `segment-routing on` command. This triggers
automatically the flooding of Extended Link LSA for all ospf interfaces where
adjacency is full. For Extended Prefix LSA, the new CLI command
`segment-routing prefix ...` will trigger the flooding of Prefix SID
TLV/SubTLVs.

When Opaque LSA Type 7 i.e. Extended Prefix and Type 8 i.e. Extended Link are
store in the LSDB, `ospf_ext_pref_update_lsa()` respectively
`ospf_ext_link_update_lsa()` are called like for Router Information LSA. In
turn, they respectively trigger `ospf_sr_ext_prefix_lsa_update()` /
`ospf_sr_ext_link_lsa_update()` or `ospf_sr_ext_prefix_lsa_delete()` /
`ospf_sr_ext_link_lsa_delete()` if the LSA age is equal to MAX_AGE.

Zebra
^^^^^

When a new MPLS entry or new Forwarding Equivalent Class (FEC) must be added or
deleted in the data plane, `add_sid_nhlfe()` respectively `del_sid_nhlfe()` are
called. Once check the validity of labels, they are send to ZEBRA layer through
`ZEBRA_MPLS_LABELS_ADD` command, respectively `ZEBRA_MPLS_LABELS_DELETE`
command for deletion. This is completed by a new labelled route through
`ZEBRA_ROUTE_ADD` command, respectively `ZEBRA_ROUTE_DELETE` command.

TI-LFA
^^^^^^

Experimental support for Topology Independent LFA (Loop-Free Alternate), see
for example 'draft-bashandy-rtgwg-segment-routing-ti-lfa-05'. The related
files are `ospf_ti_lfa.c/h`.

The current implementation is rather naive and does not support the advanced
optimizations suggested in e.g. RFC7490 or RFC8102. It focuses on providing
the essential infrastructure which can also later be used to enhance the
algorithmic aspects.

Supported features:

* Link and node protection
* Intra-area support
* Proper use of Prefix- and Adjacency-SIDs in label stacks
* Asymmetric weights (using reverse SPF)
* Non-adjacent P/Q spaces
* Protection of Prefix-SIDs

If configured for every SPF run the routing table is enriched with additional
backup paths for every prefix. The corresponding Prefix-SIDs are updated with
backup paths too within the OSPF SR update task.

Informal High-Level Algorithm Description:

::

  p_spaces = empty_list()

  for every protected_resource (link or node):
    p_space = generate_p_space(protected_resource)
    p_space.q_spaces = empty_list()

    for every destination that is affected by the protected_resource:
      q_space = generate_q_space(destination)

      # The label stack is stored in q_space
      generate_label_stack(p_space, q_space)

      # The p_space collects all its q_spaces
      p_spaces.q_spaces.add(q_space)

    p_spaces.add(p_space)

  adjust_routing_table(p_spaces)

Possible Performance Improvements:

* Improve overall datastructures, get away from linked lists for vertices
* Don't calculate a Q space for every destination, but for a minimum set of
  backup paths that cover all destinations in the post-convergence SPF. The
  thinking here is that once a backup path is known that it is also a backup
  path for all nodes on the path themselves. This can be done by using the
  leafs of a trimmed minimum spanning tree generated out of the post-
  convergence SPF tree for that particular P space.
* For an alternative (maybe better) optimization look at
  https://tools.ietf.org/html/rfc7490#section-5.2.1.3 which describes using
  the Q space of the node which is affected by e.g. a link failure. Note that
  this optimization is topology dependent.

It is highly recommended to read e.g. `Segment Routing I/II` by Filsfils to
understand the basics of Ti-LFA.

Configuration
-------------

Linux Kernel
^^^^^^^^^^^^

In order to use OSPF Segment Routing, you must setup MPLS data plane. Up to
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

Once OSPFd start with Segment Routing, you could check that MPLS routes are
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

OSPFd
^^^^^

Here it is a simple example of configuration to enable Segment Routing. Note
that `opaque capability` and `router information` must be set to activate
Opaque LSA prior to Segment
Routing.

::

   router ospf
    ospf router-id 192.168.1.11
    capability opaque
    segment-routing on
    segment-routing global-block 10000 19999 local-block 5000 5999
    segment-routing node-msd 8
    segment-routing prefix 192.168.1.11/32 index 1100

The first segment-routing statement enables it. The second and third one set
the SRGB and SRLB respectively, fourth line the MSD and finally, set the
Prefix SID index for a given prefix.

Note that only prefix of Loopback interface could be configured with a Prefix
SID. It is possible to add `no-php-flag` at the end of the prefix command to
disable Penultimate Hop Popping. This advertises to peers that they MUST NOT pop
the MPLS label prior to sending the packet.

Known limitations
-----------------

* Runs only within default VRF
* Only single Area is supported. ABR is not yet supported
* Only SPF algorithm is supported
* Extended Prefix Range is not supported
* With NO Penultimate Hop Popping, it is not possible to express a Segment
  Path with an Adjacency SID due to the impossibility for the Linux Kernel to
  perform double POP instruction.

Credits
-------

* Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
* Author: Olivier Dugeon <olivier.dugeon@orange.com>
* Copyright (C) 2016 - 2018 Orange Labs http://www.orange.com

This work has been performed in the framework of the H2020-ICT-2014
project 5GEx (Grant Agreement no. 671636), which is partially funded
by the European Commission.

