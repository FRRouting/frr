OSPF Segment Routing
====================

This is an EXPERIMENTAL support of draft draft-ietf-ospf-segment-routing-extensions-24.
DON'T use it for production network.

Implementation details
----------------------

Segment Routing used 3 differents OPAQUE LSA in OSPF to carry the various
information:

 - Router Information: flood the Segment Routing capabilities of the node.
   This include the supported algorithms, the Segment Routing Global Block
   (SRGB) and the Maximum Stack Depth (MSD).
 - Extended Link: flood the Adjaceny and Lan Adjacency Segment Identifier
 - Extended Prefix: flood the Prefix Segment Identifier

The implementation follow previous TE and Router Information code. It used the
OPAQUE LSA functions define in ospf_opaque.[c,h] as well as the OSPF API. This
latter is mandatory for the implementation as it provides the Callback to
Segment Routing functions (see below) when an Extended Link / Prefix or Router
Information is received.

Following files where modified or added:
 - ospd_ri.[c,h] have been modified to add the new TLVs for Segment Routing.
 - ospf_ext.[c,h] implement RFC7684 as base support of Extended Link and Prefix
   Opaque LSA.
 - ospf_sr.[c,h] implement the earth of Segment Routing. It adds a new Segment
   Routing database to manage Segment Identifiers per Link and Prefix and
   Segment Routing enable node, Callback functions to process incoming LSA and
   install MPLS FIB entry through Zebra.

The figure below shows the relation between the various files:

 - ospf_sr.c centralized all the Segment Routing processing. It receives Opaque
   LSA Router Information (4.0.0.0) from ospf_ri.c and Extended Prefix
   (7.0.0.X) Link (8.0.0.X) from ospf_ext.c. Once received, it parse TLVs and
   SubTLVs and store information in SRDB (which is defined in ospf_sr.h). For
   each received LSA, NHLFE is computed and send to Zebra to add/remove new
   MPLS labels entries and FEC. New CLI configurations are also centralized in
   ospf_sr.c. This CLI will trigger the flooding of new LSA Router Information
   (4.0.0.0), Extended Prefix (7.0.0.X) and Link (8.0.0.X) by ospf_ri.c,
   respectively ospf_ext.c.
 - ospf_ri.c send back to ospf_sr.c received Router Information LSA and update
   Self Router Information LSA with paramters provided by ospf_sr.c i.e. SRGB
   and MSD. It use ospf_opaque.c functions to send/received these Opaque LSAs.
 - ospf_ext.c send bacl to ospf_sr.c received Extended Prefix and Link Opaque
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

      Figure1: Overview of Segment Routing interaction


Configuration
-------------

Here it is a simple example of configuration to enable Segment Routing. Note
that ``opaque capability`` must be set to activate Opaque LSA prior to Segment
Routing.

::

 router ospf
 ospf router-id 192.168.1.11
 capability opaque
  mpls-te on
  mpls-te router-address 192.168.1.11
 router-info area 0.0.0.0
 segment-routing on
 segment-routing global-block 10000 19999
 segment-routing node-msd 8
 segment-routing prefix 192.168.1.11/32 index 1100

The first segment-routing statement enable it. The Second one set the SRGB,
third line the MSD and finally, set the Prefix SID index for tha given prefix.
Note that only prefix of Loopback interface could be configured with a Prefix
SID.

Known limitations
-----------------

 - Only single Area is supported. ABR is not yet supported
 - Only SPF algorithm is supported
 - Extended Prefix Range is not supported

Credits
-------
 * Author: Anselme Sawadogo <anselmesawadogo@gmail.com>
 * Author: Olivier Dugeon <olivier.dugeon@orange.com>
 * Copyright (C) 2016 - 2018 Orange Labs http://www.orange.com

This work has been performed in the framework of the H2020-ICT-2014
project 5GEx (Grant Agreement no. 671636), which is partially funded
by the European Commission.


