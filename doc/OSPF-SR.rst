OSPF Segment Routing
====================

This is an EXPERIMENTAL support of draft draft-ietf-ospf-segment-routing-extensions-24.
DON'T use it for production network.

Implementation details
----------------------

Segment Routing used 3 differents OPAQUE LSA in OSPF to carry the various information:
 - Router Information: flood the Segment Routing capabilities of the node. This include
 the supported algorithms, the Segment Routing Global Block (SRGB) and the Maximum Stack
 Depth.
 - Extended Link: flood the Adjaceny and Lan Adjacency Segment Identifier
 - Extended Prefix: flood the Prefix Segment Identifier

The implementation follow previous TE and Router Information code. It used the OPAQUE LSA
functions define in ospf_opaque.[c,h] as well as the OSPF API. This latter is mandatory
for the implementation as it provides the Callback to Segment Routing functions (see below)
when an Extended Link / Prefix or Router Information is received.

Following files where modified or added:
 - ospd_ri.[c,h] have been modified to add the new TLVs for Segment Routing.
 - ospf_ext.[c,h] implement RFC7684 as base support of Extended Link and Prefix Opaque LSA.
 - ospf_sr.[c,h] implement the earth of Segment Routing. It adds a new Segment Routing database
 to manage Segment Identifiers per Link and Prefix and Segment Routing enable node, Callback
 functions to process incoming LSA and install MPLS FIB entry through Zebra.

the figure below shows the relation between the various files:

 - ospf_sr.c centralized all the Segment Routing processing. It receives Opaque LSA
 Router Information (4.0.0.0) from ospf_ri.c and Extended Prefix (7.0.0.X) Link (8.0.0.X)
 from ospf_ext.c. Once received, it parse TLVs and SubTLVs and store information in SRDB
 (which is defined in ospf_sr.h). For each received LSA, NHLFE is computed and send to
 Zebra to add/remove new MPLS labels entries and FEC. New CLI configurations are also
 centralized in ospf_sr.c. This CLI will trigger the flooding os new LSA Router Information
 (4.0.0.0), Extended Prefix (7.0.0.X) and Link (8.0.0.X) by ospf_ri.c, respectively ospf_ext.c.
 - ospf_ri.c send back to ospf_sr.c received Router Information LSA and update self Router
 Information LSA with paramters provided by ospf_sr.c i.e. SRGB and MSD. It use ospf_opaque.c
 functions to send / received these Opaque LSAs.
 - ospf_ext.c send bacl to ospf_sr.c received Extended Prefix and Link Opaque LSA and send
 self Extended Prefix and Link Opaque LSA through ospf_opaque.c functions.

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


Known limitations
-----------------

 - Only single Area is supported. ABR is not yet supported
 - Only SPF algorithm is supported
 - Extended Prefix Range is not supported

