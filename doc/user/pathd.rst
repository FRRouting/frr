.. _path:

****
PATH
****

:abbr:`PATH` is a daemon that handles the installation and deletion
of Segment Routing (SR) Policies.


.. _starting-path:

Starting PATH
=============

Default configuration file for *pathd* is :file:`pathd.conf`.  The typical
location of :file:`pathd.conf` is |INSTALL_PREFIX_ETC|/pathd.conf.

If the user is using integrated config, then :file:`pathd.conf` need not be
present and the :file:`frr.conf` is read instead.

.. program:: pathd

:abbr:`PATH` supports all the common FRR daemon start options which are
documented elsewhere.


Pathd Configuration
===================

Example:

.. code-block:: frr

  segment-routing
   traffic-eng
    segment-list SL1
     index 10 mpls label 16010
     index 20 mpls label 16030
    !
    policy color 1 endpoint 1.1.1.1
     name default
     binding-sid 4000
     candidate-path preference 100 name CP1 explicit segment-list SL1
     candidate-path preference 200 name CP2 dynamic
      affinity include-any 0x000000FF
      bandwidth 100000
      metric bound msd 16 required
      metric te 10
      objective-function mcp required
    !
   !
  !


.. _path-commands:

Configuration Commands
----------------------

.. index:: segment-routing
.. clicmd:: segment-routing

   Configure segment routing.

.. index:: traffic-eng
.. clicmd:: traffic-eng

   Configure segment routing traffic engineering.

.. index:: [no] segment-list NAME
.. clicmd:: [no] segment-list NAME

   Delete or start a segment list definition.


.. index:: [no] index INDEX mpls label LABEL [nai node ADDRESS]
.. clicmd:: [no] index INDEX mpls label LABEL [nai node ADDRESS]

   Delete or specify a segment in a segment list definition.


.. index:: [no] policy color COLOR endpoint ENDPOINT
.. clicmd:: [no] policy color COLOR endpoint ENDPOINT

   Delete or start a policy definition.


.. index:: name NAME
.. clicmd:: name NAME

   Specify the policy name.


.. index:: binding-sid LABEL
.. clicmd:: binding-sid LABEL

   Specify the policy SID.


.. index:: [no] candidate-path preference PREFERENCE name NAME explicit segment-list SEGMENT-LIST-NAME
.. clicmd:: [no] candidate-path preference PREFERENCE name NAME explicit segment-list SEGMENT-LIST-NAME

   Delete or define an explicit candidate path.


.. index:: [no] candidate-path preference PREFERENCE name NAME dynamic
.. clicmd:: [no] candidate-path preference PREFERENCE name NAME dynamic

   Delete or start a dynamic candidate path definition.


.. index:: [no] affinity {exclude-any|include-any|include-all} BITPATTERN
.. clicmd:: [no] affinity {exclude-any|include-any|include-all} BITPATTERN

   Delete or specify an affinity constraint for a dynamic candidate path.


.. index:: [no] bandwidth BANDWIDTH [required]
.. clicmd:: [no] bandwidth BANDWIDTH [required]

   Delete or specify a bandwidth constraint for a dynamic candidate path.


.. index:: [no] metric [bound] METRIC VALUE [required]
.. clicmd:: [no] metric [bound] METRIC VALUE [required]

   Delete or specify a metric constraint for a dynamic candidate path.

   The possible metrics are:
    - igp: IGP metric
    - te: TE metric
    - hc: Hop Counts
    - abc: Aggregate bandwidth consumption
    - mll: Load of the most loaded link
    - igp: Cumulative IGP cost
    - cte: Cumulative TE cost
    - igp: P2MP IGP metric
    - pte: P2MP TE metric
    - phc: P2MP hop count metric
    - msd: Segment-ID (SID) Depth
    - pd: Path Delay metric
    - pdv: Path Delay Variation metric
    - pl: Path Loss metric
    - ppd: P2MP Path Delay metric
    - pdv: P2MP Path Delay variation metric
    - ppl: P2MP Path Loss metric
    - nap: Number of adaptations on a path
    - nlp: Number of layers on a path
    - dc: Domain Count metric
    - bnc: Border Node Count metric


.. index:: [no] objective-function OBJFUN1 [required]
.. clicmd:: [no] objective-function OBJFUN1 [required]

   Delete or specify a PCEP objective function constraint for a dynamic
   candidate path.

   The possible functions are:
     - mcp: Minimum Cost Path [RFC5541]
     - mlp: Minimum Load Path [RFC5541]
     - mbp: Maximum residual Bandwidth Path [RFC5541]
     - mbc: Minimize aggregate Bandwidth Consumption [RFC5541]
     - mll: Minimize the Load of the most loaded Link [RFC5541]
     - mcc: Minimize the Cumulative Cost of a set of paths [RFC5541]
     - spt: Shortest Path Tree [RFC8306]
     - mct: Minimum Cost Tree [RFC8306]
     - mplp: Minimum Packet Loss Path [RFC8233]
     - mup: Maximum Under-Utilized Path [RFC8233]
     - mrup: Maximum Reserved Under-Utilized Path [RFC8233]
     - mtd: Minimize the number of Transit Domains [RFC8685]
     - mbn: Minimize the number of Border Nodes [RFC8685]
     - mctd: Minimize the number of Common Transit Domains [RFC8685]
     - msl: Minimize the number of Shared Links [RFC8800]
     - mss: Minimize the number of Shared SRLGs [RFC8800]
     - msn: Minimize the number of Shared Nodes [RFC8800]


Introspection Commands
----------------------

.. index:: show sr-te policy [detail]
.. clicmd:: show sr-te policy [detail]

   Display the segment routing policies.

.. code-block:: frr

  router# show sr-te policy

   Endpoint  Color  Name     BSID  Status
   ------------------------------------------
   1.1.1.1   1      default  4000  Active


.. code-block:: frr

  router# show sr-te policy detail

  Endpoint: 1.1.1.1  Color: 1  Name: LOW_DELAY  BSID: 4000  Status: Active
      Preference: 100  Name: cand1  Type: explicit  Segment-List: sl1  Protocol-Origin: Local
    * Preference: 200  Name: cand1  Type: dynamic  Segment-List: 32453452  Protocol-Origin: PCEP

The asterisk (*) marks the best, e.g. active, candidate path. Note that for segment-lists which are
retrieved via PCEP a random number based name is generated.


Usage with BGP route-maps
=========================

It is possible to steer traffic 'into' a segment routing policy for routes
learned through BGP using route-maps:

.. code-block:: frr

  route-map SET_SR_POLICY permit 10
   set sr-te color 1
  !
  router bgp 1
   bgp router-id 2.2.2.2
   neighbor 1.1.1.1 remote-as 1
   neighbor 1.1.1.1 update-source lo
   !
   address-family ipv4 unicast
    neighbor 1.1.1.1 next-hop-self
    neighbor 1.1.1.1 route-map SET_SR_POLICY in
    redistribute static
   exit-address-family
   !
  !

In this case, the SR Policy with color `1` and endpoint `1.1.1.1` is selected.
