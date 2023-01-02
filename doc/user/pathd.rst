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


PCEP Support
============

A pceplib is included in the frr source tree and build by default.


To start pathd with pcep support the extra parameter `-M pathd_pcep` should be
passed to the pathd daemon.


Pathd Configuration
===================

Example:

.. code-block:: frr

  debug pathd pcep basic
  segment-routing
   traffic-eng
    mpls-te on
    mpls-te import ospfv2
    segment-list SL1
     index 10 mpls label 16010
     index 20 mpls label 16030
    !
    segment-list SL2
     index 10 nai prefix 10.1.2.1/32 iface 1
     index 20 nai adjacency 10.1.20.1 10.1.20.2
     index 30 nai prefix 10.10.10.5/32 algorithm 0
     index 40 mpls label 18001
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
    pcep
     pce-config GROUP1
      source-address ip 1.1.1.1
      tcp-md5-auth secret
      timer keep-alive 30
     !
     pce PCE1
      config GROUP1
      address ip 10.10.10.10
     !
     pce PCE2
      config GROUP1
      address ip 9.9.9.9
     !
     pcc
      peer PCE1 precedence 10
      peer PCE2 precedence 20
     !
    !
   !
  !


.. _path-commands:

Configuration Commands
----------------------

.. clicmd:: segment-routing

   Configure segment routing.

.. clicmd:: traffic-eng

   Configure segment routing traffic engineering.

.. clicmd:: mpls-te <on|off>

   Activate/Deactivate use of internal Traffic Engineering Database

.. clicmd:: mpls-te import <ospfv2|ospfv3|isis>

   Load data from the selected igp

.. clicmd:: segment-list NAME

   Delete or start a segment list definition.

.. clicmd:: index INDEX mpls label LABEL
.. clicmd:: index INDEX nai adjacency A.B.C.D A.B.C.D
.. clicmd:: index INDEX nai prefix A.B.C.D/M algorithm <0|1>
.. clicmd:: index INDEX nai prefix A.B.C.D/M iface (0-65535)

   Delete or specify a segment in a segment list definition.


.. clicmd:: policy color COLOR endpoint ENDPOINT

   Delete or start a policy definition.


.. clicmd:: name NAME

   Specify the policy name.


.. clicmd:: binding-sid LABEL

   Specify the policy SID.


.. clicmd:: candidate-path preference PREFERENCE name NAME explicit segment-list SEGMENT-LIST-NAME

   Delete or define an explicit candidate path.


.. clicmd:: candidate-path preference PREFERENCE name NAME dynamic

   Delete or start a dynamic candidate path definition.


.. clicmd:: affinity <exclude-any|include-any|include-all> BITPATTERN

   Delete or specify an affinity constraint for a dynamic candidate path.


.. clicmd:: bandwidth BANDWIDTH [required]

   Delete or specify a bandwidth constraint for a dynamic candidate path.


.. clicmd:: metric [bound] METRIC VALUE [required]

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


.. clicmd:: objective-function OBJFUN1 [required]

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


.. clicmd:: debug pathd pcep [basic|path|message|pceplib]

   Enable or disable debugging for the pcep module:

     - basic: Enable basic PCEP logging
     - path: Log the path structures
     - message: Log the PCEP messages
     - pceplib: Enable pceplib logging


.. clicmd:: pcep

   Configure PCEP support.


.. clicmd:: pce-config NAME

   Define a shared PCE configuration that can be used in multiple PCE
   declarations.


.. clicmd:: pce NAME

   Define or delete a PCE definition.


.. clicmd:: config WORD

   Select a shared configuration. If not defined, the default
   configuration will be used.


.. clicmd:: address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]

   Define the address and port of the PCE.

   If not specified, the port is the standard PCEP port 4189.

   This should be specified in the PCC peer definition.


.. clicmd:: source-address [ip A.B.C.D | ipv6 X:X::X:X] [port PORT]

   Define the address and/or port of the PCC as seen by the PCE.
   This can be used in a configuration group or a PCC peer declaration.

   If not specified, the source address will be the router identifier selected
   by zebra, and the port will be the standard PCEP port 4189.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. clicmd:: tcp-md5-auth WORD

   Enable TCP MD5 security with the given secret.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. clicmd:: sr-draft07

   Specify if a PCE only support segment routing draft 7, this flag will limit
   the PCC behavior to this draft.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. clicmd:: pce-initiated

   Specify if PCE-initiated LSP should be allowed for this PCE.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. clicmd:: timer [keep-alive (1-63)] [min-peer-keep-alive (1-255)] [max-peer-keep-alive (1-255)] [dead-timer (4-255)] [min-peer-dead-timer (4-255)] [max-peer-dead-timer (4-255)] [pcep-request (1-120)] [session-timeout-interval (1-120)] [delegation-timeout (1-60)]

   Specify the PCEP timers.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. clicmd:: pcc

   Disable or start the definition of a PCC.


.. clicmd:: msd (1-32)

   Specify the maximum SID depth in a PCC definition.


.. clicmd:: peer WORD [precedence (1-255)]

   Specify a peer and its precedence in a PCC definition.


Introspection Commands
----------------------

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


.. clicmd:: show sr-te pcep counters

   Display the counters from pceplib.


.. clicmd:: show sr-te pcep pce-config [NAME]

   Display a shared configuration. if no name is specified, the default
   configuration will be displayed.


.. clicmd:: show sr-te pcep pcc

   Display PCC information.


.. clicmd:: show sr-te pcep session [NAME]

   Display the information of a PCEP session, if not name is specified all the
   sessions will be displayed.


Utility Commands
----------------

.. clicmd:: clear sr-te pcep session [NAME]

   Reset the pcep session by disconnecting from the PCE and performing the
   normal reconnection process. No configuration is changed.


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


Sample configuration
====================

.. code-block:: frr

   ! Default pathd configuration sample
   !
   password frr
   log stdout

   segment-routing
    traffic-eng
     segment-list test1
      index 10 mpls label 123
      index 20 mpls label 456
     !
     segment-list test2
      index 10 mpls label 321
      index 20 mpls label 654
     !
     policy color 1 endpoint 1.1.1.1
      name one
      binding-sid 100
      candidate-path preference 100 name test1 explicit segment-list test1
      candidate-path preference 200 name test2 explicit segment-list test2
     !
     policy color 2 endpoint 2.2.2.2
      name two
      binding-sid 101
      candidate-path preference 100 name def explicit segment-list test2
      candidate-path preference 200 name dyn dynamic
       bandwidth 12345
       metric bound abc 16 required
       metric te 10
      !
     !
     pcep
      pcc-peer PCE1
       address ip 127.0.0.1
       sr-draft07
      !
      pcc
       peer PCE1
      !
    !
   !

