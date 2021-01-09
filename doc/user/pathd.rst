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

To build the PCC for pathd, the externall library `pceplib 1.2 <https://github.com/volta-networks/pceplib/tree/devel-1.2>`_ is required.

To build FRR with support for PCEP the following steps must be followed:

 - Checkout and build pceplib:

```
$ git clone https://github.com/volta-networks/pceplib
$ cd pceplib
$ make
$ make install
$ export PCEPLIB_ROOT=$PWD
```

 - Configure FRR with the extra parameters:

```
--enable-pcep LDFLAGS="-L${PCEPLIB_ROOT}/install/lib" CPPFLAGS="-I${PCEPLIB_ROOT}/install/include"
```

To start pathd with pcep support the extra parameter `-M pathd_pcep` should be
passed to the pathd daemon.


Pathd Configuration
===================

Example:

.. code-block:: frr

  debug pathd pcep basic
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
    pcep
     pce-config GROUP1
      source-address 1.1.1.1
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


.. index:: [no] debug pathd pcep [basic|path|message|pceplib]
.. clicmd:: [no] debug pathd pcep [basic|path|message|pceplib]

   Enable or disable debugging for the pcep module:

     - basic: Enable basic PCEP logging
     - path: Log the path structures
     - message: Log the PCEP messages
     - pceplib: Enable pceplib logging


.. index:: pcep
.. clicmd:: pcep

   Configure PCEP support.


.. index:: [no] cep-config NAME
.. clicmd:: [no] pce-config NAME

   Define a shared PCE configuration that can be used in multiple PCE
   declarations.


.. index:: [no] pce NAME
.. clicmd:: [no] pce NAME

   Define or delete a PCE definition.


.. index:: config WORD
.. clicmd:: config WORD

   Select a shared configuration. If not defined, the default
   configuration will be used.


.. index:: address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]
.. clicmd:: address <ip A.B.C.D | ipv6 X:X::X:X> [port (1024-65535)]

   Define the address and port of the PCE.

   If not specified, the port is the standard PCEP port 4189.

   This should be specified in the PCC peer definition.


.. index:: source-address [ip A.B.C.D | ipv6 X:X::X:X] [port PORT]
.. clicmd:: source-address [ip A.B.C.D | ipv6 X:X::X:X] [port PORT]

   Define the address and/or port of the PCC as seen by the PCE.
   This can be used in a configuration group or a PCC peer declaration.

   If not specified, the source address will be the router identifier selected
   by zebra, and the port will be the standard PCEP port 4189.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. index:: tcp-md5-auth WORD
.. clicmd:: tcp-md5-auth WORD

   Enable TCP MD5 security with the given secret.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. index:: sr-draft07
.. clicmd:: sr-draft07

   Specify if a PCE only support segment routing draft 7, this flag will limit
   the PCC behavior to this draft.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. index:: pce-initiated
.. clicmd:: pce-initiated

   Specify if PCE-initiated LSP should be allowed for this PCE.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. index:: timer [keep-alive (1-63)] [min-peer-keep-alive (1-255)] [max-peer-keep-alive (1-255)] [dead-timer (4-255)] [min-peer-dead-timer (4-255)] [max-peer-dead-timer (4-255)] [pcep-request (1-120)] [session-timeout-interval (1-120)] [delegation-timeout (1-60)]
.. clicmd:: timer [keep-alive (1-63)] [min-peer-keep-alive (1-255)] [max-peer-keep-alive (1-255)] [dead-timer (4-255)] [min-peer-dead-timer (4-255)] [max-peer-dead-timer (4-255)] [pcep-request (1-120)] [session-timeout-interval (1-120)] [delegation-timeout (1-60)]

   Specify the PCEP timers.

   This can be specified in either the PCC peer definition or in a
   configuration group.


.. index:: [no] pcc
.. clicmd:: [no] pcc

   Disable or start the definition of a PCC.


.. index:: msd (1-32)
.. clicmd:: msd (1-32)

   Specify the maximum SID depth in a PCC definition.


.. index:: [no] peer WORD [precedence (1-255)]
.. clicmd:: [no] peer WORD [precedence (1-255)]

   Specify a peer and its precedence in a PCC definition.


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


.. index:: show debugging pathd
.. clicmd:: show debugging pathd

   Display the current status of the pathd debugging.


.. index:: show debugging pathd-pcep
.. clicmd:: show debugging pathd-pcep

   Display the current status of the pcep module debugging.


.. index:: show sr-te pcep counters
.. clicmd:: show sr-te pcep counters

   Display the counters from pceplib.


.. index:: show sr-te pcep pce-config [NAME]
.. clicmd:: show sr-te pcep pce-config [NAME]

   Display a shared configuration. if no name is specified, the default
   configuration will be displayed.


.. index:: show sr-te pcep pcc
.. clicmd:: show sr-te pcep pcc

   Display PCC information.


.. index:: show sr-te pcep session [NAME]
.. clicmd:: show sr-te pcep session [NAME]

   Display the information of a PCEP session, if not name is specified all the
   sessions will be displayed.


Utility Commands
----------------

.. index:: clear sr-te pcep session [NAME]
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
