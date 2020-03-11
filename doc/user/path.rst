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

.. _path-commands:

Pathd Configuration
===================

Example:

.. code-block:: frr

	pcc
	 pce ip 127.0.0.1
	!
	segment-list sl
	 index 10 mpls label 16010
	 index 20 mpls label 16030
	!
	sr-policy color 1 endpoint 1.1.1.1
	 name default
	 binding-sid 4000
	 candidate-path preference 100 name cand1 explicit segment-list sl
	 candidate-path preference 200 name cand2 dynamic
	!

.. index:: pcc
.. clicmd:: pcc

.. index:: pce ip ENDPOINT
.. clicmd:: pce ip ENDPOINT

.. index:: [no] segment-list NAME
.. clicmd:: [no] segment-list NAME

.. index:: [no] index INDEX mpls label LABEL
.. clicmd:: [no] index INDEX mpls label LABEL

.. index:: [no] sr-policy color COLOR endpoint ENDPOINT
.. clicmd:: [no] sr-policy color COLOR endpoint ENDPOINT

.. index:: [no] name NAME
.. clicmd:: [no] name NAME

.. index:: [no] binding-sid LABEL
.. clicmd:: [no] binding-sid LABEL

.. index:: [no] candidate-path preference PREFERENCE name NAME explicit segment-list SEGMENT-LIST-NAME
.. clicmd:: [no] candidate-path preference PREFERENCE name NAME explicit segment-list SEGMENT-LIST-NAME

.. index:: [no] candidate-path preference PREFERENCE name NAME dynamic
.. clicmd:: [no] candidate-path preference PREFERENCE name NAME dynamic


Introspection
=============

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

It is possible to steer traffic 'into' a SR Policy for routes learned through BGP using route-maps:

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

In this case the SR Policy with color `1` and endpoint `1.1.1.1` is selected.
