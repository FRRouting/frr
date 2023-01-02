.. _fabricd:

**********
OpenFabric
**********

OpenFabric, specified in :t:`draft-white-openfabric-06.txt`, is a routing
protocol derived from IS-IS, providing link-state routing with efficient
flooding for topologies like spine-leaf networks.

FRR implements OpenFabric in a daemon called *fabricd*

.. _configuring-fabricd:

Configuring fabricd
===================

There are no *fabricd* specific options. Common options can be specified
(:ref:`common-invocation-options`) to *fabricd*. *fabricd* needs to acquire
interface information from *zebra* in order to function. Therefore *zebra* must
be running before invoking *fabricd*. Also, if *zebra* is restarted then *fabricd*
must be too.

Like other daemons, *fabricd* configuration is done in an OpenFabric specific
configuration file :file:`fabricd.conf`.

.. _openfabric-router:

OpenFabric router
=================

To enable the OpenFabric routing protocol, an OpenFabric router needs to be created
in the configuration:

.. clicmd:: router openfabric WORD

   Enable or disable the OpenFabric process by specifying the OpenFabric domain with
   'WORD'.

.. clicmd:: net XX.XXXX. ... .XXX.XX

   Set/Unset network entity title (NET) provided in ISO format.

.. clicmd:: domain-password [clear | md5] <password>

   Configure the authentication password for a domain, as clear text or md5 one.

.. clicmd:: attached-bit [receive ignore | send]

   Set attached bit for inter-area traffic:

   - receive
     If LSP received with attached bit set, create default route to neighbor
   - send
     If L1|L2 router, set attached bit in LSP sent to L1 router
   
.. clicmd:: log-adjacency-changes

   Log changes in adjacency state.
     
.. clicmd:: set-overload-bit

   Set overload bit to avoid any transit traffic.

.. clicmd:: purge-originator


   Enable or disable :rfc:`6232` purge originator identification.

.. clicmd:: fabric-tier (0-14)


   Configure a static tier number to advertise as location in the fabric

.. _openfabric-timer:

OpenFabric Timer
================

.. clicmd:: lsp-gen-interval (1-120)


   Set minimum interval in seconds between regenerating same LSP.

.. clicmd:: lsp-refresh-interval (1-65235)


   Set LSP refresh interval in seconds.

.. clicmd:: max-lsp-lifetime (360-65535)


   Set LSP maximum LSP lifetime in seconds.

.. clicmd:: spf-interval (1-120)


   Set minimum interval between consecutive SPF calculations in seconds.

.. _openfabric-interface:

OpenFabric interface
====================

.. clicmd:: ip router openfabric WORD


.. _ip-router-openfabric-word:

   Activate OpenFabric on this interface. Note that the name
   of OpenFabric instance must be the same as the one used to configure the
   routing process (see command :clicmd:`router openfabric WORD`).

.. clicmd:: openfabric csnp-interval (1-600)


   Set CSNP interval in seconds.

.. clicmd:: openfabric hello-interval (1-600)


   Set Hello interval in seconds.

.. clicmd:: openfabric hello-multiplier (2-100)


   Set multiplier for Hello holding time.

.. clicmd:: openfabric metric (0-16777215)


   Set interface metric value.

.. clicmd:: openfabric passive


   Configure the passive mode for this interface.

.. clicmd:: openfabric password [clear | md5] <password>


   Configure the authentication password (clear or encoded text) for the
   interface.

.. clicmd:: openfabric psnp-interval (1-120)


   Set PSNP interval in seconds.

.. _showing-openfabric-information:

Showing OpenFabric information
==============================

.. clicmd:: show openfabric summary

   Show summary information about OpenFabric.

.. clicmd:: show openfabric hostname

   Show which hostnames are associated with which OpenFabric system ids.

.. clicmd:: show openfabric interface

.. clicmd:: show openfabric interface detail

.. clicmd:: show openfabric interface <interface name>

   Show state and configuration of specified OpenFabric interface, or all interfaces
   if no interface is given with or without details.

.. clicmd:: show openfabric neighbor

.. clicmd:: show openfabric neighbor <System Id>

.. clicmd:: show openfabric neighbor detail

   Show state and information of specified OpenFabric neighbor, or all neighbors if
   no system id is given with or without details.

.. clicmd:: show openfabric database

.. clicmd:: show openfabric database [detail]

.. clicmd:: show openfabric database <LSP id> [detail]

.. clicmd:: show openfabric database detail <LSP id>

   Show the OpenFabric database globally, for a specific LSP id without or with
   details.

.. clicmd:: show openfabric topology

   Show calculated OpenFabric paths and associated topology information.

.. _debugging-openfabric:

Debugging OpenFabric
====================

.. clicmd:: debug openfabric adj-packets

   OpenFabric Adjacency related packets.

.. clicmd:: debug openfabric checksum-errors

   OpenFabric LSP checksum errors.

.. clicmd:: debug openfabric events

   OpenFabric Events.

.. clicmd:: debug openfabric local-updates

   OpenFabric local update packets.

.. clicmd:: debug openfabric lsp-gen

   Generation of own LSPs.

.. clicmd:: debug openfabric lsp-sched

   Debug scheduling of generation of own LSPs.

.. clicmd:: debug openfabric packet-dump

   OpenFabric packet dump.

.. clicmd:: debug openfabric protocol-errors

   OpenFabric LSP protocol errors.

.. clicmd:: debug openfabric route-events

   OpenFabric Route related events.

.. clicmd:: debug openfabric snp-packets

   OpenFabric CSNP/PSNP packets.

.. clicmd:: debug openfabric spf-events

.. clicmd:: debug openfabric spf-statistics

.. clicmd:: debug openfabric spf-triggers

   OpenFabric Shortest Path First Events, Timing and Statistic Data and
   triggering events.

.. clicmd:: debug openfabric update-packets

   Update-related packets.

.. clicmd:: show debugging openfabric

   Print which OpenFabric debug levels are active.

Sample configuration
====================

A simple example:

.. code-block:: frr

   !
   interface lo
    ip address 192.0.2.1/32
    ip router openfabric 1
    ipv6 address 2001:db8::1/128
    ipv6 router openfabric 1
   !
   interface eth0
    ip router openfabric 1
    ipv6 router openfabric 1
   !
   interface eth1
    ip router openfabric 1
    ipv6 router openfabric 1
   !
   router openfabric 1
    net 49.0000.0000.0001.00


Alternative example:

.. code-block:: frr

   hostname fabricd

   router openfabric DEAD
     net 47.0023.0000.0003.0300.0100.0102.0304.0506.00
     lsp-lifetime 65535

     hostname isisd-router
     domain-password foobar

   interface eth0
    ip router openfabric DEAD
    openfabric hello-interval 5
    openfabric lsp-interval 1000

   ! -- optional
   openfabric retransmit-interval 10
   openfabric retransmit-throttle-interval
