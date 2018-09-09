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

.. index:: router openfabric WORD
.. clicmd:: router openfabric WORD

.. index:: no router openfabric WORD
.. clicmd:: no router openfabric WORD

   Enable or disable the OpenFabric process by specifying the OpenFabric domain with
   'WORD'.

.. index:: net XX.XXXX. ... .XXX.XX
.. clicmd:: net XX.XXXX. ... .XXX.XX

.. index:: no net XX.XXXX. ... .XXX.XX
.. clicmd:: no net XX.XXXX. ... .XXX.XX

   Set/Unset network entity title (NET) provided in ISO format.

.. index:: domain-password [clear | md5] <password>
.. clicmd:: domain-password [clear | md5] <password>

.. index:: no domain-password
.. clicmd:: no domain-password

   Configure the authentication password for a domain, as clear text or md5 one.

.. index:: log-adjacency-changes
.. clicmd:: log-adjacency-changes

.. index:: no log-adjacency-changes
.. clicmd:: no log-adjacency-changes

   Log changes in adjacency state.

.. index:: set-overload-bit
.. clicmd:: set-overload-bit

.. index:: no set-overload-bit
.. clicmd:: no set-overload-bit

   Set overload bit to avoid any transit traffic.

.. index:: purge-originator
.. clicmd:: purge-originator

.. index:: no purge-originator
.. clicmd:: no purge-originator

   Enable or disable :rfc:`6232` purge originator identification.

.. index:: fabric-tier (0-14)
.. clicmd:: fabric-tier (0-14)

.. index:: no fabric-tier
.. clicmd:: no fabric-tier

   Configure a static tier number to advertise as location in the fabric

.. _openfabric-timer:

OpenFabric Timer
================

.. index:: lsp-gen-interval (1-120)
.. clicmd:: lsp-gen-interval (1-120)

.. index:: no lsp-gen-interval
.. clicmd:: no lsp-gen-interval

   Set minimum interval in seconds between regenerating same LSP.

.. index:: lsp-refresh-interval (1-65235)
.. clicmd:: lsp-refresh-interval (1-65235)

.. index:: no lsp-refresh-interval
.. clicmd:: no lsp-refresh-interval

   Set LSP refresh interval in seconds.

.. index:: max-lsp-lifetime (360-65535)
.. clicmd:: max-lsp-lifetime (360-65535)

.. index:: no max-lsp-lifetime
.. clicmd:: no max-lsp-lifetime

   Set LSP maximum LSP lifetime in seconds.

.. index:: spf-interval (1-120)
.. clicmd:: spf-interval (1-120)

.. index:: no spf-interval
.. clicmd:: no spf-interval

   Set minimum interval between consecutive SPF calculations in seconds.

.. _openfabric-interface:

OpenFabric interface
====================

.. index:: ip router openfabric WORD
.. clicmd:: ip router openfabric WORD

.. index:: no ip router openfabric WORD
.. clicmd:: no ip router openfabric WORD

.. _ip-router-openfabric-word:

   Activate OpenFabric on this interface. Note that the name
   of OpenFabric instance must be the same as the one used to configure the
   routing process (see command :clicmd:`router openfabric WORD`).

.. index:: openfabric csnp-interval (1-600)
.. clicmd:: openfabric csnp-interval (1-600)

.. index:: no openfabric csnp-interval
.. clicmd:: no openfabric csnp-interval

   Set CSNP interval in seconds.

.. index:: openfabric hello-interval (1-600)
.. clicmd:: openfabric hello-interval (1-600)

.. index:: no openfabric hello-interval
.. clicmd:: no openfabric hello-interval

   Set Hello interval in seconds.

.. index:: openfabric hello-multiplier (2-100)
.. clicmd:: openfabric hello-multiplier (2-100)

.. index:: no openfabric hello-multiplier
.. clicmd:: no openfabric hello-multiplier

   Set multiplier for Hello holding time.

.. index:: openfabric metric (0-16777215)
.. clicmd:: openfabric metric (0-16777215)

.. index:: no openfabric metric
.. clicmd:: no openfabric metric

   Set interface metric value.

.. index:: openfabric passive
.. clicmd:: openfabric passive

.. index:: no openfabric passive
.. clicmd:: no openfabric passive

   Configure the passive mode for this interface.

.. index:: openfabric password [clear | md5] <password>
.. clicmd:: openfabric password [clear | md5] <password>

.. index:: no openfabric password
.. clicmd:: no openfabric password

   Configure the authentication password (clear or encoded text) for the
   interface.

.. index:: openfabric psnp-interval (1-120)
.. clicmd:: openfabric psnp-interval (1-120)

.. index:: no openfabric psnp-interval
.. clicmd:: no openfabric psnp-interval

   Set PSNP interval in seconds.

.. _showing-openfabric-information:

Showing OpenFabric information
==============================

.. index:: show openfabric summary
.. clicmd:: show openfabric summary

   Show summary information about OpenFabric.

.. index:: show openfabric hostname
.. clicmd:: show openfabric hostname

   Show which hostnames are associated with which OpenFabric system ids.

.. index:: show openfabric interface
.. clicmd:: show openfabric interface

.. index:: show openfabric interface detail
.. clicmd:: show openfabric interface detail

.. index:: show openfabric interface <interface name>
.. clicmd:: show openfabric interface <interface name>

   Show state and configuration of specified OpenFabric interface, or all interfaces
   if no interface is given with or without details.

.. index:: show openfabric neighbor
.. clicmd:: show openfabric neighbor

.. index:: show openfabric neighbor <System Id>
.. clicmd:: show openfabric neighbor <System Id>

.. index:: show openfabric neighbor detail
.. clicmd:: show openfabric neighbor detail

   Show state and information of specified OpenFabric neighbor, or all neighbors if
   no system id is given with or without details.

.. index:: show openfabric database
.. clicmd:: show openfabric database

.. index:: show openfabric database [detail]
.. clicmd:: show openfabric database [detail]

.. index:: show openfabric database <LSP id> [detail]
.. clicmd:: show openfabric database <LSP id> [detail]

.. index:: show openfabric database detail <LSP id>
.. clicmd:: show openfabric database detail <LSP id>

   Show the OpenFabric database globally, for a specific LSP id without or with
   details.

.. index:: show openfabric topology
.. clicmd:: show openfabric topology

   Show calculated OpenFabric paths and associated topology information.

.. _debugging-openfabric:

Debugging OpenFabric
====================

.. index:: debug openfabric adj-packets
.. clicmd:: debug openfabric adj-packets

.. index:: no debug openfabric adj-packets
.. clicmd:: no debug openfabric adj-packets

OpenFabric Adjacency related packets.

.. index:: debug openfabric checksum-errors
.. clicmd:: debug openfabric checksum-errors

.. index:: no debug openfabric checksum-errors
.. clicmd:: no debug openfabric checksum-errors

OpenFabric LSP checksum errors.

.. index:: debug openfabric events
.. clicmd:: debug openfabric events

.. index:: no debug openfabric events
.. clicmd:: no debug openfabric events

OpenFabric Events.

.. index:: debug openfabric local-updates
.. clicmd:: debug openfabric local-updates

.. index:: no debug openfabric local-updates
.. clicmd:: no debug openfabric local-updates

OpenFabric local update packets.

.. index:: debug openfabric lsp-gen
.. clicmd:: debug openfabric lsp-gen

.. index:: no debug openfabric lsp-gen
.. clicmd:: no debug openfabric lsp-gen

Generation of own LSPs.

.. index:: debug openfabric lsp-sched
.. clicmd:: debug openfabric lsp-sched

.. index:: no debug openfabric lsp-sched
.. clicmd:: no debug openfabric lsp-sched

Debug scheduling of generation of own LSPs.

.. index:: debug openfabric packet-dump
.. clicmd:: debug openfabric packet-dump

.. index:: no debug openfabric packet-dump
.. clicmd:: no debug openfabric packet-dump

OpenFabric packet dump.

.. index:: debug openfabric protocol-errors
.. clicmd:: debug openfabric protocol-errors

.. index:: no debug openfabric protocol-errors
.. clicmd:: no debug openfabric protocol-errors

OpenFabric LSP protocol errors.

.. index:: debug openfabric route-events
.. clicmd:: debug openfabric route-events

.. index:: no debug openfabric route-events
.. clicmd:: no debug openfabric route-events

OpenFabric Route related events.

.. index:: debug openfabric snp-packets
.. clicmd:: debug openfabric snp-packets

.. index:: no debug openfabric snp-packets
.. clicmd:: no debug openfabric snp-packets

OpenFabric CSNP/PSNP packets.

.. index:: debug openfabric spf-events
.. clicmd:: debug openfabric spf-events

.. index:: debug openfabric spf-statistics
.. clicmd:: debug openfabric spf-statistics

.. index:: debug openfabric spf-triggers
.. clicmd:: debug openfabric spf-triggers

.. index:: no debug openfabric spf-events
.. clicmd:: no debug openfabric spf-events

.. index:: no debug openfabric spf-statistics
.. clicmd:: no debug openfabric spf-statistics

.. index:: no debug openfabric spf-triggers
.. clicmd:: no debug openfabric spf-triggers

OpenFabric Shortest Path First Events, Timing and Statistic Data and triggering
events.

.. index:: debug openfabric update-packets
.. clicmd:: debug openfabric update-packets

.. index:: no debug openfabric update-packets
.. clicmd:: no debug openfabric update-packets

Update related packets.

.. index:: show debugging openfabric
.. clicmd:: show debugging openfabric

   Print which OpenFabric debug levels are active.

OpenFabric configuration example
================================

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
