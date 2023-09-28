.. _snmp-support:

************
SNMP Support
************

:abbr:`SNMP (Simple Network Managing Protocol)` is a widely implemented feature
for collecting network information from router and/or host. FRR itself does
not support SNMP agent (server daemon) functionality but is able to connect to
a SNMP agent using the the AgentX protocol (:rfc:`2741`) and make the
routing protocol MIBs available through it.

Note that SNMP Support needs to be enabled at compile-time and loaded as module
on daemon startup. Refer to :ref:`loadable-module-support` on the latter.  If
you do not start the daemons with snmp module support snmp will not work
properly.

.. _getting-and-installing-an-snmp-agent:

Getting and installing an SNMP agent
====================================

The supported SNMP agent is AgentX. We recommend to use
the latest version of `net-snmp` which was formerly known as `ucd-snmp`. It is
free and open software and available at `http://www.net-snmp.org/ <http://www.net-snmp.org/>`_
and as binary package for most Linux distributions.

.. _net-smtp-configuration:

NET-SNMP configuration
======================

Routers with a heavy amount of routes (e.g. BGP full table) might experience
problems with a hanging vtysh from time to time, 100% CPU on the snmpd or
even crashes of the frr daemon(s) due to stalls within AgentX. Once snmp
agents connects they start receiving a heavy amount of SNMP data (all the
routes) which cannot be handled quick enough. It's recommended (by several
vendors as well) to exclude these OID's unless you really need them, which
can be achieved by amending the default view from SNMP

:file:`/etc/snmp/snmpd.conf`:

::

   # This is the default view
   view all    included  .1 80
   # Remove ipRouteTable from view
   view all    excluded  .1.3.6.1.2.1.4.21
   # Remove ipNetToMediaTable from view
   view all    excluded  .1.3.6.1.2.1.4.22
   # Remove ipNetToPhysicalPhysAddress from view
   view all    excluded  .1.3.6.1.2.1.4.35
   # Remove ipCidrRouteTable  from view
   view all    excluded  .1.3.6.1.2.1.4.24
   # Optionally protect SNMP private/secret values
   view all    excluded  .1.3.6.1.6.3.15
   view all    excluded  .1.3.6.1.6.3.16
   view all    excluded  .1.3.6.1.6.3.18
   # Optionally allow SNMP public info (sysName, location, etc)
   view system included  .iso.org.dod.internet.mgmt.mib-2.system


.. _agentx-configuration:

AgentX configuration
====================

.. program:: configure

To enable AgentX protocol support, FRR must have been build with the
:option:`--enable-snmp` or `--enable-snmp=agentx` option. Both the
master SNMP agent (snmpd) and each of the FRR daemons must be configured. In
:file:`/etc/snmp/snmpd.conf`, the ``master agentx`` directive should be added.
In each of the FRR daemons, ``agentx`` command will enable AgentX support.

:file:`/etc/snmp/zebra.conf`:

::

   #
   # example access restrictions setup
   #
   com2sec readonly default public
   group MyROGroup v1 readonly
   view all included .1 80
   access MyROGroup "" any noauth exact all none none
   #
   # enable master agent for AgentX subagents
   #
   master agentx

:file:`/etc/frr/ospfd.conf:`

   .. code-block:: frr

      ! ... the rest of ospfd.conf has been omitted for clarity ...
      !
      agentx
      !


Upon successful connection, you should get something like this in the log of
each FRR daemons:

::

   2012/05/25 11:39:08 ZEBRA: snmp[info]: NET-SNMP version 5.4.3 AgentX subagent connected


Then, you can use the following command to check everything works as expected:

::

   # snmpwalk -c public -v1 localhost .1.3.6.1.2.1.14.1.1
   OSPF-MIB::ospfRouterId.0 = IpAddress: 192.168.42.109
   [...]

An example below is how to query SNMP for BGP:

   .. code-block:: shell

      $ # BGP4-MIB (https://www.circitor.fr/Mibs/Mib/B/BGP4-MIB.mib)
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.2.1.15

      $ # BGP4V2-MIB (http://www.circitor.fr/Mibs/Mib/B/BGP4V2-MIB.mib)
      $ # Information about the peers (bgp4V2PeerTable):
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.3.5.1.1.2
      ...
      .1.3.6.1.3.5.1.1.2.1.1.1.4.192.168.10.124 = Gauge32: 0
      .1.3.6.1.3.5.1.1.2.1.1.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 0
      .1.3.6.1.3.5.1.1.2.1.2.1.4.192.168.10.124 = INTEGER: 1
      .1.3.6.1.3.5.1.1.2.1.2.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.3.1.4.192.168.10.124 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.3.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 2A 02 47 80 0A BC 00 00 00 00 00 00 00 00 00 01
      .1.3.6.1.3.5.1.1.2.1.4.1.4.192.168.10.124 = INTEGER: 1
      .1.3.6.1.3.5.1.1.2.1.4.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.5.1.4.192.168.10.124 = Hex-STRING: C0 A8 0A 7C
      .1.3.6.1.3.5.1.1.2.1.5.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 2A 02 47 80 0A BC 00 00 00 00 00 00 00 00 00 02
      .1.3.6.1.3.5.1.1.2.1.6.1.4.192.168.10.124 = Gauge32: 179
      .1.3.6.1.3.5.1.1.2.1.6.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 179
      .1.3.6.1.3.5.1.1.2.1.7.1.4.192.168.10.124 = Gauge32: 65002
      .1.3.6.1.3.5.1.1.2.1.7.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 65002
      .1.3.6.1.3.5.1.1.2.1.8.1.4.192.168.10.124 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.8.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: C0 A8 0A 11
      .1.3.6.1.3.5.1.1.2.1.9.1.4.192.168.10.124 = Gauge32: 41894
      .1.3.6.1.3.5.1.1.2.1.9.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 39960
      .1.3.6.1.3.5.1.1.2.1.10.1.4.192.168.10.124 = Gauge32: 65001
      .1.3.6.1.3.5.1.1.2.1.10.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 65001
      .1.3.6.1.3.5.1.1.2.1.11.1.4.192.168.10.124 = Hex-STRING: C8 C8 C8 CA
      .1.3.6.1.3.5.1.1.2.1.11.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: C8 C8 C8 CA
      .1.3.6.1.3.5.1.1.2.1.12.1.4.192.168.10.124 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.12.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 2
      .1.3.6.1.3.5.1.1.2.1.13.1.4.192.168.10.124 = INTEGER: 6
      .1.3.6.1.3.5.1.1.2.1.13.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = INTEGER: 6

      $ # Information about the BGP table (bgp4V2NlriTable):
      $ snmpwalk -c public -v2c -On -Ln localhost .1.3.6.1.3.5.1.1.9
      ...
      .1.3.6.1.3.5.1.1.9.1.22.1.4.10.0.2.0.24.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.10.10.100.0.24.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.172.16.31.1.32.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.172.16.31.2.32.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.172.16.31.3.32.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.192.168.0.0.24.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.192.168.1.0.24.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.1.4.192.168.10.0.24.192.168.10.124 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.22.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.0.64.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Gauge32: 1
      .1.3.6.1.3.5.1.1.9.1.24.1.4.10.0.2.0.24.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.10.10.100.0.24.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.172.16.31.1.32.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.172.16.31.2.32.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.172.16.31.3.32.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.192.168.0.0.24.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.192.168.1.0.24.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.1.4.192.168.10.0.24.192.168.10.124 = Hex-STRING: 02 01 FD E9
      .1.3.6.1.3.5.1.1.9.1.24.2.16.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.0.64.42.2.71.128.10.188.0.0.0.0.0.0.0.0.0.2 = Hex-STRING: 02 01 FD E9

The AgentX protocol can be transported over a Unix socket or using TCP or UDP.
It usually defaults to a Unix socket and depends on how NetSNMP was built. If
need to configure FRR to use another transport, you can configure it through
:file:`/etc/snmp/frr.conf`:

::

   [snmpd]
   # Use a remote master agent
   agentXSocket tcp:192.168.15.12:705


Here is the syntax for using AgentX:

.. clicmd:: agentx

   Once enabled, it can't be unconfigured. Only removing from the daemons file
   the keyword ``agentx`` takes an effect.

.. include:: snmptrap.rst
