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


.. include:: snmptrap.rst
