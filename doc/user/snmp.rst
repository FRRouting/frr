.. _snmp-support:

************
SNMP Support
************

:abbr:`SNMP (Simple Network Managing Protocol)` is a widely implemented feature
for collecting network information from router and/or host. FRR itself does
not support SNMP agent (server daemon) functionality but is able to connect to
a SNMP agent using the SMUX protocol (:rfc:`1227`) or the AgentX protocol
(:rfc:`2741`) and make the routing protocol MIBs available through it.

Note that SNMP Support needs to be enabled at compile-time and loaded as module
on daemon startup. Refer to :ref:`loadable-module-support` on the latter.

.. _getting-and-installing-an-snmp-agent:

Getting and installing an SNMP agent
====================================

There are several SNMP agent which support SMUX or AgentX. We recommend to use
the latest version of `net-snmp` which was formerly known as `ucd-snmp`. It is
free and open software and available at `http://www.net-snmp.org/ <http://www.net-snmp.org/>`_
and as binary package for most Linux distributions. `net-snmp` has to be
compiled with `--with-mib-modules=agentx` to be able to accept connections from
FRR using AgentX protocol or with `--with-mib-modules=smux` to use SMUX
protocol.

Nowadays, SMUX is a legacy protocol. The AgentX protocol should be preferred
for any new deployment. Both protocols have the same coverage.

.. _agentx-configuration:

AgentX configuration
====================

.. program:: configure

To enable AgentX protocol support, FRR must have been build with the
:option:`--enable-snmp` or `--enable-snmp=agentx` option. Both the
master SNMP agent (snmpd) and each of the FRR daemons must be configured. In
:file:`/etc/snmp/snmpd.conf`, the ``master agentx`` directive should be added.
In each of the FRR daemons, ``agentx`` command will enable AgentX support.

:file:`/etc/snmp/snmpd.conf`:

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


.. _smux-configuration:

SMUX configuration
==================

To enable SMUX protocol support, FRR must have been build with the
:option:`--enable-snmp` option.

A separate connection has then to be established between the SNMP agent (snmpd)
and each of the FRR daemons. This connections each use different OID numbers
and passwords. Be aware that this OID number is not the one that is used in
queries by clients, it is solely used for the intercommunication of the
daemons.

In the following example the ospfd daemon will be connected to the snmpd daemon
using the password "frr_ospfd". For testing it is recommending to take exactly
the below snmpd.conf as wrong access restrictions can be hard to debug.

:file:`/etc/snmp/snmpd.conf`:

::

   #
   # example access restrictions setup
   #
   com2sec readonly default public
   group MyROGroup v1 readonly
   view all included .1 80
   access MyROGroup "" any noauth exact all none none
   #
   # the following line is relevant for FRR
   #
   smuxpeer .1.3.6.1.4.1.3317.1.2.5 frr_ospfd

:file:`/etc/frr/ospf`:

::

   ! ... the rest of ospfd.conf has been omitted for clarity ...
   !
   smux peer .1.3.6.1.4.1.3317.1.2.5 frr_ospfd
   !


After restarting snmpd and frr, a successful connection can be verified in the
syslog and by querying the SNMP daemon:

::

   snmpd[12300]: [smux_accept] accepted fd 12 from 127.0.0.1:36255
   snmpd[12300]: accepted smux peer: \\
      oid GNOME-PRODUCT-ZEBRA-MIB::ospfd, frr-0.96.5

   # snmpwalk -c public -v1 localhost .1.3.6.1.2.1.14.1.1
   OSPF-MIB::ospfRouterId.0 = IpAddress: 192.168.42.109


Be warned that the current version (5.1.1) of the Net-SNMP daemon writes a line
for every SNMP connect to the syslog which can lead to enormous log file sizes.
If that is a problem you should consider to patch snmpd and comment out the
troublesome `snmp_log()` line in the function `netsnmp_agent_check_packet()` in
`agent/snmp_agent.c`.

MIB and command reference
=========================

The following OID numbers are used for the interprocess communication of snmpd and
the FRR daemons with SMUX only.::

  .    (OIDs below .iso.org.dod.internet.private.enterprises)
  zebra	.1.3.6.1.4.1.3317.1.2.1 .gnome.gnomeProducts.zebra.zserv
  bgpd	.1.3.6.1.4.1.3317.1.2.2 .gnome.gnomeProducts.zebra.bgpd
  ripd	.1.3.6.1.4.1.3317.1.2.3 .gnome.gnomeProducts.zebra.ripd
  ospfd	.1.3.6.1.4.1.3317.1.2.5 .gnome.gnomeProducts.zebra.ospfd
  ospf6d	.1.3.6.1.4.1.3317.1.2.6 .gnome.gnomeProducts.zebra.ospf6d


Sadly, SNMP has not been implemented in all daemons yet. The following
OID numbers are used for querying the SNMP daemon by a client:::

  zebra	.1.3.6.1.2.1.4.24   .iso.org.dot.internet.mgmt.mib-2.ip.ipForward
  ospfd	.1.3.6.1.2.1.14	    .iso.org.dot.internet.mgmt.mib-2.ospf
  bgpd	.1.3.6.1.2.1.15	    .iso.org.dot.internet.mgmt.mib-2.bgp
  ripd	.1.3.6.1.2.1.23	    .iso.org.dot.internet.mgmt.mib-2.rip2
  ospf6d	.1.3.6.1.3.102	    .iso.org.dod.internet.experimental.ospfv3


The following syntax is understood by the FRR daemons for configuring SNMP
using SMUX:

.. index:: smux peer OID
.. clicmd:: smux peer OID
.. index:: no smux peer OID
.. clicmd:: no smux peer OID
.. index:: smux peer OID PASSWORD
.. clicmd:: smux peer OID PASSWORD
.. index:: no smux peer OID PASSWORD
.. clicmd:: no smux peer OID PASSWORD

Here is the syntax for using AgentX:

.. index:: agentx
.. clicmd:: agentx
.. index:: no agentx
.. clicmd:: no agentx


.. include:: snmptrap.rst
