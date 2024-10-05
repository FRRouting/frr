.. _eigrp:

*****
EIGRP
*****

.. glossary::

   DUAL
      The *Diffusing Update ALgorithm*, a :term:`Bellman-Ford` based routing
      algorithm used by EIGRP.

EIGRP -- Routing Information Protocol is widely deployed interior gateway
routing protocol. EIGRP was developed in the 1990's. EIGRP is a
:term:`distance-vector` protocol and is based on the :term:`DUAL` algorithms.
As a distance-vector protocol, the EIGRP router send updates to its
neighbors as networks change, thus allowing the convergence to a
known topology.

*eigrpd* supports EIGRP as described in RFC7868

.. _starting-and-stopping-eigrpd:

Starting and Stopping eigrpd
============================

.. include:: config-include.rst

If starting daemons by hand then please note, the EIGRP protocol requires
interface information maintained by *zebra* daemon. So running *zebra* is
mandatory to run *eigrpd*. Thus minimum sequence for running EIGRP is:

::

  # zebra -d
  # eigrpd -d

Please note that *zebra* must be invoked before *eigrpd*.

To stop *eigrpd*, please use::

   kill `cat /var/run/frr/eigrpd.pid`

Certain signals have special meanings to *eigrpd*.

+------------------+-----------------------------------------------------------+
| Signal           | Meaning                                                   |
+==================+===========================================================+
| SIGHUP & SIGUSR1 | Rotate the log file                                       |
+------------------+-----------------------------------------------------------+
| SIGINT & SIGTERM | Sweep all installed EIGRP routes and gracefully terminate |
+------------------+-----------------------------------------------------------+


*eigrpd* invocation options. Common options that can be specified
(:ref:`common-invocation-options`).

.. program:: eigrpd

.. _eigrp-configuration:

EIGRP Configuration
===================

.. clicmd:: router eigrp (1-65535) [vrf NAME]

   The `router eigrp` command is necessary to enable EIGRP. To disable EIGRP,
   use the `no router eigrp (1-65535)` command. EIGRP must be enabled before
   carrying out any of the EIGRP commands.  Specify vrf NAME if you want
   eigrp to work within the specified vrf.

.. clicmd:: network NETWORK

   Set the EIGRP enable interface by `network`. The interfaces which
   have addresses matching with `network` are enabled.

   This group of commands either enables or disables EIGRP interfaces between
   certain numbers of a specified network address. For example, if the
   network for 10.0.0.0/24 is EIGRP enabled, this would result in all the
   addresses from 10.0.0.0 to 10.0.0.255 being enabled for EIGRP. The `no
   network` command will disable EIGRP for the specified network.

   Below is very simple EIGRP configuration. Interface `eth0` and
   interface which address match to `10.0.0.0/8` are EIGRP enabled.

   .. code-block:: frr

      !
      router eigrp 1
       network 10.0.0.0/8
      !


.. clicmd:: passive-interface (IFNAME|default)


   This command sets the specified interface to passive mode. On passive mode
   interface, all receiving packets are ignored and eigrpd does not send either
   multicast or unicast EIGRP packets except to EIGRP neighbors specified with
   `neighbor` command. The interface may be specified as `default` to make
   eigrpd default to passive on all interfaces.

   The default is to be passive on all interfaces.

.. _how-to-announce-eigrp-route:

How to Announce EIGRP route
===========================

Redistribute routes into EIGRP:

.. clicmd:: redistribute <babel|bgp|connected|isis|kernel|openfabric|ospf|rip|sharp|static|table> [metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)]

   The ``redistribute`` family of commands imports routing information from
   other sources into EIGRP's tables. Redistribution may be disabled with the
   ``no`` form of the commands.

   Note that connected routes on interfaces EIGRP is enabled on are announced
   by default.

   Optionally, various EIGRP metrics may be specified. These metrics will be
   applied to the imported routes.


.. _show-eigrp-information:

Show EIGRP Information
======================

.. clicmd:: show ip eigrp [vrf NAME] topology

   Display current EIGRP status.

   ::

      eigrpd> **show ip eigrp topology**
      # show ip eigrp topo

      EIGRP Topology Table for AS(4)/ID(0.0.0.0)

      Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply
             r - reply Status, s - sia Status

      P  10.0.2.0/24, 1 successors, FD is 256256, serno: 0
             via Connected, enp0s3

.. clicmd:: show ip eigrp [vrf NAME] interface

   Display the list of interfaces associated with a particular eigrp
   instance.

.. clicmd:: show ip eigrp [vrf NAME] neighbor

   Display the list of neighbors that have been established within
   a particular eigrp instance.

EIGRP Debug Commands
====================

Debug for EIGRP protocol.

.. clicmd:: debug eigrp packets

   Debug eigrp packets

   ``debug eigrp`` will show EIGRP packets that are sent and received.

.. clicmd:: debug eigrp transmit

   Debug eigrp transmit events

   ``debug eigrp transmit`` will display detailed information about the EIGRP
   transmit events.

.. clicmd:: show debugging eigrp

   Display *eigrpd*'s debugging option.

   ``show debugging eigrp`` will show all information currently set for eigrpd
   debug.


Sample configuration
====================

.. code-block:: frr

   hostname eigrpd
   password zebra
   enable password please-set-at-here
   !
   router eigrp 4453
     network 192.168.1.0/24
   !
   log stdout

