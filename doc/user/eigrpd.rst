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

The default configuration file name of *eigrpd*'s is :file:`eigrpd.conf`. When
invocation *eigrpd* searches directory |INSTALL_PREFIX_ETC|. If
:file:`eigrpd.conf` is not there next search current directory. If an
integrated config is specified configuration is written into :file:`frr.conf`.

The EIGRP protocol requires interface information maintained by *zebra* daemon.
So running *zebra* is mandatory to run *eigrpd*. Thus minimum sequence for
running EIGRP is:

::

  # zebra -d
  # eigrpd -d


Please note that *zebra* must be invoked before *eigrpd*.

To stop *eigrpd*, please use ::
   kill `cat /var/run/eigrpd.pid`

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

.. index:: router eigrp (1-65535)
.. clicmd:: router eigrp (1-65535)

   The `router eigrp` command is necessary to enable EIGRP. To disable EIGRP,
   use the `no router eigrp (1-65535)` command. EIGRP must be enabled before
   carrying out any of the EIGRP commands.

.. index:: no router eigrp (1-65535)
.. clicmd:: no router eigrp (1-65535)

   Disable EIGRP.

.. index:: network NETWORK
.. clicmd:: network NETWORK

.. index:: no network NETWORK
.. clicmd:: no network NETWORK

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


.. index:: passive-interface (IFNAME|default)
.. clicmd:: passive-interface (IFNAME|default)

.. index:: no passive-interface IFNAME
.. clicmd:: no passive-interface IFNAME

   This command sets the specified interface to passive mode. On passive mode
   interface, all receiving packets are ignored and eigrpd does not send either
   multicast or unicast EIGRP packets except to EIGRP neighbors specified with
   `neighbor` command. The interface may be specified as `default` to make
   eigrpd default to passive on all interfaces.

   The default is to be passive on all interfaces.

.. _how-to-announce-eigrp-route:

How to Announce EIGRP route
===========================

.. index:: redistribute kernel
.. clicmd:: redistribute kernel

.. index:: redistribute kernel metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)
.. clicmd:: redistribute kernel metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

.. index:: no redistribute kernel
.. clicmd:: no redistribute kernel

   `redistribute kernel` redistributes routing information from kernel route
   entries into the EIGRP tables. `no redistribute kernel` disables the routes.

.. index:: redistribute static
.. clicmd:: redistribute static

.. index:: redistribute static metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)
.. clicmd:: redistribute static metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

.. index:: no redistribute static
.. clicmd:: no redistribute static

   `redistribute static` redistributes routing information from static route
   entries into the EIGRP tables. `no redistribute static` disables the routes.

.. index:: redistribute connected
.. clicmd:: redistribute connected

.. index:: redistribute connected metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)
.. clicmd:: redistribute connected metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

.. index:: no redistribute connected
.. clicmd:: no redistribute connected

   Redistribute connected routes into the EIGRP tables. `no redistribute
   connected` disables the connected routes in the EIGRP tables. This command
   redistribute connected of the interface which EIGRP disabled. The connected
   route on EIGRP enabled interface is announced by default.

.. index:: redistribute ospf
.. clicmd:: redistribute ospf

.. index:: redistribute ospf metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)
.. clicmd:: redistribute ospf metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

.. index:: no redistribute ospf
.. clicmd:: no redistribute ospf

   `redistribute ospf` redistributes routing information from ospf route
   entries into the EIGRP tables. `no redistribute ospf` disables the routes.

.. index:: redistribute bgp
.. clicmd:: redistribute bgp

.. index:: redistribute bgp metric  (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)
.. clicmd:: redistribute bgp metric  (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

.. index:: no redistribute bgp
.. clicmd:: no redistribute bgp

   `redistribute bgp` redistributes routing information from bgp route entries
   into the EIGRP tables. `no redistribute bgp` disables the routes.

.. _show-eigrp-information:

Show EIGRP Information
======================

.. index:: show ip eigrp topology
.. clicmd:: show ip eigrp topology

   Display current EIGRP status.

   ::

      eigrpd> **show ip eigrp topology**
      # show ip eigrp topo

      EIGRP Topology Table for AS(4)/ID(0.0.0.0)

      Codes: P - Passive, A - Active, U - Update, Q - Query, R - Reply
             r - reply Status, s - sia Status

      P  10.0.2.0/24, 1 successors, FD is 256256, serno: 0
             via Connected, enp0s3


EIGRP Debug Commands
====================

Debug for EIGRP protocol.

.. index:: debug eigrp packets
.. clicmd:: debug eigrp packets

   Debug eigrp packets

   ``debug eigrp`` will show EIGRP packets that are sent and received.

.. index:: debug eigrp transmit
.. clicmd:: debug eigrp transmit

   Debug eigrp transmit events

   ``debug eigrp transmit`` will display detailed information about the EIGRP
   transmit events.

.. index:: show debugging eigrp
.. clicmd:: show debugging eigrp

   Display *eigrpd*'s debugging option.

   ``show debugging eigrp`` will show all information currently set for eigrpd
   debug.

