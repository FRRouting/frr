.. _EIGRP:

*****
EIGRP
*****

EIGRP -- Routing Information Protocol is widely deployed interior gateway
routing protocol. EIGRP was developed in the 1990's. EIGRP is a
@dfn{distance-vector} protocol and is based on the @dfn{dual} algorithms.
As a distance-vector protocol, the EIGRP router send updates to its
neighbors as networks change, thus allowing the convergence to a
known topology.

*eigrpd* supports EIGRP as described in RFC7868

.. _Starting_and_Stopping_eigrpd:

Starting and Stopping eigrpd
============================

The default configuration file name of *eigrpd*'s is
:file:`eigrpd.conf`. When invocation *eigrpd* searches directory
|INSTALL_PREFIX_ETC|. If :file:`eigrpd.conf` is not there next
search current directory. If an integrated config is specified
configuration is written into frr.conf

The EIGRP protocol requires interface information
maintained by *zebra* daemon. So running *zebra*
is mandatory to run *eigrpd*. Thus minimum sequence for running
EIGRP is like below:

::

  # zebra -d
  # eigrpd -d
  

Please note that *zebra* must be invoked before *eigrpd*.

To stop *eigrpd*. Please use @command{kill `cat
/var/run/eigrpd.pid`}. Certain signals have special meanings to *eigrpd*.

+------------------+-----------------------------------------------------------+
| Signal           | Meaning                                                   |
+==================+===========================================================+
| SIGHUP & SIGUSR1 | Rotate the log file                                       |
+------------------+-----------------------------------------------------------+
| SIGINT & SIGTERM | Sweep all installed EIGRP routes and gracefully terminate |
+------------------+-----------------------------------------------------------+


*eigrpd* invocation options. Common options that can be specified
(:ref:`Common_Invocation_Options`).

.. program:: eigrpd

.. option:: -r
.. option:: --retain

   When the program terminates, retain routes added by *eigrpd*.

.. _EIGRP_Configuration:

EIGRP Configuration
===================

.. index:: router eigrp (1-65535)

``router eigrp (1-65535)``
   The `router eigrp` command is necessary to enable EIGRP. To disable EIGRP,
   use the `no router eigrp (1-65535)` command. EIGRP must be enabled before
   carrying out any of the EIGRP commands.

.. index:: no router eigrp (1-65535)

``no router eigrp (1-65535)``
   Disable EIGRP.

.. index:: network NETWORK

``network NETWORK``
.. index:: no network NETWORK

``no network NETWORK``
   Set the EIGRP enable interface by `network`. The interfaces which
   have addresses matching with `network` are enabled.

   This group of commands either enables or disables EIGRP interfaces between
   certain numbers of a specified network address. For example, if the
   network for 10.0.0.0/24 is EIGRP enabled, this would result in all the
   addresses from 10.0.0.0 to 10.0.0.255 being enabled for EIGRP. The `no
   network` command will disable EIGRP for the specified network.

   Below is very simple EIGRP configuration. Interface `eth0` and
   interface which address match to `10.0.0.0/8` are EIGRP enabled.

::

    !
    router eigrp 1
     network 10.0.0.0/8
    !
    

  Passive interface

.. index:: passive-interface (IFNAME|default)

``passive-interface (IFNAME|default)``
.. index:: no passive-interface IFNAME

``no passive-interface IFNAME``
   This command sets the specified interface to passive mode. On passive mode
   interface, all receiving packets are ignored and eigrpd does
   not send either multicast or unicast EIGRP packets except to EIGRP neighbors
   specified with `neighbor` command. The interface may be specified
   as `default` to make eigrpd default to passive on all interfaces. 

   The default is to be passive on all interfaces.

.. _How_to_Announce_EIGRP_route:

How to Announce EIGRP route
===========================

.. index:: redistribute kernel

``redistribute kernel``
.. index:: redistribute kernel metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

``redistribute kernel metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)``
.. index:: no redistribute kernel

``no redistribute kernel``
  `redistribute kernel` redistributes routing information from
  kernel route entries into the EIGRP tables. `no redistribute kernel`
  disables the routes.

.. index:: redistribute static

``redistribute static``
.. index:: redistribute static metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

``redistribute static metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)``
.. index:: no redistribute static

``no redistribute static``
    `redistribute static` redistributes routing information from
    static route entries into the EIGRP tables. `no redistribute static`
    disables the routes.

.. index:: redistribute connected

``redistribute connected``
.. index:: redistribute connected metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

``redistribute connected metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)``
.. index:: no redistribute connected

``no redistribute connected``
  Redistribute connected routes into the EIGRP tables. `no redistribute
  connected` disables the connected routes in the EIGRP tables. This command
  redistribute connected of the interface which EIGRP disabled. The connected
  route on EIGRP enabled interface is announced by default.

.. index:: redistribute ospf

``redistribute ospf``
.. index:: redistribute ospf metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

``redistribute ospf metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)``
.. index:: no redistribute ospf

``no redistribute ospf``
  `redistribute ospf` redistributes routing information from ospf route
  entries into the EIGRP tables. `no redistribute ospf` disables the
  routes.

.. index:: redistribute bgp

``redistribute bgp``
.. index:: redistribute bgp metric  (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)

``redistribute bgp metric  (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)``
.. index:: no redistribute bgp

``no redistribute bgp``
  `redistribute bgp` redistributes routing information from
  bgp route entries into the EIGRP tables. `no redistribute bgp`
  disables the routes.

.. _Show_EIGRP_Information:

Show EIGRP Information
======================

To display EIGRP routes.

.. index:: show ip eigrp topology

``show ip eigrp topology``
  Show EIGRP routes.

The command displays all EIGRP routes.

.. index:: show ip eigrp topology

``show ip eigrp topology``
  The command displays current EIGRP status

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

``debug eigrp packets``
  Debug eigrp packets

`debug eigrp` will show EIGRP packets that are sent and recevied.

.. index:: debug eigrp transmit

``debug eigrp transmit``
  Debug eigrp transmit events

`debug eigrp transmit` will display detailed information about the EIGRP transmit events.

.. index:: show debugging eigrp

``show debugging eigrp``
  Display *eigrpd*'s debugging option.

`show debugging eigrp` will show all information currently set for eigrpd
debug.

