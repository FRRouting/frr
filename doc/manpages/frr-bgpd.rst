****
BGPD
****

.. include:: defines.rst
.. |DAEMON| replace:: bgpd

SYNOPSIS
========
|DAEMON| |synopsis-options-hv|

|DAEMON| |synopsis-options|

DESCRIPTION
===========
|DAEMON| is a routing component that works with the FRRouting routing engine.

OPTIONS
=======
OPTIONS available for the |DAEMON| command:

.. include:: common-options.rst

.. option:: -p, --bgp_port <port>

   Set the bgp protocol's port number. When port number is 0, that means do not
   listen bgp port.

.. option:: -l, --listenon

   Specify a specific IP address for bgpd to listen on, rather than its default
   of ``0.0.0.0`` / ``::``. This can be useful to constrain bgpd to an internal
   address, or to run multiple bgpd processes on one host.

.. option:: -n, --no_kernel

   Do not install learned routes into the linux kernel.  This option is useful
   for a route-reflector environment or if you are running multiple bgp
   processes in the same namespace.  This option is different than the --no_zebra
   option in that a ZAPI connection is made.

.. option:: -e, --ecmp

   Run BGP with a limited ecmp capability, that is different than what BGP
   was compiled with.  The value specified must be greater than 0 and less
   than or equal to the MULTIPATH_NUM specified on compilation.

.. option:: -Z, --no_zebra

   Do not communicate with zebra at all.  This is different than the --no_kernel
   option in that we do not even open a ZAPI connection to the zebra process.

.. option:: -s, --socket_size

   When opening tcp connections to our peers, set the socket send buffer
   size that the kernel will use for the peers socket.  This option
   is only really useful at a very large scale.  Experimentation should
   be done to see if this is helping or not at the scale you are running
   at.

LABEL MANAGER
-------------

.. option:: -I, --int_num

   Set zclient id. This is required when using Zebra label manager in proxy mode.

FILES
=====

|INSTALL_PREFIX_SBIN|/|DAEMON|
   The default location of the |DAEMON| binary.

|INSTALL_PREFIX_ETC|/|DAEMON|.conf
   The default location of the |DAEMON| config file.

$(PWD)/|DAEMON|.log
   If the |DAEMON| process is configured to output logs to a file, then you
   will find this file in the directory where you started |DAEMON|.

.. include:: epilogue.rst

CONFIGURATION NOTES
===================

eBGP Multihop and Reachability
------------------------------

When configuring eBGP sessions with the ''ebgp-multihop'' option, remember that 
this command only increases the allowed TTL for BGP packets.
It does *not* establish IP reachability on its own.

If you configure a neighbor that is not directly connected, you must:

*Ensure that an IGP or static route exists to reach the neighbor's address.
*If using loopback addresses, configure an update source:

    ::
	router bgp 64001
	  neighbor 192.0.2.2 remote-as 65002
	  neighbor 192.0.2.2 ebgp-multihop 5
	  neighbor 192.0.2.2 update-source l0

Without proper reachability, the session will remain in **Active** state and
bgpd will log messages such as:
Waiting for NHT, no path to neighbor present

This behavior is expected: ''ebgp-multihop'' does not create a route, it only relaxes the connected-check
so that BGP packets can traverse multiple hops.
