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

   Do not install BGP routes into zebra (and therefore not into the Linux
   kernel).  This is the supported way to keep BGP from programming routes,
   for example on a route reflector or when running multiple bgpd processes
   in the same namespace.

   bgpd still opens a ZAPI connection to zebra.  FRR protocol daemons are
   tightly integrated with zebra and are not intended to run without it.

.. option:: -e, --ecmp

   Run BGP with a limited ecmp capability, that is different than what BGP
   was compiled with.  The value specified must be greater than 0 and less
   than or equal to the MULTIPATH_NUM specified on compilation.

.. option:: -Z, --no_zebra

   Deprecated.  This option is buggy and misleading: it does not fully stop
   communication with zebra, and FRR is tightly integrated with zebra.

   Do not use this option.  It will be removed in a future release.  To avoid
   installing BGP routes into zebra, use ``-n`` / ``--no_kernel`` (or
   ``bgp no-rib`` at runtime).

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

