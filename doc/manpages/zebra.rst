*****
ZEBRA
*****

.. include:: defines.rst
.. |DAEMON| replace:: zebra

SYNOPSIS
========
|DAEMON| |synopsis-options-hv|

|DAEMON| |synopsis-options|

DESCRIPTION
===========
|DAEMON| is a routing manager that implements the zebra route engine. zebra supports all protocol daemons in the FRRouting suite.

OPTIONS
=======
OPTIONS available for the |DAEMON| command:

.. include:: common-options.rst

.. option:: -b, --batch

   Runs in batch mode, zebra parses its config and exits.

.. option:: -k, --keep_kernel

   On startup, don't delete self inserted routes.

.. option:: -s, --nl-bufsize <netlink-buffer-size>

   Set netlink receive buffer size. There are cases where zebra daemon can't handle flood of netlink messages from kernel. If you ever see "recvmsg overrun" messages in zebra log, you are in trouble.

   Solution is to increase receive buffer of netlink socket. Note that kernel < 2.6.14 doesn't allow to increase it over maximum value defined in /proc/sys/net/core/rmem_max. If you want to do it, you have to increase maximum before starting zebra.

   Note that this affects Linux only.


.. option:: -n, --vrfwnetns

   Enable namespace VRF backend. By default, the VRF backend relies on VRF-lite support from the Linux kernel. This option permits discovering Linux named network namespaces and mapping it to FRR VRF contexts.

ROUTES
------

.. option:: -r, --retain

   When the program terminates, do not flush routes installed by zebra from the kernel.


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

