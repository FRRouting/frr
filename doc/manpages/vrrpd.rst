*****
VRRPD
*****

.. include:: defines.rst
.. |DAEMON| replace:: vrrpd

SYNOPSIS
========
|DAEMON| |synopsis-options-hv|

|DAEMON| |synopsis-options|

DESCRIPTION
===========
|DAEMON| is a routing component that works with the FRRouting routing engine.
It implements the Virtual Router Redundancy Protocol. Support for both VRRPv2
and VRRPv3 is present.

OPTIONS
=======
OPTIONS available for the |DAEMON| command:

.. include:: common-options.rst

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

