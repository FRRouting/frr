.. _RIPng:

*****
RIPng
*****

*ripngd* supports the RIPng protocol as described in RFC2080.  It's an
IPv6 reincarnation of the RIP protocol.

.. _Invoking_ripngd:

Invoking ripngd
===============

There are no `ripngd` specific invocation options.  Common options
can be specified (:ref:`Common_Invocation_Options`).

.. _ripngd_Configuration:

ripngd Configuration
====================

Currently ripngd supports the following commands:

.. index:: Command {router ripng} {}

Command {router ripng} {}
  Enable RIPng.

.. index:: {RIPng Command} {flush_timer `time`} {}

{RIPng Command} {flush_timer `time`} {}
  Set flush timer.

.. index:: {RIPng Command} {network `network`} {}

{RIPng Command} {network `network`} {}
  Set RIPng enabled interface by `network`

.. index:: {RIPng Command} {network `ifname`} {}

{RIPng Command} {network `ifname`} {}
  Set RIPng enabled interface by `ifname`

.. index:: {RIPng Command} {route `network`} {}

{RIPng Command} {route `network`} {}
  Set RIPng static routing announcement of `network`.

.. index:: Command {router zebra} {}

Command {router zebra} {}
  This command is the default and does not appear in the configuration.
  With this statement, RIPng routes go to the *zebra* daemon.

.. _ripngd_Terminal_Mode_Commands:

ripngd Terminal Mode Commands
=============================

.. index:: Command {show ip ripng} {}

Command {show ip ripng} {}

.. index:: Command {show debugging ripng} {}

Command {show debugging ripng} {}
.. index:: Command {debug ripng events} {}

Command {debug ripng events} {}
.. index:: Command {debug ripng packet} {}

Command {debug ripng packet} {}
.. index:: Command {debug ripng zebra} {}

Command {debug ripng zebra} {}

ripngd Filtering Commands
=========================

.. index:: Command {distribute-list `access_list` (in|out) `ifname`} {}

Command {distribute-list `access_list` (in|out) `ifname`} {}
  You can apply an access-list to the interface using the
  `distribute-list` command.  `access_list` is an access-list
  name.  `direct` is @samp{in} or @samp{out}.  If `direct` is
  @samp{in}, the access-list is applied only to incoming packets.

::

    distribute-list local-only out sit1
    

