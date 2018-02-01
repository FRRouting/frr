.. _ripng:

*****
RIPng
*****

*ripngd* supports the RIPng protocol as described in :rfc:`2080`. It's an IPv6
reincarnation of the RIP protocol.

.. _invoking-ripngd:

Invoking ripngd
===============

There are no `ripngd` specific invocation options. Common options can be
specified (:ref:`common-invocation-options`).

.. _ripngd-configuration:

ripngd Configuration
====================

Currently ripngd supports the following commands:

.. index:: router ripng
.. clicmd:: router ripng

   Enable RIPng.

.. index:: flush_timer TIME
.. clicmd:: flush_timer TIME

   Set flush timer.

.. index:: network NETWORK
.. clicmd:: network NETWORK

   Set RIPng enabled interface by NETWORK.

.. index:: network IFNAME
.. clicmd:: network IFNAME

   Set RIPng enabled interface by IFNAME.

.. index:: route NETWORK
.. clicmd:: route NETWORK

   Set RIPng static routing announcement of NETWORK.

.. index:: router zebra
.. clicmd:: router zebra

   This command is the default and does not appear in the configuration. With
   this statement, RIPng routes go to the *zebra* daemon.

.. _ripngd-terminal-mode-commands:

ripngd Terminal Mode Commands
=============================

.. index:: show ip ripng
.. clicmd:: show ip ripng

.. index:: show debugging ripng
.. clicmd:: show debugging ripng

.. index:: debug ripng events
.. clicmd:: debug ripng events

.. index:: debug ripng packet
.. clicmd:: debug ripng packet

.. index:: debug ripng zebra
.. clicmd:: debug ripng zebra


ripngd Filtering Commands
=========================

.. index:: distribute-list ACCESS_LIST (in|out) IFNAME
.. clicmd:: distribute-list ACCESS_LIST (in|out) IFNAME

   You can apply an access-list to the interface using the `distribute-list`
   command. ACCESS_LIST is an access-list name. `direct` is ``in`` or
   ``out``. If `direct` is ``in``, the access-list is applied only to incoming
   packets.::

      distribute-list local-only out sit1

