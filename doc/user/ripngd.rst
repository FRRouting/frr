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

.. clicmd:: router ripng

   Enable RIPng.

.. clicmd:: flush_timer TIME

   Set flush timer.

.. clicmd:: network NETWORK

   Set RIPng enabled interface by NETWORK.

.. clicmd:: network IFNAME

   Set RIPng enabled interface by IFNAME.

.. clicmd:: route NETWORK

   Set RIPng static routing announcement of NETWORK.


.. _ripngd-terminal-mode-commands:

ripngd Terminal Mode Commands
=============================

.. clicmd:: show ip ripng

.. clicmd:: show debugging ripng

.. clicmd:: debug ripng events

.. clicmd:: debug ripng packet

.. clicmd:: debug ripng zebra


ripngd Filtering Commands
=========================

.. clicmd:: distribute-list ACCESS_LIST (in|out) IFNAME

   You can apply an access-list to the interface using the `distribute-list`
   command. ACCESS_LIST is an access-list name. `direct` is ``in`` or
   ``out``. If `direct` is ``in``, the access-list is applied only to incoming
   packets.::

      distribute-list local-only out sit1

