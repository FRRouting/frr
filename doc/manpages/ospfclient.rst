**********
OSPFCLIENT
**********

.. include:: defines.rst

SYNOPSIS
========
ospfclient <ospfd> <lsatype> <opaquetype> <opaqueid> <ifaddr> <areaid>

DESCRIPTION
===========
ospfclient is an example ospf-api client to test the ospfd daemon.

OPTIONS
=======

.. option:: ospfd

   A router where the API-enabled OSPF daemon is running.

.. option:: lsatype

   The value has to be either "9", "10", or "11", depending on the flooding scope.

.. option:: opaquetype

   The value has to be in the range of 0-255 (for example, experimental applications might use opaquetype larger than 128).

.. option:: opaqueid

   Arbitrary application instance (24 bits).

.. option:: ifaddr

   Interface IP address for type 9, otherwise it will be ignored.

.. option:: areaid

   Area in the IP address format for type 10, otherwise it will be ignored.


.. include:: epilogue.rst
