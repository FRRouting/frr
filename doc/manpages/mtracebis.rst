*********
MTRACEBIS
*********

.. include:: defines.rst
.. |PROGRAM| replace:: mtracebis

SYNOPSIS
========
|PROGRAM| |synopsis-options-hv|

|PROGRAM| <multicast source>

DESCRIPTION
===========
|PROGRAM| is a program to initiate multicast traceroute, or "mtrace", queries.

The initial version of the program requires multicast source IP address and
initiates a weak traceroute across the network. This tests whether the
interfaces towards the source are multicast enabled. The first query sent is a
full query, capable of crossing the network all the way to the source. If this
fails, hop-by-hop queries are initiated.

Hop-by-hop queries start by requesting only a response from the nearest router.
Following that, next query is extended to the next two routers, and so on...
until a set of routers is tested for connectivity.

FILES
=====

|INSTALL_PREFIX_SBIN|/|PROGRAM|
   The default location of the |PROGRAM| binary.

.. include:: epilogue.rst

AUTHORS
=======

Mladen Sablic
