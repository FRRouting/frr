*********
MTRACEBIS
*********

.. include:: defines.rst
.. |PROGRAM| replace:: mtracebis

SYNOPSIS
========
|PROGRAM| |synopsis-options-hv|

|PROGRAM| <multicast source> [<multicast group>]

DESCRIPTION
===========
|PROGRAM| is a program for initiating multicast traceroute, or "mtrace", queries.

It can initiate two types of mtrace queries: weak and group.

Weak tests whether the interfaces towards the source are multicast enabled and is
initiated by supplying only the multicast source address.

Group tests whether there is multicast routing protocol state for particular
multicast group and is initiated by supplying mutlicast source and group.

The first query sent is a full query, capable of crossing the network all the way
to the source. If this fails, hop-by-hop queries are initiated.

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
