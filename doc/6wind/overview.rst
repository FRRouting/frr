.. Copyright 2018-2019 6WIND S.A.

========
Overview
========

|CP-ROUTING| enables route management over a wide variety of routing protocols.
It is supported by the ``zebra`` daemon, from the open source |frr| project.

You can manage routes via configuration files, or interactively in a specific
|cli|.

.. seealso::

   For more information on |frr|, see the `project's online documentation`__.

__ https://frrouting.org/user-guide/

Features
========

- |bgp|, BGP4+
- |ospf|\v2, |ospf|\v3
- |rip|, |ripng|
- |xvrf|
- Static Routes
- ECMP
- |pbr|
- |mpls| |ldp|
- |bgp| |l3vpn|
- |bgp| Flowspec

Dependencies
============

6WINDGate modules
-----------------

- |fpforw4|
- |fpforw6| (for IPv6)
- |fp-pbr| (for |pbr| and |bgp| Flowspec)
- |fp-mpls| (for |mpls| |ldp| and |bgp| |l3vpn|)
- |linux-fp-sync|
