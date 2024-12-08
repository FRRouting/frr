FRRouting User Guide
====================

<<<<<<< HEAD
############
Introduction
############

.. _introduction:
.. toctree::
   :maxdepth: 2

   overview
   installation
   setup

######
Basics
######

.. _basics:
.. toctree::
   :maxdepth: 2

   basic
   extlog
   vtysh
   grpc
   filter
   routemap
   affinitymap
   ipv6
   kernel
   snmp
   scripting
   nexthop_groups
.. modules

#########
Protocols
#########

.. _protocols:
.. toctree::
   :maxdepth: 2

   zebra
   bfd
   bgp
   babeld
   fabricd
   ldpd
   eigrpd
   evpn
   isisd
   nhrpd
   ospfd
   ospf6d
   pathd
   pim
   pimv6
   pbr
   ripd
   ripngd
   sharp
   static
   vnc
   vrrp
   bmp
   watchfrr
   mgmtd

########
Appendix
########

.. _appendix:
.. toctree::
=======
FRR is a fully featured, high performance, free software IP routing suite.  It
implements all standard routing protocols such as BGP, RIP, OSPF, IS-IS and
more (see :ref:`feature-matrix`), as well as many of their extensions. It can
handle full Internet routing tables and is suitable for use on hardware ranging
from cheap SBCs to commercial grade routers, and is actively used in production
by hundreds of companies, universities, research labs and governments.

FRR runs on all modern \*NIX operating systems, including Linux and the BSDs.
Feature support varies by platform; see the :ref:`feature-matrix`.

FRR is distributed under GPLv2, with development modeled after the Linux
kernel. Anyone may contribute features, bug fixes, tools, documentation
updates, or anything else.

FRR is a fork of `Quagga <http://www.quagga.net/>`_.

.. toctree::
   :maxdepth: 2

   introduction
   basics
   protocols

.. toctree::
   :caption: Appendix
>>>>>>> 3d89c67889 (bgpd: Print the actual prefix when we try to import in vpn_leak_to_vrf_update)
   :maxdepth: 2

   bugs
   packet-dumps
   glossary
   frr-reload

################
Copyright notice
################

Copyright (c) 1996-2018 Kunihiro Ishiguro, et al.

Permission is granted to make and distribute verbatim copies of this
manual provided the copyright notice and this permission notice are
preserved on all copies.

Permission is granted to copy and distribute modified versions of this
manual under the conditions for verbatim copying, provided that the
entire resulting derived work is distributed under the terms of a
permission notice identical to this one.

Permission is granted to copy and distribute translations of this manual
into another language, under the above conditions for modified versions,
except that this permission notice may be stated in a translation
approved by Kunihiro Ishiguro.
