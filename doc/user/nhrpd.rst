.. _nhrp:

****
NHRP
****

*nhrpd* is an implementation of the :abbr:NHRP `(Next Hop Routing Protocol)`.
NHRP is described in :rfc`2332`.

NHRP is used to improve the efficiency of routing computer network traffic over
:abbr:`NBMA (Non-Broadcast, Multiple Access)` networks. NHRP provides an
ARP-like solution that allows a system to dynamically learn the NBMA address of
the other systems that are part of that network, allowing these systems to
directly communicate without requiring traffic to use an intermediate hop.

Cisco Dynamic Multipoint VPN (DMVPN) is based on NHRP, and |PACKAGE_NAME| nhrpd
implements this scenario.

.. _routing-design:

Routing Design
==============

nhrpd never handles routing of prefixes itself. You need to run some
real routing protocol (e.g. BGP) to advertise routes over the tunnels.
What nhrpd does it establishes 'shortcut routes' that optimizes the
routing protocol to avoid going through extra nodes in NBMA GRE mesh.

nhrpd does route NHRP domain addresses individually using per-host prefixes.
This is similar to Cisco FlexVPN; but in contrast to opennhrp which uses
a generic subnet route.

To create NBMA GRE tunnel you might use the following (Linux terminal
commands):::

   ip tunnel add gre1 mode gre key 42 ttl 64
   ip addr add 10.255.255.2/32 dev gre1
   ip link set gre1 up


Note that the IP-address is assigned as host prefix to gre1. nhrpd will
automatically create additional host routes pointing to gre1 when
a connection with these hosts is established.

The gre1 subnet prefix should be announced by routing protocol from the
hub nodes (e.g. BGP 'network' announce). This allows the routing protocol
to decide which is the closest hub and determine the relay hub on prefix
basis when direct tunnel is not established.

nhrpd will redistribute directly connected neighbors to zebra. Within
hub nodes, these routes should be internally redistributed using some
routing protocol (e.g. iBGP) to allow hubs to be able to relay all traffic.

This can be achieved in hubs with the following bgp configuration (network
command defines the GRE subnet):

.. code-block:: frr

  router bgp 65555
   address-family ipv4 unicast
     network 172.16.0.0/16
     redistribute nhrp
   exit-address-family


.. _configuring-nhrp:

Configuring NHRP
================

FIXME

.. _hub-functionality:

Hub Functionality
=================

In addition to routing nhrp redistributed host prefixes, the hub nodes
are also responsible to send NHRP Traffic Indication messages that
trigger creation of the shortcut tunnels.

nhrpd sends Traffic Indication messages based on network traffic captured
using NFLOG. Typically you want to send Traffic Indications for network
traffic that is routed from gre1 back to gre1 in rate limited manner.
This can be achieved with the following iptables rule.

.. code-block:: shell

   iptables -A FORWARD -i gre1 -o gre1 \\
       -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 \\
       --hashlimit-mode srcip,dstip --hashlimit-srcmask 24 --hashlimit-dstmask 24 \\
       --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-range 128


You can fine tune the src/dstmask according to the prefix lengths you
announce internal, add additional IP range matches, or rate limitation
if needed. However, the above should be good in most cases.

This kernel NFLOG target's nflog-group is configured in global nhrp config
with:

.. code-block:: frr

   nhrp nflog-group 1

To start sending these traffic notices out from hubs, use the nhrp
per-interface directive:

.. code-block:: frr

   interface gre1
    ip nhrp redirect


.. _integration-with-ike:

Integration with IKE
====================

nhrpd needs tight integration with IKE daemon for various reasons.
Currently only strongSwan is supported as IKE daemon.

nhrpd connects to strongSwan using VICI protocol based on UNIX socket
(hardcoded now as /var/run/charon.vici).

strongSwan currently needs few patches applied. Please check out the
https://git.alpinelinux.org/user/tteras/strongswan/log/?h=tteras-release
and
https://git.alpinelinux.org/user/tteras/strongswan/log/?h=tteras
git repositories for the patches.

.. _nhrp-events:

NHRP Events
===========

FIXME

Configuration Example
=====================

FIXME

