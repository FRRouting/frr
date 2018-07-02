.. _flowspec:

Flowspec
========

.. _features-of-the-current-implementation-flowspec:

Overview
---------

Flowspec introduces a new :abbr:`NLRI (Network Layer Reachability Information)`
encoding format that is used to distribute traffic rule flow specifications.
Basically, instead of simply relying on destination IP address for IP prefixes,
the IP prefix is replaced by a n-tuple consisting of a rule. That rule can be a
more or less complex combination of the following:


- Network source/destination (can be one or the other, or both).
- Layer 4 information for UDP/TCP: source port, destination port, or any port.
- Layer 4 information for ICMP type and ICMP code.
- Layer 4 information for TCP Flags.
- Layer 3 information: DSCP value, Protocol type, packet length, fragmentation.
- Misc layer 4 TCP flags.

A combination of the above rules is applied for traffic filtering. This is
encoded as part of specific BGP extended communities and the action can range
from the obvious rerouting (to nexthop or to separate VRF) to shaping, or
discard.

The following IETF drafts and RFCs have been used to implement FRR Flowspec:

- :rfc:`5575`
- [Draft-IETF-IDR-Flowspec-redirect-IP]_

.. _design-principles-flowspec:

Design Principles
-----------------

FRR implements the Flowspec client side, that is to say that BGP is able to
receive Flowspec entries, but is not able to act as manager and send Flowspec
entries.

Linux provides the following mechanisms to implement policy based routing:

- Filtering the traffic with ``Netfilter``.
  ``Netfilter`` provides a set of tools like ``ipset`` and ``iptables`` that are
  powerful enough to be able to filter such Flowspec filter rule.

- using non standard routing tables via ``iproute2`` (via the ``ip rule``
  command provided by ``iproute2``).
  ``iproute2`` is already used by FRR's :ref:`pbr` daemon which provides basic
  policy based routing based on IP source and destination criterion.

Below example is an illustration of what Flowspec will inject in the underlying
system:

.. code-block:: shell

   # linux shell
   ipset create match0x102 hash:net,net counters
   ipset add match0x102 32.0.0.0/16,40.0.0.0/16
   iptables -N match0x102 -t mangle
   iptables -A match0x102 -t mangle -j MARK --set-mark 102
   iptables -A match0x102 -t mangle -j ACCEPT
   iptables -i ntfp3 -t mangle -I PREROUTING -m set --match-set match0x102
                src,dst -g match0x102
   ip rule add fwmark 102 lookup 102
   ip route add 40.0.0.0/16 via 44.0.0.2 table 102

For handling an incoming Flowspec entry, the following workflow is applied:

- Incoming Flowspec entries are handled by *bgpd*, stored in the BGP RIB.
- Flowspec entry is installed according to its complexity.

It will be installed if one of the following filtering action is seen on the
BGP extended community: either redirect IP, or redirect VRF, in conjunction
with rate option, for redirecting traffic. Or rate option set to 0, for
discarding traffic.

According to the degree of complexity of the Flowspec entry, it will be
installed in *zebra* RIB. For more information about what is supported in the
FRR implementation as rule, see :ref:`flowspec-known-issues` chapter. Flowspec
entry is split in several parts before being sent to *zebra*.

- *zebra* daemon receives the policy routing configuration

Policy Based Routing entities necessary to policy route the traffic in the
underlying system, are received by *zebra*. Two filtering contexts will be
created or appended in ``Netfilter``: ``ipset`` and ``iptable`` context. The
former is used to define an IP filter based on multiple criterium. For
instance, an ipset ``net:net`` is based on two ip addresses, while
``net,port,net`` is based on two ip addresses and one port (for ICMP, UDP, or
TCP). The way the filtering is used (for example, is src port or dst port
used?) is defined by the latter filtering context. ``iptable`` command will
reference the ``ipset`` context and will tell how to filter and what to do. In
our case, a marker will be set to indicate ``iproute2`` where to forward the
traffic to. Sometimes, for dropping action, there is no need to add a marker;
the ``iptable`` will tell to drop all packets matching the ``ipset`` entry.

Configuration Guide
-------------------

In order to configure an IPv4 Flowspec engine, use the following configuration.
As of today, it is only possible to configure Flowspec on the default VRF.

.. code-block:: frr

   router bgp <AS>
     neighbor <A.B.C.D> remote-as <remoteAS>
     address-family ipv4 flowspec
      neighbor <A.B.C.D> activate
    exit
   exit

You can see Flowspec entries, by using one of the following show commands:

.. index:: show bgp ipv4 flowspec [detail | A.B.C.D]
.. clicmd:: show bgp ipv4 flowspec [detail | A.B.C.D]


Per-interface configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^

One nice feature to use is the ability to apply Flowspec to a specific
interface, instead of applying it to the whole machine. Despite the following
IETF draft [Draft-IETF-IDR-Flowspec-Interface-Set]_ is not implemented, it is
possible to manually limit Flowspec application to some incoming interfaces.
Actually, not using it can result to some unexpected behaviour like accounting
twice the traffic, or slow down the traffic (filtering costs). To limit
Flowspec to one specific interface, use the following command, under
`flowspec address-family` node.

.. index:: [no] local-install <IFNAME | any>
.. clicmd:: [no] local-install <IFNAME | any>

By default, Flowspec is activated on all interfaces. Installing it to a named
interface will result in allowing only this interface. Conversely, enabling any
interface will flush all previously configured interfaces.

VRF redirection
^^^^^^^^^^^^^^^

Another nice feature to configure is the ability to redirect traffic to a
separate VRF. This feature does not go against the ability to configure
Flowspec only on default VRF. Actually, when you receive incoming BGP flowspec
entries on that default VRF, you can redirect traffic to an other VRF.

As a reminder, BGP flowspec entries have a BGP extended community that contains
a Route Target. Finding out a local VRF based on Route Target consists in the
following:

- A configuration of each VRF must be done, with its Route Target set
  Each VRF is being configured within a BGP VRF instance with its own Route
  Target list. Route Target accepted format matches the following:
  ``A.B.C.D:U16``, or ``U16:U32``, ``U32:U16``.

- The first VRF with the matching Route Target will be selected to route traffic
  to. Use the following command under ipv4 unicast address-family node

.. index:: [no] rt redirect import RTLIST...
.. clicmd:: [no] rt redirect import RTLIST...

In order to illustrate, if the Route Target configured in the Flowspec entry is
``E.F.G.H:II``, then a BGP VRF instance with the same Route Target will be set
set.  That VRF will then be selected. The below full configuration example
depicts how Route Targets are configured and how VRFs and cross VRF
configuration is done.  Note that the VRF are mapped on Linux Network
Namespaces. For data traffic to cross VRF boundaries, virtual ethernet
interfaces are created with private IP adressing scheme.

.. code-block:: frr

   router bgp <ASx>
    neighbor <A.B.C.D> remote-as <ASz>
    address-family ipv4 flowspec
     neighbor A.B.C.D activate
    exit
   exit
   router bgp <ASy> vrf vrf2
    address-family ipv4 unicast
     rt redirect import <E.F.G.H:II>
    exit
   exit

Flowspec monitoring & troubleshooting
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can monitor policy-routing objects by using one of the following commands.
Those command rely on the filtering contexts configured from BGP, and get the
statistics information retrieved from the underlying system. In other words,
those statistics are retrieved from ``Netfilter``.

.. index:: show pbr ipset IPSETNAME | iptable
.. clicmd:: show pbr ipset IPSETNAME | iptable

``IPSETNAME`` is the policy routing object name created by ``ipset``.  About
rule contexts, it is possible to know which rule has been configured to
policy-route some specific traffic. The :clicmd:`show pbr iptable` command
displays for forwarded traffic, which table is used. Then it is easy to use
that table identifier to dump the routing table that the forwarded traffic will
match.

.. code-block:: frr

.. index:: show ip route table TABLEID
.. clicmd:: show ip route table TABLEID

   ``TABLEID`` is the table number identifier referencing the non standard
   routing table used in this example.

.. index:: [no] debug bgp flowspec
.. clicmd:: [no] debug bgp flowspec

   You can troubleshoot Flowspec, or BGP policy based routing. For instance, if
   you encounter some issues when decoding a Flowspec entry, you should enable
   :clicmd:`debug bgp flowspec`.

.. index:: [no] debug bgp pbr [error]
.. clicmd:: [no] debug bgp pbr [error]

   If you fail to apply the flowspec entry into *zebra*, there should be some
   relationship with policy routing mechanism. Here,
   :clicmd:`debug bgp pbr error` could help.

   To get information about policy routing contexts created/removed, only use
   :clicmd:`debug bgp pbr` command.

Ensuring that a Flowspec entry has been correctly installed and that incoming
traffic is policy-routed correctly can be checked as demonstrated below. First
of all, you must check whether the Flowspec entry has been installed or not.

.. code-block:: frr

   CLI# show bgp ipv4 flowspec 5.5.5.2/32
    BGP flowspec entry: (flags 0x418)
      Destination Address 5.5.5.2/32
      IP Protocol = 17
      Destination Port >= 50 , <= 90
      FS:redirect VRF RT:255.255.255.255:255
      received for 18:41:37
      installed in PBR (match0x271ce00)

This means that the Flowspec entry has been installed in an ``iptable`` named
``match0x271ce00``. Once you have confirmation it is installed, you can check
whether you find the associate entry by executing following command. You can
also check whether incoming traffic has been matched by looking at counter
line.

.. code-block:: frr

   CLI# show pbr ipset match0x271ce00
   IPset match0x271ce00 type net,port
        to 5.5.5.0/24:proto 6:80-120 (8)
           pkts 1000, bytes 1000000
        to 5.5.5.2:proto 17:50-90 (5)
           pkts 1692918, bytes 157441374

As you can see, the entry is present. note that an ``iptable`` entry can be
used to host several Flowspec entries. In order to know where the matching
traffic is redirected to, you have to look at the policy routing rules. The
policy-routing is done by forwarding traffic to a routing table number. That
routing table number is reached by using a ``iptable``. The relationship
between the routing table number and the incoming traffic is a ``MARKER`` that
is set by the IPtable referencing the IPSet. In Flowspec case, ``iptable``
referencing the ``ipset`` context have the same name. So it is easy to know
which routing table is used by issuing following command:

.. code-block:: frr

   CLI# show pbr iptable
      IPtable match0x271ce00 action redirect (5)
        pkts 1700000, bytes 158000000
        table 257, fwmark 257
   ...

As you can see, by using following Linux commands, the MARKER ``0x101`` is
present in both ``iptable`` and ``ip rule`` contexts.

.. code-block:: shell

   # iptables -t mangle --list match0x271ce00 -v
   Chain match0x271ce00 (1 references)
   pkts bytes target     prot opt in     out     source              destination
   1700K  158M MARK       all  --  any    any     anywhere             anywhere
        MARK set 0x101
   1700K  158M ACCEPT     all  --  any    any     anywhere             anywhere

   # ip rule list
   0:from all lookup local
   0:from all fwmark 0x101 lookup 257
   32766:from all lookup main
   32767:from all lookup default

This allows us to see where the traffic is forwarded to.

.. _flowspec-known-issues:

Limitations / Known Issues
--------------------------

As you can see, Flowspec is rich and can be very complex. As of today, not all
Flowspec rules will be able to be converted into Policy Based Routing actions.

- The ``Netfilter`` driver is not integrated into FRR yet. Not having this
  piece of code prevents from injecting flowspec entries into the underlying
  system.

- There are some limitations around filtering contexts

  If I take example of UDP ports, or TCP ports in Flowspec, the information
  can be a range of ports, or a unique value. This case is handled.
  However, complexity can be increased, if the flow is a combination of a list
  of range of ports and an enumerate of unique values. Here this case is not
  handled. Similarly, it is not possible to create a filter for both src port
  and dst port. For instance, filter on src port from [1-1000] and dst port =
  80. The same kind of complexity is not possible for packet length, ICMP type,
  ICMP code.

There are some other known issues:

- The validation procedure depicted in :rfc:`5575` is not available.

  This validation procedure has not been implemented, as this feature was not
  used in the existing setups you shared wih us.

- The filtering action shaper value, if positive, is not used to apply shaping.

  If value is positive, the traffic is redirected to the wished destination,
  without any other action configured by Flowspec.
  It is recommended to configure Quality of Service if needed, more globally on
  a per interface basis.

- Upon an unexpected crash or other event, *zebra* may not have time to flush
  PBR contexts.

  That is to say ``ipset``, ``iptable`` and ``ip rule`` contexts. This is also a
  consequence due to the fact that ip rule / ipset / iptables are not discovered
  at startup (not able to read appropriate contexts coming from Flowspec).

Appendix
--------

More information with a public presentation that explains the design of Flowspec
inside FRRouting.

[Presentation]_

.. [Draft-IETF-IDR-Flowspec-redirect-IP] <https://tools.ietf.org/id/draft-ietf-idr-flowspec-redirect-ip-02.txt>
.. [Draft-IETF-IDR-Flowspec-Interface-Set] <https://tools.ietf.org/id/draft-ietf-idr-flowspec-interfaceset-03.txt>
.. [Presentation] <https://docs.google.com/presentation/d/1ekQygUAG5yvQ3wWUyrw4Wcag0LgmbW1kV02IWcU4iUg/edit#slide=id.g378f0e1b5e_1_44>
