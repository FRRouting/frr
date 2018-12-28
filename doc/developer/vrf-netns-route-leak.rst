VRF netns route leak
====================

VRF netns route leak is a feature allowing to cross VRF boundaries when VRF
has a netns backend. This can be done by using veth pairs configured between
VRFs. It is currenty only used with BGP L3-VPN in two situations : leaking
from a BGP-VPN to a local VRF (and vice-versa) or when leaking between local
VRF. Basically, the former will rely on MPLS labels. Both will use veth pair
as nexthop route entry to reach remote VRF/VPN.

Veth pair configuration
-----------------------

Actually, crossing VRF can be done by using virtual ethernet interfaces.
On linux, it is possible to do so, by creating veth pair of devices.

Below example illustrates how a veth pair device can be configured and used
to leak between two VRFs.

::

   ip link add vrf1 type veth peer name vrf2
   ip link set dev vrf1 arp off
   ip link set dev vrf2 arp off
   ip link set dev vrf1 address 00:80:ed:01:01:01
   ip link set dev vrf2 address 00:80:ed:01:01:01
   ip link set vrf1 netns vrf2
   ip link set vrf2 netns vrf1
   ip netns exec vrf1 ip link set dev vrf2 up
   ip netns exec vrf2 ip link set dev vrf1 up

To work in an IP-less mode, we *must* have

- ARP disabled,
- Same mac address configured on both sides.

Consequently, it is possible to configure a connected route to that
interface, and send some traffic across that interface. Linux kernel permits a
packet to be transmitted with equal source and destination mac address.

::

   ip netns exec vrf1 ip route add 2.2.2.0/24 dev vrf2
   ip netns exec vrf2 ip route add 1.1.1.0/24 dev vrf1

   # ip netns exec vrf1 ip route show
   2.2.2.0/24 dev vrf2 scope link

   # ip netns exec vrf2 ip route show
   1.1.1.0/24 dev vrf2 scope link

   # ip netns exec vrf1 ping 2.2.2.2 -I 1.1.1.1
   # ip netns exec vrf2 ping 1.1.1.1 -I 2.2.2.2

Once the veth infrastrucure is set, the route leak requires very little
configuration : no extra adress, and a simple route through an interface.
This solution does not alter the isolation property of netns based VRFs, as
the leak infrastrucuture (veth pairs) needs to be explicitely set up : to
keep a VRF fully isolated, just don't build veth pair pointing to another VRF.

The drawback of that solution is that it may require a lot of veth pairs :
one per VRF-pair where leaking is desired.

FRR veth pair configuration
---------------------------

Similarly to what has been done for vrf-lite cases, there is a strong
relationship between veth names and VRF names. In order to leak from a VRF
named "vrf-a" to a  a VRF named "vrf-b", FRR will explicitely search in
"vrf-a" a veth interface named with the target VRF, i.e. "vrf-b"; same naming
convention applies for the return traffic.

Configurable naming convention for veth pairs, and/or automatic creation of
such pairs by FRR has been envisionned but not yet implemented.

This implies that X-vrf veth provisionning must be done prior to FRR being
started, or at least before any X-vrf route is computed by FRR. The presence
of those veth pair will be considered as enough by the frrouting process to
decide whether or not it is possible to do vrf route leak.

.. note::

   The user has to ensure that the veth pairs are well named and configured.
   It is worth to be noted that the veth framework will fail in case mac address
   of veth pairs are not the same, or the IFF_NOARP flag is not present, or the
   operational status of veth pairs is not up. Not setting it may be well handled
   by Zebra daemon (mainly thanks to nexthop tracking), but in some cases, may
   lead to some inconsistencies (this is the case when incoming MPLS traffic from
   VPN has to cross the boundaries to reach a VRF. For that, it is recommended to
   have the veth pair well configured before restarting FRR).

BGP route leaking resolution
----------------------------

The following kind of leaking route entries are handled.

- connected routes, generally redistributed via BGP.
  those are imported route entries on a separate VRF.
- nexthop route entries. Those are route entries learnt by remote VPN (through MPLS VPN
  protocol), or remote BGP ( through imported entries from a BGP PE on a VRF).

As remind, whatever the service used, leaking from a BGP-VPN to a local VRF (and
vice-versa) or when leaking between local VRF, the two services will result in handling
the two kinds of above routes. The two leak services will both use the vpn to export
entries to, and import entries from. The only difference will result in the path used,
if the `nexthop origin` is in a local vrf, or in the VPN.

The checks for first kind of route will rely on API `vrf_route_leak_possible()`.
Actually, as the route imported is connected, no need to check that the route is
reachable in the target VRF. This API just returns the feasability of crossing the
vrf borders by giving two parameters : the origin vrf, and the target VRF. An interface
index is returned, giving the interface to use by the origin VRF to reach the target VRF.

The checks for the second kind of routes relies on nexthop tracking module.
Like for vrf-lite case, the nexthop is submitted to Zebra route nexthop tracking module.
Once the nexthop resolved in the target VRF, if the vrf backend is netns based VRFs, then
an addition checking is done against the veth pair framework. An interface index is then
obtained by Zebra route nexthop tracking; that interface index is the interface to use by
the origin VRF to reach the target VRF and the associated nexthop.

Once BGP checked the validity of the BGP route entry, if an interface index is available,
BGP will use it to ask Zebra to insert an extra nexthop rule, so as to redirect the route
through the correct veth interface. A specific function will create an extra nexthop entry
: `bgp_zebra_handle_nexthop_vrf()`. Upon detection of a route leak, the route entry to be
passed to ZEBRA will contain `ZEBRA_FLAG_CROSS_VRF_IFACE` flag. The flag explanation is given
below.

BGP MPLS route leaking resolution
---------------------------------

When importing a route entry from VPN, an MPLS label is associated to the
nexthop of the route. This is to perfom MPLS encapsulation, and needs to be
part of the route entry that has to be injected in the FIB.

A VPN route needs also an extra MPLS encaspulation to occur, with the label
used by the MPLS backbone. This is handled thanks to a "recursive" route, each
level carrying it own label.

Let's see it on an exemple, let's say for a VPN route `5.1.0.0/24` needing to
be installed in VRF "vrf1", and needing the double MPLS encapsulation with
labels 101 (for VPN), and 17 (for MPLS backbone), and compare the outputs for
both vrf-lite and netns backends.

With vrf-lite backend this will appear as follow :

::

   # show ip route vrf vrf1
   ...
   B>  5.1.0.0/24 [200/98] via 1.1.1.1(vrf default) (recursive), label 101, 00:00:05
   *                       via 10.0.2.2, r4-eth0(vrf default), label 17, 00:00:05

Thanks to vrf-lite lack of isolation at vrf level, both MPLS encaspulation can
occur at the same time (more precisely operation will be done in vrf1).

With netns backend, a FIB route in vrf1 can not refer to interface of another
VRF, so it has to be done with an extra hop, hence splitting the final route in
two parts. The first one is going though the X-vrf infrastrucutre, with the
double MPLS encpasulation set ; at this level, because of possible conflicts
the outer MPLS label can not be the one used by (and learnt from) MPLS backbone.
It must be locally assigned, and then processed in the default vrf, where a
swap operation will take place, finally setting the proper label needed by MPLS
backbone. In other words, all is as if MPLS backbone was extended with an
extra node in the default vrf.

::

   # show ip route vrf vrf1
   ...
   B>* 5.1.0.0/24 [200/98] is directly connected, vrf0, label 85/101, 00:00:01
                                via 1.1.1.1(vrf vrf0) (recursive), label 101, 00:00:01
     *                          via 10.0.2.2, r4-eth0(vrf vrf0), label 17, 00:00:01
   ...
   # show mpls table
   Inbound                            Outbound
     Label     Type          Nexthop     Label
   --------  -------  ---------------  --------
      85      BGP           10.0.2.2        17

The following operations are then performed for each vpn entry:

- in vrf1, the VPN label (101), and the internal label (85) are added
- in vrf0, the internal label (85) is replaced by the MPLS backbone label (17)

Note that as we're operating  at backbone level or equivalent, there are not
as many internal label as there are MPLS vpn lsp : we need one per tuple
(nexthop, target label).
The MPLS swap entry is created once the nexthop entry is considered as valid by
BGP nexthop management, thanks to the callback `bgp_vpn_leak_mpls_callback()`.

Zebra route leaking handling
----------------------------

BGP RIB injection in ZEBRA will contain an extra nexthop entry that contains
the interface index of the veth interface to use.

Then one flag will be appended to the route entry:
`ZEBRA_FLAG_CROSS_VRF_IFACE`. That flag will be used to determine that at least one nexthop
is a rule to cross a VRF by using an interface. For instance, each line in the below route
entry stands for a nexthop entry in the zapi message sent by BGP to ZEBRA. The first entry will
be identified as the entry that will replace the two next ones.

::

   # show ip route vrf vrf1
   ...
   B>* 5.1.0.0/24 [200/98] is directly connected, vrf0, label 85/101, 00:00:01
                                via 1.1.1.1(vrf vrf0) (recursive), label 101, 00:00:01
     *                          via 10.0.2.2, r4-eth0(vrf vrf0), label 17, 00:00:01

Adding to this, one other flag will be used in the last 2 nexthop entries:

`NEXTHOP_FLAG_INFO_ONLY`. That flag will be used by ZEBRA. It will be applied to the two last
nexthop entries. This will inform ZEBRA to not install the entries in the system. This
information is kept, since it illustrates the relationship between Zebra entry and BGP entry.
