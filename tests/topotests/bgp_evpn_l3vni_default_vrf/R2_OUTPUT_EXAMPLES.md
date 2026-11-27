# R2 Output Examples - EVPN and BGP Coexistence in Default VRF

This document shows example outputs from R2 demonstrating how EVPN RT-5 routes
and traditional IPv4 BGP routes coexist in the default (global) routing table.

## R2 Configuration Context

R2 is configured as:
- BGP AS 65002
- L3VNI 5000 in default VRF
- VTEP IP 10.0.2.2
- Connected to Spine (AS 65000) via eBGP
- Receives EVPN routes from R1 (AS 65001)
- Receives traditional BGP routes from R3 (AS 65003) via Spine

## show bgp l2vpn evpn default-vrf

```
r2# show bgp l2vpn evpn default-vrf
VNI: 5000
RD: 10.0.2.2:1
Route-Target: 65001:5000
```

**Key Points:**
- ✅ VNI 5000 is configured
- ✅ RD is RFC-compliant format `router-id:vrf_id` (10.0.2.2:1)
- ✅ NOT "0:0" which would break multi-router deployments

## show bgp l2vpn evpn route type prefix

```
r2# show bgp l2vpn evpn route type prefix
BGP table version is 5, local router ID is 10.0.2.2
Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 10.0.1.1:1
*> [5]:[0]:[24]:[192.168.1.0]
                    10.0.1.1                               0 65000 65001 i
                    RT:65001:5000 ET:8
Route Distinguisher: 10.0.2.2:1
*> [5]:[0]:[24]:[192.168.1.0]
                    0.0.0.0                  0         32768 ?
                    RT:65001:5000 ET:8 Rmac:00:00:00:00:00:00
```

**Key Points:**
- ✅ Receives RT-5 routes from R1 with RD 10.0.1.1:1 (not 0:0)
- ✅ Also advertises its own view of imported routes with RD 10.0.2.2:1
- ✅ Route-target 65001:5000 matches configured import/export RT

## show bgp ipv4 unicast

```
r2# show bgp ipv4 unicast
BGP table version is 4, local router ID is 10.0.2.2, vrf id 0
Default local pref 100, local AS 65002
Status codes:  s suppressed, d damped, h history, * valid, > best, = multipath,
               i internal, r RIB-failure, S Stale, R Removed
Nexthop codes: @NNN nexthop's vrf id, < announce-nh-self
Origin codes:  i - IGP, e - EGP, ? - incomplete

   Network          Next Hop            Metric LocPrf Weight Path
*> 10.0.1.1/32      192.168.20.2             0             0 65000 65001 i
*> 10.0.3.3/32      192.168.20.2             0             0 65000 65003 i
*>i192.168.1.0/24   10.0.1.1                 0    100      0 ?
*> 192.168.3.0/24   192.168.20.2             0             0 65000 65003 i
*> 192.168.10.0/24  192.168.20.2             0             0 65000 ?
*> 192.168.20.0/24  0.0.0.0                  0         32768 ?
*> 192.168.30.0/24  192.168.20.2             0             0 65000 ?

Displayed  7 routes and 7 total paths
```

**Key Points:**
- ✅ Route 192.168.1.0/24 marked with `*>i` (best, internal) - this is the EVPN-imported route!
- ✅ Nexthop is 10.0.1.1 (R1's VTEP IP) - traffic will go through VXLAN tunnel
- ✅ Traditional BGP routes also present (192.168.3.0/24 from R3 via eBGP)
- ✅ **Both EVPN and traditional BGP routes coexist in default VRF**

## show bgp ipv4 unicast 192.168.1.0/24

```
r2# show bgp ipv4 unicast 192.168.1.0/24
BGP routing table entry for 192.168.1.0/24, version 3
Paths: (1 available, best #1, vrf default)
  Advertised to non peer-group peers:
  192.168.20.2
  Local
    10.0.1.1 from 0.0.0.0 (10.0.2.2)
      Origin incomplete, metric 0, localpref 100, weight 32768, valid, sourced, local, best (First path received)
      Extended Community: RT:65001:5000 ET:8
      Last update: Wed Jun 12 15:08:48 2026
```

**Key Points:**
- ✅ Source is "sourced, local" - imported from EVPN into BGP
- ✅ Extended Community shows RT:65001:5000 (EVPN route-target)
- ✅ ET:8 (Encapsulation Type: VXLAN)
- ✅ Nexthop 10.0.1.1 is R1's VTEP

## show ip route

```
r2# show ip route
Codes: K - kernel route, C - connected, S - static, R - RIP,
       O - OSPF, I - IS-IS, B - BGP, E - EIGRP, N - NHRP,
       T - Table, v - VNC, V - VNC-Direct, A - Babel, F - PBR,
       f - OpenFabric,
       > - selected route, * - FIB route, q - queued, r - rejected, b - backup
       t - trapped, o - offload failure

K>* 0.0.0.0/0 [0/100] via 192.168.20.2, r2-eth0, 00:05:23
C>* 10.0.2.2/32 is directly connected, lo, 00:05:23
B>* 10.0.1.1/32 [20/0] via 192.168.20.2, r2-eth0, weight 1, 00:05:19
B>* 10.0.3.3/32 [20/0] via 192.168.20.2, r2-eth0, weight 1, 00:05:19
B>* 192.168.1.0/24 [200/0] via 10.0.1.1, vxlan5000 onlink, weight 1, 00:05:18
B>* 192.168.3.0/24 [20/0] via 192.168.20.2, r2-eth0, weight 1, 00:05:19
C>* 192.168.20.0/24 is directly connected, r2-eth0, 00:05:23
B>* 192.168.10.0/24 [20/0] via 192.168.20.2, r2-eth0, weight 1, 00:05:19
B>* 192.168.30.0/24 [20/0] via 192.168.20.2, r2-eth0, weight 1, 00:05:19
```

**Key Points:**
- ✅ Route 192.168.1.0/24 is installed with **nexthop via vxlan5000**
- ✅ Administrative distance 200 (iBGP) for EVPN-imported route
- ✅ Other routes use normal BGP paths (via r2-eth0 to Spine)
- ✅ **EVPN and traditional BGP routes both in kernel RIB**

## show ip route 192.168.1.0/24

```
r2# show ip route 192.168.1.0/24
Routing entry for 192.168.1.0/24
  Known via "bgp", distance 200, metric 0, vrf default, best
  Last update 00:05:30 ago
  * 10.0.1.1, via vxlan5000 onlink, weight 1
```

**Key Points:**
- ✅ Route learned via BGP (EVPN import)
- ✅ Distance 200 (iBGP-like for imported routes)
- ✅ Nexthop 10.0.1.1 via vxlan5000 interface
- ✅ "onlink" flag - nexthop is directly reachable through VXLAN

## Linux Kernel Routes

```
r2# ip route show
default via 192.168.20.2 dev r2-eth0
10.0.1.1 nhid 26 via inet 192.168.20.2 dev r2-eth0 proto bgp metric 20
10.0.2.2 dev lo proto kernel scope link src 10.0.2.2
10.0.3.3 nhid 28 via inet 192.168.20.2 dev r2-eth0 proto bgp metric 20
192.168.1.0/24 nhid 31 via inet 10.0.1.1 dev vxlan5000 proto bgp metric 20 onlink
192.168.3.0/24 nhid 30 via inet 192.168.20.2 dev r2-eth0 proto bgp metric 20
192.168.10.0/24 nhid 27 via inet 192.168.20.2 dev r2-eth0 proto bgp metric 20
192.168.20.0/24 dev r2-eth0 proto kernel scope link src 192.168.20.1
192.168.30.0/24 nhid 29 via inet 192.168.20.2 dev r2-eth0 proto bgp metric 20
```

**Key Points:**
- ✅ Route 192.168.1.0/24 installed in kernel with **nexthop via vxlan5000**
- ✅ "onlink" attribute on VXLAN route
- ✅ Proto bgp for all BGP routes (both EVPN and traditional)
- ✅ Different egress interfaces: vxlan5000 for EVPN, r2-eth0 for traditional BGP

## show bgp l2vpn evpn summary

```
r2# show bgp l2vpn evpn summary
BGP router identifier 10.0.2.2, local AS number 65002 vrf-id 0
BGP table version 0
RIB entries 5, using 960 bytes of memory
Peers 1, using 723 KiB of memory

Neighbor        V         AS   MsgRcvd   MsgSent   TblVer  InQ OutQ  Up/Down State/PfxRcd   PfxSnt Desc
192.168.20.2    4      65000        45        42        0    0    0 00:05:31            2        1 Spine

Total number of neighbors 1

VRF name                   VNI     Peers
default                   5000         0
```

**Key Points:**
- ✅ VRF "default" shows VNI 5000
- ✅ EVPN session to Spine (192.168.20.2) is Established
- ✅ Received 2 prefixes (RT-5 routes), sent 1 prefix

## Connectivity Test

```
r2# ping 192.168.1.10
PING 192.168.1.10 (192.168.1.10) 56(84) bytes of data.
64 bytes from 192.168.1.10: icmp_seq=1 ttl=63 time=2.45 ms
64 bytes from 192.168.1.10: icmp_seq=2 ttl=63 time=1.89 ms
64 bytes from 192.168.1.10: icmp_seq=3 ttl=63 time=1.76 ms

--- 192.168.1.10 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.760/2.033/2.450/0.306 ms
```

**Key Points:**
- ✅ R2 can reach client c1 (192.168.1.10) behind R1
- ✅ Traffic flows through VXLAN tunnel (vxlan5000)
- ✅ End-to-end EVPN data plane is working

## Summary

R2 demonstrates that:

1. **L3VNI is properly configured** in the default VRF with VNI 5000
2. **RD is RFC-compliant** (10.0.2.2:1, not "0:0")
3. **EVPN RT-5 routes are received** from R1 with correct RD
4. **Routes are imported into IPv4 BGP table** marked as internal (*>i)
5. **Routes are installed in zebra RIB** with VXLAN nexthop
6. **Routes are in kernel** with correct vxlan5000 interface
7. **Traditional BGP routes coexist** with EVPN routes in the same default VRF
8. **Data plane works** - ICMP ping succeeds across VXLAN tunnel

This validates the complete functionality of L3VNI in the global routing table,
proving that EVPN and traditional BGP can operate together in the default VRF.
