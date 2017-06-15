# Configuring EVPN for VxLAN
There are two essential steps involved in configuring the EVPN control plane for VxLAN.
## Enabling EVPN between BGP neighbors
This is done by activating the EVPN address-family for a neighbor. A sample configuration looks as follows:

```
router bgp 65001
 bgp router-id 110.0.0.1
 neighbor SPINE peer-group
 neighbor SPINE remote-as external
 neighbor swp1 interface peer-group SPINE
 neighbor swp2 interface peer-group SPINE
 !
 address-family ipv4 unicast
  network 110.0.0.1/32
 exit-address-family
 !
 address-family l2vpn evpn
  neighbor SPINE activate
 exit-address-family
!
```

## Advertising all local VNIs (and their MACs and neighbors)
There is a single global command to enable the EVPN control plane on a VTEP - called "advertise-all-vni". This will cause the FRR to learn about all VNIs that are locally present on the system and the MACs and neighbors (ARP/ND) that pertain to such VNIs and advertise the corresponding information using EVPN procedures to all BGP peers with whom the EVPN address-family has been negotiated. It will also cause any EVPN routes learnt from BGP peers to be installed into the appropriate local VNI(s). Received EVPN type-3 routes will translate into the list of remote VTEPs that participate in a particular VNI and received EVPN type-2 routes will get installed as MAC and neighbor entries pertaining to a specific VNI.
A sample configuration looks as follows:

```
router bgp 65001
 address-family l2vpn evpn
  neighbor SPINE activate
  advertise-all-vni
 exit-address-family
!
```

**Notes** 

1. This configuration is needed only on VTEPs; hence, it is not needed on route reflectors or BGP speakers that merely exchange EVPN routing information.

2. EVPN routes received from a BGP peer are accepted even without this configuration. These routes are maintained in the global EVPN routing table. However, they will get "installed" into a VNI only after EVPN (advertise-all-vni) is configured.

3. The configuration of VNIs (VxLAN interfaces), association of VLAN to VNI etc. is outside the scope of FRR and is to be performed using other tools that interact directly with the underlying OS. In the case of Linux, this would be using a standard utility such as iproute2.

## Configuring Route Distinguisher (RD) and Route Targets (RTs) for VNIs (optional)
In addition to the above essential steps, the RD and RTs can be configured for a VNI. This step is optional, and in the absence of explicit configuration, the RD and RTs will be automatically derived as follows:

- RD will be derived as <Router Id>:<Unique VNI index>, where the "Unique VNI index" is an internal number that uniquely identifies the VNI on the local system
- The import RT and the export RT will be derived as <AS>:<VNI> with the lower 16 bits of the AS being used in the case of large (4-byte) AS numbers.

A sample configuration with specific RD and RT for a VNI is as shown below:

```
router bgp 65001
 address-family l2vpn evpn
  neighbor SPINE activate
  vni 10100
   rd 1:10100
   route-target import 1:10100
  exit-vni
  advertise-all-vni
 exit-address-family
!
```

In the above example, only the RD and import RT have been configured; in this case, the export RT will use the auto-derived value of 65001:10100.

Multiple RTs can be configured for a VNI by specifying multiple "route-target" lines in the configuration.


# Managing EVPN for VxLAN
There are many operational commands to verify EVPN operation. The key ones are described below.

## Examining VNIs present on the system

```
l1# show evpn vni
Number of VNIs: 2
VNI        VxLAN IF              VTEP IP         # MACs   # ARPs   # Remote VTEPs 
10200      vxlan200              110.0.0.1       0        0        3              
10100      vxlan100              110.0.0.1       2        2        3              
l1# 
l1# 
```

A specific VNI can also be examined.
```
l1# show evpn vni 10100
VNI: 10100
 VxLAN interface: vxlan100 ifIndex: 7 VTEP IP: 110.0.0.1
 Remote VTEPs for this VNI:
  110.0.0.2
  110.0.0.4
  110.0.0.3
 Number of MACs (local and remote) known for this VNI: 2
 Number of ARPs (IPv4 and IPv6, local and remote) known for this VNI: 2
l1# 
```

## Examining MACs and neighbors in a VNI

```
l1# show evpn mac vni 10100
Number of MACs (local and remote) known for this VNI: 2
MAC               Type   Intf/Remote VTEP      VLAN 
00:02:00:00:00:01 local  swp3                  100  
00:02:00:00:00:05 remote 110.0.0.3            
l1# 
l1# show evpn arp-cache vni 10100
Number of ARPs (local and remote) known for this VNI: 2
IP              Type   MAC               Remote VTEP          
50.1.1.11       local  00:02:00:00:00:01 
50.1.1.31       remote 00:02:00:00:00:05 110.0.0.3            
l1#
```

Specific entries can be examined by specifying the MAC address or IP address.

## Examining VNIs in BGP and their RD/RT information

```
l1# show bgp l2vpn evpn vni
Advertise All VNI flag: Enabled
Number of VNIs: 2
Flags: * - Kernel 
  VNI        Orig IP         RD                    Import RT                 Export RT                
* 10200      110.0.0.1       110.0.0.1:2           65001:10200               65001:10200              
* 10100      110.0.0.1       110.0.0.1:1           65001:10100               65001:10100              
l1#
```

The above command will specify which VNIs are also defined in the system (i.e., known to the underlying OS).

## Examining the global EVPN routing table

EVPN routes in the global routing table are maintained in the form of <RD>:<prefix> in a similar fashion to how L3VPN routes are maintained.

```
l1# show bgp l2vpn evpn route
BGP table version is 0, local router ID is 110.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete
EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]

   Network          Next Hop            Metric LocPrf Weight Path
Route Distinguisher: 1:10100
*> [3]:[0]:[32]:[110.0.0.1]
                    110.0.0.1                          32768 i
Route Distinguisher: 110.0.0.1:2
*> [3]:[0]:[32]:[110.0.0.1]
                    110.0.0.1                          32768 i
Route Distinguisher: 110.0.0.2:1
*  [3]:[0]:[32]:[110.0.0.2]
                    110.0.0.2                              0 65100 65002 i
*> [3]:[0]:[32]:[110.0.0.2]
                    110.0.0.2                              0 65100 65002 i
<snip>

Displayed 8 prefixes (14 paths)
l1#
```

The attributes and details for a specific route can be examined by specifying the RD for the route.

## Examining the routes pertaining to a VNI
EVPN routes specific to a VNI - local as well as remote - are maintained in a per-VNI routing table. Since this is per-VNI, there is no need for the RD and the routes are keyed merely on their prefix.

```
l1# show bgp l2vpn evpn route vni 10100
BGP table version is 0, local router ID is 110.0.0.1
Status codes: s suppressed, d damped, h history, * valid, > best, i - internal
Origin codes: i - IGP, e - EGP, ? - incomplete
EVPN type-2 prefix: [2]:[ESI]:[EthTag]:[MAClen]:[MAC]:[IPlen]:[IP]
EVPN type-3 prefix: [3]:[EthTag]:[IPlen]:[OrigIP]

   Network          Next Hop            Metric LocPrf Weight Path
*> [2]:[0]:[0]:[48]:[00:02:00:00:00:01]
                    110.0.0.1                          32768 i
*> [2]:[0]:[0]:[48]:[00:02:00:00:00:01]:[32]:[50.1.1.11]
                    110.0.0.1                          32768 i
*  [2]:[0]:[0]:[48]:[00:02:00:00:00:05]
                    110.0.0.3                              0 65100 65003 i
*> [2]:[0]:[0]:[48]:[00:02:00:00:00:05]
                    110.0.0.3                              0 65100 65003 i
*  [2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31]
                    110.0.0.3                              0 65100 65003 i
*> [2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31]
                    110.0.0.3                              0 65100 65003 i
*> [3]:[0]:[32]:[110.0.0.1]
                    110.0.0.1                          32768 i
*  [3]:[0]:[32]:[110.0.0.2]
                    110.0.0.2                              0 65100 65002 i
*> [3]:[0]:[32]:[110.0.0.2]
                    110.0.0.2                              0 65100 65002 i
*  [3]:[0]:[32]:[110.0.0.3]
                    110.0.0.3                              0 65100 65003 i
*> [3]:[0]:[32]:[110.0.0.3]
                    110.0.0.3                              0 65100 65003 i
*  [3]:[0]:[32]:[110.0.0.4]
                    110.0.0.4                              0 65100 65004 i
*> [3]:[0]:[32]:[110.0.0.4]
                    110.0.0.4                              0 65100 65004 i

Displayed 8 prefixes (13 paths)
l1#
```

Many options exist to examine routes by type and by MAC address and/or IP address.

```
l1# 
l1# show bgp l2vpn evpn route vni 10100 mac 00:02:00:00:00:05 ip 50.1.1.31
BGP routing table entry for [2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31]
Paths: (2 available, best #2)
  Not advertised to any peer
  Route [2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31] VNI 10100
  Imported from 110.0.0.3:1:[2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31]
  65100 65003
    110.0.0.3 from s2(swp2) (20.0.0.2)
      Origin IGP, localpref 100, valid, external
      Extended Community: RT:65003:10100 ET:8
      AddPath ID: RX 0, TX 50
      Last update: Fri May 26 22:46:38 2017

  Route [2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31] VNI 10100
  Imported from 110.0.0.3:1:[2]:[0]:[0]:[48]:[00:02:00:00:00:05]:[32]:[50.1.1.31]
  65100 65003
    110.0.0.3 from s1(swp1) (20.0.0.1)
      Origin IGP, localpref 100, valid, external, bestpath-from-AS 65100, best
      Extended Community: RT:65003:10100 ET:8
      AddPath ID: RX 0, TX 46
      Last update: Fri May 26 22:46:38 2017


Displayed 2 paths for requested prefix
l1#
```


