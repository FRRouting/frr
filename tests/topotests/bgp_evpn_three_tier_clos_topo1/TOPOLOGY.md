# BGP EVPN VXLAN Topology 2 - Complete Node Diagram

## Overview
- **Total Nodes:** 16
- **Topology Type:** 3-Tier CLOS with EVPN
- **Underlay:** eBGP (supports both IPv4 and IPv6 numbered)
- **Overlay:** L2VPN EVPN
- **VTEP Type:** Single VXLAN Device (SVD) - IPv6 VTEPs
- **External Connectivity:** Per-VRF eBGP sessions for EVPN Type-5 routes + external host (host-1)
- **Test Modes:** Parametrized tests run with both IPv4 and IPv6 underlay configurations
- **Addresses:** RFC-compliant private and documentation ranges (RFC 5737, RFC 3849, RFC 1918, RFC 4193)

---

## Address Migration - RFC Compliance

This topology uses RFC-compliant address ranges for documentation and testing purposes.

### IPv4 Address Mapping (RFC 1918 + RFC 5737)

| Purpose | Old Address | New Address | RFC |
|---------|------------|-------------|-----|
| **Loopbacks/VTEPs** | 6.0.0.x/32 | 10.0.0.x/32 | RFC 1918 |
| **Underlay Links** | 10.254.0.x/30 | 10.254.0.x/30 | RFC 1918 (unchanged) |
| **Host VLAN 111** | 60.1.1.0/24 | 192.168.11.0/24 | RFC 1918 |
| **Host VLAN 112** | 50.1.1.0/24 | 192.168.12.0/24 | RFC 1918 |
| **External Peering VRF1 (bordertor-11)** | 144.1.1.0/30 | 192.0.2.0/30 | RFC 5737 TEST-NET-1 |
| **External Peering VRF2 (bordertor-11)** | 144.1.1.4/30 | 192.0.2.4/30 | RFC 5737 TEST-NET-1 |
| **External Peering VRF1 (bordertor-12)** | 144.2.1.0/30 | 192.0.2.8/30 | RFC 5737 TEST-NET-1 |
| **External Peering VRF2 (bordertor-12)** | 144.2.1.4/30 | 192.0.2.12/30 | RFC 5737 TEST-NET-1 |
| **External Networks (ext-1)** | 81.1.1-4.0/24 | 198.51.100-103.0/24 | RFC 5737 TEST-NET-2 |
| **Static Routes VRF1** | 72.21-22.1.0/24 | 203.0.113.21-22/24 | RFC 5737 TEST-NET-3 |
| **Static Routes VRF2** | 73.21-22.1.0/24 | 203.0.113.121-122/24 | RFC 5737 TEST-NET-3 |

### IPv6 Address Mapping (RFC 4193 ULA + RFC 3849)

| Purpose | Old Address | New Address | RFC |
|---------|------------|-------------|-----|
| **Loopbacks/VTEPs** | 2006:20:20::x/128 | fd00:0:20::x/128 | RFC 4193 ULA |
| **Underlay Links** | 2010:2254::/32 subnets | fd00:10:254::/48 subnets | RFC 4193 ULA |
| **Host VLAN 111** | 2060:1:1:1::/64 | fd00:60:1:1::/64 | RFC 4193 ULA |
| **Host VLAN 112** | 2050:1:1:1::/64 | fd00:50:1:1::/64 | RFC 4193 ULA |
| **External Peering VRF1 (bordertor-11)** | 2144:1:1:1::/64 | 2001:db8:144:1::/64 | RFC 3849 |
| **External Peering VRF2 (bordertor-11)** | 2144:1:1:2::/64 | 2001:db8:144:2::/64 | RFC 3849 |
| **External Peering VRF1 (bordertor-12)** | 2144:2:1:1::/64 | 2001:db8:144:11::/64 | RFC 3849 |
| **External Peering VRF2 (bordertor-12)** | 2144:2:1:2::/64 | 2001:db8:144:12::/64 | RFC 3849 |
| **External Networks (ext-1)** | 2081:1:1:1-4::/64 | 2001:db8:81:1-4::/64 | RFC 3849 |
| **Static Routes VRF1** | 2001:21-22:1:1::/64 | 2001:db8:72:21-22::/64 | RFC 3849 |
| **Static Routes VRF2** | 2003:21-22:1:1::/64 | 2001:db8:73:21-22::/64 | RFC 3849 |

---

## Complete Topology Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                  SPINE LAYER (AS 652000)                                 │
│                         eBGP (IPv4/IPv6) + L2VPN EVPN Overlay                            │
└─────────────────────────────────────────────────────────────────────────────────────────┘

                    ┌──────────────────────┐              ┌──────────────────────┐
                    │      spine-1         │              │      spine-2         │
                    │    AS: 652000        │              │    AS: 652000        │
                    │ Router-ID: 10.0.0.28 │              │ Router-ID: 10.0.0.29 │
                    │  Lo: fd00:0:20::28    │              │  Lo: fd00:0:20::29    │
                    │                      │              │                      │
                    │  [swp1][swp2][swp3]  │              │  [swp1][swp2][swp3]  │
                    │        [swp4]        │              │        [swp4]        │
                    └──┬──┬──┬──┬──────────┘              └──┬──┬──┬──┬──────────┘
                       │  │  │  │                            │  │  │  │
         IPv6: ::14:0:2│  │  │  │::20:0:2      IPv6: ::15:0:2│  │  │  │::21:0:2
            (eBGP+EVPN)│  │  │  │(eBGP+EVPN)      (eBGP+EVPN)│  │  │  │(eBGP+EVPN)
                       │  │  │  │                            │  │  │  │
                    ::18:0:2 │::1c:0:2                    ::19:0:2 │::1d:0:2

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                   LEAF LAYER (Pod 1 & 2)                                 │
│                    eBGP (IPv4/IPv6) Underlay + L2VPN EVPN Route Reflector Clients       │
└─────────────────────────────────────────────────────────────────────────────────────────┘

              ┌────────────┴────────┐                  ┌────────────┴────────┐
              │                     │                  │                     │
       ┌──────▼──────┐      ┌──────▼──────┐    ┌──────▼──────┐      ┌──────▼──────┐
       │   leaf-11   │      │   leaf-12   │    │   leaf-21   │      │   leaf-22   │
       │  AS: 651001 │      │  AS: 651001 │    │  AS: 651004 │      │  AS: 651004 │
       │ RID: 10.0.0.24│    │ RID: 10.0.0.25│   │ RID: 10.0.0.26│    │ RID: 10.0.0.27│
       │Lo:fd00:0:20::24│    │Lo:fd00:0:20::25│   │Lo:fd00:0:20::26│    │Lo:fd00:0:20::27│
       │              │      │              │    │              │      │              │
       │[swp1] [swp2] │      │[swp1] [swp2] │    │[swp1] [swp2] │      │[swp1] [swp2] │
       │[swp3] [swp4] │      │[swp3] [swp4] │    │[swp3] [swp4] │      │[swp3] [swp4] │
       └──┬──┬────────┘      └──┬──┬────────┘    └──┬──┬────────┘      └──┬──┬────────┘
          │  │                  │  │                 │  │                  │  │
   ::2/126│  │::7:0:2/126       │  │::8:0:2/126     │  │::1e:0:2/126      │  │::23:0:2/126
  (eBGP+  │  │                  │  │                 │  │                  │  │
   EVPN)  │  │                  │  │                 │  │                  │  │
       ::1:0:1/126            ::1:0:2/126       ::1f:0:2/126          ::22:0:2/126

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                      BORDER TOR & TOR LAYER (EVPN VTEPs)                                │
│    eBGP (IPv4/IPv6) Underlay + L2VPN EVPN Overlay + VXLAN Tunnels (IPv6 VTEPs)         │
└─────────────────────────────────────────────────────────────────────────────────────────┘

        ┌────────▼─────────┐  ┌──────▼────────┐    ┌────────▼─────────┐  ┌────────▼──────┐
        │  bordertor-11 ★  │  │bordertor-12 ★ │    │    tor-21 ★      │  │   tor-22 ★    │
        │   AS: 660000     │  │  AS: 660000   │    │  AS: 650030      │  │  AS: 650031   │
        │ RID: 10.0.0.1    │  │ RID: 10.0.0.2 │    │ RID: 10.0.0.30   │  │ RID: 10.0.0.31│
        │VTEP:fd00:0:20::1  │  │VTEP:fd00:0:20::2│   │VTEP:fd00:0:20::30 │  │VTEP:fd00:0:20::31│
        │                  │  │               │    │                  │  │               │
        │ vxlan48 (SVD)    │  │ vxlan48 (SVD) │    │ vxlan48 (SVD)    │  │ vxlan48 (SVD) │
        │ L2VNI: 1000111   │  │ L2VNI: 1000111│    │ L2VNI: 1000111   │  │ L2VNI: 1000111│
        │        1000112   │  │       1000112 │    │        1000112   │  │       1000112 │
        │ L3VNI: 104001    │  │ L3VNI: 104001 │    │ L3VNI: 104001    │  │ L3VNI: 104001 │
        │        104002    │  │       104002  │    │        104002    │  │       104002  │
        │                  │  │               │    │                  │  │               │
        │[swp1]  [swp2]    │  │[swp1]  [swp2] │    │[swp1]  [swp2]    │  │[swp1]  [swp2] │
        │[swp3]────────────┼──┼───[swp3]      │    │[swp3]            │  │[swp3]         │
        │  │ VRF VRF       │  │    │ VRF VRF  │    │                  │  │               │
        │  ↓  1   2        │  │    ↓  1   2   │    │                  │  │               │
        │[swp4]  [swp5]    │  │[swp4] [swp5]  │    │                  │  │               │
        │                  │  │               │    │                  │  │               │
        └──┬───┬───────────┘  └──┬───┬────────┘    └────┬─────────────┘  └────┬──────────┘
           │   │                 │   │                   │                     │
    ::2:0:1│   │::2:0:2          │   │::9:0:2            │                     │
           │   ↓ .4001/.4002     │   ↓ .4001/.4002      │                     │
           │   BGP per-VRF       │   BGP per-VRF        │                     │
           │   peering           │   peering            │                     │
        ┌──▼───┴─────────────────┴───┴──┐               │                     │
        │   ext-1 (External Router)     │               │                     │
        │        AS: 655000              │               │                     │
        │     Router-ID: 10.0.0.3         │               │                     │
        │    Lo: fd00:0:20::3           │               │                     │
        │  [swp1]              [swp2]    │               │                     │
        │  │.4001 │.4002    │.4001│.4002 │               │                     │
        │  ↓ VRF1 ↓ VRF2    ↓ VRF1↓ VRF2 │               │                     │
        │  BGP    BGP       BGP   BGP    │               │                     │
        │ 192.0  192.0     192.0 192.0   │               │                     │
        │  .2.2   .2.6      .2.10 .2.14  │               │                     │
        │  [swp3] [swp4] [swp5] [swp6]   │               │                     │
        │  │      │      │      │         │               │                     │
        │  ↓      ↓      ↓      ↓         │               │                     │
        │ 198.51 198.51 198.51 198.51    │               │                     │
        │ .100.1 .100.2 .100.3 .100.4    │               │                     │
        │  /24    /24    /24    /24       │               │                     │
        └────────────────────────────────┘               │                     │

┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                  HOST LAYER                                              │
│      Connected to bordertor-11, bordertor-12, tor-21, and tor-22                        │
│                                (VLAN 111 / VRF2 only)                                    │
└─────────────────────────────────────────────────────────────────────────────────────────┘

    Connected to bordertor-11:                    Connected to bordertor-12:

    ┌─────────────┐                              ┌─────────────┐
    │  host-111   │                              │  host-121   │
    │             │                              │             │
    │ 192.168.11.111│                            │ 192.168.11.121│
    │  VLAN 111   │                              │  VLAN 111   │
    │   VRF2      │                              │   VRF2      │
    │   [swp1]    │                              │   [swp1]    │
    └──────┬──────┘                              └──────┬──────┘
           │                                            │
        to swp4                                      to swp4

    Connected to tor-21:                          Connected to tor-22:

         ┌─────────────┐                               ┌─────────────┐
         │  host-211   │                               │  host-221   │
         │             │                               │             │
         │ 192.168.11.211│                             │ 192.168.11.221│
         │  VLAN 111   │                               │  VLAN 111   │
         │   VRF2      │                               │   VRF2      │
         │   [swp1]    │                               │   [swp1]    │
         └──────┬──────┘                               └──────┬──────┘
                │                                             │
           to swp3                                       to swp3

Legend:
  ★ = EVPN VTEP (IPv4 or IPv6 source for VXLAN tunnels, depending on test configuration)
  ═══ = Layer boundary
  [swpX] = Switch port
  AS = Autonomous System Number
  RID = BGP Router ID
  Lo = Loopback interface
  VRF = Virtual Routing and Forwarding
  .400X = VLAN sub-interface for L3VNI peering
  
Note: The diagram shows IPv6 addresses/prefixes. When running with IPv4 underlay, 
corresponding IPv4 addresses are used (e.g., VTEP: 10.0.0.1 instead of fd00:0:20::1)
```

---

## Node Details

### Spine Layer (Route Reflectors for EVPN)

#### spine-1
- **AS:** 652000
- **Router-ID:** 10.0.0.28
- **Loopback:** 10.0.0.28/32, fd00:0:20::28/128
- **Interfaces:**
  - swp1 → leaf-11 (fd00:10:254::14:0:2/126)
  - swp2 → leaf-12 (fd00:10:254::18:0:2/126)
  - swp3 → leaf-21 (fd00:10:254::1c:0:2/126)
  - swp4 → leaf-22 (fd00:10:254::20:0:2/126)
- **BGP:** eBGP + L2VPN EVPN with all leafs

#### spine-2
- **AS:** 652000
- **Router-ID:** 10.0.0.29
- **Loopback:** 10.0.0.29/32, fd00:0:20::29/128
- **Interfaces:**
  - swp1 → leaf-11 (fd00:10:254::15:0:2/126)
  - swp2 → leaf-12 (fd00:10:254::19:0:2/126)
  - swp3 → leaf-21 (fd00:10:254::1d:0:2/126)
  - swp4 → leaf-22 (fd00:10:254::21:0:2/126)
- **BGP:** eBGP + L2VPN EVPN with all leafs

---

### Leaf Layer (Pod 1 - AS 651001)

#### leaf-11
- **AS:** 651001
- **Router-ID:** 10.0.0.24
- **Loopback:** 10.0.0.24/32, fd00:0:20::24/128
- **Interfaces:**
  - swp1 → spine-1 (fd00:10:254::14:0:1/126)
  - swp2 → spine-2 (fd00:10:254::15:0:1/126)
  - swp3 → bordertor-11 (fd00:10:254::2/126)
  - swp4 → bordertor-12 (fd00:10:254::7:0:2/126)
- **BGP:** eBGP + L2VPN EVPN with spines and bordertors

#### leaf-12
- **AS:** 651001
- **Router-ID:** 10.0.0.25
- **Loopback:** 10.0.0.25/32, fd00:0:20::25/128
- **Interfaces:**
  - swp1 → spine-1 (fd00:10:254::18:0:1/126)
  - swp2 → spine-2 (fd00:10:254::19:0:1/126)
  - swp3 → bordertor-11 (fd00:10:254::1:0:2/126)
  - swp4 → bordertor-12 (fd00:10:254::8:0:2/126)
- **BGP:** eBGP + L2VPN EVPN with spines and bordertors

---

### Leaf Layer (Pod 2 - AS 651004)

#### leaf-21
- **AS:** 651004
- **Router-ID:** 10.0.0.26
- **Loopback:** 10.0.0.26/32, fd00:0:20::26/128
- **Interfaces:**
  - swp1 → spine-1 (fd00:10:254::1c:0:1/126)
  - swp2 → spine-2 (fd00:10:254::1d:0:1/126)
  - swp3 → tor-21 (fd00:10:254::1e:0:1/126)
  - swp4 → tor-22 (fd00:10:254::1f:0:1/126)
- **BGP:** eBGP + L2VPN EVPN with spines and tors

#### leaf-22
- **AS:** 651004
- **Router-ID:** 10.0.0.27
- **Loopback:** 10.0.0.27/32, fd00:0:20::27/128
- **Interfaces:**
  - swp1 → spine-1 (fd00:10:254::20:0:1/126)
  - swp2 → spine-2 (fd00:10:254::21:0:1/126)
  - swp3 → tor-21 (fd00:10:254::22:0:2/126)
  - swp4 → tor-22 (fd00:10:254::23:0:2/126)
- **BGP:** eBGP + L2VPN EVPN with spines and tors

---

### VTEP Layer (Border ToRs - Pod 1)

#### bordertor-11 ★
- **AS:** 660000
- **Router-ID:** 10.0.0.1
- **Loopback:** 10.0.0.1/32, fd00:0:20::1/128
- **VTEP Address:** fd00:0:20::1 (for VXLAN tunnels)
- **VXLAN:** vxlan48 (TRUE SVD - all VNIs)
  - L2VNI: 1000111 (VLAN 111), 1000112 (VLAN 112)
  - L3VNI: 104001 (VLAN 4001/vrf1), 104002 (VLAN 4002/vrf2)
- **Interfaces:**
  - swp1 → leaf-11 (fd00:10:254::1/126)
  - swp2 → leaf-12 (fd00:10:254::1:0:1/126)
  - swp3 → ext-1 (fd00:10:254::2:0:1/126) - Physical interface
  - **swp3.4001** → ext-1 swp1.4001 (192.0.2.2/30, 2001:db8:144:1::2/64) - VRF1 L3VNI peering
  - **swp3.4002** → ext-1 swp1.4002 (192.0.2.6/30, 2001:db8:144:2::6/64) - VRF2 L3VNI peering
  - swp4 → host-111 (VLAN 111, VRF2)
- **VRFs:** vrf1 (vni 104001), vrf2 (vni 104002)
- **BGP:**
  - **Global:** eBGP + L2VPN EVPN with leafs (TOR-LEAF-SPINE peer-group)
  - **VRF vrf1:** eBGP with ext-1 (192.0.2.1, 2001:db8:144:1::1) for Type-5 routes
  - **VRF vrf2:** eBGP with ext-1 (192.0.2.5, 2001:db8:144:2::5) for Type-5 routes

#### bordertor-12 ★
- **AS:** 660000
- **Router-ID:** 10.0.0.2
- **Loopback:** 10.0.0.2/32, fd00:0:20::2/128
- **VTEP Address:** fd00:0:20::2 (for VXLAN tunnels)
- **VXLAN:** vxlan48 (TRUE SVD - all VNIs)
  - L2VNI: 1000111 (VLAN 111), 1000112 (VLAN 112)
  - L3VNI: 104001 (VLAN 4001/vrf1), 104002 (VLAN 4002/vrf2)
- **Interfaces:**
  - swp1 → leaf-11 (fd00:10:254::7:0:1/126)
  - swp2 → leaf-12 (fd00:10:254::8:0:1/126)
  - swp3 → ext-1 (fd00:10:254::9:0:1/126) - Physical interface
  - **swp3.4001** → ext-1 swp2.4001 (192.0.2.10/30, 2001:db8:144:11::2/64) - VRF1 L3VNI peering
  - **swp3.4002** → ext-1 swp2.4002 (192.0.2.14/30, 2001:db8:144:12::6/64) - VRF2 L3VNI peering
  - swp4 → host-121 (VLAN 111, VRF2)
- **VRFs:** vrf1 (vni 104001), vrf2 (vni 104002)
- **BGP:**
  - **Global:** eBGP + L2VPN EVPN with leafs (TOR-LEAF-SPINE peer-group)
  - **VRF vrf1:** eBGP with ext-1 (192.0.2.9, 2001:db8:144:11::1) for Type-5 routes
  - **VRF vrf2:** eBGP with ext-1 (192.0.2.13, 2001:db8:144:12::5) for Type-5 routes

---

### VTEP Layer (ToRs - Pod 2)

#### tor-21 ★
- **AS:** 650030
- **Router-ID:** 10.0.0.30
- **Loopback:** 10.0.0.30/32, fd00:0:20::30/128
- **VTEP Address:** fd00:0:20::30 (for VXLAN tunnels)
- **VXLAN:** vxlan48 (TRUE SVD - all VNIs)
  - L2VNI: 1000111 (VLAN 111), 1000112 (VLAN 112)
  - L3VNI: 104001 (VLAN 4001/vrf1), 104002 (VLAN 4002/vrf2)
- **Interfaces:**
  - swp1 → leaf-21 (fd00:10:254::1e:0:2/126)
  - swp2 → leaf-22 (fd00:10:254::22:0:2/126)
  - swp3 → host-211 swp1 (VLAN 111, VRF2)
  - swp4 → host-211 swp2 (VLAN 112, VRF1)
- **VRFs:** vrf1 (vni 104001), vrf2 (vni 104002)
- **BGP:** eBGP + L2VPN EVPN with leafs

#### tor-22 ★
- **AS:** 650031
- **Router-ID:** 10.0.0.31
- **Loopback:** 10.0.0.31/32, fd00:0:20::31/128
- **VTEP Address:** fd00:0:20::31 (for VXLAN tunnels)
- **VXLAN:** vxlan48 (TRUE SVD - all VNIs)
  - L2VNI: 1000111 (VLAN 111), 1000112 (VLAN 112)
  - L3VNI: 104001 (VLAN 4001/vrf1), 104002 (VLAN 4002/vrf2)
- **Interfaces:**
  - swp1 → leaf-21 (fd00:10:254::1f:0:2/126)
  - swp2 → leaf-22 (fd00:10:254::23:0:2/126)
  - swp3 → host-221 swp1 (VLAN 111, VRF2)
  - swp4 → host-221 swp2 (VLAN 112, VRF1)
- **VRFs:** vrf1 (vni 104001), vrf2 (vni 104002)
- **BGP:** eBGP + L2VPN EVPN with leafs

---

### External Router

#### ext-1
- **AS:** 655000
- **Router-ID:** 10.0.0.3
- **Loopback:** 10.0.0.3/32, fd00:0:20::3/128
- **Interfaces:**
  - swp1 → bordertor-11 (fd00:10:254::2:0:2/126)
  - **swp1.4001** → bordertor-11 swp3.4001 (192.0.2.1/30, 2001:db8:144:1::1/64) - VRF1 peering
  - **swp1.4002** → bordertor-11 swp3.4002 (192.0.2.5/30, 2001:db8:144:2::5/64) - VRF2 peering
  - swp2 → bordertor-12 (fd00:10:254::9:0:2/126)
  - **swp2.4001** → bordertor-12 swp3.4001 (192.0.2.9/30, 2001:db8:144:11::1/64) - VRF1 peering
  - **swp2.4002** → bordertor-12 swp3.4002 (192.0.2.13/30, 2001:db8:144:12::5/64) - VRF2 peering
  - swp3 → host-1 swp1 (198.51.100.0/24, 2001:db8:81:1::1/64)
  - swp4 → host-1 swp2 (198.51.101.0/24, 2001:db8:81:2::1/64)
  - swp5 → host-1 swp3 (198.51.102.0/24, 2001:db8:81:3::1/64)
  - swp6 → host-1 swp4 (198.51.103.0/24, 2001:db8:81:4::1/64)
- **BGP:**
  - **Global:** eBGP with bordertor-11 and bordertor-12 per-VRF
  - **Advertises:** 198.51.100-103.0/24, 2001:db8:81::/48 via prefix-lists and route-maps
  - **Route Filtering:** EXT_HOSTS (IPv4), EXT_HOSTS_v6 (IPv6) prefix-lists
  - **RFC 5549:** Supports capability extended-nexthop for IPv4 routes over IPv6 BGP sessions

#### host-1 (External Host)
- **Type:** External host connected to ext-1
- **Purpose:** Represents external networks/hosts beyond the EVPN fabric
- **Interfaces:**
  - swp1 → ext-1 swp3 (198.51.100.0/24, 2001:db8:81:1::2/64)
  - swp2 → ext-1 swp4 (198.51.101.0/24, 2001:db8:81:2::2/64)
  - swp3 → ext-1 swp5 (198.51.102.0/24, 2001:db8:81:3::2/64)
  - swp4 → ext-1 swp6 (198.51.103.0/24, 2001:db8:81:4::2/64)
- **Connectivity:** 4 links to ext-1 for redundancy and bandwidth

---

### Host Layer

#### Hosts on bordertor-11 (Pod 1) - VLAN 111 only

**host-111**
- **IP:** 192.168.11.111/24, fd00:60:1:1::111/64
- **VLAN:** 111
- **VRF:** vrf2
- **L2VNI:** 1000111
- **Gateway:** bordertor-11 (192.168.11.11)
- **Interface:** swp1 → bordertor-11 swp4

#### Hosts on bordertor-12 (Pod 1) - VLAN 111 only

**host-121**
- **IP:** 192.168.11.121/24, fd00:60:1:1::121/64
- **VLAN:** 111
- **VRF:** vrf2
- **L2VNI:** 1000111
- **Gateway:** bordertor-12 (192.168.11.12)
- **Interface:** swp1 → bordertor-12 swp4

#### Hosts on tor-21 (Pod 2) - VLAN 111 & 112

**host-211**
- **Interfaces:**
  - swp1 → tor-21 swp3
    - IP: 192.168.11.211/24, fd00:60:1:1::211/64
    - VLAN: 111, VRF: vrf2, L2VNI: 1000111
    - Gateway: tor-21 (192.168.11.21)
  - swp2 → tor-21 swp4
    - IP: 192.168.12.212/24, fd00:50:1:1::212/64
    - VLAN: 112, VRF: vrf1, L2VNI: 1000112
    - Gateway: tor-21 (192.168.12.21)

#### Hosts on tor-22 (Pod 2) - VLAN 111 & 112

**host-221**
- **Interfaces:**
  - swp1 → tor-22 swp3
    - IP: 192.168.11.221/24, fd00:60:1:1::221/64
    - VLAN: 111, VRF: vrf2, L2VNI: 1000111
    - Gateway: tor-22 (192.168.11.22)
  - swp2 → tor-22 swp4
    - IP: 192.168.12.222/24, fd00:50:1:1::222/64
    - VLAN: 112, VRF: vrf1, L2VNI: 1000112
    - Gateway: tor-22 (192.168.12.22)

---

## EVPN Architecture

### EVPN Route Flow Path

```
EVPN Type-2 (MAC/IP) and Type-3 (IMET) Route Propagation:

bordertor-11 (VTEP, AS 660000)
    │
    │ L2VPN EVPN over eBGP (IPv4 or IPv6 underlay)
    ↓
leaf-11, leaf-12 (AS 651001)
    │
    │ L2VPN EVPN over eBGP (IPv4 or IPv6 underlay)
    ↓
spine-1, spine-2 (Route Reflector, AS 652000)
    │
    │ L2VPN EVPN over eBGP (IPv4 or IPv6 underlay)
    ↓
leaf-21, leaf-22 (AS 651004)
    │
    │ L2VPN EVPN over eBGP (IPv4 or IPv6 underlay)
    ↓
tor-21, tor-22 (VTEP, AS 650030/650031)
```

### EVPN Type-5 (IP Prefix) Route Exchange

```
External Prefixes → EVPN Fabric:

ext-1 (AS 655000, External Networks: 198.51.100.0/16)
    │
    │ Per-VRF eBGP (NOT EVPN)
    ↓
bordertor-11/12 VRFs (AS 660000)
    │
    │ Advertised as EVPN Type-5 in l2vpn evpn address-family
    ↓
EVPN Fabric Distribution (via leaf → spine → leaf)
    ↓
tor-21/22 VRFs (AS 650030/650031)
    │
    ↓
Internal hosts get external routes
```

### VXLAN Data Plane

```
VXLAN Tunnel Endpoints:

IPv6 Underlay Mode:
  bordertor-11 (fd00:0:20::1) ←→ bordertor-12 (fd00:0:20::2)
                  ↕                           ↕
             tor-21 (fd00:0:20::30) ←→ tor-22 (fd00:0:20::31)

IPv4 Underlay Mode:
  bordertor-11 (10.0.0.1) ←→ bordertor-12 (10.0.0.2)
              ↕                       ↕
         tor-21 (10.0.0.30) ←→ tor-22 (10.0.0.31)

All tunnels carry:
- L2VNI traffic: 1000111, 1000112 (intra-VLAN)
- L3VNI traffic: 104001, 104002 (inter-VLAN routing)
```

### VRF to L3VNI Mapping

```
vrf1 → L3VNI 104001 (VLAN 4001)
  ├─ Contains: 192.168.12.0/24 (VLAN 112)
  ├─ External Connectivity:
  │    192.0.2.0/30 (bordertor-11 .2 ↔ ext-1 .1)
  │    192.0.2.8/30 (bordertor-12 .10 ↔ ext-1 .9)
  └─ Hosts: host-113, host-114, host-123, host-124 (not in current topology)

vrf2 → L3VNI 104002 (VLAN 4002)
  ├─ Contains: 192.168.11.0/24 (VLAN 111)
  ├─ External Connectivity:
  │    192.0.2.4/30 (bordertor-11 .6 ↔ ext-1 .5)
  │    192.0.2.12/30 (bordertor-12 .14 ↔ ext-1 .13)
  └─ Hosts: host-111, host-121, host-211, host-221
```

---

## Traffic Flow Examples

### Example 1: Intra-VLAN (Same L2VNI)
**host-111 → host-121** (both in VLAN 111, VRF2)
1. host-111 sends L2 frame
2. bordertor-11 learns MAC via EVPN
3. EVPN Type-2 route advertised to all VTEPs
4. bordertor-12 receives route, learns MAC
5. Traffic flows via VXLAN tunnel (L2VNI 1000111)
6. No routing needed (same subnet)

### Example 2: Inter-VLAN (Different L2VNIs, Same VRF)
**host-111 (VLAN 111) → host-113 (VLAN 112)** - FAILS (different VRFs)

### Example 3: Inter-VLAN via L3VNI (Symmetric IRB)
**host-111 (VLAN 111/VRF2) → host-121 (VLAN 111/VRF2) on different VTEP**
1. host-111 → bordertor-11 (default gateway)
2. bordertor-11 routes in VRF2
3. Encapsulates in L3VNI 104002
4. VXLAN tunnel to bordertor-12
5. bordertor-12 decapsulates L3VNI
6. Routes in VRF2 to host-121

### Example 4: External Connectivity via L3VNI BGP (NEW)
**host-111 (VLAN 111/VRF2) → ext-1 (External networks via 198.51.100.0/16)**
1. host-111 → bordertor-11 (default gateway)
2. bordertor-11 routes in VRF2
3. Matches external prefix learned via eBGP from ext-1
4. Routes via swp3.4002 to ext-1
5. ext-1 forwards to external network

**External network → host-111:**
1. ext-1 knows 192.168.11.0/24 via eBGP from bordertor-11
2. ext-1 forwards to bordertor-11 via swp1.4002
3. bordertor-11 routes in VRF2
4. Encapsulates in L2VNI 1000111
5. VXLAN tunnel delivers to host-111

---

## Key Configuration Elements

### Single VXLAN Device (TRUE SVD)
Each VTEP has:
```
vxlan48: Single device for ALL VNIs
  ├─ L2VNI 1000111 (VLAN 111)
  ├─ L2VNI 1000112 (VLAN 112)
  ├─ L3VNI 104001 (VLAN 4001)
  └─ L3VNI 104002 (VLAN 4002)
```

### Bridge Configuration
```
br_default: Single VLAN-aware bridge
  ├─ VLANs: 111, 112, 4001, 4002
  ├─ vxlan48 attached with vlan_tunnel
  ├─ Host ports (swp4-5) on bordertor VTEPs
  └─ All VLAN-to-VNI mappings
```

### BorderToR L3VNI External Connectivity

**bordertor-11:**
```
Per-VRF VLAN Sub-interfaces (VRF peering to ext-1):
  ├─ swp3.4001 (VRF1) → ext-1 swp1.4001
  │    IPv4: 192.0.2.2/30 (bordertor .2 ↔ ext-1 .1)
  │    IPv6: 2001:db8:144:1::2/64
  │    BGP neighbor 192.0.2.1 remote-as external
  │
  └─ swp3.4002 (VRF2) → ext-1 swp1.4002
       IPv4: 192.0.2.6/30 (bordertor .6 ↔ ext-1 .5)
       IPv6: 2001:db8:144:2::6/64
       BGP neighbor 192.0.2.5 remote-as external
```

**bordertor-12:**
```
Per-VRF VLAN Sub-interfaces (VRF peering to ext-1):
  ├─ swp3.4001 (VRF1) → ext-1 swp2.4001
  │    IPv4: 192.0.2.10/30 (bordertor .10 ↔ ext-1 .9)
  │    IPv6: 2001:db8:144:11::2/64
  │    BGP neighbor 192.0.2.9 remote-as external
  │
  └─ swp3.4002 (VRF2) → ext-1 swp2.4002
       IPv4: 192.0.2.14/30 (bordertor .14 ↔ ext-1 .13)
       IPv6: 2001:db8:144:12::6/64
       BGP neighbor 192.0.2.13 remote-as external
```

### BGP Configuration Highlights
- **FRR Defaults:** datacenter
- **Underlay:** eBGP (IPv4 or IPv6 numbered)
- **Overlay:** L2VPN EVPN on all fabric BGP sessions
- **External:** Per-VRF eBGP sessions (NOT EVPN) for Type-5 route exchange
- **RFC 5549:** BGP Extended Nexthop capability enabled for IPv4 routes over IPv6 BGP sessions
- **Route Targets:** Auto-derived from L3VNI
- **Route Distinguisher:** Auto-generated
- **Peer-Groups:** TOR-LEAF-SPINE with aggressive timers (3/10)
  - `advertisement-interval 0` - Immediate route advertisements
  - `timers 3 10` - Fast BGP keepalive/hold timers
  - `timers connect 5` - Quick connection retry
  - `capability extended-nexthop` - RFC 5549 support (IPv6 underlay)
  - `allowas-in 1` - Allow own AS in path (for CLOS)
- **ECMP:** `bgp bestpath as-path multipath-relax` + `bgp bestpath compare-routerid` + `maximum-paths 16`

---

## Connection Matrix

| From Node    | Interface  | To Node      | Interface  | IPv4/IPv6 Address (From) | Protocol      | Description               |
|--------------|------------|--------------|------------|--------------------------|---------------|---------------------------|
| spine-1      | swp1       | leaf-11      | swp1       | fd00:10:254::14:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-1      | swp2       | leaf-12      | swp1       | fd00:10:254::18:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-1      | swp3       | leaf-21      | swp1       | fd00:10:254::1c:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-1      | swp4       | leaf-22      | swp1       | fd00:10:254::20:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-2      | swp1       | leaf-11      | swp2       | fd00:10:254::15:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-2      | swp2       | leaf-12      | swp2       | fd00:10:254::19:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-2      | swp3       | leaf-21      | swp2       | fd00:10:254::1d:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| spine-2      | swp4       | leaf-22      | swp2       | fd00:10:254::21:0:2/126    | eBGP+EVPN     | Underlay + Overlay        |
| leaf-11      | swp3       | bordertor-11 | swp1       | fd00:10:254::2/126         | eBGP+EVPN     | Underlay + Overlay        |
| leaf-11      | swp4       | bordertor-12 | swp1       | fd00:10:254::7:0:2/126     | eBGP+EVPN     | Underlay + Overlay        |
| leaf-12      | swp3       | bordertor-11 | swp2       | fd00:10:254::1:0:2/126     | eBGP+EVPN     | Underlay + Overlay        |
| leaf-12      | swp4       | bordertor-12 | swp2       | fd00:10:254::8:0:2/126     | eBGP+EVPN     | Underlay + Overlay        |
| leaf-21      | swp3       | tor-21       | swp1       | fd00:10:254::1e:0:1/126    | eBGP+EVPN     | Underlay + Overlay        |
| leaf-21      | swp4       | tor-22       | swp1       | fd00:10:254::1f:0:1/126    | eBGP+EVPN     | Underlay + Overlay        |
| leaf-22      | swp3       | tor-21       | swp2       | fd00:10:254::22:0:1/126    | eBGP+EVPN     | Underlay + Overlay        |
| leaf-22      | swp4       | tor-22       | swp2       | fd00:10:254::23:0:1/126    | eBGP+EVPN     | Underlay + Overlay        |
| bordertor-11 | swp3       | ext-1        | swp1       | fd00:10:254::2:0:1/126     | IPv6          | Physical link             |
| bordertor-11 | swp3.4001  | ext-1        | swp1.4001  | 192.0.2.2/30             | eBGP (VRF1)   | L3VNI peering             |
| bordertor-11 | swp3.4001  | ext-1        | swp1.4001  | 2001:db8:144:1::2/64         | eBGP (VRF1)   | L3VNI peering (IPv6)      |
| bordertor-11 | swp3.4002  | ext-1        | swp1.4002  | 192.0.2.6/30             | eBGP (VRF2)   | L3VNI peering             |
| bordertor-11 | swp3.4002  | ext-1        | swp1.4002  | 2001:db8:144:2::6/64         | eBGP (VRF2)   | L3VNI peering (IPv6)      |
| bordertor-12 | swp3       | ext-1        | swp2       | fd00:10:254::9:0:1/126     | IPv6          | Physical link             |
| bordertor-12 | swp3.4001  | ext-1        | swp2.4001  | 192.0.2.10/30            | eBGP (VRF1)   | L3VNI peering             |
| bordertor-12 | swp3.4001  | ext-1        | swp2.4001  | 2001:db8:144:11::2/64         | eBGP (VRF1)   | L3VNI peering (IPv6)      |
| bordertor-12 | swp3.4002  | ext-1        | swp2.4002  | 192.0.2.14/30            | eBGP (VRF2)   | L3VNI peering             |
| bordertor-12 | swp3.4002  | ext-1        | swp2.4002  | 2001:db8:144:12::6/64         | eBGP (VRF2)   | L3VNI peering (IPv6)      |
| bordertor-11 | swp4       | host-111     | swp1       | VLAN 111                 | L2 (EVPN)     | Host access               |
| bordertor-12 | swp4       | host-121     | swp1       | VLAN 111                 | L2 (EVPN)     | Host access               |
| tor-21       | swp3       | host-211     | swp1       | VLAN 111                 | L2 (EVPN)     | Host access               |
| tor-21       | swp4       | host-211     | swp2       | VLAN 112                 | L2 (EVPN)     | Host access (VRF1)        |
| tor-22       | swp3       | host-221     | swp1       | VLAN 111                 | L2 (EVPN)     | Host access               |
| tor-22       | swp4       | host-221     | swp2       | VLAN 112                 | L2 (EVPN)     | Host access (VRF1)        |
| ext-1        | swp3       | host-1       | swp1       | 198.51.100.0/24            | L3            | External host link 1      |
| ext-1        | swp4       | host-1       | swp2       | 198.51.101.0/24            | L3            | External host link 2      |
| ext-1        | swp5       | host-1       | swp3       | 198.51.102.0/24            | L3            | External host link 3      |
| ext-1        | swp6       | host-1       | swp4       | 198.51.103.0/24            | L3            | External host link 4      |

---

## Summary Statistics

- **Total Nodes:** 16
- **Spines:** 2 (Route Reflectors)
- **Leafs:** 4 (2 per pod)
- **VTEPs:** 4 (2 border ToRs + 2 ToRs) using Single VXLAN Device (SVD)
- **External Routers:** 1
- **Hosts:** 5 (4 EVPN hosts on VLAN 111 + 1 external host on ext-1)
- **Total BGP Sessions:** 28+ (IPv4/IPv6 underlay + per-VRF external)
- **Total EVPN Sessions:** 20 (L2VPN EVPN overlay)
- **External BGP Sessions:** 4 (2 VRFs × 2 BorderToRs to ext-1)
- **L2VNIs:** 2 (1000111, 1000112)
- **L3VNIs:** 2 (104001, 104002)
- **VRFs:** 2 (vrf1, vrf2)
- **VLANs:** 4 (111, 112, 4001, 4002)
- **L3VNI Peering Subnets:** 4 (192.0.2.0/30, 192.0.2.4/30, 192.0.2.8/30, 192.0.2.12/30)
- **External Networks:** 4 separate /24 networks (198.51.100-103.0/24)

## Key Features Tested

### EVPN/VXLAN Features
- ✅ **Single VXLAN Device (SVD)** - All L2 and L3 VNIs on one vxlan device (vxlan48)
- ✅ **VLAN-aware bridge** - Single bridge (br_default) for all VLANs
- ✅ **L2VNI** - Intra-VLAN forwarding (Type-2, Type-3 routes)
- ✅ **L3VNI** - Inter-VRF routing with symmetric IRB
- ✅ **EVPN Type-5 routes** - External prefix advertisement and import
- ✅ **Head-end Replication (HREP)** - BUM traffic handling
- ✅ **Router MAC (RMAC)** - Inter-VNI routing MAC learning
- ✅ **Nexthop Groups** - Linux kernel ECMP nexthop groups validation
- ✅ **'onlink' flag** - Kernel nexthop flag validation for EVPN routes

### BGP Features
- ✅ **eBGP underlay** - Both IPv4 and IPv6 numbered underlay support
- ✅ **L2VPN EVPN overlay** - Full mesh via route reflectors
- ✅ **RFC 5549** - IPv4 routes with IPv6 next-hops (`capability extended-nexthop`)
- ✅ **Per-VRF BGP sessions** - External connectivity via L3VNI
- ✅ **ECMP** - `multipath-relax` + `compare-routerid` + `maximum-paths 16`
- ✅ **Peer-groups** - TOR-LEAF-SPINE with aggressive timers
- ✅ **AS-PATH allowas-in** - For CLOS topology with AS path relaxation

### Test Coverage
- ✅ **Parametrized tests** - All tests run with both IPv4 and IPv6 underlay
- ✅ **Control plane validation** - BGP, EVPN, VNI state verification
- ✅ **Data plane validation** - Kernel route/nexthop verification, ping tests
- ✅ **JSON-based validation** - Expected vs actual FRR/kernel output comparison
- ✅ **Retry logic** - `topotest.run_and_expect` for flap tolerance

---

## Test Framework

### Test Cases

The test suite (`test_bgp_evpn_v4_v6_vtep.py`) includes comprehensive validation.

**Note:** All tests are parametrized to run with both IPv4 and IPv6 underlay configurations.

1. **`test_bgp_summary_neighbor_state`** - Validates BGP session establishment (ipv4Unicast/ipv6Unicast based on underlay)
2. **`test_evpn_routes_advertised`** - Checks EVPN Type-2/Type-3 route advertisement on all VTEPs
3. **`test_evpn_vni_remote_vtep_and_hrep`** - Verifies remote VTEP learning and HREP entries for each VNI
4. **`test_evpn_local_vtep_ip`** - Validates VTEP source IP configuration in kernel/FRR for all VNIs (L2 and L3)
5. **`test_vni_state`** - Verifies VNI operational state for both L2 and L3 VNIs
6. **`test_l3vni_rmacs`** - Validates L3VNI Router MACs (RMACs) from remote VTEPs
7. **`test_vrf_routes`** - Displays route learning in VRF routing tables (informational)
8. **`test_evpn_vtep_nexthops`** - Verifies EVPN L3VNI next-hops from remote VTEPs (IPv4/IPv6 agnostic)
9. **`test_evpn_check_overlay_route`** - Verifies EVPN Type-5 overlay routes in FRR RIB and Linux kernel
   - Validates route 198.51.100.0/24 in vrf1 on tor-21
   - Checks ECMP next-hops (bordertor-11, bordertor-12)
   - Verifies kernel nexthop groups with 'onlink' flag
   - Tests RFC 5549: IPv4 routes with IPv6 next-hops (IPv6 underlay)
10. **`test_host_to_host_ping`** - Verifies end-to-end connectivity (host-211 → host-111)
    - IPv4 connectivity test (when using IPv4 underlay)
    - IPv6 connectivity test (when using IPv6 underlay)
11. **`test_memory_leak`** - Memory leak detection

### Library Functions (`tests/topotests/lib/evpn.py`)

Generic EVPN helper functions for reuse across topotests:

#### VNI and VTEP Verification
- **`evpn_verify_vni_remote_vteps`** - Verify expected remote VTEPs are learned for each L2VNI (validates IMET route info synced in zebra via EVPN control plane and bridge FDB HREP entries with MAC=00:00:00:00:00:00 and src_vni)
- **`evpn_verify_vni_vtep_src_ip`** - Verify VTEP source IP in kernel/FRR/BGP for VNIs
- **`evpn_verify_vni_state`** - Verify VNI operational state (L2/L3, remote VTEPs, VRF association)
- **`evpn_verify_bgp_vni_state`** - Verify L2VNI state using `show bgp l2vpn evpn vni {vni} json` with flexible field validation (supports RD, advertiseGatewayMacip, inKernel checks)

#### EVPN Route Verification
- **`evpn_verify_route_advertisement`** - Verify EVPN route types (Type-2, Type-3, Type-5) in BGP

#### L3VNI and Routing Verification
- **`evpn_verify_l3vni_rmacs`** - Verify L3VNI Router MACs from remote VTEPs
- **`evpn_verify_l3vni_remote_rmacs`** - Orchestrate L3VNI RMAC verification across topology
- **`evpn_verify_l3vni_remote_nexthops`** - Verify EVPN L3VNI next-hops using `show evpn next-hops vni {vni} json` (auto-discovers VTEP IPs, IPv4/IPv6 agnostic)
- **`evpn_verify_vrf_rib_route`** - Verify specific VRF route in FRR RIB using `show ip route vrf {vrf} {route} json` with expected JSON comparison
- **`evpn_verify_overlay_route_in_kernel`** - Verify EVPN overlay route in Linux kernel using `ip -j route show` and `ip -j nexthop get id`, validates:
  - Route exists with nexthop group ID (nhid)
  - Nexthop group contains expected individual nexthops
  - Each nexthop has correct gateway IP and output device
  - Each nexthop has 'onlink' flag set (critical for EVPN/VXLAN)

#### Connectivity and MAC Learning
- **`evpn_verify_ping_connectivity`** - Generic ping test (IPv4/IPv6 auto-detect) with retry logic, asserts 0% packet loss
- **`evpn_trigger_arp_scapy`** - Trigger ARP/NDP from hosts using Scapy to populate MAC tables

### Setup Functions

- **`setup_vtep`** - Configure TRUE SVD (Single VXLAN Device) on VTEPs
- **`setup_bordertor_ext_connectivity`** - Configure VLAN sub-interfaces for L3VNI external peering
- **`setup_ext1`** - Configure external router interfaces and VLAN sub-interfaces

### MAC Learning

Hosts automatically trigger ARP/NDP requests during setup using `evpn_trigger_arp_scapy`:
- Uses Scapy to send ARP (IPv4) or NDP (IPv6) packets
- Sends 3 packets per host-gateway pair to their default gateway
- 1-second interval between packets
- Ensures MAC addresses are learned by VTEPs for EVPN Type-2 route advertisement
- Supports multiple VLANs and interfaces (swp1 for VLAN 111, swp2 for VLAN 112)

### Static Routes for EVPN Type-5 Testing

ToRs (tor-21, tor-22) advertise static blackhole routes via BGP to test EVPN Type-5 route propagation:

**tor-21 VRF1:**
- `ip route 203.0.113.0/24 blackhole`
- `ipv6 route 2001:db8:72:21::/64 blackhole`

**tor-21 VRF2:**
- `ip route 203.0.115.0/24 blackhole`
- `ipv6 route 2001:db8:73:21::/64 blackhole`

**tor-22 VRF1:**
- `ip route 203.0.114.0/24 blackhole`
- `ipv6 route 2001:db8:72:22::/64 blackhole`

**tor-22 VRF2:**
- `ip route 203.0.116.0/24 blackhole`
- `ipv6 route 2001:db8:73:22::/64 blackhole`

These routes are redistributed via `redistribute static` under BGP VRF address families and advertised as EVPN Type-5 routes to the fabric.

**Note:** `advertise-default-gw` is removed from `l2vpn evpn` address family VRF configuration to avoid conflicts with Type-5 route advertisement.

### Test Data Files

Expected JSON outputs are stored in version-specific directories:

**IPv4 Underlay (`ipv4/` directory):**
- `tor-21/type5_prefix1.json` - Expected output for route 198.51.100.0/24 with IPv4 next-hops (10.0.0.1, 10.0.0.2)

**IPv6 Underlay (`ipv6/` directory):**
- `tor-21/type5_prefix1.json` - Expected output for route 198.51.100.0/24 with IPv6 next-hops (fd00:0:20::1, fd00:0:20::2)

These files are used by `test_evpn_check_overlay_route` to validate FRR RIB state using `evpn_verify_vrf_rib_route`.
