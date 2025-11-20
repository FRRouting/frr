# BGP EVPN MH IPv4/IPv6 Numbered - Network Topology

## Topology Diagram

```
                                 SPINE LAYER (AS 65001)
                            ┌─────────────────────────────┐
                            │                             │
                    ┌───────┴────────┐          ┌────────┴────────┐
                    │    spine1      │          │    spine2       │
                    │  AS 65001      │          │  AS 65001       │
                    │  lo: 2001:db8: │          │  lo: 2001:db8:  │
                    │      100::13   │          │      100::14    │
                    └────┬──────┬────┘          └────┬──────┬─────┘
                         │      │                    │      │
                    eth0 │      │ eth1          eth0 │      │ eth1
              ::50::1/127│      │::51::1/127 ::60::1/127   │::61::1/127
                         │      │                    │      │
                         │      └─────────┐    ┏─────┘      │
                         │                │    │            │
                    ┌────┴──────┐    ┌────┴────┴──┐    ┌────┴────────┐
                    │   leaf1   │    │   leaf2    │    │             │
                    │  AS 65101 │    │  AS 65101  │    │             │
                    │  lo: 2001:│    │  lo: 2001: │    │             │
                    │  db8:200::│    │  db8:200:: │    │             │
                    │      13   │    │      14    │    │             │
                    └─┬──┬──┬──┬┘    └─┬──┬──┬───┬┘    │             │
                 eth2 │  │  │  │       │  │  │   │     │             │
                      │  │  │  └───────┘  │  │   └─────┘             │
                      │  │  │             │  │                        │
                      │  │  └─────────────┼──┼────────────────────────┘
                      │  │                │  │
                      │  └────────────────┼──┼──────────────┐
                      │                   │  │              │
                      │ eth3          eth4│  │eth5      eth2│ eth3
                      │                   │  │              │
                      │                   │  │              │
                    ┌─┴─────────┐  ┌──────┴──┴────┐  ┌─────┴───────┐  ┌──────────────┐
                    │  torm11   │  │   torm12     │  │  torm21     │  │   torm22     │
                    │ AS 65002  │  │  AS 65003    │  │ AS 65004    │  │  AS 65005    │
                    │ VTEP:     │  │  VTEP:       │  │ VTEP:       │  │  VTEP:       │
                    │ 2001:db8: │  │  2001:db8:   │  │ 2001:db8:   │  │  2001:db8:   │
                    │ 100::15   │  │  100::16     │  │ 100::17     │  │  100::18     │
                    └─┬───────┬─┘  └─┬────────┬───┘  └─┬───────┬───┘  └─┬────────┬───┘
                 eth2 │       │eth3  │eth2    │eth3    │eth2   │eth3    │eth2    │eth3
                      │       │      │        │        │       │        │        │
                      │       └──────┼────┐   │   ┌────┼───────┘        │   ┌────┘
                      │              │    │   │   │    │                │   │
                    ┌─┴─────┐  ┌─────┴──┐ │   │   │ ┌──┴──────┐  ┌──────┴───┴──┐
                    │hostd11│  │hostd12 │ │   │   │ │hostd21  │  │  hostd22    │
                    │(bond) │  │(bond)  │ │   │   │ │(bond)   │  │  (bond)     │
                    └───┬───┘  └────┬───┘ │   │   │ └────┬────┘  └─────┬───────┘
                        │           │     │   │   │      │             │
                        └───────────┴─────┴───┴───┴──────┴─────────────┘
                              Rack 1                  Rack 2
                         ES sys-mac:             ES sys-mac:
                      44:38:39:ff:ff:01       44:38:39:ff:ff:02
```

## Layer Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SPINE LAYER                                │
│                                                                   │
│  spine1 (AS 65001)              spine2 (AS 65001)                │
│  - BGP Route Reflector          - BGP Route Reflector            │
│  - L2VPN EVPN                   - L2VPN EVPN                     │
└──────────────────────────────────────────────────────────────────┘
                              ▲  │
                              │  ▼
┌──────────────────────────────────────────────────────────────────┐
│                         LEAF LAYER                                │
│                                                                   │
│  leaf1 (AS 65101)               leaf2 (AS 65101)                 │
│  - BGP Route Reflector          - BGP Route Reflector            │
│  - Aggregation                  - Aggregation                    │
└──────────────────────────────────────────────────────────────────┘
                              ▲  │
                              │  ▼
┌──────────────────────────────────────────────────────────────────┐
│                          TOR LAYER (VTEP)                         │
│                                                                   │
│  Rack 1:                        Rack 2:                          │
│  ├─ torm11 (AS 65002)          ├─ torm21 (AS 65004)             │
│  │  VTEP: 2001:db8:100::15    │  VTEP: 2001:db8:100::17        │
│  └─ torm12 (AS 65003)          └─ torm22 (AS 65005)             │
│     VTEP: 2001:db8:100::16        VTEP: 2001:db8:100::18        │
│                                                                   │
│  Features:                                                        │
│  - EVPN Multihoming (ES-ID, ES sys-mac)                         │
│  - VXLAN (VNI 1000)                                              │
│  - PIM6 for BUM traffic                                          │
│  - SVI: VLAN 1000                                                │
└──────────────────────────────────────────────────────────────────┘
                              ▲  │
                              │  ▼
┌──────────────────────────────────────────────────────────────────┐
│                         HOST LAYER                                │
│                                                                   │
│  Rack 1:                        Rack 2:                          │
│  ├─ hostd11 (dual-attached)   ├─ hostd21 (dual-attached)        │
│  └─ hostd12 (dual-attached)   └─ hostd22 (dual-attached)        │
│                                                                   │
│  - LACP bonds to both TORs                                       │
│  - IPv6 addressing in VLAN 1000                                  │
└──────────────────────────────────────────────────────────────────┘
```

## Detailed Connection Table

### Spine to Leaf Connections

| Source Device | Source Interface | Source IPv6 Address | Destination Device | Destination Interface | Destination IPv6 Address | AS Pair |
|--------------|------------------|---------------------|-------------------|----------------------|--------------------------|---------|
| spine1 | spine1-eth0 | 2001:db8:50::1/127 | leaf1 | leaf1-eth0 | 2001:db8:50::0/127 | 65001 ↔ 65101 |
| spine1 | spine1-eth1 | 2001:db8:51::1/127 | leaf2 | leaf2-eth0 | 2001:db8:51::0/127 | 65001 ↔ 65101 |
| spine2 | spine2-eth0 | 2001:db8:60::1/127 | leaf1 | leaf1-eth1 | 2001:db8:60::0/127 | 65001 ↔ 65101 |
| spine2 | spine2-eth1 | 2001:db8:61::1/127 | leaf2 | leaf2-eth1 | 2001:db8:61::0/127 | 65001 ↔ 65101 |

### Leaf to TOR Connections (Rack 1)

| Source Device | Source Interface | Source IPv6 Address | Destination Device | Destination Interface | Destination IPv6 Address | AS Pair |
|--------------|------------------|---------------------|-------------------|----------------------|--------------------------|---------|
| leaf1 | leaf1-eth2 | 2001:db8:1::1/127 | torm11 | torm11-eth0 | 2001:db8:1::0/127 | 65101 ↔ 65002 |
| leaf1 | leaf1-eth3 | 2001:db8:2::1/127 | torm12 | torm12-eth0 | 2001:db8:2::0/127 | 65101 ↔ 65003 |
| leaf2 | leaf2-eth2 | 2001:db8:5::1/127 | torm11 | torm11-eth1 | 2001:db8:5::0/127 | 65101 ↔ 65002 |
| leaf2 | leaf2-eth3 | 2001:db8:6::1/127 | torm12 | torm12-eth1 | 2001:db8:6::0/127 | 65101 ↔ 65003 |

### Leaf to TOR Connections (Rack 2)

| Source Device | Source Interface | Source IPv6 Address | Destination Device | Destination Interface | Destination IPv6 Address | AS Pair |
|--------------|------------------|---------------------|-------------------|----------------------|--------------------------|---------|
| leaf1 | leaf1-eth4 | 2001:db8:3::1/127 | torm21 | torm21-eth0 | 2001:db8:3::0/127 | 65101 ↔ 65004 |
| leaf1 | leaf1-eth5 | 2001:db8:4::1/127 | torm22 | torm22-eth0 | 2001:db8:4::0/127 | 65101 ↔ 65005 |
| leaf2 | leaf2-eth4 | 2001:db8:7::1/127 | torm21 | torm21-eth1 | 2001:db8:7::0/127 | 65101 ↔ 65004 |
| leaf2 | leaf2-eth5 | 2001:db8:8::1/127 | torm22 | torm22-eth1 | 2001:db8:8::0/127 | 65101 ↔ 65005 |

### TOR to Host Connections (Rack 1)

| Source Device | Source Interface | Destination Device | Destination Interface | Bond Interface | ES-ID | ES System MAC |
|--------------|------------------|-------------------|----------------------|----------------|-------|---------------|
| torm11 | torm11-eth2 | hostd11 | hostd11-eth0 | hostbond1 | 1 | 44:38:39:ff:ff:01 |
| torm11 | torm11-eth3 | hostd12 | hostd12-eth0 | hostbond2 | 2 | 44:38:39:ff:ff:01 |
| torm12 | torm12-eth2 | hostd11 | hostd11-eth1 | hostbond1 | 1 | 44:38:39:ff:ff:01 |
| torm12 | torm12-eth3 | hostd12 | hostd12-eth1 | hostbond2 | 2 | 44:38:39:ff:ff:01 |

### TOR to Host Connections (Rack 2)

| Source Device | Source Interface | Destination Device | Destination Interface | Bond Interface | ES-ID | ES System MAC |
|--------------|------------------|-------------------|----------------------|----------------|-------|---------------|
| torm21 | torm21-eth2 | hostd21 | hostd21-eth0 | hostbond1 | 1 | 44:38:39:ff:ff:02 |
| torm21 | torm21-eth3 | hostd22 | hostd22-eth0 | hostbond2 | 2 | 44:38:39:ff:ff:02 |
| torm22 | torm22-eth2 | hostd21 | hostd21-eth1 | hostbond1 | 1 | 44:38:39:ff:ff:02 |
| torm22 | torm22-eth3 | hostd22 | hostd22-eth1 | hostbond2 | 2 | 44:38:39:ff:ff:02 |

## IPv6 Addressing Scheme

### Loopback Addresses (Dual-Stack)

All routers have both IPv4 and IPv6 loopback addresses for proper BGP router-id and IPv6 VTEP functionality.

#### Spine Routers
| Device | IPv4 Loopback | IPv6 Loopback | BGP Router-ID | AS Number |
|--------|--------------|---------------|---------------|-----------|
| spine1 | 10.0.0.13/32 | 2001:db8:100::13/128 | 10.0.0.13 | 65001 |
| spine2 | 10.0.0.14/32 | 2001:db8:100::14/128 | 10.0.0.14 | 65001 |

#### Leaf Routers
| Device | IPv4 Loopback | IPv6 Loopback | BGP Router-ID | AS Number |
|--------|--------------|---------------|---------------|-----------|
| leaf1 | 10.0.0.13/32 | 2001:db8:200::13/128 | 10.0.0.13 | 65101 |
| leaf2 | 10.0.0.14/32 | 2001:db8:200::14/128 | 10.0.0.14 | 65101 |

#### TOR Routers (VTEP)
| Device | IPv4 Loopback | IPv6 Loopback (VTEP) | BGP Router-ID | AS Number |
|--------|--------------|---------------------|---------------|-----------|
| torm11 | 10.0.0.15/32 | **2001:db8:100::15/128** | 10.0.0.15 | 65002 |
| torm12 | 10.0.0.16/32 | **2001:db8:100::16/128** | 10.0.0.16 | 65003 |
| torm21 | 10.0.0.17/32 | **2001:db8:100::17/128** | 10.0.0.17 | 65004 |
| torm22 | 10.0.0.18/32 | **2001:db8:100::18/128** | 10.0.0.18 | 65005 |

**Note**: TOR routers use IPv6 addresses (2001:db8:100::15-18) as VTEP source addresses for VXLAN tunnels. IPv4 loopbacks are configured for BGP router-id compatibility.

### Point-to-Point Link Addresses (/127 Networks)

#### Spine to Leaf Links
| Network | Device 1 | Address 1 | Device 2 | Address 2 |
|---------|----------|-----------|----------|-----------|
| 2001:db8:50::/127 | spine1-eth0 | ::1 | leaf1-eth0 | ::0 |
| 2001:db8:51::/127 | spine1-eth1 | ::1 | leaf2-eth0 | ::0 |
| 2001:db8:60::/127 | spine2-eth0 | ::1 | leaf1-eth1 | ::0 |
| 2001:db8:61::/127 | spine2-eth1 | ::1 | leaf2-eth1 | ::0 |

#### Leaf to TOR Links (Rack 1)
| Network | Device 1 | Address 1 | Device 2 | Address 2 |
|---------|----------|-----------|----------|-----------|
| 2001:db8:1::/127 | leaf1-eth2 | ::1 | torm11-eth0 | ::0 |
| 2001:db8:2::/127 | leaf1-eth3 | ::1 | torm12-eth0 | ::0 |
| 2001:db8:5::/127 | leaf2-eth2 | ::1 | torm11-eth1 | ::0 |
| 2001:db8:6::/127 | leaf2-eth3 | ::1 | torm12-eth1 | ::0 |

#### Leaf to TOR Links (Rack 2)
| Network | Device 1 | Address 1 | Device 2 | Address 2 |
|---------|----------|-----------|----------|-----------|
| 2001:db8:3::/127 | leaf1-eth4 | ::1 | torm21-eth0 | ::0 |
| 2001:db8:4::/127 | leaf1-eth5 | ::1 | torm22-eth0 | ::0 |
| 2001:db8:7::/127 | leaf2-eth4 | ::1 | torm21-eth1 | ::0 |
| 2001:db8:8::/127 | leaf2-eth5 | ::1 | torm22-eth1 | ::0 |

### SVI and Host Addresses (2001:db8:45::/64)

#### VLAN 1000 SVI Addresses
| Device | SVI Address | Interface | Purpose |
|--------|-------------|-----------|---------|
| torm11 | 2001:db8:45::2/64 | vlan1000 | TOR SVI |
| torm12 | 2001:db8:45::3/64 | vlan1000 | TOR SVI |
| torm21 | 2001:db8:45::4/64 | vlan1000 | TOR SVI |
| torm22 | 2001:db8:45::5/64 | vlan1000 | TOR SVI |
| All TORs | 2001:db8:45::1/64 | vlan1000-v0 | **Anycast Gateway** |

#### Host Addresses
| Device | Host Address | Interface | MAC Address |
|--------|--------------|-----------|-------------|
| hostd11 | 2001:db8:45::11/64 | torbond | 00:00:00:00:00:11 |
| hostd12 | 2001:db8:45::12/64 | torbond | 00:00:00:00:00:12 |
| hostd21 | 2001:db8:45::21/64 | torbond | 00:00:00:00:00:21 |
| hostd22 | 2001:db8:45::22/64 | torbond | 00:00:00:00:00:22 |

## BGP AS Number Scheme

### AS Number Allocation
| Layer | Device(s) | AS Number | Role |
|-------|-----------|-----------|------|
| Spine | spine1, spine2 | 65001 | Route Reflectors for Leaf layer |
| Leaf | leaf1, leaf2 | 65101 | Aggregation, Route Reflectors for TOR layer |
| TOR Rack1 | torm11 | 65002 | VTEP, EVPN PE |
| TOR Rack1 | torm12 | 65003 | VTEP, EVPN PE |
| TOR Rack2 | torm21 | 65004 | VTEP, EVPN PE |
| TOR Rack2 | torm22 | 65005 | VTEP, EVPN PE |

### BGP Session Summary

**Total BGP Sessions**: 20

#### Spine Layer (4 sessions)
- spine1 ↔ leaf1 (AS 65001 ↔ 65101)
- spine1 ↔ leaf2 (AS 65001 ↔ 65101)
- spine2 ↔ leaf1 (AS 65001 ↔ 65101)
- spine2 ↔ leaf2 (AS 65001 ↔ 65101)

#### Leaf to Rack 1 (8 sessions)
- leaf1 ↔ torm11 (AS 65101 ↔ 65002)
- leaf1 ↔ torm12 (AS 65101 ↔ 65003)
- leaf2 ↔ torm11 (AS 65101 ↔ 65002)
- leaf2 ↔ torm12 (AS 65101 ↔ 65003)

#### Leaf to Rack 2 (8 sessions)
- leaf1 ↔ torm21 (AS 65101 ↔ 65004)
- leaf1 ↔ torm22 (AS 65101 ↔ 65005)
- leaf2 ↔ torm21 (AS 65101 ↔ 65004)
- leaf2 ↔ torm22 (AS 65101 ↔ 65005)

## EVPN Multihoming Configuration

### Ethernet Segment Configuration

#### Rack 1 (ES System MAC: 44:38:39:ff:ff:01)
| Host | TOR Interfaces | Bond Name | ES-ID | ES Type |
|------|---------------|-----------|-------|---------|
| hostd11 | torm11-eth2, torm12-eth2 | hostbond1 | 1 | All-Active |
| hostd12 | torm11-eth3, torm12-eth3 | hostbond2 | 2 | All-Active |

**ESI Format**: 03:44:38:39:ff:ff:01:00:00:0X (where X = ES-ID)

#### Rack 2 (ES System MAC: 44:38:39:ff:ff:02)
| Host | TOR Interfaces | Bond Name | ES-ID | ES Type |
|------|---------------|-----------|-------|---------|
| hostd21 | torm21-eth2, torm22-eth2 | hostbond1 | 1 | All-Active |
| hostd22 | torm21-eth3, torm22-eth3 | hostbond2 | 2 | All-Active |

**ESI Format**: 03:44:38:39:ff:ff:02:00:00:0X (where X = ES-ID)

### VXLAN Configuration

| Parameter | Value |
|-----------|-------|
| VNI | 1000 |
| VLAN | 1000 |
| Multicast Group | ff0e::100 (IPv6) |
| UDP Port | 4789 (standard VXLAN) |
| MTU | 9152 |
| TTL | 64 |
| Learning | Disabled (EVPN control plane) |

## Interface Summary by Device

### spine1
```
lo              : 10.0.0.13/32 (IPv4) + 2001:db8:100::13/128 (IPv6)
spine1-eth0     : 2001:db8:50::1/127    → leaf1-eth0
spine1-eth1     : 2001:db8:51::1/127    → leaf2-eth0
```

### spine2
```
lo              : 10.0.0.14/32 (IPv4) + 2001:db8:100::14/128 (IPv6)
spine2-eth0     : 2001:db8:60::1/127    → leaf1-eth1
spine2-eth1     : 2001:db8:61::1/127    → leaf2-eth1
```

### leaf1
```
lo              : 10.0.0.13/32 (IPv4) + 2001:db8:200::13/128 (IPv6)
leaf1-eth0      : 2001:db8:50::0/127    → spine1-eth0
leaf1-eth1      : 2001:db8:60::0/127    → spine2-eth0
leaf1-eth2      : 2001:db8:1::1/127     → torm11-eth0
leaf1-eth3      : 2001:db8:2::1/127     → torm12-eth0
leaf1-eth4      : 2001:db8:3::1/127     → torm21-eth0
leaf1-eth5      : 2001:db8:4::1/127     → torm22-eth0
```

### leaf2
```
lo              : 10.0.0.14/32 (IPv4) + 2001:db8:200::14/128 (IPv6)
leaf2-eth0      : 2001:db8:51::0/127    → spine1-eth1
leaf2-eth1      : 2001:db8:61::0/127    → spine2-eth1
leaf2-eth2      : 2001:db8:5::1/127     → torm11-eth1
leaf2-eth3      : 2001:db8:6::1/127     → torm12-eth1
leaf2-eth4      : 2001:db8:7::1/127     → torm21-eth1
leaf2-eth5      : 2001:db8:8::1/127     → torm22-eth1
```

### torm11 (IPv6 VTEP: 2001:db8:100::15/128)
```
lo              : 10.0.0.15/32 (IPv4 router-id) + 2001:db8:100::15/128 (IPv6 VTEP)
torm11-eth0     : 2001:db8:1::0/127     → leaf1-eth2 (PIM6, MH uplink)
torm11-eth1     : 2001:db8:5::0/127     → leaf2-eth2 (PIM6, MH uplink)
torm11-eth2     : L2 only               → hostd11-eth0 (in hostbond1)
torm11-eth3     : L2 only               → hostd12-eth0 (in hostbond2)
vlan1000        : 2001:db8:45::2/64     (SVI)
vlan1000-v0     : 2001:db8:45::1/64     (Anycast GW)
vx-1000         : VNI 1000, local 2001:db8:100::15, group ff0e::100
bridge          : VLAN aware bridge
ipmr-lo         : Multicast termination device
hostbond1       : ES-ID 1, sys-mac 44:38:39:ff:ff:01
hostbond2       : ES-ID 2, sys-mac 44:38:39:ff:ff:01
```

### torm12 (IPv6 VTEP: 2001:db8:100::16/128)
```
lo              : 10.0.0.16/32 (IPv4 router-id) + 2001:db8:100::16/128 (IPv6 VTEP)
torm12-eth0     : 2001:db8:2::0/127     → leaf1-eth3 (PIM6, MH uplink)
torm12-eth1     : 2001:db8:6::0/127     → leaf2-eth3 (PIM6, MH uplink)
torm12-eth2     : L2 only               → hostd11-eth1 (in hostbond1)
torm12-eth3     : L2 only               → hostd12-eth1 (in hostbond2)
vlan1000        : 2001:db8:45::3/64     (SVI)
vlan1000-v0     : 2001:db8:45::1/64     (Anycast GW)
vx-1000         : VNI 1000, local 2001:db8:100::16, group ff0e::100
bridge          : VLAN aware bridge
ipmr-lo         : Multicast termination device
hostbond1       : ES-ID 1, sys-mac 44:38:39:ff:ff:01
hostbond2       : ES-ID 2, sys-mac 44:38:39:ff:ff:01
```

### torm21 (IPv6 VTEP: 2001:db8:100::17/128)
```
lo              : 10.0.0.17/32 (IPv4 router-id) + 2001:db8:100::17/128 (IPv6 VTEP)
torm21-eth0     : 2001:db8:3::0/127     → leaf1-eth4 (PIM6, MH uplink)
torm21-eth1     : 2001:db8:7::0/127     → leaf2-eth4 (PIM6, MH uplink)
torm21-eth2     : L2 only               → hostd21-eth0 (in hostbond1)
torm21-eth3     : L2 only               → hostd22-eth0 (in hostbond2)
vlan1000        : 2001:db8:45::4/64     (SVI)
vlan1000-v0     : 2001:db8:45::1/64     (Anycast GW)
vx-1000         : VNI 1000, local 2001:db8:100::17, group ff0e::100
bridge          : VLAN aware bridge
ipmr-lo         : Multicast termination device
hostbond1       : ES-ID 1, sys-mac 44:38:39:ff:ff:02
hostbond2       : ES-ID 2, sys-mac 44:38:39:ff:ff:02
```

### torm22 (IPv6 VTEP: 2001:db8:100::18/128)
```
lo              : 10.0.0.18/32 (IPv4 router-id) + 2001:db8:100::18/128 (IPv6 VTEP)
torm22-eth0     : 2001:db8:4::0/127     → leaf1-eth5 (PIM6, MH uplink)
torm22-eth1     : 2001:db8:8::0/127     → leaf2-eth5 (PIM6, MH uplink)
torm22-eth2     : L2 only               → hostd21-eth1 (in hostbond1)
torm22-eth3     : L2 only               → hostd22-eth1 (in hostbond2)
vlan1000        : 2001:db8:45::5/64     (SVI)
vlan1000-v0     : 2001:db8:45::1/64     (Anycast GW)
vx-1000         : VNI 1000, local 2001:db8:100::18, group ff0e::100
bridge          : VLAN aware bridge
ipmr-lo         : Multicast termination device
hostbond1       : ES-ID 1, sys-mac 44:38:39:ff:ff:02
hostbond2       : ES-ID 2, sys-mac 44:38:39:ff:ff:02
```

### hostd11
```
hostd11-eth0    : In bond torbond       → torm11-eth2
hostd11-eth1    : In bond torbond       → torm12-eth2
torbond         : 2001:db8:45::11/64, MAC: 00:00:00:00:00:11
```

### hostd12
```
hostd12-eth0    : In bond torbond       → torm11-eth3
hostd12-eth1    : In bond torbond       → torm12-eth3
torbond         : 2001:db8:45::12/64, MAC: 00:00:00:00:00:12
```

### hostd21
```
hostd21-eth0    : In bond torbond       → torm21-eth2
hostd21-eth1    : In bond torbond       → torm22-eth2
torbond         : 2001:db8:45::21/64, MAC: 00:00:00:00:00:21
```

### hostd22
```
hostd22-eth0    : In bond torbond       → torm21-eth3
hostd22-eth1    : In bond torbond       → torm22-eth3
torbond         : 2001:db8:45::22/64, MAC: 00:00:00:00:00:22
```

## Routing Protocol Summary

### BGP Configuration

| Device | BGP Features |
|--------|-------------|
| spine1, spine2 | IPv6 unicast, L2VPN EVPN, Route Reflector role |
| leaf1, leaf2 | IPv6 unicast, L2VPN EVPN, Route Reflector role, Peer groups |
| torm11-22 | IPv6 unicast, L2VPN EVPN, advertise-all-vni, advertise-svi-ip |

### PIM6 Configuration

Only on TOR routers:
- Protocol: PIM6 (IPv6 PIM)
- Interfaces: All uplink interfaces (eth0, eth1) and ipmr-lo
- Join-Prune Interval: 5 seconds
- Multicast Group: ff0e::100 (for VXLAN BUM traffic)

## Traffic Flow Examples

### East-West Traffic (hostd11 → hostd21)

```
hostd11 (2001:db8:45::11)
    ↓ (torbond - LACP to torm11/torm12)
torm11 or torm12 (DF election determines forwarder)
    ↓ (VXLAN encapsulation with VTEP 2001:db8:100::15 or ::16)
    ↓ (IPv6 underlay: through leaf1/leaf2 and spine1/spine2)
    ↓ (Destination VTEP: 2001:db8:100::17 or ::18)
torm21 or torm22 (ES load balancing)
    ↓ (VXLAN decapsulation)
    ↓ (hostbond1 - LACP)
hostd21 (2001:db8:45::21)
```

### BUM Traffic (Broadcast/Unknown Unicast/Multicast)

```
Source TOR (e.g., torm11)
    ↓ (Encapsulate in IPv6 multicast: ff0e::100)
    ↓ (PIM6 distributes to all VTEPs)
All other TORs (torm12, torm21, torm22)
    ↓ (Receive via multicast, decapsulate)
    ↓ (Forward to local hosts)
```

## Notes

1. **Dual-Stack Loopbacks**: All routers have both IPv4 and IPv6 loopback addresses
   - IPv4: Used for BGP router-id (10.0.0.13-18)
   - IPv6: Used for VTEP addresses and routing (2001:db8:100::x, 2001:db8:200::x)

2. **All P2P links use /127**: More efficient than /64 for IPv6 point-to-point

3. **EBGP Numbered**: Explicit neighbor IPv6 addresses configured

4. **Extended Nexthop**: Capability enabled for IPv4 over IPv6 BGP sessions

5. **IPv6-Only Links**: `no bgp default ipv4-unicast` - pure IPv6 underlay for BGP

6. **IPv6 VTEP Source**: TOR routers use IPv6 loopback (2001:db8:100::15-18) as VXLAN local address

7. **EVPN Type-1 Routes**: Used for ES discovery and EAD - advertise IPv6 VTEP

8. **EVPN Type-2 Routes**: Used for MAC/IP advertisement

9. **DF Election**: Based on ES-ID and modulo algorithm

10. **Anycast Gateway**: Same IPv6/MAC (2001:db8:45::1) on all TORs for first-hop redundancy

11. **PIM6**: IPv6 multicast (ff0e::100) for BUM traffic in VXLAN
