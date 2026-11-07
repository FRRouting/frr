# BGP EVPN DAD Native Topology

## Topology

```
             underlay: 10.0.0.0/30

          swp1 10.0.0.1/30      swp1 10.0.0.2/30
        +------------------+   +------------------+
        |      tor-11      |---|      tor-21      |
        | VTEP 10.0.0.11   |   | VTEP 10.0.0.21   |
        +--------+---------+   +---------+--------+
                 | swp2                   | swp2
                 | VLAN 111               | VLAN 111
        +--------+---------+   +---------+--------+
        |     host-111     |   |     host-211     |
        | swp1             |   | swp1             |
        +------------------+   +------------------+
```

Both ToRs use a native VLAN-aware bridge/VXLAN layout:

- bridge: `br_default`
- SVI: `vlan111`
- VXLAN device: `vxlan48`
- VLAN: `111`
- L2 VNI: `1000111`

## Addressing

| Node | Interface | Address |
| --- | --- | --- |
| `tor-11` | `swp1` | `10.0.0.1/30` |
| `tor-21` | `swp1` | `10.0.0.2/30` |
| `tor-11` | `lo` | `10.0.0.11/32` |
| `tor-21` | `lo` | `10.0.0.21/32` |
| `tor-11` | `vlan111` | `60.1.1.11/24`, `2060:1:1:1::11/64` |
| `tor-21` | `vlan111` | `60.1.1.21/24`, `2060:1:1:1::21/64` |

Synthetic moving host identity:

| Address family | Moving IP | MAC behind `tor-11` | MAC behind `tor-21` |
| -------------- | --------- | ------------------- | ------------------- |
| IPv4           | `60.1.1.100`      | `aa:11:aa:aa:aa:aa` | `aa:21:aa:aa:aa:aa` |
| IPv6           | `2060:1:1:1::100` | `aa:11:aa:aa:aa:aa` | `aa:21:aa:aa:aa:aa` |

## Test Notes

`dad_snooper.py` runs on either host to model host presence. For this testcase,
it sends GARP for the moving IPv4 address, replies to ARP requests and IPv6
Neighbor Solicitations, and leaves IPv6 neighbor creation to explicit
`ip -6 neigh replace` commands.

Current testcase:

- `test_dad_remote_mac_del_keeps_local_kernel_mac`

This testcase moves the same IPv4/IPv6 host identity between the ToRs until DAD
freezes the remote duplicate, withdraws that remote entry, and verifies the
newer local kernel neighbor is preserved and restored as local EVPN state.
