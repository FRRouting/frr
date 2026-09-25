# SRv6 L3VPN Lab - IP Address Reference

## Core Network Links

| Link    | Network          | r1 addr | r2 addr | r3 addr | r4 addr | r5 addr | r6 addr |
|---------|------------------|---------|---------|---------|---------|---------|---------|
| r1-r2   | 2001:db8:12::/64 | ::1     | ::2     | -       | -       | -       | -       |
| r1-r3   | 2001:db8:31::/64 | ::1     | -       | ::3     | -       | -       | -       |
| r1-r5   | 2001:db8:15::/64 | ::1     | -       | -       | -       | ::5     | -       |
| r2-r6   | 2001:db8:26::/64 | -       | ::2     | -       | -       | -       | ::6     |
| r3-r4   | 2001:db8:34::/64 | -       | -       | ::3     | ::4     | -       | -       |
| r4-r5   | 2001:db8:45::/64 | -       | -       | -       | ::4     | ::5     | -       |
| r5-r6   | 2001:db8:56::/64 | -       | -       | -       | -       | ::5     | ::6     |

## Loopback Addresses

| Router | Loopback         | Has Loopback? |
|--------|------------------|---------------|
| r1     | 2001:db8:11::1/64| Yes           |
| r2     | 2001:db8:22::2/64| Yes           |
| r3     | 2001:db8:33::3/64| Yes           |
| r4     | N/A              | No            |
| r5     | N/A              | No            |
| r6     | 2001:db8:66::6/64| Yes           |

## SRv6 Locators (PE Routers Only!)

| Router | Locator Name | Locator Prefix      | Role |
|--------|--------------|---------------------|------|
| r3     | FRR3         | 2001:dead:30::/64   | PE   |
| r6     | FRR6         | 2001:dead:60::/64   | PE   |

**Note:** Core transit routers (r1, r2, r4, r5) do NOT have SRv6 locators!

## VRF Client1 (PE-CE)

| Link    | Network (IPv4)     | Network (IPv6)         | r3 addr       | r6 addr       | r7 addr       | r8 addr       |
|---------|--------------------|------------------------|---------------|---------------|---------------|---------------|
| r3-r7   | 172.16.11.0/24     | 2001:cafe:11::/64      | .3            | -             | .1            | -             |
| r6-r8   | 172.16.12.0/24     | 2001:cafe:12::/64      | -             | .6            | -             | .1            |

## VRF Client2 (PE-CE)

| Link    | Network (IPv4)     | Network (IPv6)         | r3 addr       | r6 addr       | r9 addr       | r10 addr      |
|---------|--------------------|------------------------|---------------|---------------|---------------|---------------|
| r3-r9   | 172.16.21.0/24     | 2001:cafe:21::/64      | .3            | -             | .1            | -             |
| r6-r10  | 172.16.22.0/24     | 2001:cafe:22::/64      | -             | .6            | -             | .1            |

## CE Loopbacks

| Router | IPv4 Loopback    | IPv6 Loopback          | VRF     |
|--------|------------------|------------------------|---------|
| r7     | 192.168.11.1/32  | 2001:dead:11::1/128    | Client1 |
| r8     | 192.168.12.1/32  | 2001:dead:12::1/128    | Client1 |
| r9     | 192.168.21.1/32  | 2001:dead:21::1/128    | Client2 |
| r10    | 192.168.22.1/32  | 2001:dead:22::1/128    | Client2 |

## BGP Peering

- **AS Number:** 65000 (iBGP)
- **r3 ↔ r6:** 2001:db8:33::3 ↔ 2001:db8:66::6
- **Address Families:** VPNv4, VPNv6
- **VRF Client1 RD/RT:** 65000:1
- **VRF Client2 RD/RT:** 65000:2


### On any core router (r1-r6):
```bash
show isis neighbor
show ipv6 route isis
```

### On PE routers (r3, r6):
```bash
show segment-routing srv6 locator
show bgp summary
show bgp ipv4 vpn
show bgp vrf Client1 ipv4
show ip route vrf Client1
```

### On CE routers (r7, r8, r9, r10):
```bash
show ip ospf neighbor
show ip route
# Test connectivity within same VRF:
ping 192.168.12.1   # From r7 to r8 (Client1)
ping 192.168.22.1   # From r9 to r10 (Client2)
# Verify VRF isolation (should fail):
ping 192.168.21.1   # From r7 to r9 (different VRFs - should NOT work)
```
