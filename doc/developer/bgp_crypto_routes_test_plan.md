# BGP crypto-routes test plan

## What we need to prove

The feature is correct only if crypto metadata behaves like BGP control-plane
state while staying out of forwarding.

The tests should prove:

- BGP peers can negotiate `address-family crypto-routes`.
- A configured `crypto-peer` is advertised to an activated neighbor.
- Updating the same `crypto-peer` sends the new metadata.
- Removing the `crypto-peer` withdraws it.
- The route does not appear in Zebra or the kernel route table.
- Normal IPv4 unicast still works at the same time.

## Unit test checklist

These are the low-level tests that should be added around the codec when a C
unit-test harness is available:

- Valid crypto NLRI encode/decode.
- Malformed NLRI length is rejected.
- Missing peer-id is rejected.
- Unsupported version is rejected.
- Oversized algorithm/certificate/public-key fields are rejected.
- Withdraw by peer-id removes the route.

## Topotest topology

The executable topotest uses two routers:

```text
      192.168.255.0/24
  r1 ---------------- r2
 AS65001          AS65002
```

r1 has:

- IPv4 unicast route `10.10.10.1/32`
- one local crypto-peer object

r2 learns:

- the IPv4 unicast route through normal IPv4 unicast BGP
- the crypto-peer object through crypto-routes

## Test steps

1. Start r1 and r2.
2. Wait for BGP to reach Established.
3. Verify r2 learns the initial crypto route from r1.
4. Update r1's crypto-peer metadata.
5. Verify r2 sees the updated algorithm, certificate-id, public-key-id,
   capabilities, and trust-level.
6. Remove r1's crypto-peer.
7. Verify r2 no longer shows that crypto route.
8. Verify r2 still has IPv4 unicast route `10.10.10.1/32`.
9. Verify Zebra/kernel route output does not contain crypto peer data.

## How to run

From the FRR build environment:

```bash
pytest -q tests/topotests/bgp_crypto_routes/test_bgp_crypto_routes.py
```

The test requires the normal FRR topotest dependencies and a built FRR tree.
