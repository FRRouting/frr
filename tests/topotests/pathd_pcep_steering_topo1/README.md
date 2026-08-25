# pathd PCEP Steering Test

## Overview

This test validates that pathd installs a per-destination steering
route for a PCE-initiated SR policy, withdraws it when the policy goes
down, and reinstalls it when the policy comes back up. Both address
families are covered: the PCE initiates one policy to an IPv4 endpoint
and one to an IPv6 endpoint, and every check asserts both steering
routes.

This is also the first topotest to establish a live PCEP session: no
PCE implementation exists in the test framework, these tests use a
scripted PCE (`mock_pce.py`) to implement a lightweight pce to
implement pcep testing.

## Topology

```
         +-------------+                       +-------------+
         |             |eth-rt2         eth-rt1|             |
         |     RT1     +-----------------------+     RT2     |
         | 1.1.1.1     |     10.0.1.0/24       | 2.2.2.2     |
         | 2001:db8::1 |  2001:db8:10:1::/64   | 2001:db8::2 |
         +-------------+                       +-------------+
                |
         mock PCE (127.0.0.1:4189, inside RT1's namespace)
```

Loopbacks (= policy endpoints):

| Router | IPv4       | IPv6            |
|--------|------------|-----------------|
| RT1    | 1.1.1.1/32 | 2001:db8::1/128 |
| RT2    | 2.2.2.2/32 | 2001:db8::2/128 |

- **RT1**: SR-TE headend. zebra + isisd (IS-IS SR, SRGB 16000-23999,
  IPv4 + IPv6 topologies) + pathd with the `pathd_pcep` module
  (`-M pathd_pcep`).
- **RT2**: policy endpoint. Loopbacks 2.2.2.2/32 (prefix-SID index
  20, label 16020) and 2001:db8::2/128 (prefix-SID index 21, label
  16021).
- **mock PCE**: a Python TCP server started inside RT1's network
  namespace; pathd's PCC connects to it at 127.0.0.1:4189. It
  initiates one policy per address family.

## The scripted PCE

`mock_pce.py` implements just enough of RFC 5440 (PCEP), RFC 8231
(stateful), RFC 8281 (PCE-initiated) and RFC 8664 (SR ERO) to drive
pathd as a PCC:

1. Exchange Open/Keepalive (Open carries the STATEFUL-PCE-CAPABILITY
   U|I bits, SR-PCE-CAPABILITY and PATH-SETUP-TYPE-CAPABILITY TLVs).
2. Wait for the PCC's end-of-state-sync PCRpt (LSP object, PLSP-ID 0,
   SYNC flag clear) — pathd silently discards any PCInitiate received
   before that point.
3. Send PCInitiate messages creating SR policies (SRP + LSP with
   symbolic path name + IPv4 or IPv6 END-POINTS + ERO with SID-only
   SR subobjects; an optional VENDOR-INFO object sets the policy
   color).
4. Answer nothing else; send Keepalives every 10 seconds.

The PCE logs every state transition to a file which the test dumps on
failure. It can also remove initiated policies (PCInitiate with the
SRP R flag) driven through a command file — see `--command-file`.

## Tests

Every steering-route check asserts both address families (ipv4, ipv6).

1. **test_isis_sr_convergence**: IS-IS SR converges and RT2's
   prefix-SID labels (16020, 16021) are installed in RT1's LFIB. The
   PCE-initiated policies resolve through these labels.
2. **test_steering_route_installed**: after the PCEP session
   establishes and the PCE initiates both policies, RT1 installs the
   steering routes: `2.2.2.2/32` and `2001:db8::2/128`, proto `srte`,
   distance 10, each resolving through its policy via SR-TE color.
3. **test_steering_route_withdrawn_on_policy_down**: shutting RT2's
   link takes the labels away, the policies go down, and pathd
   withdraws both steering routes (gone from the RIB entirely, not
   just inactive).
4. **test_steering_route_reinstalled_on_policy_up**: bringing the
   link back revalidates the policies and pathd reinstalls both
   steering routes.
5. **test_policy_churn_scale**: the PCE initiates 100 further
   policies per address family — 100 for the IPv4 endpoint and 100
   for the IPv6 endpoint (distinct colors, driven through the
   command file). All 202 come up, and each endpoint's steering
   route aggregates one colored nexthop per policy, capped at
   zebra's multipath limit (read from `show zebra`; colors beyond
   the cap are logged and unrepresented — each route must carry
   exactly `min(policies, ECMP max)` nexthops).
6. **test_policy_churn_remove_readd**: per family, remove 40 of the
   churn policies, re-add 20 (same names and colors — pathd hands
   back the PLSP-IDs it retained for these keys), then remove every
   churn policy. The policy count tracks each step and both steering
   routes collapse back to a single nexthop. Together with the
   teardown memory check this is the leak stress: 240 PCInitiate
   creates and 240 removes through one session.

## Notes

- pathd runs with `-M pathd_pcep`; the module is built whenever pathd
  is enabled.
