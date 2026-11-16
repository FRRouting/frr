# Experimental native BGP/BFD NSR interfaces

Design reference for [FRRouting/frr#24434](https://github.com/FRRouting/frr/issues/24434).
This branch is based on upstream **frr-10.7.1**, commit
`f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1`, which GitHub marked as the
latest formal release when checked on 2026-11-16. It is not based on master.

## What is published

The first ten commits apply the FRR hook/FSM/timer patch series directly to
native source files. The reference modules and Linux transport helpers are
included here so reviewers can inspect actual consumers of those interfaces.
They are experimental code, not an upstream-ready patch submission, stable API,
or independently deployable HA product. No NSR mode is enabled by a normal
FRR build without loading/configuring these experimental components.

- `bgpd_native_journal.c`: connection identity, complete source input,
  actual successful output bytes, native scheduling events and timer/TCP export.
- `bgpd_native_follow.c`: native shadow FSM, ordered application and output
  comparison, independent transport attachment and guarded activation.
- `bfdd_native_journal.c` / `bfdd_native_follow.c`: native receive-applied
  BFD state, discriminator restoration, remaining timers and transmit gating.
- `tcp_snapshot.*`, `tcp_stage_*`: Linux TCP_REPAIR image handling, queue/window
  restoration and local attachment of an independently created standby socket.
- `tcp_output_gate*`: reference NFQUEUE output/ACK gate primitives.

The local Unix sockets are **device-local adapters**, not the inter-device
replication channel. SCM_RIGHTS attaches a socket created on the standby device
to that device's own bgpd; it does not transfer the source device's FD.
The owner adapter in `owner_claim.h` requires an external authority. Its local
request/reply interface does not itself establish cross-device fencing.

## Build for code review

Use Linux and the normal FRR source-build dependencies, including libyang,
json-c and libnetfilter_queue development headers/libraries. Follow FRR's
[build documentation](https://docs.frrouting.org/projects/dev-guide/en/latest/building.html)
to bootstrap/configure this checkout first. Then:

```sh
JOBS=2 bash tools/nsr-experimental/build.sh /absolute/path/to/new-nsr-build
```

The script builds bgpd/bfdd and compiles four module shared objects and four
transport/gate executables with warnings treated as errors. It does not install
anything or change networking. Modules are paired with the exact patched FRR
binary/headers. `upstream.lock` pins the release source archive provenance.
Do not load untrusted modules or socket images into a privileged routing daemon.

For this public extraction, the previous lab-specific socket/export directory
allowlist is consistently replaced by **`/run/frr-nsr/`** (including the trailing
slash). Keep this device-local directory private to the authorized runtime
account. Existing environment variable names remain `CNLAB_NSR_*`; they are
prototype controls, not proposed upstream configuration syntax.

## Integration deliberately outside this branch

A complete NSR runtime still needs authenticated network replication, durable
WAL and applied-frontier ACKs, bounded clock mapping, state freshness and FIB
checks, coordinated freeze, independent quorum/epoch ownership, actual external
fencing with readback, and atomic component release. The deployment controller,
network fabric implementation and end-to-end oracle are not part of this
native-interface reference. A successful local socket RPC is not sufficient
proof of persistence, fencing, readiness or NSR acceptance.

Do not invoke the activation/gate tools against an existing routing environment.
Run a complete integration only in a dedicated isolated fixture with its own
network namespaces, routes, firewall/NFQUEUE rules and trusted control endpoints.
No complete end-to-end reproduction or new NSR acceptance claim is provided by
this extraction. Earlier integrated experiments are not a validation of the
public checkout or every unsupported configuration.

## Semantics and limitations to review

- Replay must account for actual asynchronous route work and output bytes;
  packet input alone is insufficient. Output mismatch must reject readiness.
- Only explicitly enabled FD-less shadows isolate local retry/NHT/BFD-to-BGP
  reset callbacks. Native BFD expiry still rejects readiness. Real transport
  activation restores normal live-session behavior and owner listening.
- Hold/keepalive and BFD remaining budgets must not be extended on takeover.
  The prototype's 500 ms freshness bound and BFD 300 ms x 3 target are admission
  constraints, not a hard real-time guarantee.
- Current native restoration is limited to the supported IPv4, single-hop,
  unauthenticated BFD Control and Linux TCP ABI. No general IPv6, MD5/AO,
  BFD Echo/authentication, outstanding SACK holes/ECN or mixed-version guarantee.
- Replaying a historical OPEN uses the source's recorded GR restart decision;
  it must not mask an output mismatch by changing expected wire bytes.
- The separate Control-only ARP change skips Echo peer-MAC lookup when Echo
  is not configured; it does not establish Echo NSR support.

The main design question is whether maintainable checkpoint/restore interfaces
would be preferable to this event-replay approach. The existing environment
switches, tight internal-structure coupling, synchronous callbacks and ad hoc
control protocols need review before any upstream proposal.

## Validation of this public checkout

See `VALIDATION.md` for checks actually run on this exact public extraction.
Build/smoke validation is distinct from upstream topotests, complete failure
injection, protocol continuity, business traffic continuity and physical-device
HA qualification.
