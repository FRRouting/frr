# Master-port validation — 2026-11-16

Base: upstream master `49d35a1b9f27a18c92fca8f303474634791b8246`
(FRR 10.9.0-dev). Environment: Linux x86_64, Debian 10, GCC 8.3,
libyang 2.1.128. These results are separate from the historical release-only
results in `VALIDATION-10.7.1.md`.

## Completed on this port

- Fresh bootstrap/configure and bgpd/bfdd build, with unrelated optional
  components disabled as in the release reference.
- All four native shared modules and four transport/gate executables built
  with the published build entry point. Module/helper compilation uses
  `-Wall -Wextra -Werror` with the documented FRR-specific exceptions.
- Newly built bgpd and bfdd both report version `10.9.0-dev`.
- All required dynamic symbols of the four modules are available in their
  corresponding newly built daemon and actual dependency libraries.
  This is a symbol availability check, not live module initialization.
- Empty, eight-byte truncated and invalid-header TCP images are rejected
  by `tcp_stage_node --inspect` with nonzero exit status, without changing
  networking or opening repair sockets. Results: `validation-smoke.json`.
- `bash -n tools/nsr-experimental/build.sh` and `git diff --check` passed.

The port preserves upstream's connection-aware packet hook and BFD include.
The transition observer now accepts `struct peer_connection *` and ignores
non-current connections. BFD Demand mode is detected from the configured flag
or remote-demand state and remains unsupported/refused; the removed native
session `demand_mode` field is not recreated or silently treated as false.
These API adaptations have compile/symbol coverage, not live semantic coverage.

## Not performed / unavailable

The optional `frr-format` GCC plugin could not build because GCC plugin
development headers are unavailable in this environment. Make continued without
it. This compiler format checker was not validated.

Upstream unit/topotests, live module activation, collision/reconnect execution,
BFD fault/recovery, complete HA orchestration, traffic-loss/failover tests,
physical cross-device failure and long-running stability were not rerun.
This is a Draft/RFC for design review, not a new NSR acceptance result.
The separate 10.7.1 validation must not be used as proof for this master port.
