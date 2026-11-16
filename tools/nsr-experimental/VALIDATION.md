# Public reference validation — 2026-11-16

Base: FRR `frr-10.7.1` / `f8c0b08dcb0c78f9e42b9b86ae70b049e4e617c1`.
Environment: Linux x86_64, Debian 10, GCC 8.3, libyang 2.1.128.
All checks below use the extracted public source, including its normalized
`/run/frr-nsr/` socket path policy.

## Completed

1. All ten native patches applied in order to the exact official release commit.
2. `git diff --check` and `bash -n tools/nsr-experimental/build.sh` passed.
3. Fresh bootstrap/configure completed with bgpd and bfdd enabled. Optional
   mgmtd, documentation and unrelated routing daemons were excluded; protobuf,
   gRPC and SNMP were disabled. No configure warnings were emitted.
4. The published build entry point built bgpd/bfdd, four native shared modules
   and four TCP/gate helpers. Modules/helpers used `-Wall -Wextra -Werror` with
   the documented FRR/module-specific warning exceptions.
5. Both newly built daemon binaries returned FRR 10.7.1 for `--version`.
6. The required dynamic symbols of every shared module were present in its
   corresponding freshly built daemon and actual dependency libraries.
   This is a symbol availability check, not a live module activation test.
7. `tcp_stage_node --inspect IMAGE` rejected an empty image, an eight-byte
   truncated image and a 4096-byte zero-filled invalid-header image, all with
   nonzero exit status. No repair socket or network change was attempted.

The cold-build entry point explicitly generates `lib/gitversion.h`,
`lib/route_types.h` and `lib/vtysh_daemons.h` before requesting daemon targets.
Direct daemon targets alone do not perform the top-level generated-header step
on a fresh checkout.

## Not performed for this public extraction

Upstream unit/topotests, live module initialization and activation, peer-session
continuity, BFD fault/recovery, complete HA orchestration, traffic-loss tests,
physical cross-device failure and long-running stability were not rerun here.
The public branch is code for design review, not a new NSR acceptance result.
Historical integrated experiments must not be substituted for these checks.

Machine-readable parser/symbol check results are in `validation-smoke.json`.
