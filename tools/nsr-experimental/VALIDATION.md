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

## CI repair follow-up

The first upstream CI run exposed `-Werror=misleading-indentation` in the
route scheduling hook and missing `bgp_nsr.h` from RPM source packages.
The native formatting changes preserve all non-whitespace characters; the
same sources rebuilt locally with `-Werror=misleading-indentation`.
Both new native headers are now in Automake's noinst_HEADERS, and the
optional reference tool sources/documentation are listed in EXTRA_DIST.
Distribution membership is checked from a real generated distdir.

Commit messages are normalized with a blank line before the body/trailers,
and each author commit carries its matching Signed-off-by trailer.
Local build/distribution checks do not substitute for the next upstream CI run.

## BFD strict hold timer test precondition follow-up

For head `058b2e0`, NetDEF build 24826 passed all 23 build jobs and source
verification. Basic Tests passed 48/49 jobs; Ubuntu 24.04 Part 2 failed
`test_bfd_strict_hold_timer_peer_delete_no_stale_crash` before peer deletion:
BFD was Down, BGP remained Established, and the strict hold timer was never
armed. The CI observation at convergence had `bgpTimerUpMsec: 0`.
The first Down observation had BGP uptime 1000 ms and BFD lastUpdate one
second ago, consistent with both establishment and the Down callback falling
in the same monotonic second. The unchanged native callback requires
`bss->last_event > peer->uptime`, with both timestamps in seconds.

The test now requires an observed BGP uptime of at least 1000 ms, in addition
to BGP Established and BFD Up, before stopping bfdd. It retains the original
Down, running hold timer, peer deletion and post-deadline liveness checks;
no daemon behavior or protocol timeout is changed.

Targeted local validation used the matching master bgpd/bfdd/zebra binaries
in two isolated network namespaces: three runs with the new uptime
precondition armed the timer and kept bgpd alive after deletion and seven
seconds of observation. Two runs without the precondition also passed locally,
so they do not independently reproduce the original CI timing. A further
50 ms BFD interval control passed with and without the precondition.
Five boundary cases executed the exact convergence predicate extracted from
the test (missing/0/999/1000 ms uptime and BFD Down); Python compilation and
`git diff --check` passed. This is targeted native validation, not a local run
of the complete Topogen/pytest suite; the refreshed upstream CI remains
authoritative.
