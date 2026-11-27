# BGP AgentX notification backpressure

## Overview

This topotest checks that a burst of BGP traps is handed to snmpd rather than
discarded. It brings up 500 dynamic BGP neighbors from one ExaBGP process,
waits until every session is Established and the AgentX queue is idle, then
runs `clear bgp *`. Leaving Established queues one `bgpBackwardTransition`
trap per session. ExaBGP reconnects, and each new session queues one
`bgpEstablished` trap.

`bgpd` does not send that burst in one write. The AgentX queue drains 16
notifications every 10 ms, and only while the master socket has room.
`show agentx status` reports the queue without changing it. The test reads
that command in the same vtysh session as the clear, while the drain is still
walking the burst, and again after the sessions have returned.

The pass condition is:

- `pendingNotifications` is above 0 on the sample taken with the clear.
- After the sessions return, `pendingNotifications` is 0.
- `droppedNotifications` is the same value it had before the clear.
- `socketSendQueued` is back to idle (at most 8192 bytes).
- All 500 neighbors are Established dynamic peers again.

`droppedNotifications` increases when the queue is full or the master stays
down. Those are the paths that discard a trap. A queue that returns to empty
with that counter unchanged was drained by `send_v2trap` toward snmpd.

`bgpEstablished` is generated only when the previous FSM state was
OpenConfirm, so the reconnect produces it and a session that was already
Established does not. `bgpBackwardTransition` is generated when a session
leaves Established, which `clear bgp *` does for every session. The idle
check before the clear keeps the startup traps out of the burst under test.

## Topology

```text
        r1                          peer1
   zebra, bgpd -M snmp,         one ExaBGP process
   snmpd (AgentX master)        500 neighbor blocks
        AS 65001                    AS 65002
        10.0.0.1/8                  10.0.0.2/8
            |                           |
            +------------+--------------+
                         |
                    switch s1
```

There is one link. Both gears have `10.0.0.0/8` on it, so every session is
directly connected eBGP. The test does not set `ebgp-multihop` or
`disable-connected-check`.

| Role | Address | Count |
| --- | --- | --- |
| r1 primary, BGP router-id | `10.0.0.1/8` | 1 |
| peer1 primary | `10.0.0.2/8` | 1 |
| ExaBGP `local-address`, dynamic-neighbor source | `10.1.0.1` upward, `/32` on `peer1-eth0` | 500, through `10.1.1.244` |
| ExaBGP destination, `/32` on `r1-eth0` | `10.2.0.1` upward | 500, through `10.2.1.244` |

r1 accepts the sources with `bgp listen range 10.1.0.0/16`. Every source for
the default 500 sessions is inside that prefix. The dynamic-neighbor limit
defaults to 100, so the test sets `bgp listen limit` to the session count.

`FRR_AGENTX_BGP_NEIGHBORS` selects the session count. The default is 500.
Values below 1 or above 65535 are skipped, because 65535 is the largest
`bgp listen limit`. The drain window scales with the count: 500 notifications
take about 320 ms.

## r1 configuration

`bgpd` is started with `-M snmp`. The configuration is generated at runtime:

```text
router bgp 65001
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 bgp router-id 10.0.0.1
 bgp listen limit 500
 neighbor DYN peer-group
 neighbor DYN remote-as 65002
 neighbor DYN timers 60 180
 no neighbor DYN capability extended-nexthop
 address-family ipv4 unicast
  neighbor DYN activate
  neighbor DYN route-map RM-DYN in
  neighbor DYN route-map RM-DYN out
 exit-address-family
 bgp listen range 10.1.0.0/16 peer-group DYN
agentx
```

`RM-DYN` is `permit 10` with no match, so policy cannot reset the sessions.
`no bgp ebgp-requires-policy` means the sessions still reach Established
without it. `zebra.conf` is also generated: `10.0.0.1/8` plus one `/32` per
destination, on `r1-eth0`.

`r1/snmpd.conf` is the AgentX master setup used by the other SNMP topotests.
snmpd listens on `/etc/frr/agentx` with `agentXPerms 777 755 root frr`. The
test leaves snmpd running. Stopping it makes the AgentX ping time out, drops
the master, and counts the burst as dropped.

## ExaBGP

peer1 is one `TopoExaBGP` gear, the same gear the other ExaBGP topotests use.
It is one process and one BGP speaker configuration, not 500 processes and
not 500 links. `tests/topotests/lib/exabgp_scale.py` only writes the
configuration and the extra addresses. `TopoExaBGP.start()` launches the
process, and `stop_topology()` stops it.

Each session is one neighbor block. `neighbor_block()` sets `router-id` from
`local-address`:

```text
neighbor 10.2.0.1 {
  router-id 10.1.0.1;
  local-address 10.1.0.1;
  local-as 65002;
  peer-as 65001;
  family {
    ipv4 unicast;
  }
}
```

ExaBGP rejects a second block only when the peer address, local address, both
AS numbers, and router-id are all the same (`duplicate peer definition`). The
peer address may be repeated when the local address differs, and the local
address may be repeated when the peer address differs. This test varies both.
The helper sets router-id from the local address, so two blocks that share
both addresses are rejected.

`add_exabgp_peer()` configures only `10.0.0.2/8`. ExaBGP cannot bind a
`local-address` that is not configured on the gear, so the 500 sources are
added with one `ip -force -batch` on `peer1-eth0` before the process starts.
The destinations are addresses on r1, not on peer1.

`exabgp.env` is the standard environment used by the other topotests.
`exabgp.daemon.daemonize` is true, the pid file is
`/var/run/exabgp/exabgp.pid` (the file `TopoExaBGP.stop()` kills), and the
process drops to user `exabgp`. `exabgp.tcp.delay` is 0. That knob is the
minute modulo on which routes are announced, not a connect delay.
`exabgp.bgp.openwait` is 60 seconds, which is how long ExaBGP waits for an
OPEN after TCP is up.

`TopoExaBGP.start()` copies the generated config and `exabgp.env` into the
gear's private `/etc/exabgp`, creates the `/var/run/exabgp.in` and
`/var/run/exabgp.out` fifos, and runs:

```text
env exabgp.log.level=INFO exabgp.log.destination=<rundir>/peer1/exabgp.log \
    exabgp --env /etc/exabgp/exabgp.env /etc/exabgp/exabgp.cfg
```

The flag is `--env`. ExaBGP 4.2.11, 4.2.21, and the CI pin accept both `-e`
and `--env`. ExaBGP 4.2.25 rejects `-e` and exits before writing a pid or a
log. `--env` is the form that works on all of them.

The `exabgp` in that command is whatever `get_exabgp_cmd()` found, in this
order: an `exabgp` binary on `PATH`, then `python3 -m exabgp`, then
`python -m exabgp`. The version must be 4.2.11 or newer. `sudo` replaces
`PATH` with its own `secure_path`, so the directory that contains the wanted
`exabgp` has to be put in front of `PATH` for that command.

The process runs as user `exabgp`. That user must be able to execute the
binary. A copy installed under `/root` fails with `Permission denied` because
`/root` is mode 0700, and ExaBGP then logs that it lost the helper process and
stops the peer. CI installs ExaBGP into the image's system Python, which is
world-readable. On this machine the usable copies are `/opt/exabgp-ci/bin`
(4.2.21, the CI pin) and `/opt/exabgp-4.2.25/bin`.

CI installs ExaBGP from
`git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311`,
which reports version 4.2.21. The test has been run against that pin and
against 4.2.25.

At startup ExaBGP calls `socket.getfqdn()` once per process. On a host whose
name is not in `/etc/hosts` that lookup stalls for several tens of seconds and
prints "Your OS is very slow when returning the host FQDN". The stall happens
inside `peer.start()`, before the establish wait. The CI image adds `peer1`
through `peer20` to `/etc/hosts` for this reason. The 90 second wait that
follows is for the BGP sessions, not for that lookup.

After `clear bgp *`, a SYN that arrives before the dynamic peer has been
deleted is rejected ("Received an open connection for a peering that we have
not fully closed down yet"). ExaBGP backs off and retries. The 90 second
settle window covers those retries.

Before the sessions connect, the test raises `net.core.somaxconn` and
`net.ipv4.tcp_max_syn_backlog` to 4096 in both namespaces. The default accept
queue is too small for 500 SYNs at once. The neighbor GC sysctls are not set:
a fresh netns has no `gc_thresh` files, and 500 ARP entries sit under the
default `gc_thresh2` of 512. The default nofile limit of 1024 holds the 500
sockets. A much larger `FRR_AGENTX_BGP_NEIGHBORS` can run out of descriptors,
because `TopoExaBGP.start()` does not raise the limit.

## What the test reads

`show bgp ipv4 unicast summary json` puts `peers` on the top object.
`show bgp summary json` nests them under `ipv4Unicast`, and this test does
not use that form. `state` is the FSM state (`Established`). `dynamicPeer` is
true only for a dynamic neighbor. The test requires both counts to equal the
session count.

`show agentx status json` from vtysh is wrapped as `{"bgpd": {...}}`,
including when vtysh is run with `-d bgpd`. The fields this test uses are:

| Field | Meaning |
| --- | --- |
| `moduleLoaded` | `bgpd_snmp` is loaded. Requires a build configured with `--enable-snmp`. |
| `enabled` | `agentx` is configured in bgpd. |
| `connected` | The AgentX master session to snmpd is up. |
| `pendingNotifications` | Notifications still in the bgpd queue. |
| `droppedNotifications` | Notifications discarded, not handed to snmpd. |
| `socketSendQueued` | Bytes sitting in the kernel send buffer, not a notification count. |

The clear and the two shows are one vtysh session:

```text
clear bgp *
show agentx status json
show agentx status json
```

vtysh sends one line and waits for that reply before sending the next. bgpd
runs the clear, queues the backward-transition traps, and the following show
is read while the 16-per-10ms drain is still in progress. A vtysh process
started after the clear has returned normally finds the queue already empty.
The two shows do not help if the queue is already empty before the first one.
That window is about 320 ms for 500 notifications. A client that does not get
the show into bgpd inside it fails the `pendingNotifications > 0` check even
though the traps were sent.

`test_memory_leak` is the standard leak report. It is skipped unless the
memory-leak report is enabled.

## Running

From this directory, with ExaBGP 4.2.25:

```bash
sudo -E env PATH=/opt/exabgp-4.2.25/bin:$PATH \
  /root/topotests-venv/bin/python -m pytest -s -vv \
  test_bgp_snmp_agentx_backpressure.py
```

The same command with `PATH=/opt/exabgp-ci/bin:$PATH` runs the CI pin, which
reports 4.2.21. `PATH=` applies only to that command. `echo $PATH`
afterwards still shows the shell's normal value, and `/usr/local/bin` does
not contain `exabgp`. The log line `Using ExaBGP version ... in ...` names
the binary the test actually started.

From `tests/topotests`, which is how CI invokes pytest:

```bash
sudo -E env PATH=/opt/exabgp-4.2.25/bin:$PATH \
  /root/topotests-venv/bin/python -m pytest -s -vv \
  bgp_snmp_agentx_backpressure/test_bgp_snmp_agentx_backpressure.py
```

A smaller run, for a first check:

```bash
sudo -E env FRR_AGENTX_BGP_NEIGHBORS=50 PATH=/opt/exabgp-4.2.25/bin:$PATH \
  /root/topotests-venv/bin/python -m pytest -s -vv \
  test_bgp_snmp_agentx_backpressure.py
```

The module is marked `bgpd` and `snmp`. It skips when `snmpd` is not
installed, and it skips when bgpd fails to start. A build without
`--enable-snmp` has no `bgpd_snmp.so` and no `show agentx status`, and the
module check fails rather than skipping.

On failure the assertion includes the tail of `<rundir>/peer1/exabgp.log`.
bgpd's own log is `<rundir>/r1/bgpd.log`, and snmpd's is
`<rundir>/r1/snmpd.log`. The rundir is `/tmp/topotests/<module>.<test>/`
unless `--rundir` says otherwise.
