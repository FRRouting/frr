# FRR container image for containerlab

This directory builds the FRR image used by
[containerlab](https://containerlab.dev)'s `frr` kind.

It is the released FRR image with an SSH server added. The stock image ships
none, so a running FRR container cannot be reached with `ssh`; containerlab
writes the host's public keys to `/root/.ssh/authorized_keys` and expects an
`sshd` to be listening. Host keys are generated on first start rather than at
build time, so containers do not all share one key.

It also carries a few conveniences a lab router wants and the release image
does not:

- an `admin` user whose login shell is `vtysh`, so `ssh admin@<node>` lands in
  the routing CLI. It belongs to the `frr` and `frrvty` groups, so it can
  configure and `write memory` as well as look around. `root` keeps a normal
  shell.

  The image sets no password for either user, so out of the box both accept
  ssh keys only. containerlab installs the host's public keys for both, and sets
  `admin`'s password from the node's credentials when it deploys the node —
  `admin` unless the topology says otherwise.
- an `/etc/motd`, shown on every ssh login, naming the two ways in and where
  FRR's log goes.
- no default route. The management network offers one for v4 and for v6; the
  start script drops both, since a leftover default gets redistributed into the
  IGP and is often the very route the lab exists to test. The management network
  stays reachable over its connected route.

FRR's daemons log only to the targets `frr.conf` names, and with no `log` line
they log nowhere. The image runs no syslog daemon, so `log syslog` is lost too.
Put `log stdout` in the node's configuration to see the log with
`docker logs <node>`; containerlab's default configuration for the `frr` kind
already does.

Everything else, FRR included, comes from the base image unchanged.

The image is published as `quay.io/frrouting/frr:containerlab-$VERSION` and built on
every release; see `doc/developer/frr-release-procedure.rst`.

## Building

The base image is the release built from `docker/alpine/Dockerfile`, so build
that first. `TAG` selects which release to build on top of and defaults to the
latest published one. The build context is the repository root:

```console
docker build -f docker/containerlab/Dockerfile \
    --build-arg TAG=10.7.1 \
    -t quay.io/frrouting/frr:containerlab-10.7.1 .
```

## Usage

```yaml
name: frr01

topology:
  nodes:
    router1:
      kind: frr
      image: quay.io/frrouting/frr:containerlab-10.7.1
      startup-config: router1/frr.conf
```

Containerlab writes `/etc/frr/frr.conf`, `/etc/frr/daemons` and
`/etc/frr/vtysh.conf` for each node. The routers are reachable with
`ssh root@clab-frr01-router1` for a shell, or `ssh admin@clab-frr01-router1`
for `vtysh`. See the
[`frr` kind documentation](https://containerlab.dev/manual/kinds/frr/).
