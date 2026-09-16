# FRR container image for containerlab

This directory builds the FRR image used by
[containerlab](https://containerlab.dev)'s `frr` kind.

It is the released FRR image with an SSH server added. The stock image ships
none, so a running FRR container cannot be reached with `ssh`; containerlab
writes the host's public keys to `/root/.ssh/authorized_keys` and expects an
`sshd` to be listening. Host keys are generated on first start rather than at
build time, so containers do not all share one key.

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
`/etc/frr/vtysh.conf` for each node, and the routers are reachable with
`ssh root@clab-frr01-router1`. See the
[`frr` kind documentation](https://containerlab.dev/manual/kinds/frr/).
