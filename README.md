<p align="center">
<img src="https://docs.frrouting.org/en/latest/_static/frr-icon.svg" alt="Icon" width="20%"/>
</p>

FRRouting
=========

[![github-ci](https://github.com/FRRouting/frr/actions/workflows/github-ci.yml/badge.svg?branch=master)](https://github.com/FRRouting/frr/actions/workflows/github-ci.yml)
[![Documentation Status](https://readthedocs.org/projects/frrouting/badge/?version=latest)](https://docs.frrouting.org/en/latest/)

FRR is free software that implements and manages various IPv4 and IPv6 routing
protocols. It runs on nearly all distributions of Linux and BSD and
supports all modern CPU architectures. The project website is
[frrouting.org](https://frrouting.org/).

FRR currently supports the following protocols:

* BGP
* OSPFv2
* OSPFv3
* RIPv1
* RIPv2
* RIPng
* IS-IS
* PIM (SM, DM, SSM, MSDP)
* LDP
* BFD
* Babel
* PBR
* OpenFabric
* VRRP
* EIGRP (alpha)
* NHRP (alpha)

Not every protocol or feature is available on every platform; see the
[feature matrix](https://docs.frrouting.org/en/latest/about.html#feature-matrix)
in the user guide.

**Centralized FRR configuration (work in progress):** the **mgmtd** daemon
applies **YANG** configuration to the routing protocol daemons through the
**northbound** API (instead of each daemon only having its own legacy
configuration path). **Not all daemons are migrated yet**; expect ongoing
changes. See [mgmtd](https://docs.frrouting.org/en/latest/mgmtd.html) in the
user guide.

Installation & Use
------------------

For source tarballs, see the
[releases page](https://github.com/FRRouting/frr/releases).

Pre-built packages: APT for Debian and derivatives
([deb.frrouting.org](https://deb.frrouting.org/)), and RPM for RHEL, Fedora,
and related distributions ([rpm.frrouting.org](https://rpm.frrouting.org/)).

Instructions on building and installing from source for supported platforms may
be found in the
[developer docs](https://docs.frrouting.org/projects/dev-guide/en/latest/building.html).

Once installed, please refer to the [user guide](https://docs.frrouting.org/)
for instructions on use.

Community
---------

See [lists.frrouting.org](https://lists.frrouting.org/) for the list index,
subscription, and archives. The public lists include:

| Topic             | List                         |
|-------------------|------------------------------|
| Development       | dev@lists.frrouting.org      |
| Users & Operators | frog@lists.frrouting.org     |
| Announcements     | announce@lists.frrouting.org |

For chat, we use [Slack](https://frrouting.slack.com). New members can join
via the invite link on the [community](https://frrouting.org/community/) page.


Contributing
------------

See [submitting patches and enhancements](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#submitting-patches-and-enhancements)
and the [commit guidelines](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html#commit-guidelines)
when contributing. FRR maintains
[developer's documentation](https://docs.frrouting.org/projects/dev-guide/en/latest/index.html)
with the full [project workflow](https://docs.frrouting.org/projects/dev-guide/en/latest/workflow.html)
and contributor expectations; technical documentation on internals is also
available.

We welcome and appreciate all contributions, no matter how small!


License
-------

Per-file licenses use SPDX identifiers; see `COPYING` and `doc/licenses/`.
The combined work is generally understood to be distributable under **GNU
General Public License version 2 or later** (GPLv2+); see `COPYING` for
details. FRR's documentation uses a separate custom permissive license (see
`COPYING` for background).


Security
--------

To report security issues, please use our security mailing list:

```
security [at] lists.frrouting.org
```
