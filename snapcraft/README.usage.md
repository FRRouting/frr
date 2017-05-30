Using the FRRouting Snap
===============================

After installing the Snap, the priviledged plug need to be connected:

    snap connect frr:network-control core:network-control

Enabling/Disabling FRRouting Daemons
-------------------------------------------

By default (at this time), all FRRouting daemons will be enabled
on installation. If you want to disable a specific daemon, then use 
the systemctl commands

ie for `ospf6d` (OSPFv3):

    systemctl disable snap.frr.ospf6d.service
    systemctl enable snap.frr.ospf6d.service

The daemons are: `ripd`, `ripngd`, `ospfd`, `ospf6d`, `isisd`, `bgpd`, 
`pimd`, `zebra`

Commands defined by this snap
-----------------------------

- `frr.vtysh`:
	FRRouting VTY Shell (configuration tool)
- `frr.version`:
	Returns output of `zebra --version` to display version and configured 
	options
- `frr.readme`:
	Returns this document `cat README_usage.md`
- `frr.set`:
	Allows to enable `FPM` module. See FPM section below

and for debugging defined at this time (May get removed later - do not 
depend on them). These are mainly intended to debug the Snap

- `frr.zebra-debug`:
	Starts zebra daemon in foreground
- `frr.ripd-debug`:
	Starts ripd daemon in foreground
- `frr.ripngd-debug`:
	Starts ripng daemon in foreground
- `frr.ospfd-debug`:
	Starts ospfd daemon in foreground
- `frr.ospf6d-debug`:
	Starts ospf6d daemon in foreground
- `frr.isisd-debug`:
	Starts isisd daemon in foreground
- `frr.bgpd-debug`:
	Starts bgpd daemon in foreground
- `frr.pimd-debug`:
	Starts pimd daemon in foreground
- `frr.ldpd-debug`:
    Starts ldpd daemon in foreground

MPLS (LDP)
----------
The MPLS forwarding requires a Linux Kernel version 4.5 or newer and
specific MPLS kernel modules loaded. It will be auto-detected by
FRR. You can check the detected setup with the `show mpls status`
command from within `frr.vtysh`

The following kernel modules `mpls-router` and `mpls-iptunnel`
need to be loaded. On Ubuntu 16.04, this can be done by editing 
'/etc/modules-load.d/modules.conf' and add the following lines:

	# Load MPLS Kernel Modules
	mpls-router
	mpls-iptunnel

For other distributions, please check the documentation on loading
modules. You need to either reboot or use `modprobe` to manually load
the modules as well before MPLS will be available.

In addition to this, the MPLS Label-Processing needs to be enabled
with `sysctl` on the required interfaces. Assuming the interfaces
are named `eth0`, `eth1` and `eth2`, then the additional lines in
`/etc/sysctl.conf` will enable it on a Ubuntu 16.04 system:

	# Enable MPLS Label processing on all interfaces
	net.mpls.conf.eth0.input=1
	net.mpls.conf.eth1.input=1
	net.mpls.conf.eth2.input=1
	net.mpls.platform_labels=100000

These settings require either a reboot or a manual configuration with
`sysctl` as well.

FPM Module
----------
The `frr.set` allows to turn FPM module on or off.

    frr.set fpm {disable|protobuf|netlink}
    
    Disables FPM or enables FPM with selected mode

By default, the FPM module is disabled, but installed with netlink and
protobuf support. To enable the FPM module, use the `frr.set fpm protobuf`
or `frr.set fpm netlink` command. The command will only enable the mode
for the next restart of zebra. Please reboot or restart zebra after
changing the mode to become effective.

FAQ
---
- frr.vtysh displays `--MORE--` on long output. How to suppress this?
    - Define `VTYSH_PAGER` to `cat` (default is `more`). (Ie add 
      `export VTYSH_PAGER=cat` to the end of your `.profile`)

- ospfd / ospf6d are not running after installation
    - Installing a new snap starts the daemons, but at this time they
      may not have the required privileged access. Make sure you 
      issue the `snap connect` command as given above (can be verified
      with `snap interfaces`) and **THEN** restart the daemons (or
      reboot the system). 
      This is a limitation of any snap package at this time which
      requires privileged interfaces (ie to manipulate routing tables)

- Can I run vtysh directly without the "frr." prefix?
    - Yes, enable the vtysh alias in the frr snap package by:
      sudo snap alias frr vtysh
	
Sourcecode available
====================

The source for this SNAP is available as part of the FRRouting
Source Code Distribution under `GPLv2 or later`

<https://github.com/frrouting/frr.git>

Instructions for rebuilding the snap are in `snapcraft/README.snap_build.md`

*Please checkout the desired branch before following the instructions
as they may have changed between versions of FRR*

Official Webpage for FRR
========================

Official webpage for FRR is at <https://www.frrouting.org/>

Feedback welcome
================

Please send Feedback about this snap to Martin Winter at 
`mwinter@opensourcerouting.org`
