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

FAQ
---
- frr.vtysh displays `--MORE--` on long output. How to suppress this?
    - Define `VTYSH_PAGER` to `cat` (default is `more`). (Ie add 
      `export VTYSH_PAGER=cat` to the end of your `.profile`)

Sourcecode available
====================

The source for this SNAP is available as part of the FRRouting
Source Code Distribution. 

    https://github.com/frrouting/frr.git

Instructions for rebuilding the snap are in `README.snap_build.md`

Feedback welcome
================

Please send Feedback about this snap to Martin Winter at 
`mwinter@opensourcerouting.org`

