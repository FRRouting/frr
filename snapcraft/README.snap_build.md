Building your own FRRouting Snap
========================================
(Tested on Ubuntu 16.04 with Snap Version 2, does not work on Ubuntu 15.x
which uses earlier versions of snaps)

1. Install snapcraft:

        sudo apt-get install snapcraft
	
2. Checkout FRRouting under a **unpriviledged** user account

        git clone https://github.com/frrouting/frr.git
        cd frr

3. (Optional) Add extra version information to 
   `snapcraft/extra_version_info.txt`. Information in this file will
   be displayed with the frr.version command (simple `cat` after
   the display of the `zebra --version` output)

4. Run Bootstrap and make distribution tar.gz

        ./bootstrap.sh
        ./configure --with-pkg-extra-version=-MySnapVersion
        make dist
			
    Note: configure parameters are not important for the Snap building,
    except the `with-pkg-extra-version` if you want to give the Snap
    a specific name to mark your own unoffical build

    This will build `frr-something.tar.gz` - the distribution tar and 
    the snapcraft/snapcraft.yaml with the matching version number

5. Create snap

        cd snapcraft
        snapcraft

    You should now end up with `frr_something.snap`

Installing the snap 
===================
(This can be done on a different system)

1. Install snapd

        sudo apt-get install snapd

2. Install self-built frr snap. (`--force-dangerous` is required to
   install a unsigned self-built snap)

        snap install --force-dangerous ./frr*.snap

    Connect the priviledged `network-control` plug to the snap:

        snap connect frr:network-control core:network-control

See README.usage.md for more details on setting up and using the snap
        
DONE.

The Snap will be auto-started and running. 

Operations
==========

### FRRouting Daemons
At this time, all FRRouting daemons are auto-started.

A daemon can be stopped/started with (ie ospf6d)

    systemctl stop snap.frr.ospf6d.service
    systemctl start snap.frr.ospf6d.service

or disabled/enabled with

    systemctl disable snap.frr.ospf6d.service
    systemctl enable snap.frr.ospf6d.service

### FRRouting Commands
All the commands are prefixed with frr.

    frr.vtysh       -> vtysh
    frr.version     -> Just gives version output (zebra --version)
    frr.readme      -> Returns simple README with hints on using FRR

    frr.bgpd-debug  -> Directly start each daemon (without service)
    frr.isisd-debug
    frr.ospf6d-debug
    frr.ospfd-debug
    frr.pimd-debug
    frr.ripd-debug
    frr.ripngd-debug
    frr.ldp-debug
    frr.zebra-debug

vtysh can be accessed as frr.vtysh (Make sure you have /snap/bin in your
path). If access as `vtysh` instead of `frr.vtysh` is needed, you can enable it
via a snap alias as follows:

   sudo snap alias frr vtysh

This will add the vtysh command to your /snap/bin for direct access. The output of

   sudo snap aliases

should list vtysh command alias as enabled:

App          Alias    Notes
frr.vtysh    vtysh    enabled
