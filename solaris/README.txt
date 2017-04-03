To build packages for Solaris 10:

Requirements:
-------------

- Development environment including gcc (eg as shipped with Solaris 10)

- The Package tools from Solaris 10 or Solaris Nevada/Express.

- i.manifest and r.manifest scripts as supplied with Solaris Express
  in /usr/sadm/install/scripts/ or from OpenSolaris.org:

  http://cvs.opensolaris.org/source/xref/usr/src/pkgdefs/common_files/i.manifest
  http://cvs.opensolaris.org/source/xref/usr/src/pkgdefs/common_files/r.manifest
  
  i.manifest must be at least version 1.5. Place these scripts in
  this directory if you are using Solaris 10 GA (which does not ship with
  these scripts), or in the solaris/ directory in the FRRouting source.


Package creation instructions:
------------------------------

1. Configure and build FRRouting (frr) in the top level build directory as per normal, eg:

	./configure --prefix=/usr/local/frr \
		--localstatedir=/var/run/frr \
		--enable-gcc-rdynamic --enable-opaque-lsa --enable-ospf-te \
		--enable-multipath=64 --enable-user=frr \
		--enable-ospfclient=yes --enable-ospfapi=yes  \
		--enable-group=frr --enable-nssa --enable-opaque-lsa

You will need /usr/sfw/bin and /usr/ccs/bin in your path.

2. make install in the top-level build directory, it's a good idea to make
use of DESTDIR to install to an alternate root, eg:

	gmake DESTDIR=/var/tmp/qroot install

3. In this directory (solaris/), run make packages, specifying DESTDIR if
appropriate, eg:

	gmake DESTDIR=/var/tmp/qroot packages

This should result in 4 packages being created:

	frr-libs-...-$ARCH.pkg 	- FRRlibs
	frr-daemons-...-$ARCH.pkg	- FRRdaemons
	frr-doc-...-$ARCH.pkg	- FRRdoc
	frr-dev-...-$ARCH.pkg	- FRRdev
	frr-smf-...-$ARCH.pkg	- FRRsmf

FRRlibs and FRRdaemons are needed for daemon runtime. FRRsmf
provides the required bits for Solaris 10+ SMF support.


Install and post-install configuration notes:
---------------------------------------------

- If you specified a user/group which does not exist per default on Solaris
  (eg frr/frr) you *must* create these before installing these on a
  system. The packages do *not* create the users.

- The configuration files are not created. You must create the configuration
  file yourself, either with your complete desired configuration, or else if
  you wish to use the telnet interface for further configuration you must
  create them containing at least:

	 password whatever

  The user which frr runs as must have write permissions on this file, no
  other user should have read permissions, and you would also have to enable
  the telnet interface (see below).

- SMF notes:

  - FRRsmf installs a svc:/network/routing/frr service, with an
    instance for each daemon
  
  - The state of all instances of frr service can be inspected with:
  
  	svcs -l svc:/network/routing/frr
  
    or typically just with a shortcut of 'frr':
    
    	svcs -l frr
  
  - A specific instance of the frr service can be inspected by specifying
    the daemon name as the instance, ie frr:<daemon>:
    
    	svcs -l svc:/network/routing/frr:zebra
    	svcs -l svc:/network/routing/frr:ospfd
    	<etc>

    or typically just with the shortcut of 'frr:<daemon>' or even
    <daemon>:
    
    	svcs -l frr:zebra
    	svcs -l ospfd
    
    Eg:
    
    # # svcs -l ripd
    fmri         svc:/network/routing/frr:ripd
    name         FRRouting: ripd, RIPv1/2 IPv4 routing protocol daemon.
    enabled      true
    state        online
    next_state   none
    state_time   Wed Jun 15 16:21:02 2005
    logfile      /var/svc/log/network-routing-frr:ripd.log
    restarter    svc:/system/svc/restarter:default
    contract_id  93 
    dependency   require_all/restart svc:/network/routing/frr:zebra (online)
    dependency   require_all/restart file://localhost//usr/local/frr/etc/ripd.conf (online)
    dependency   require_all/none svc:/system/filesystem/usr:default (online)
    dependency   require_all/none svc:/network/loopback (online)

  - Configuration of startup options is by way of SMF properties in a
    property group named 'frr'. The defaults should automatically be
    inline with how you configured FRRouting in Step 1 above. 
  
  - By default the VTY interface is disabled. To change this, see below for
    how to set the 'frr/vty_port' property as appropriate for
    /each/ service. Also, the VTY is set to listen only to localhost by
    default, you may change the 'frr/vty_addr' property as appropriate
    for both of the 'frr' service and specific individual instances of
    the 'frr' service (ie frr:zebra, frr:ospfd, etc..).
    
  - Properties belonging to the 'frr' service are inherited by all
    instances. Eg:
    
    # svcprop -p frr svc:/network/routing/frr
    frr/group astring root
    frr/retain boolean false
    frr/user astring root
    frr/vty_addr astring 127.1
    frr/vty_port integer 0
    
    # svcprop -p frr svc:/network/routing/frr:ospfd
    frr/retain_routes boolean false
    frr/group astring root
    frr/retain boolean false
    frr/user astring root
    frr/vty_addr astring 127.1
    frr/vty_port integer 0
    
    All instances will inherit these properties, unless the instance itself
    overrides these defaults. This also implies one can modify properties of
    the 'frr' service and have them apply to all daemons.
    
    # svccfg -s svc:/network/routing/frr \
    	setprop frr/vty_addr = astring: ::1
    
    # svcprop -p frr svc:/network/routing/frr
    frr/group astring root
    frr/retain boolean false
    frr/user astring root
    frr/vty_port integer 0
    frr/vty_addr astring ::1
    
    # # You *must* refresh instances to have the property change
    # # take affect for the 'running snapshot' of service state.
    # svcadm refresh frr:ospfd
    
    # svcprop -p frr svc:/network/routing/frr:ospfd
    frr/retain_routes boolean false
    frr/group astring root
    frr/retain boolean false
    frr/user astring root
    frr/vty_port integer 0
    frr/vty_addr astring ::1
    
    Other daemon-specific options/properties may be available, however they
    are not yet honoured/used (eg ospfd/apiserver on svc:/network/ospf).

  - As SMF is dependency aware, restarting network/zebra will restart all the
    other daemons.
  
  - To upgrade from one set of FRRouting packages to a newer release,
    one must first pkgrm the installed packages. When one pkgrm's FRRsmf all
    property configuration will be lost, and any customisations will have to
    redone after installing the updated FRRsmf package.
  
- These packages are not supported by Sun Microsystems, report bugs via the
  usual FRRouting channels, ie Issue Tracker. Improvements/contributions of course would be greatly appreciated.

