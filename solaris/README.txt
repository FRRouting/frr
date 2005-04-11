To build packages for Solaris 10:

Requirements:
-------------

- Development environment including gcc (eg as shipped with Solaris 10)

- The Package tools from S10

- i.manifest and r.manifest scripts as supplied with Solaris Express
  in /usr/sadm/install/scripts/ or alternatively from the
  download/binaries/solaris/ directory on quagga.net. i.manifest must be at
  least version 1.5. You can place these scripts in this directory if you
  are using Solaris 10 GA (which does not ship with these scripts).


Package creation instructions:
------------------------------

1. Configure and build Quagga in the top level build directory as per
normal, eg:

	./configure --prefix=/usr/local/quagga \
		--localstatedir=/var/run/quagga
		--enable-gcc-rdynamic --enable-opaque-lsa --enable-ospf-te \
		--enable-multipath=64 --enable-user=quagga \
		--enable-ospfclient=yes --enable-ospfapi=yes  \
		--enable-group=quagga --enable-nssa --enable-opaque-lsa

You will need /usr/sfw/bin and /usr/ccs/bin in your path.

2. make install in the top-level build directory, it's a good idea to make
use of DESTDIR to install to an alternate root, eg:

	make DESTDIR=/var/tmp/qroot install

3. In this directory, run make packages, specifying DESTDIR if appropriate,
eg:

	make DESTDIR=/var/tmp/qroot packages

This should result in 4 packages being created:

	quagga-libs-...-$ARCH.pkg 	- QUAGGAlibs
	quagga-daemons-...-$ARCH.pkg	- QUAGGAdaemons
	quagga-doc-...-$ARCH.pkg	- QUAGGAdoc
	quagga-dev-...-$ARCH.pkg	- QUAGGAdev

QUAGGAlibs and QUAGGAdaemons are needed for daemon runtime.


Install and post-install configuration notes:
---------------------------------------------

- If you specified a user/group which does not exist per default on Solaris
  (eg quagga/quagga) you *must* create these before installing these on a
  system. The packages do *not* create the users.

- The configuration files are not created. You must create the configuration
  file yourself, either with your complete desired configuration, or else if
  you wish to use the telnet interface for further configuration you must
  create them containing at least:

	 password whatever

  The user which quagga runs as must have write permissions on this file, no
  other user should have read permissions, and you would also have to enable
  the telnet interface (see below).

- Configuration of common options are by way of SMF properties named Quagga,
  the defaults should be inline with how you configured Quagga in Step 1
  above, eg:

	Quagga/config_file astring /usr/local/quagga/etc/zebra.conf
	Quagga/daemon_name astring zebra
	Quagga/group astring quagga
	Quagga/pid_file astring /var/run/quagga/zebra.pid
	Quagga/stability astring Evolving
	Quagga/user astring quagga
	Quagga/vty_addr astring 127.1
	Quagga/vty_port integer 0

  Note that by default the telnet 'vty' interface is disabled -
  Quagga/vty_port is set to 0. Other daemon-specific options may be
  available, however they are not yet honoured/used (eg ospfd/apiserver on
  svc:/network/ospf).

  You can change these properties with the 'svccfg' SMF utility, eg:

	# svccfg 
	svc:> select svc:/network/zebra
	svc:/network/zebra> listprop Quagga/vty_port
	Quagga/vty_port  integer  0
	svc:/network/zebra> setprop Quagga/vty_port = 2601
	svc:/network/zebra> listprop Quagga/vty_port
	Quagga/vty_port  integer  2601
	svc:/network/zebra> quit
	# svcprop -p Quagga/vty_port network/zebra
	2601

  As SMF is dependency aware, restarting network/zebra will restart all the
  other daemons.

- These packages are not supported by Sun Microsystems, report bugs via the
  usual Quagga channels, ie Bugzilla. Improvements/contributions of course
  would be greatly appreciated.

