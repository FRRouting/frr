# FRRouting Topology Tests with Mininet

## Installation of Mininet for running tests
Only tested with Ubuntu 16.04 (which uses Mininet 2.2.0)

Instructions are the same for all setups (ie ExaBGP is only used for BGP 
tests)

### Installing Mininet Infrastructure:

1. apt-get install mininet
2. apt-get install python-pip
3. apt-get install iproute
4. pip install ipaddr
5. pip install pytest
6. pip install exabgp
7. useradd -d /var/run/exabgp/ -s /bin/false exabgp

### Enable Coredumps
Optional, will give better output

1. apt-get install gdb
2. disable apport (which move core files)

	Set `enabled=0` in `/etc/default/apport`
		
3. Update security limits

	Add/change `/etc/security/limits.conf` to
	
		#<domain>      <type>  <item>         <value>
		*               soft    core          unlimited
		root            soft    core          unlimited
		*               hard    core          unlimited
		root            hard    core          unlimited
 
4. reboot (for options to take effect)

## FRRouting (FRR) Installation
FRR needs to be installed separatly. It is assume to be configured 
like the standard Ubuntu Packages:

- Binaries in /usr/lib/frr
- State Directory /var/run/frr
- Running under user frr, group frr
- vtygroup: frrvty
- config directory: /etc/frr
- For FRR Packages, install the dbg package as well for coredump decoding

No FRR config needs to be done and no FRR daemons should be run ahead
of the test. They are all started as part of the test

#### Manual FRRouting (FRR) build

If you prefer to manually build FRR, then use the following suggested config:

	./configure \
		--prefix=/usr \
		--localstatedir=/var/run/frr \
		--sbindir=/usr/lib/frr \
		--sysconfdir=/etc/frr \
		--enable-vtysh \
		--enable-pimd \
		--enable-multipath=64 \
		--enable-user=frr \
		--enable-group=frr \
		--enable-vty-group=frrvty \
		--with-pkg-extra-version=-my-manual-build

And create frr User and frrvty group as follows:

	addgroup --system --gid 92 frr
	addgroup --system --gid 85 frrvty
	adduser --system --ingroup frr --home /var/run/frr/ \
	   --gecos "FRRouting suite" --shell /bin/false frr
	usermod -G frrvty frr

## Executing Tests

#### Execute all tests with output to console

	py.test -s -v --tb=no

All test_* scripts in subdirectories are detected and executed (unless disabled in
`pytest.ini` file)

`--tb=no` disables the python traceback which might be irrelevant unless the
test script itself is debugged

#### Execute single test
	
	cd test_to_be_run
	./test_to_be_run.py
	
For further options, refer to pytest documentation

Test will set exit code which can be used with `git bisect`

For the simulated topology, see the description in the python file

If you need to clear the mininet setup between tests (if it isn't cleanly
shutdown), then use the `mn -c` command to clean up the environment

## License

All the configs and scripts are licensed under a ISC-style license. See
Python scripts for details.
