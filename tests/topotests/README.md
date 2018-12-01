# FRRouting Topology Tests with Mininet

## Running tests with docker

There is a docker image which allows to run topotests. Instructions can be
found [here](docker/README.md).

## Guidelines

Instructions for  use, write or debug topologies can be found in the
[guidelines](GUIDELINES.md). To learn/remember common code snippets see
[here](SNIPPETS.md).

Before creating a new topology, make sure that there isn't one already
that does what you need. If nothing is similar, then you may create a
new topology, preferably, using the newest
[template](example-test/test_template.py).

## Installation of Mininet for running tests
Only tested with Ubuntu 16.04 and Ubuntu 18.04 (which uses Mininet 2.2.x)

Instructions are the same for all setups (ie ExaBGP is only used for BGP 
tests)

### Installing Mininet Infrastructure:

1. apt-get install mininet
2. apt-get install python-pip
3. apt-get install iproute
4. pip install ipaddr
5. pip install pytest
6. pip install exabgp==3.4.17
   (Newer 4.0 version of exabgp is not yet supported)
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

All test_* scripts in subdirectories are detected and executed (unless
disabled in `pytest.ini` file)

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

#### (Optional) StdErr log from daemos after exit

To enable the reporting of any messages seen on StdErr after the
daemons exit, the following env variable can be set.

	export TOPOTESTS_CHECK_STDERR=Yes

(The value doesn't matter at this time. The check is if the env variable
exists or not)
There is no pass/fail on this reporting. The Output will be reported to
the console

	export TOPOTESTS_CHECK_MEMLEAK="/home/mydir/memleak_"

This will enable the check and output to console and the writing of
the information to files with the given prefix (followed by testname),
ie `/home/mydir/memcheck_test_bgp_multiview_topo1.txt` in case of a 
memory leak.

#### (Optional) Collect Memory Leak Information

FreeRangeRouting processes have the capabilities to report remaining memory
allocations upon exit. To enable the reporting of the memory, define an
enviroment variable `TOPOTESTS_CHECK_MEMLEAK` with the file prefix, ie

	export TOPOTESTS_CHECK_MEMLEAK="/home/mydir/memleak_"

This will enable the check and output to console and the writing of
the information to files with the given prefix (followed by testname),
ie `/home/mydir/memcheck_test_bgp_multiview_topo1.txt` in case of a 
memory leak.

#### (Optional) Run topotests with GCC AddressSanitizer enabled

Topotests can be run with the GCC AddressSanitizer. It requires GCC 4.8 or
newer. (Ubuntu 16.04 as suggested here is fine with GCC 5 as default)
For more information on AddressSanitizer, see 
https://github.com/google/sanitizers/wiki/AddressSanitizer

The checks are done automatically in the library call of `checkRouterRunning`
(ie at beginning of tests when there is a check for all daemons running).
No changes or extra configuration for topotests is required beside compiling
the suite with AddressSanitizer enabled.

If a daemon crashed, then the errorlog is checked for AddressSanitizer
output. If found, then this is added with context (calling test) to
`/tmp/AddressSanitizer.txt` in markdown compatible format.

Compiling for GCC AddressSanitizer requires to use gcc as a linker as well
(instead of ld). Here is a suggest way to compile frr with AddressSanitizer
for `stable/3.0` branch:

	git clone https://github.com/FRRouting/frr.git
	cd frr
	git checkout stable/3.0
	./bootstrap.sh
	export CC=gcc
	export CFLAGS="-O1 -g -fsanitize=address -fno-omit-frame-pointer"
	export LD=gcc
	export LDFLAGS="-g -fsanitize=address -ldl"
	./configure --enable-shared=no \
		--prefix=/usr/lib/frr --sysconfdir=/etc/frr \
		--localstatedir=/var/run/frr \
		--sbindir=/usr/lib/frr --bindir=/usr/lib/frr \
		--enable-exampledir=/usr/lib/frr/examples \
		--with-moduledir=/usr/lib/frr/modules \
		--enable-multipath=0 --enable-rtadv \
		--enable-tcp-zebra --enable-fpm --enable-pimd
	make
	sudo make install
	# Create symlink for vtysh, so topotest finds it in /usr/lib/frr
	sudo ln -s /usr/lib/frr/vtysh /usr/bin/

and create `frr` user and `frrvty` group as shown above

## License

All the configs and scripts are licensed under a ISC-style license. See
Python scripts for details.
