Building your own FRRouting Debian Package
==========================================
(Tested on Ubuntu 12.04, 14.04, 16.04, 17.10, Debian 8 and 9)

**Note:**  If you try to build for a different distro, then it will most likely
fail because of the missing backport. See debianpkg/backports/README about
adding a new backport.

1. Follow the package installation as outlined in doc/Building_on_XXXX.md
   (XXXX refers your OS Distribution) to install the required build packages

2. Install the following additional packages:

        apt-get install realpath equivs groff fakeroot debhelper devscripts

3. Checkout FRR under a **unpriviledged** user account

        git clone https://github.com/frrouting/frr.git frr
        cd frr
	# git checkout <branch>    - if different branch than master

4. Run Bootstrap and make distribution tar.gz

        ./bootstrap.sh
        ./configure --with-pkg-extra-version=-MyDebPkgVersion
        make dist
            
    Note: configure parameters are not important for the Debian Package
    building - except the `with-pkg-extra-version` if you want to give the
    Debian Package a specific name to mark your own unoffical build

5. Edit `debianpkg/rules` and set the configuration as needed

    Look for section `dh_auto_configure` to modify the configure
    options as needed. Options might be different between main `rules` and 
    `backports/XXXX/debian/rules`. Please adjust as needed on all files

6. Create backports debian sources
 
    Move the `debianpkg` to `debian` and create the backports
    (Debian requires to not ship a `debian` directory inside the source
    directory to avoid build conflicts with the reserved `debian` subdirectory
    name during the build)

        mv debianpkg debian
        make -f debian/rules backports

    This will create a `frr_*.orig.tar.gz` with the source (same as dist tar),
    and multiple `frr_*.debian.tar.xz` and `frr_*.dsc` for the debian package
    source on each backport supported distribution

7. Create a new directory to build the package and populate with package src

        mkdir frrpkg
        cd frrpkg
        tar xf ~/frr/frr_*.orig.tar.gz
        cd frr*
        . /etc/os-release
        tar xf ~/frr/frr_*${ID}${VERSION_ID}*.debian.tar.xz

8. Build Debian Package Dependencies and install them as needed

        sudo mk-build-deps --install debian/control

9. Build Debian Package

    Building with standard options:

        debuild -b -uc -us

    Or change some options:
    (see `rules` file for available options)

        export WANT_BGP_VNC=1
        export WANT_CUMULUS_MODE=1
        debuild -b -uc -us

DONE.

If all works correctly, then you should end up with the Debian packages under 
`frrpkg`. If distributed, please make sure you distribute it together with
the sources (`frr_*.orig.tar.gz`, `frr_*.debian.tar.xz` and `frr_*.dsc`)


Enabling daemons after installation of the package:
---------------------------------------------------

1. Edit `/etc/frr/daemons` and enable required routing daemons (Zebra is
probably needed for most deployments, so make sure to enable it.)
 
2. Check your firewall / IPtables to make sure the routing protocols are
allowed.
        
3. Enable FRR at startup

    - On `init.d` based systems (Ubuntu 12.04)

            sudo update-rc.d frr defaults

    - On `systemd` based systems (Debian 8, 9, Ubuntu 14.04, 16.04, 17.10)

            sudo systemctl enable frr

4. Start/Restart the daemons (or reboot)

    - On `init.d` based systems (Ubuntu 12.04)

            sudo invoke-rc.d frr start

    - on `systemd` based systems (Debian 8, 9, Ubuntu 14.04, 16.04, 17.10)

            sudo systemctl start frr


Configuration is stored in `/etc/frr/*.conf` files and daemon selection
is stored in `/etc/frr/daemons`.
