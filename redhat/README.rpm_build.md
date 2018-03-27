Building your own FRRouting RPM
======================================
(Tested on CentOS 6, CentOS 7 and Fedora 24.)

1. On CentOS 6 (which doesn't provide a bison/automake/autoconf of a recent enough version):
    - Check out ../doc/Building_FRR_on_CentOS6.md for details on installing
    a bison/automake/autoconf to support frr building.

    Newer automake/autoconf/bison is only needed to build the rpm and is
    **not** needed to install the binary rpm package

2. Install the build packages as documented in doc/Building_on_xxxxx.md 
   and the following additional packages:

        yum install rpm-build net-snmp-devel pam-devel

    Additionally, on systems with systemd (CentOS 7, Fedora)

        yum install systemd-devel

    (use `dnf install` on new Fedora instead of `yum install`)

3. Checkout FRR under a **unpriviledged** user account

        git clone https://github.com/frrouting/frr.git frr

4. Run Bootstrap and make distribution tar.gz

        cd frr
        ./bootstrap.sh
        ./configure --with-pkg-extra-version=-MyRPMVersion
        make SPHINXBUILD=sphinx-build2.7 dist
            
    Note: configure parameters are not important for the RPM building - except the `with-pkg-extra-version` if you want to give the RPM a specific name to
    mark your own unoffical build

5. Create RPM directory structure and populate with sources

        mkdir rpmbuild
        mkdir rpmbuild/SOURCES
        mkdir rpmbuild/SPECS
        cp redhat/*.spec rpmbuild/SPECS/
        cp frr*.tar.gz rpmbuild/SOURCES/

6. Edit rpm/SPECS/frr.spec with configuration as needed
    Look at the beginning of the file and adjust the following parameters to enable or disable features as required:
    
        ############### FRRouting (FRR) configure options #################
        # with-feature options
        %{!?with_pam:           %global  with_pam           0 }
        %{!?with_ospfclient:    %global  with_ospfclient    1 }
        %{!?with_ospfapi:       %global  with_ospfapi       1 }
        %{!?with_irdp:          %global  with_irdp          1 }
        %{!?with_rtadv:         %global  with_rtadv         1 }
        %{!?with_ldpd:          %global  with_ldpd          1 }
        %{!?with_nhrpd:         %global  with_nhrpd         1 }
        %{!?with_eigrp:         %global  with_eigrpd        1 }
        %{!?with_shared:        %global  with_shared        1 }
        %{!?with_multipath:     %global  with_multipath     256 }
        %{!?frr_user:           %global  frr_user           frr }
        %{!?vty_group:          %global  vty_group          frrvty }
        %{!?with_fpm:           %global  with_fpm           0 }
        %{!?with_watchfrr:      %global  with_watchfrr      1 }
        %{!?with_bgp_vnc:       %global  with_bgp_vnc       0 }
        %{!?with_pimd:          %global  with_pimd          1 }
        %{!?with_rpki:          %global  with_rpki          0 }

7. Build the RPM

        rpmbuild --define "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/frr.spec

   If building with RPKI, then download and install the additional RPKI
   packages from
        https://ci1.netdef.org/browse/RPKI-RTRLIB/latestSuccessful/artifact

DONE.

If all works correctly, then you should end up with the RPMs under 
`rpmbuild/RPMS` and the Source RPM under `rpmbuild/SRPMS`


Enabling daemons after installation of the package:
---------------------------------------------------

### init.d based systems (ie CentOS 6):

1. Edit /etc/frr/daemons and enable required routing daemons (Zebra is probably needed for most deployments, so make sure to enable it.)

2. Enable the daemons as needed to run after boot (Zebra is mandatory)
    
        chkconfig frr on

3. Check your firewall / IPtables to make sure the routing protocols are
allowed.
        
5. Start the FRR daemons (or reboot)

        service frr start
            
Configuration is stored in `/etc/frr/*.conf` files and daemon selection is stored in `/etc/frr/daemons`.


### systemd based systems (ie CentOS 7, Fedora 24)

1. Edit /etc/frr/daemons and enable required routing daemons (Zebra is probably needed for most deployments, so make sure to enable it.)
 
2. Enable the frr daemons to run after boot.
    
        systemctl enable frr

2. Check your firewall / IPtables to make sure the routing protocols are
allowed.
        
3. Start the daemons (or reboot)

        systemctl start frr
            
Configuration is stored in `/etc/frr/*.conf` files and daemon selection is stored in `/etc/frr/daemons`.

