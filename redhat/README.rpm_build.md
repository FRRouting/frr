Building your own FRRouting RPM
======================================
(Tested on CentOS 6, CentOS 7 and Fedora 24.)

1. Install the following packages to build the RPMs:

        yum install git autoconf automake libtool make gawk readline-devel \
        texinfo dejagnu net-snmp-devel groff rpm-build net-snmp-devel \
        libcap-devel texi2html bison flex

    Additionally, on systems with systemd (CentOS 7, Fedora)

        yum install systemd-devel

    (use `dnf install` on new Fedora instead of `yum install`)

    **CentOS 6:** Please check doc/Building_FRR_on_CentOS6.md for details on
    how to install required version of autoconf, automake and bison. The
    versions in the common Repo are too old.

2. Checkout FRR under a **unpriviledged** user account

        git clone https://github.com/frrouting/frr.git frr

3. Run Bootstrap and make distribution tar.gz

        cd frr
        ./bootstrap.sh
        ./configure --with-pkg-extra-version=-MyRPMVersion
        make dist
            
    Note: configure parameters are not important for the RPM building - except the `with-pkg-extra-version` if you want to give the RPM a specific name to
    mark your own unoffical build

4. Create RPM directory structure and populate with sources

        mkdir rpmbuild
        mkdir rpmbuild/SOURCES
        mkdir rpmbuild/SPECS
        cp redhat/*.spec rpmbuild/SPECS/
        cp frr*.tar.gz rpmbuild/SOURCES/

5. Edit rpm/SPECS/frr.spec with configuration as needed
    Look at the beginning of the file and adjust the following parameters to enable or disable features as required:
    
        ################# frr configure options ####################
        # with-feature options
        %{!?with_snmp:         %global  with_snmp       1 }
        %{!?with_tcp_zebra:    %global  with_tcp_zebra  0 }
        %{!?with_pam:          %global  with_pam        1 }
        %{!?with_ospfclient:   %global  with_ospfclient 1 }
        %{!?with_ospfapi:      %global  with_ospfapi    1 }
        %{!?with_irdp:         %global  with_irdp       1 }
        %{!?with_rtadv:        %global  with_rtadv      1 }
        %{!?with_ldpd:         %global  with_ldpd       0 }
        %{!?with_shared:       %global  with_shared     1 }
        %{!?with_multipath:    %global  with_multipath  64 }
        %{!?frr_user:          %global  frr_user        frr }
        %{!?vty_group:         %global  vty_group       frrvt }
        %{!?with_fpm:          %global  with_fpm        0 }
        %{!?with_watchfrr:     %global  with_watchfrr   1 }
        %{!?with_bgp_vnc:      %global  with_bgp_vnc    0 }
        %{!?with_pimd:         %global  with_pimd       1 }

6. Build the RPM

        rpmbuild --define "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/frr.spec

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

