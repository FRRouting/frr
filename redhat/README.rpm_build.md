Building your own Quagga RPM
============================
(Tested on CentOS 6, CentOS 7 and Fedora 22.)

1. Install the following packages to build the RPMs:

		yum install git autoconf automake libtool make gawk readline-devel \
		texinfo dejagnu net-snmp-devel groff rpm-build net-snmp-devel \
		libcap-devel texi2html

	(use `dnf install` on new Fedora instead of `yum install	`)
	
2. Checkout Quagga under a **unpriviledged** user account

		git clone git://git.savannah.nongnu.org/quagga.git quagga

3. Run Bootstrap and make distribution tar.gz

		cd quagga
		./bootstrap.sh
		./configure --with-pkg-extra-version=-MyRPMVersion
		make dist
			
	Note: configure parameters are not important for the RPM building - except the
	`with-pkg-extra-version` if you want to give the RPM a specific name to
	mark your own unoffical build

4. Create RPM directory structure and populate with sources

		mkdir rpmbuild
		mkdir rpmbuild/SOURCES
		mkdir rpmbuild/SPECS
		cp redhat/*.spec rpmbuild/SPECS/
		cp quagga*.tar.gz rpmbuild/SOURCES/

5. Edit rpm/SPECS/quagga.spec with configuration as needed
	Look at the beginning of the file and adjust the following parameters to enable
	or disable features as required:
	
		################# Quagga configure options ####################
		# with-feature options
        %{!?with_snmp:         %global  with_snmp       1 }
        %{!?with_vtysh:        %global  with_vtysh      1 }
        %{!?with_ospf_te:      %global  with_ospf_te    1 }
		%{!?with_opaque_lsa:   %global  with_opaque_lsa 1 }
		%{!?with_tcp_zebra:	   %global  with_tcp_zebra  0 }
		%{!?with_vtysh:        %global  with_vtysh      1 }
		%{!?with_pam:          %global  with_pam        1 }
        %{!?with_ospfclient:   %global  with_ospfclient 1 }
		%{!?with_ospfapi:      %global  with_ospfapi    1 }
		%{!?with_irdp:         %global  with_irdp       1 }
		%{!?with_rtadv:        %global  with_rtadv      1 }
		%{!?with_isisd:        %global  with_isisd      1 }
		%{!?with_pimd:         %global  with_pimd       1 }
		%{!?with_shared:       %global  with_shared     1 }
		%{!?with_multipath:    %global  with_multipath  64 }
		%{!?quagga_user:       %global  quagga_user     quagga }
		%{!?vty_group:         %global  vty_group       quaggavt }
		%{!?with_fpm:          %global  with_fpm        0 }
		%{!?with_watchquagga:  %global  with_watchquagga 1 }

6. Build the RPM

		rpmbuild --define "_topdir `pwd`/rpmbuild" -ba rpmbuild/SPECS/quagga.spec

DONE.

If all works correctly, then you should end up with the RPMs under `rpmbuild/RPMS`
and the Source RPM under `rpmbuild/SRPMS`


Enabling daemons after installation of the package:
---------------------------------------------------

### init.d based systems (ie CentOS 6):

1. Enable the daemons as needed to run after boot (Zebra is mandatory)
	
		chkconfig zebra on
		chkconfig ospfd on
		chkconfig ospf6d on
		chkconfig bgpd on
		... etc

2. If you want to run `watchquagga`, then configure `/etc/sysconfig/quagga` 
   and uncomment the line with the daemons for `watchquagga` to monitor,
   then enable watchquagga

		chkconfig watchquagga on

3. Check your firewall / IPtables to make sure the routing protocols are
allowed.
		
4. Start the daemons (or reboot)

		service zebra start
		service bgpd start
		service ospfd start
		... etc
			
Configuration is stored in `/etc/quagga/*.conf` files.


### systemd based systems (ie CentOS 7, Fedora 22)

1. Enable the daemons as needed to run after boot (Zebra is mandatory)
	
		systemctl enable zebra
		systemctl enable ospfd
		systemctl enable ospf6d
		systemctl enable bgpd
		... etc

	Note: There is no watchquagga on systemd based systems. Systemd contains
	the functionality of monitoring and restarting daemons.

2. Check your firewall / IPtables to make sure the routing protocols are
allowed.
		
3. Start the daemons (or reboot)

		systemctl start zebra
		systemctl start bgpd
		systemctl start ospfd
		... etc
			
Configuration is stored in `/etc/quagga/*.conf` files.

