# conditionals
%define 	with_snmp	0
%define		with_vtysh	1
%define		with_ospf_te	1
%define		with_nssa	1
%define		with_opaque_lsa 1
%define		with_tcp_zebra	0
%define		with_vtysh	1
%define		with_pam	1
%define		with_ipv6	1
%define		with_multipath	64

# path defines
%define		_sysconfdir	/etc/zebra
%define		zeb_src		%{_builddir}/%{name}-%{version}
%define		zeb_rh_src	%{zeb_src}/redhat
%define		zeb_docs	%{zeb_src}/doc

Summary: Routing daemon
Name:		zebra
Version:	0.94
Release:	2003021301
License:	GPL
Group: System Environment/Daemons
Source0:	ftp://ftp.zebra.org/pub/zebra/%{name}-%{version}.tar.gz
URL:		http://www.zebra.org/
%if %with_snmp
BuildRequires:	ucd-snmp-devel
Prereq:		ucd-snmp
%endif
%if %with_vtysh
BuildRequires:	readline readline-devel ncurses ncurses-devel
Prereq:		readline ncurses
%endif
BuildRequires:	texinfo tetex autoconf openssl-devel pam-devel patch
# Initscripts > 5.60 is required for IPv6 support
Prereq:		initscripts >= 5.60
Prereq:		openssl ncurses readline pam
Prereq:		/sbin/install-info
Provides:	routingdaemon
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Obsoletes:	bird gated mrt

%description
GNU Zebra is a free software that manages TCP/IP based routing
protocol. It takes multi-server and multi-thread approach to resolve
the current complexity of the Internet.

GNU Zebra supports BGP4, BGP4+, OSPFv2, OSPFv3, RIPv1, RIPv2, and RIPng.

GNU Zebra is intended to be used as a Route Server and a Route
Reflector. It is not a toolkit, it provides full routing power under
a new architecture. GNU Zebra is unique in design in that it has a
process for each protocol.

%prep
%setup  -q

%build
%configure \
	--with-cflags="-O2" \
	--enable-netlink \
%if %with_ipv6
	--enable-ipv6 \
%endif
%if %with_snmp
	--enable-snmp \
%endif
%if %with_multipath
	--enable-multipath=%with_multipath \
%endif
%if %with_tcp_zebra
	--enable-tcp-zebra \
%endif
%if %with_nssa
	--enable-nssa \
%endif
%if %with_opaque_lsa
	--enable-opaque-lsa \
%endif
%if %with_ospf_te
	--enable-ospf-te \
%endif
%if %with_vtysh
	--enable-vtysh \
%endif
%if %with_pam
	--with-libpam
%endif

pushd vtysh
make %{?_smp_mflags} rebuild
popd

make %{?_smp_mflags} MAKEINFO="makeinfo --no-split"

pushd doc
texi2html zebra.texi
popd

%install
rm -rf $RPM_BUILD_ROOT

install -d $RPM_BUILD_ROOT/etc/{rc.d/init.d,sysconfig,logrotate.d,pam.d} \
	$RPM_BUILD_ROOT/var/log/zebra $RPM_BUILD_ROOT%{_infodir}

make install \
	DESTDIR=$RPM_BUILD_ROOT

install %{zeb_rh_src}/zebra.init $RPM_BUILD_ROOT/etc/rc.d/init.d/zebra
install %{zeb_rh_src}/bgpd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/bgpd
%if %with_ipv6
install %{zeb_rh_src}/ospf6d.init $RPM_BUILD_ROOT/etc/rc.d/init.d/ospf6d
install %{zeb_rh_src}/ripngd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/ripngd
%endif
install %{zeb_rh_src}/ospfd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/ospfd
install %{zeb_rh_src}/ripd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/ripd
install -m644 %{zeb_rh_src}/zebra.pam $RPM_BUILD_ROOT/etc/pam.d/zebra
install -m644 %{zeb_rh_src}/zebra.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/zebra

%post
# zebra_spec_add_service <service name> <port/proto> <comment>
# e.g. zebra_spec_add_service zebrasrv 2600/tcp "zebra service"

zebra_spec_add_service ()
{
  # Add port /etc/services entry if it isn't already there 
  if [ -f /etc/services ] && ! grep -q "^$1[^a-zA-Z0-9]" /etc/services ; then
    echo "$1		$2			# $3"  >> /etc/services
  fi
}

zebra_spec_add_service zebrasrv 2600/tcp "zebra service"
zebra_spec_add_service zebra    2601/tcp "zebra vty"
zebra_spec_add_service ripd     2602/tcp "RIPd vty"
%if %with_ipv6
zebra_spec_add_service ripngd   2603/tcp "RIPngd vty"
%endif
zebra_spec_add_service ospfd    2604/tcp "OSPFd vty"
zebra_spec_add_service bgpd     2605/tcp "BGPd vty"
%if %with_ipv6
zebra_spec_add_service ospf6d   2606/tcp "OSPF6d vty"
%endif

/sbin/chkconfig --add zebra 
/sbin/chkconfig --add ripd
%if %with_ipv6
/sbin/chkconfig --add ripngd
/sbin/chkconfig --add ospf6d
%endif
/sbin/chkconfig --add ospfd
/sbin/chkconfig --add bgpd

/sbin/install-info %{_infodir}/zebra.info.gz %{_infodir}/dir

# Create dummy files if they don't exist so basic functions can be used.
if [ ! -e %{_sysconfdir}/zebra.conf ]; then
	echo "hostname `hostname`" > %{_sysconfdir}/zebra.conf
	chmod 640 %{_sysconfdir}/zebra.conf
fi
if [ ! -e %{_sysconfdir}/vtysh.conf ]; then
	touch %{_sysconfdir}/vtysh.conf
	chmod 640 %{_sysconfdir}/vtysh.conf
fi

%postun
if [ "$1" -ge  "1" ]; then
	/etc/rc.d/init.d/zebra  condrestart >/dev/null 2>&1
	/etc/rc.d/init.d/ripd   condrestart >/dev/null 2>&1
%if %with_ipv6
	/etc/rc.d/init.d/ripngd condrestart >/dev/null 2>&1
%endif
	/etc/rc.d/init.d/ospfd  condrestart >/dev/null 2>&1
%if %with_ipv6
	/etc/rc.d/init.d/ospf6d condrestart >/dev/null 2>&1
%endif
	/etc/rc.d/init.d/bgpd   condrestart >/dev/null 2>&1
fi
/sbin/install-info --delete %{_infodir}/zebra.info.gz %{_infodir}/dir

%preun
if [ "$1" = "0" ]; then
        /sbin/chkconfig --del zebra
	/sbin/chkconfig --del ripd
%if %with_ipv6
	/sbin/chkconfig --del ripngd
%endif
	/sbin/chkconfig --del ospfd
%if %with_ipv6
	/sbin/chkconfig --del ospf6d
%endif
	/sbin/chkconfig --del bgpd
fi

%clean
#rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc */*.sample* tools AUTHORS COPYING
%doc doc/zebra.html
%doc doc/mpls
%doc ChangeLog INSTALL NEWS README REPORTING-BUGS SERVICES TODO
%dir %attr(750,root,root) %{_sysconfdir}
%dir %attr(750,root,root) /var/log/zebra
%dir %attr(755,root,root) /usr/share/info
%{_infodir}/*info*
%{_mandir}/man*/*
%{_sbindir}/*
%if %with_vtysh
%{_bindir}/*
%endif
%config /etc/zebra/*
%config /etc/rc.d/init.d/*
%config(noreplace) /etc/pam.d/zebra
%config(noreplace) %attr(640,root,root) /etc/logrotate.d/*

%changelog
* Mon Jan 20 2003 Paul Jakma <paul@dishone.st>
- update to latest cvs
- Yon's "show thread cpu" patch - 17217
- walk up tree - 17218
- ospfd NSSA fixes - 16681
- ospfd nsm fixes - 16824
- ospfd OLSA fixes and new feature - 16823 
- KAME and ifindex fixes - 16525
- spec file changes to allow redhat files to be in tree

* Sat Dec 28 2002 Alexander Hoogerhuis <alexh@ihatent.com>
- Added conditionals for building with(out) IPv6, vtysh, RIP, BGP
- Fixed up some build requirements (patch)
- Added conditional build requirements for vtysh / snmp
- Added conditional to %files for %_bindir depending on vtysh

* Mon Nov 11 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add Greg Troxel's md5 buffer copy/dup fix
- add RIPv1 fix
- add Frank's multicast flag fix

* Wed Oct 09 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- timestamped crypt_seqnum patch
- oi->on_write_q fix

* Mon Sep 30 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add vtysh 'write-config (integrated|daemon)' patch
- always 'make rebuild' in vtysh/ to catch new commands

* Fri Sep 13 2002 Paul Jakma <paulj@alphyra.ie>
- update to 0.93b

* Wed Sep 11 2002 Paul Jakma <paulj@alphyra.ie>
- update to latest CVS
- add "/sbin/ip route flush proto zebra" to zebra RH init on startup

* Sat Aug 24 2002 Paul Jakma <paulj@alphyra.ie>
- update to current CVS
- add OSPF point to multipoint patch
- add OSPF bugfixes
- add BGP hash optimisation patch

* Fri Jun 14 2002 Paul Jakma <paulj@alphyra.ie>
- update to 0.93-pre1 / CVS
- add link state detection support
- add generic PtP and RFC3021 support
- various bug fixes

* Thu Aug 09 2001 Elliot Lee <sopwith@redhat.com> 0.91a-6
- Fix bug #51336

* Wed Aug  1 2001 Trond Eivind Glomsrød <teg@redhat.com> 0.91a-5
- Use generic initscript strings instead of initscript specific
  ( "Starting foo: " -> "Starting $prog:" )

* Fri Jul 27 2001 Elliot Lee <sopwith@redhat.com> 0.91a-4
- Bump the release when rebuilding into the dist.

* Tue Feb  6 2001 Tim Powers <timp@redhat.com>
- built for Powertools

* Sun Feb  4 2001 Pekka Savola <pekkas@netcore.fi> 
- Hacked up from PLD Linux 0.90-1, Mandrake 0.90-1mdk and one from zebra.org.
- Update to 0.91a
- Very heavy modifications to init.d/*, .spec, pam, i18n, logrotate, etc.
- Should be quite Red Hat'isque now.
