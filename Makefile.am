## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ \
         @ISISD@ @VTYSH@ @OSPFCLIENT@ doc

DIST_SUBDIRS = lib zebra bgpd ripd ripngd ospfd ospf6d vtysh \
	       ospfclient doc \
	       isisd

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS vtysh/Makefile.in \
	vtysh/Makefile.am update-autotools doc/mpls

dist-hook:
	mkdir $(distdir)/tools
	cp -p $(srcdir)/tools/*.pl $(distdir)/tools
	cp -p $(srcdir)/tools/*.el $(distdir)/tools
	cp -p $(srcdir)/tools/*.cgi $(distdir)/tools
	cp -p $(srcdir)/redhat/*.init $(distdir)/redhat
	cp -p $(srcdir)/redhat/quagga.* $(distdir)/redhat
	rm -rf `find $(distdir)/doc -type d -name CVS`
