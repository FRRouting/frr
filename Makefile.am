## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ \
         @ISISD@ @VTYSH@ @OSPFCLIENT@ redhat doc

DIST_SUBDIRS = lib zebra bgpd ripd ripngd ospfd ospf6d \
	  isisd vtysh ospfclient doc redhat tests

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS vtysh/Makefile.in \
	vtysh/Makefile.am update-autotools \
	tools/mrlg.cgi tools/rrcheck.pl tools/rrlookup.pl tools/zc.pl \
	tools/zebra.el m4
	

ACLOCAL_AMFLAGS = -I m4
