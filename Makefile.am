## Process this file with automake to produce Makefile.in.

SUBDIRS = lib @ZEBRA@ @BGPD@ @RIPD@ @RIPNGD@ @OSPFD@ @OSPF6D@ \
         @ISISD@ @WATCHQUAGGA@ @VTYSH@ @OSPFCLIENT@ doc m4 @pkgsrcdir@ \
         redhat solaris

DIST_SUBDIRS = lib zebra bgpd ripd ripngd ospfd ospf6d \
	  isisd watchquagga vtysh ospfclient doc m4 pkgsrc redhat tests \
	  solaris

EXTRA_DIST = aclocal.m4 SERVICES TODO REPORTING-BUGS vtysh/Makefile.in \
	vtysh/Makefile.am update-autotools \
	tools/mrlg.cgi tools/rrcheck.pl tools/rrlookup.pl tools/zc.pl \
	tools/zebra.el

ACLOCAL_AMFLAGS = -I m4
