## Process this file with automake to produce Makefile.in.

EPSTOPDF = epstopdf

# rather twisted logic because we have to build PDFs of the EPS figures
# and yet build one PDF, quagga.pdf, from texi source. Which means we cant
# rely on a single automatic rule for *.pdf.
# If you are an automake wizard, please feel free to compact it somehow.
#figures_pdfs = Normal-Announcement-processing.eps \
#	       RS-Announcement-processing.eps \
#	       topologias_full.eps topologias_rs.eps 

# Built from defines.texi.in
BUILT_SOURCES = defines.texi

info_TEXINFOS = quagga.texi

CLEANFILES = *.pdf

# The figure sources
figures_SOURCES = fig-normal-processing.eps \
		  fig_topologies_full.eps \
		  fig-rs-processing.eps \
		  fig_topologies_rs.eps

# Have to manually 		  
quagga.pdf: quagga.texi \
            fig-normal-processing.pdf fig_topologies_full.pdf \
	    fig-rs-processing.pdf fig_topologies_rs.pdf
	$(TEXI2PDF) -o "$@" $(info_TEXINFOS)

quagga_TEXINFOS = appendix.texi basic.texi bgpd.texi filter.texi install.texi \
	ipv6.texi kernel.texi main.texi ospf6d.texi ospfd.texi overview.texi \
	protocol.texi ripd.texi ripngd.texi routemap.texi snmp.texi \
	vtysh.texi routeserver.texi defines.texi $(figures_SOURCES)

%.pdf: %.eps
	$(EPSTOPDF) --outfile="$@" $<

man_MANS = vtysh.1 bgpd.8 ospf6d.8 ospfd.8 ripd.8 ripngd.8 zebra.8 isisd.8

EXTRA_DIST = BGP-TypeCode draft-zebra-00.ms draft-zebra-00.txt $(man_MANS) \
	mpls/ChangeLog.opaque.txt mpls/cli_summary.txt \
	mpls/opaque_lsa.txt mpls/ospfd.conf

draft-zebra-00.txt:
	groff -T ascii -ms draft-zebra-00.ms > draft-zebra-00.txt
