## Process this file with automake to produce Makefile.in.

# Dia, the version i have at least, doesn't do very good EPS output
# (some of the text is scaled strangely). So this will work, but 
# it is probably better to use something like gimp to convert the 
# dia exported PNG files to EPS manually.
#
# Here we use 'convert' from the well known 'ImageMagick' package
# to do conversion from png to eps.
#
# PDF is required for quagga.pdf, we use epstopdf from the well known TeTeX
# TeX implementation, which we depend on already anyway.
#
# dia -> (dia) -> png -> (convert) -> eps -> (epstopdf) -> pdf
DIATOPNG = dia -t png -e
DIATOEPS = dia -t eps -e
PNGTOEPS = convert
EPSTOPDF = epstopdf

# The figure sources
figures_names_parts = -normal-processing -rs-processing \
	_topologies_full _topologies_rs
figures_sources := $(figures_names_parts:%=fig%.dia)
figures_png := $(figures_names_parts:%=fig%.png)
figures_pdf := $(figures_names_parts:%=fig%.pdf)
figures_eps := $(figures_names_parts:%=fig%.eps)

# rather twisted logic because we have to build PDFs of the EPS figures for
# PDFTex and yet build one PDF, quagga.pdf, from texi source. Which means we
# cant rely on a single automatic rule for *.pdf, eg the one automatically
# provided by automake. If you are an automake wizard, please feel free to
# compact it somehow.

# Built from defines.texi.in
BUILT_SOURCES = defines.texi

info_TEXINFOS = quagga.texi

# Have to manually specify the quagga.pdf rule in order to allow
# us to have a generic automatic .pdf rule to build the figure sources
# because it cant just work from the png's directly it seems - contrary
# to the documentation...
quagga.pdf: $(info_TEXINFOS) $(figures_pdf)
	$(TEXI2PDF) -o "$@" $<

quagga_TEXINFOS = appendix.texi basic.texi bgpd.texi filter.texi install.texi \
	ipv6.texi kernel.texi main.texi ospf6d.texi ospfd.texi overview.texi \
	protocol.texi ripd.texi ripngd.texi routemap.texi snmp.texi \
	vtysh.texi routeserver.texi defines.texi $(figures_png) snmptrap.texi

%.eps: %.png
	$(PNGTOEPS) $< "$@"

%.pdf: %.eps
	$(EPSTOPDF) --outfile="$@" $<

%.png: %.dia
	$(DIATOPNG) "$@" $<

man_MANS = vtysh.1 bgpd.8 ospf6d.8 ospfd.8 ripd.8 ripngd.8 zebra.8 isisd.8

EXTRA_DIST = BGP-TypeCode draft-zebra-00.ms draft-zebra-00.txt $(man_MANS) \
	mpls/ChangeLog.opaque.txt mpls/cli_summary.txt \
	mpls/opaque_lsa.txt mpls/ospfd.conf \
	$(figures_sources) $(figures_png)

draft-zebra-00.txt:
	groff -T ascii -ms draft-zebra-00.ms > draft-zebra-00.txt
