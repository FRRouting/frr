## Process this file with automake to produce Makefile.in.

# Dia, the version i have at least, doesn't do very good EPS output
# (some of the text is scaled strangely). So this will work, but 
# it is probably better to use something like gimp to convert the 
# dia exported PNG files to EPS manually.
#
# Here we use 'convert' from the well known 'ImageMagick' package
# to do conversion from png to eps/pdf for figures. 
# PDF form is required for frr.pdf, using PDFTex at least.
#
# TeX implementation, which we depend on already anyway.
#
# dia -> (dia) -> png -> (convert) -> eps -> (epstopdf) -> pdf
SUFFIXES = .png .eps .dia .pdf
DIATOPNG = dia -t png -e
DIATOEPS = dia -t eps -e
PNGTOEPS = convert -antialias -contrast -despeckle
PNGTOPDF = $(PNGTOEPS)
EPSTOPDF = epstopdf

VNCFIGURES_PNG = 
VNCFIGURES_DIA = -vnc-mesh -vnc-frr-route-reflector		\
-vnc-commercial-route-reflector -vnc-redundant-route-reflectors	\
-vnc-gw -vnc-gw-rr

# TODO: A target that creates an empty text file for each member of
# VNCFIGURES_TXT
VNCFIGURES_TXT = $(VNCFIGURES:%.png=%.txt)

# The figure sources
figures_names_parts = -normal-processing -rs-processing \
	_topologies_full _topologies_rs \
	$(VNCFIGURES_DIA)

figures_sources = $(figures_names_parts:%=fig%.dia)
figures_png = $(figures_names_parts:%=fig%.png) $(VNCFIGURES_PNG)
figures_pdf = $(figures_names_parts:%=fig%.pdf) $(VNCFIGURES_PNG:%.png=%.pdf)
figures_eps = $(figures_names_parts:%=fig%.eps) $(VNCFIGURES_PNG:%.png=%.eps)
figures_txt = $(figures_names_parts:%=fig%.txt)

# rather twisted logic because we have to build PDFs of the EPS figures for
# PDFTex and yet build one PDF, frr.pdf, from texi source. Which means we
# cant rely on a single automatic rule for *.pdf, eg the one automatically
# provided by automake. If you are an automake wizard, please feel free to
# compact it somehow.

info_TEXINFOS = frr.texi

# Have to manually specify the frr.pdf rule in order to allow
# us to have a generic automatic .pdf rule to build the figure sources
# because it cant just work from the png's directly it seems - contrary
# to the documentation...
frr.pdf: $(info_TEXINFOS) $(figures_pdf) $(frr_TEXINFOS) defines.texi
	$(TEXI2PDF) -o "$@" $< || true

# don't ask me why the info file is in srcdir
$(srcdir)/frr.info: $(frr_TEXINFOS) defines.texi
frr.dvi: $(frr_TEXINFOS) defines.texi
frr.html: $(frr_TEXINFOS) defines.texi

frr_TEXINFOS = \
	appendix.texi \
	basic.texi \
	bgpd.texi \
	isisd.texi \
	filter.texi \
	vnc.texi \
	babeld.texi \
	install.texi \
	ipv6.texi  \
	kernel.texi \
	main.texi \
	nhrpd.texi \
	eigrpd.texi \
	ospf6d.texi \
	ospfd.texi \
	overview.texi \
	protocol.texi \
	ripd.texi \
	ripngd.texi \
	routemap.texi \
	snmp.texi \
	vtysh.texi \
	routeserver.texi \
	$(figures_png) \
	snmptrap.texi \
	ospf_fundamentals.texi \
	isisd.texi $(figures_txt) \
	rpki.texi \
	pimd.texi \
	#END

.png.eps:
	$(PNGTOEPS) $< "$@"

.png.pdf:
	$(PNGTOPDF) $< "$@"

.dia.png:
	$(DIATOPNG) "$@" $<

man_MANS = frr.1 frr-args.8

if PIMD
man_MANS += pimd.8
man_MANS += mtracebis.8
endif

if BGPD
man_MANS += bgpd.8
endif

if ISISD
man_MANS += isisd.8
endif

if OSPF6D
man_MANS += ospf6d.8
endif

if OSPFCLIENT
man_MANS += ospfclient.8
endif

if OSPFD
man_MANS += ospfd.8
endif

if LDPD
man_MANS += ldpd.8
endif

if RIPD
man_MANS += ripd.8
endif

if RIPNGD
man_MANS += ripngd.8
endif

if NHRPD
man_MANS += nhrpd.8
endif

if VTYSH
man_MANS += vtysh.1
endif

if WATCHFRR
man_MANS += watchfrr.8
endif

if ZEBRA
man_MANS += zebra.8
endif

if EIGRPD
man_MANS += eigrpd.8
endif

EXTRA_DIST = BGP-TypeCode draft-zebra-00.ms draft-zebra-00.txt \
	\
	bgpd.8.in \
	isisd.8.in \
	ospf6d.8.in \
	ospfclient.8.in \
	ospfd.8.in \
	ldpd.8.in \
	ripd.8.in \
	ripngd.8.in \
	pimd.8.in \
	mtracebis.8.in \
	nhrpd.8.in \
	vtysh.1.in \
	watchfrr.8.in \
	zebra.8.in \
	frr.1.in \
	eigrpd.8.in \
	\
	mpls/ChangeLog.opaque.txt mpls/cli_summary.txt \
	mpls/opaque_lsa.txt mpls/ospfd.conf \
	$(figures_sources) $(figures_png) $(figures_txt)

draft-zebra-00.txt: draft-zebra-00.ms
	groff -T ascii -ms $< > $@

# Ensure that all of the figures are copied into the html directory
html-local: $(HTMLS)
	if test -d $(HTMLS) ; then \
		cp -p $(figures_png) $(HTMLS) ; \
	else \
		echo "$(HTMLS) is not a directory. Make it so, the rerun make."; \
	fi
