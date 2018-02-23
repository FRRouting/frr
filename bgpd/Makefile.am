## Process this file with automake to produce Makefile.in.
AUTOMAKE_OPTIONS = subdir-objects

include ../common.am

if ENABLE_BGP_VNC
#o file to keep linker happy
BGP_VNC_RFP_LIB=rfapi/rfapi_descriptor_rfp_utils.o @top_builddir@/$(LIBRFP)/librfp.a 
BGP_VNC_RFP_INC=-I@top_srcdir@/$(RFPINC)
BGP_VNC_RFP_HD=\
	@top_srcdir@/$(RFPINC)/rfp.h
BGP_VNC_RFP_LD_FLAGS_FILE=@top_srcdir@/$(LIBRFP)/rfp_ld_flags
BGP_VNC_RFP_LD_FLAGS=`if [ -e  "$(BGP_VNC_RFP_LD_FLAGS_FILE)" ] ; then cat "$(BGP_VNC_RFP_LD_FLAGS_FILE)" ; fi `

#BGP_VNC_RFAPI_SRCDIR=rfapi
BGP_VNC_RFAPI_SRCDIR=
BGP_VNC_RFAPI_INC=-Irfapi
BGP_VNC_RFAPI_SRC=rfapi/bgp_rfapi_cfg.c \
	rfapi/rfapi_import.c \
	rfapi/rfapi.c \
	rfapi/rfapi_ap.c \
	rfapi/rfapi_descriptor_rfp_utils.c \
	rfapi/rfapi_encap_tlv.c \
	rfapi/rfapi_nve_addr.c \
	rfapi/rfapi_monitor.c \
	rfapi/rfapi_rib.c \
	rfapi/rfapi_vty.c \
	rfapi/vnc_debug.c \
	rfapi/vnc_export_bgp.c \
	rfapi/vnc_export_table.c \
	rfapi/vnc_import_bgp.c \
	rfapi/vnc_zebra.c
BGP_VNC_RFAPI_HD=rfapi/bgp_rfapi_cfg.h \
	rfapi/rfapi_import.h \
	rfapi/rfapi.h \
	rfapi/rfapi_ap.h \
	rfapi/rfapi_backend.h \
	rfapi/rfapi_descriptor_rfp_utils.h \
	rfapi/rfapi_encap_tlv.h \
	rfapi/rfapi_nve_addr.h \
	rfapi/rfapi_monitor.h \
	rfapi/rfapi_private.h \
	rfapi/rfapi_rib.h \
	rfapi/rfapi_vty.h \
	rfapi/vnc_debug.h \
	rfapi/vnc_export_bgp.h \
	rfapi/vnc_export_table.h \
	rfapi/vnc_import_bgp.h \
	rfapi/vnc_zebra.h \
	rfapi/vnc_export_bgp_p.h \
	rfapi/vnc_import_bgp_p.h \
	bgp_vnc_types.h $(BGP_VNC_RFP_HD)

else
BGP_VNC_RFAPI_INC=
BGP_VNC_RFAPI_SRC=
BGP_VNC_RFAPI_HD=
BGP_VNC_RFP_LIB=
BGP_VNC_RFP_INC=
BGP_VNC_RFP_HD=
BGP_VNC_RFP_LD_FLAGS=
endif

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib \
	$(BGP_VNC_RFAPI_INC) $(BGP_VNC_RFP_INC)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

AM_CFLAGS = $(WERROR)

noinst_LIBRARIES = libbgp.a
module_LTLIBRARIES =
sbin_PROGRAMS = bgpd
bin_PROGRAMS = bgp_btoa

BUILT_SOURCES = 

libbgp_a_SOURCES = \
	bgp_memory.c \
	bgpd.c bgp_fsm.c bgp_aspath.c bgp_community.c bgp_attr.c \
	bgp_debug.c bgp_route.c bgp_zebra.c bgp_open.c bgp_routemap.c \
	bgp_packet.c bgp_network.c bgp_filter.c bgp_regex.c bgp_clist.c \
	bgp_dump.c bgp_ecommunity.c bgp_lcommunity.c \
	bgp_mplsvpn.c bgp_nexthop.c \
	bgp_damp.c bgp_table.c bgp_advertise.c bgp_vty.c bgp_mpath.c \
	bgp_nht.c bgp_updgrp.c bgp_updgrp_packet.c bgp_updgrp_adv.c bgp_bfd.c \
	bgp_encap_tlv.c $(BGP_VNC_RFAPI_SRC) bgp_attr_evpn.c \
	bgp_evpn.c bgp_evpn_vty.c bgp_vpn.c bgp_label.c bgp_rd.c \
	bgp_keepalives.c bgp_io.c

noinst_HEADERS = \
	bgp_memory.h \
	bgp_aspath.h bgp_attr.h bgp_community.h bgp_debug.h bgp_fsm.h \
	bgp_network.h bgp_open.h bgp_packet.h bgp_regex.h bgp_route.h \
	bgpd.h bgp_filter.h bgp_clist.h bgp_dump.h bgp_zebra.h \
	bgp_ecommunity.h bgp_lcommunity.h \
	bgp_mplsvpn.h bgp_nexthop.h bgp_damp.h bgp_table.h \
	bgp_advertise.h bgp_vty.h bgp_mpath.h bgp_nht.h \
	bgp_updgrp.h bgp_bfd.h bgp_encap_tlv.h bgp_encap_types.h \
	$(BGP_VNC_RFAPI_HD) bgp_attr_evpn.h bgp_evpn.h bgp_evpn_vty.h \
        bgp_vpn.h bgp_label.h bgp_rd.h bgp_evpn_private.h bgp_keepalives.h \
	bgp_io.h

bgpd_SOURCES = bgp_main.c
bgpd_LDADD = libbgp.a  $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ @LIBM@
bgpd_LDFLAGS = $(BGP_VNC_RFP_LD_FLAGS)

bgp_btoa_SOURCES = bgp_btoa.c
bgp_btoa_LDADD = libbgp.a $(BGP_VNC_RFP_LIB) ../lib/libfrr.la @LIBCAP@ @LIBM@
bgp_btoa_LDFLAGS = $(BGP_VNC_RFP_LD_FLAGS)

if SNMP
module_LTLIBRARIES += bgpd_snmp.la
endif

bgpd_snmp_la_SOURCES = bgp_snmp.c
bgpd_snmp_la_CFLAGS = $(WERROR) $(SNMP_CFLAGS)
bgpd_snmp_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
bgpd_snmp_la_LIBADD = ../lib/libfrrsnmp.la

if RPKI
module_LTLIBRARIES += bgpd_rpki.la
BUILT_SOURCES += bgp_rpki_clippy.c
endif

bgpd_rpki_la_SOURCES = bgp_rpki.c
bgpd_rpki_la_CFLAGS = $(WERROR) $(RTRLIB_CFLAGS)
bgpd_rpki_la_LDFLAGS = -avoid-version -module -shared -export-dynamic
bgpd_rpki_la_LIBADD = $(RTRLIB_LIBS)

examplesdir = $(exampledir)
dist_examples_DATA = bgpd.conf.sample bgpd.conf.sample2 \
	bgpd.conf.vnc.sample

bgp_vty.o: bgp_vty_clippy.c
bgp_route.o: bgp_route_clippy.c

EXTRA_DIST = BGP4-MIB.txt

