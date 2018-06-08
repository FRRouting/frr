## Process this file with Automake to create Makefile.in

include ../common.am

if ENABLE_BGP_VNC
BGP_VNC_RFP_SRCDIR   = @top_srcdir@/@LIBRFP@
BGP_VNC_RFP_INCDIR   = -I$(BGP_VNC_RFP_SRCDIR)
BGP_VNC_RFP_SRC      = $(BGP_VNC_RFP_SRCDIR)/*.c
BGP_VNC_RFAPI_SRCDIR = @top_srcdir@/bgpd/rfapi
BGP_VNC_RFAPI_INCDIR = -I$(BGP_VNC_RFAPI_SRCDIR) -I$(top_srcdir)/bgpd
BGP_VNC_RFAPI_SRC    = $(BGP_VNC_RFAPI_SRCDIR)/*.c
else
BGP_VNC_RFP_INCDIR   =
BGP_VNC_RFP_SRCDIR   =
BGP_VNC_RFP_SRC      =
BGP_VNC_RFAPI_INCDIR =
BGP_VNC_RFAPI_SRCDIR =
BGP_VNC_RFAPI_SRC    =
endif
AM_CPPFLAGS += -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib \
	$(BGP_VNC_RFAPI_INCDIR) $(BGP_VNC_RFP_INCDIR)
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"

LIBS = @LIBS@ @CURSES@ @LIBPAM@

bin_PROGRAMS = vtysh

vtysh_SOURCES = vtysh_main.c vtysh.c vtysh_user.c vtysh_config.c
nodist_vtysh_SOURCES = vtysh_cmd.c
CLEANFILES = vtysh_cmd.c
noinst_HEADERS = vtysh.h vtysh_user.h
vtysh_LDADD = ../lib/libfrr.la @LIBCAP@ @LIBREADLINE@

examplesdir = $(exampledir)
dist_examples_DATA = vtysh.conf.sample

EXTRA_DIST = extract.pl

vtysh_scan =

if PIMD
vtysh_scan += $(top_srcdir)/pimd/pim_cmd.c
endif

if BGPD
vtysh_scan += $(top_srcdir)/bgpd/bgp_bfd.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_debug.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_dump.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_evpn_vty.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_filter.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_mplsvpn.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_nexthop.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_route.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_routemap.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_vty.c
vtysh_scan += $(top_srcdir)/bgpd/bgp_flowspec_vty.c
endif

if RPKI
vtysh_scan += $(top_srcdir)/bgpd/bgp_rpki.c
endif

if ISISD
vtysh_scan += $(top_srcdir)/isisd/isis_redist.c
vtysh_scan += $(top_srcdir)/isisd/isis_spf.c
vtysh_scan += $(top_srcdir)/isisd/isis_te.c
vtysh_scan += $(top_srcdir)/isisd/isis_vty.c
vtysh_scan += $(top_srcdir)/isisd/isisd.c
endif

if OSPFD
vtysh_scan += $(top_srcdir)/ospfd/ospf_bfd.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_dump.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_opaque.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_ri.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_routemap.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_te.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_sr.c
vtysh_scan += $(top_srcdir)/ospfd/ospf_vty.c
endif

if OSPF6D
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_abr.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_asbr.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_area.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_bfd.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_flood.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_interface.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_intra.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_lsa.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_message.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_neighbor.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_route.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_spf.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_top.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6_zebra.c
vtysh_scan += $(top_srcdir)/ospf6d/ospf6d.c
endif

if RIPD
vtysh_scan += $(top_srcdir)/ripd/rip_debug.c
vtysh_scan += $(top_srcdir)/ripd/rip_interface.c
vtysh_scan += $(top_srcdir)/ripd/rip_offset.c
vtysh_scan += $(top_srcdir)/ripd/rip_zebra.c
vtysh_scan += $(top_srcdir)/ripd/ripd.c
endif

if RIPNGD
vtysh_scan += $(top_srcdir)/ripngd/ripng_debug.c
vtysh_scan += $(top_srcdir)/ripngd/ripng_interface.c
vtysh_scan += $(top_srcdir)/ripngd/ripng_offset.c
vtysh_scan += $(top_srcdir)/ripngd/ripng_zebra.c
vtysh_scan += $(top_srcdir)/ripngd/ripngd.c
endif

if LDPD
vtysh_scan += $(top_srcdir)/ldpd/ldp_vty_cmds.c
endif

if NHRPD
vtysh_scan += $(top_srcdir)/nhrpd/nhrp_vty.c
endif

if EIGRPD
vtysh_scan += $(top_srcdir)/eigrpd/eigrp_dump.c
#vtysh_scan += $(top_srcdir)/eigrpd/eigrp_routemap.c
vtysh_scan += $(top_srcdir)/eigrpd/eigrp_vty.c
endif

if BABELD
vtysh_scan += $(top_srcdir)/babeld/babel_interface.c
vtysh_scan += $(top_srcdir)/babeld/babel_zebra.c
vtysh_scan += $(top_srcdir)/babeld/babeld.c
endif

if SHARPD
vtysh_scan += $(top_srcdir)/sharpd/sharp_vty.c
endif

if SNMP
vtysh_scan += $(top_srcdir)/lib/agentx.c
endif

if PBRD
vtysh_scan += $(top_srcdir)/pbrd/pbr_vty.c
vtysh_scan += $(top_srcdir)/pbrd/pbr_debug.c
endif

vtysh_cmd_FILES = $(vtysh_scan) \
		  $(top_srcdir)/lib/keychain.c $(top_srcdir)/lib/routemap.c \
		  $(top_srcdir)/lib/filter.c $(top_srcdir)/lib/plist.c \
		  $(top_srcdir)/lib/distribute.c $(top_srcdir)/lib/if_rmap.c \
		  $(top_srcdir)/lib/vrf.c \
		  $(top_srcdir)/lib/vty.c $(top_srcdir)/zebra/debug.c \
		  $(top_srcdir)/lib/logicalrouter.c \
		  $(top_srcdir)/lib/nexthop_group.c \
		  $(top_srcdir)/zebra/interface.c \
		  $(top_srcdir)/zebra/irdp_interface.c \
		  $(top_srcdir)/zebra/rtadv.c $(top_srcdir)/zebra/zebra_vty.c \
		  $(top_srcdir)/zebra/zserv.c $(top_srcdir)/zebra/router-id.c \
		  $(top_srcdir)/zebra/zebra_routemap.c \
	          $(top_srcdir)/zebra/zebra_fpm.c \
		  $(top_srcdir)/zebra/zebra_ptm.c \
		  $(top_srcdir)/zebra/zebra_mpls_vty.c \
		  $(top_srcdir)/zebra/zebra_pw.c \
		  $(top_srcdir)/watchfrr/watchfrr_vty.c \
	          $(BGP_VNC_RFAPI_SRC) $(BGP_VNC_RFP_SRC)

vtysh_cmd.c: $(vtysh_cmd_FILES) extract.pl
	./extract.pl $(vtysh_cmd_FILES) > vtysh_cmd.c
