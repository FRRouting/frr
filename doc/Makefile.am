## Process this file with automake to produce Makefile.in.

# Pass down make invocation to each subdirectory.
#
# Each of these directories contains a Sphinx-generated Makefile that has been
# modified to implement all the targets required by Automake, as documented in
# the 'Third-Party Makefiles' section of the Automake docs.
#
# Note the absence of the 'developer' directory here; development docs are
# never built as part of a regular build. They are only built when explicitly
# asked for. See comment further down.

# Sphinx is not designed to be invoked multiple times against the same toctree.
.NOTPARALLEL:

SUBDIRS = manpages user
AM_MAKEFLAGS = DESTDIR=${DESTDIR} infodir=${infodir}

MANPAGE_BUILDDIR = manpages/_build/man

# This is a hack, see comment further down.
man_MANS = $(MANPAGE_BUILDDIR)/frr.1

if PIMD
man_MANS += $(MANPAGE_BUILDDIR)/pimd.8
man_MANS += $(MANPAGE_BUILDDIR)/mtracebis.8
endif

if PBRD
man_MANS += $(MANPAGE_BUILDDIR)/pbrd.8
endif

if BGPD
man_MANS += $(MANPAGE_BUILDDIR)/bgpd.8
endif

if ISISD
man_MANS += $(MANPAGE_BUILDDIR)/isisd.8
endif

if OSPF6D
man_MANS += $(MANPAGE_BUILDDIR)/ospf6d.8
endif

if OSPFCLIENT
man_MANS += $(MANPAGE_BUILDDIR)/ospfclient.8
endif

if OSPFD
man_MANS += $(MANPAGE_BUILDDIR)/ospfd.8
endif

if LDPD
man_MANS += $(MANPAGE_BUILDDIR)/ldpd.8
endif

if RIPD
man_MANS += $(MANPAGE_BUILDDIR)/ripd.8
endif

if RIPNGD
man_MANS += $(MANPAGE_BUILDDIR)/ripngd.8
endif

if NHRPD
man_MANS += $(MANPAGE_BUILDDIR)/nhrpd.8
endif

if VTYSH
man_MANS += $(MANPAGE_BUILDDIR)/vtysh.1
endif

if WATCHFRR
man_MANS += $(MANPAGE_BUILDDIR)/watchfrr.8
endif

if ZEBRA
man_MANS += $(MANPAGE_BUILDDIR)/zebra.8
endif

if EIGRPD
man_MANS += $(MANPAGE_BUILDDIR)/eigrpd.8
endif

if SHARPD
man_MANS += $(MANPAGE_BUILDDIR)/sharpd.8
endif

# Automake is particular about manpages. It is aware of them and has some
# special facilities for handling them, but it assumes that manpages are always
# given in groff source and so these facilities are limited to simply
# specifying the path to the groff sources in a special variable. There is no
# target for building manpages that can be extended, as there are for pdf,
# html, dvi, etc. Unfortunately this leaves us with hijacking the
# 'install-data' and 'all' targets in the 3rd-party Makefile in manpages/ to
# make sure manpages are always built, and then using the special Automake
# variable defined above in order to take advantage of automatic installation.
#
# However, it is conceivable that someone may want to build just the manpages,
# so here's an explicit target for that.
man:
	$(MAKE) -C manpages man

# Automake automatically defines targets for various document formats. All of
# the child 3rd-party Makefiles are aware of all Automake targets and implement
# the ones we are interested in.
#
# The SUBDIRS variable at the top of this Makefile.am causes the following
# implicit Automake targets to only build user documentation, and not developer
# documentation:
# - info
# - html
# - pdf
#
# If you wish to build developer documentation, use these targets:
developer-info:
	$(MAKE) -C developer info

developer-pdf:
	$(MAKE) -C developer latexpdf

developer-html:
	$(MAKE) -C developer html

# If you want to build the developer's docs in other formats, try the
# following:
#
# $ cd developer
# $ make help

# dist tarballs want doc sources
EXTRA_DIST = frr-sphinx.mk \
	manpages/bgpd.rst \
	manpages/common-options.rst \
	manpages/conf.py \
	manpages/defines.rst \
	manpages/eigrpd.rst \
	manpages/epilogue.rst \
	manpages/frr.rst \
	manpages/index.rst \
	manpages/isisd.rst \
	manpages/ldpd.rst \
	manpages/Makefile.am \
	manpages/mtracebis.rst \
	manpages/nhrpd.rst \
	manpages/ospf6d.rst \
	manpages/ospfclient.rst \
	manpages/ospfd.rst \
	manpages/pimd.rst \
	manpages/ripd.rst \
	manpages/pbrd.rst \
	manpages/ripngd.rst \
	manpages/sharpd.rst \
	manpages/vtysh.rst \
	manpages/watchfrr.rst \
	manpages/zebra.rst \
	developer/bgpd.rst \
	developer/bgp-typecodes.rst \
	developer/building-frr-on-alpine.rst \
	developer/building-frr-on-centos6.rst \
	developer/building-frr-on-centos7.rst \
	developer/building-frr-on-debian8.rst \
	developer/building-frr-on-debian9.rst \
	developer/building-frr-on-fedora24.rst \
	developer/building-frr-on-freebsd10.rst \
	developer/building-frr-on-freebsd11.rst \
	developer/building-frr-on-freebsd9.rst \
	developer/building-frr-on-lede-openwrt.rst \
	developer/building-frr-on-netbsd6.rst \
	developer/building-frr-on-netbsd7.rst \
	developer/building-frr-on-omnios.rst \
	developer/building-frr-on-openbsd6.rst \
	developer/building-frr-on-ubuntu1204.rst \
	developer/building-frr-on-ubuntu1404.rst \
	developer/building-frr-on-ubuntu1604.rst \
	developer/building-frr-on-ubuntu1804.rst \
	developer/building.rst \
	developer/cli.rst \
	developer/conf.py \
	developer/draft-zebra-00.ms \
	developer/hooks.rst \
	developer/index.rst \
	developer/ldpd-basic-test-setup.md \
	developer/library.rst \
	developer/Makefile.in \
	developer/memtypes.rst \
	developer/modules.rst \
	developer/next-hop-tracking.rst \
	developer/ospf-api.rst \
	developer/ospf.rst \
	developer/ospf-sr.rst \
	developer/workflow.rst \
	developer/zebra.rst \
	user/babeld.rst \
	user/basic.rst \
	user/bgp.rst \
	user/bugs.rst \
	user/conf.py \
	user/eigrpd.rst \
	user/filter.rst \
	user/glossary.rst \
	user/index.rst \
	user/installation.rst \
	user/ipv6.rst \
	user/isisd.rst \
	user/kernel.rst \
	user/Makefile.am \
	user/nhrpd.rst \
	user/ospf6d.rst \
	user/ospfd.rst \
	user/ospf_fundamentals.rst \
	user/overview.rst \
	user/packet-dumps.rst \
	user/pim.rst \
	user/ripd.rst \
	user/pbr.rst \
	user/ripngd.rst \
	user/routemap.rst \
	user/routeserver.rst \
	user/rpki.rst \
	user/setup.rst \
	user/sharp.rst \
	user/snmp.rst \
	user/snmptrap.rst \
	user/Useful_Sysctl_Settings.md \
	user/vnc.rst \
	user/vtysh.rst \
	user/zebra.rst \
	mpls/ChangeLog.opaque.txt \
	mpls/ospfd.conf \
	mpls/cli_summary.txt \
	mpls/opaque_lsa.txt \
	figures/cligraph.png \
	figures/cligraph.svg \
	figures/fig-normal-processing.dia \
	figures/fig-normal-processing.png \
	figures/fig-normal-processing.txt \
	figures/fig-rs-processing.dia \
	figures/fig-rs-processing.png \
	figures/fig-rs-processing.txt \
	figures/fig_topologies_full.dia \
	figures/fig_topologies_full.png \
	figures/fig_topologies_full.txt \
	figures/fig_topologies_rs.dia \
	figures/fig_topologies_rs.png \
	figures/fig_topologies_rs.txt \
	figures/fig-vnc-commercial-route-reflector.dia \
	figures/fig-vnc-commercial-route-reflector.png \
	figures/fig-vnc-commercial-route-reflector.txt \
	figures/fig-vnc-frr-route-reflector.dia \
	figures/fig-vnc-frr-route-reflector.png \
	figures/fig-vnc-frr-route-reflector.txt \
	figures/fig-vnc-gw.dia \
	figures/fig-vnc-gw.png \
	figures/fig-vnc-gw-rr.dia \
	figures/fig-vnc-gw-rr.png \
	figures/fig-vnc-gw-rr.txt \
	figures/fig-vnc-gw.txt \
	figures/fig-vnc-mesh.dia \
	figures/fig-vnc-mesh.png \
	figures/fig-vnc-mesh.txt \
	figures/fig-vnc-redundant-route-reflectors.dia \
	figures/fig-vnc-redundant-route-reflectors.png \
	figures/fig-vnc-redundant-route-reflectors.txt \
	figures/frr-icon.svg \
	figures/frr-logo-icon.png \
	figures/frr-logo-medium.png \
	figures/frr-logo.png \
	figures/frr-logo-small.png \
	figures/git_branches.png \
	figures/git_branches.svg \
	figures/ospf_api_architecture.png \
	figures/ospf_api_msghdr.png \
	figures/ospf_api_msgs1.png \
	figures/ospf_api_msgs2.png \
	extra/frrlexer.py
