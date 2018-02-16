## Process this file with automake to produce Makefile.in.

# Tell Automake to invoke 'make' in the manpages directory with argument 'man'
SUBDIRS = manpages
AM_MAKEFLAGS = man

MANPAGE_BUILDDIR = manpages/_build/man

# Once that is done these will all exist
man_MANS = $(MANPAGE_BUILDDIR)/frr.1

if PIMD
man_MANS += $(MANPAGE_BUILDDIR)/pimd.8
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

# handled by subdir target
man: ;

FRR.info:
	$(MAKE) -C user info

user.pdf:
	$(MAKE) -C user latexpdf

user.html:
	$(MAKE) -C user html

developer.pdf:
	$(MAKE) -C developer latexpdf

developer.html:
	$(MAKE) -C developer html

# include sources for shipped docs
EXTRA_DIST = manpages/defines.rst \
	manpages/ldpd.rst \
	manpages/index.rst \
	manpages/bgpd.rst \
	manpages/watchfrr.rst \
	manpages/ospfclient.rst \
	manpages/ripd.rst \
	manpages/zebra.rst \
	manpages/epilogue.rst \
	manpages/eigrpd.rst \
	manpages/isisd.rst \
	manpages/ospf6d.rst \
	manpages/common-options.rst \
	manpages/ospfd.rst \
	manpages/vtysh.rst \
	manpages/nhrpd.rst \
	manpages/pimd.rst \
	manpages/ripngd.rst \
	manpages/frr.rst \
	manpages/conf.py \
	manpages/Makefile \
	developer/Building_FRR_on_NetBSD7.rst \
	developer/ldpd-basic-test-setup.md \
	developer/cli.rst \
	developer/index.rst \
	developer/library.rst \
	developer/memtypes.rst \
	developer/bgpd.rst \
	developer/draft-zebra-00.ms \
	developer/dev-modules.md \
	developer/conf.py \
	developer/next-hop-tracking.rst \
	developer/Building_FRR_on_FreeBSD11.rst \
	developer/building.rst \
	developer/Building_FRR_on_CentOS6.rst \
	developer/Building_FRR_on_Ubuntu1604.rst \
	developer/ospf-api.rst \
	developer/ospf-sr.rst \
	developer/Building_FRR_on_OpenBSD6.rst \
	developer/Building_FRR_on_Debian8.rst \
	developer/Building_FRR_on_NetBSD6.rst \
	developer/Building_FRR_on_Debian9.rst \
	developer/Building_FRR_on_LEDE-OpenWRT.rst \
	developer/modules.rst \
	developer/Building_FRR_on_FreeBSD10.rst \
	developer/Building_FRR_on_Ubuntu1204.rst \
	developer/Building_FRR_on_Fedora24.rst \
	developer/Makefile \
	developer/Building_FRR_on_FreeBSD9.rst \
	developer/BGP-TypeCode \
	developer/Building_FRR_on_OmniOS.rst \
	developer/Building_FRR_on_CentOS7.rst \
	developer/hooks.rst \
	developer/OSPF-API.md \
	developer/workflow.rst \
	developer/Building_FRR_on_Ubuntu1404.rst \
	user/ospf_fundamentals.rst \
	user/routemap.rst \
	user/index.rst \
	user/conf.py \
	user/ipv6.rst \
	user/ripd.rst \
	user/vnc.rst \
	user/zebra.rst \
	user/installation.rst \
	user/overview.rst \
	user/protocol.rst \
	user/eigrpd.rst \
	user/rpki.rst \
	user/kernel.rst \
	user/isisd.rst \
	user/ospf6d.rst \
	user/Useful_Sysctl_Settings.md \
	user/basic.rst \
	user/ospfd.rst \
	user/vtysh.rst \
	user/filter.rst \
	user/nhrpd.rst \
	user/Makefile \
	user/routeserver.rst \
	user/appendix.rst \
	user/bgp.rst \
	user/babeld.rst \
	user/snmp.rst \
	user/pim.rst \
	user/ripngd.rst \
	user/snmptrap.rst \
	user/glossary.rst \
	mpls/ChangeLog.opaque.txt \
	mpls/ospfd.conf \
	mpls/cli_summary.txt \
	mpls/opaque_lsa.txt \
	figures/frr-logo.png \
	figures/fig-vnc-commercial-route-reflector.dia \
	figures/ospf_api_msghdr.png \
	figures/fig-normal-processing.txt \
	figures/fig-vnc-gw-rr.txt \
	figures/fig-vnc-mesh.dia \
	figures/frr-logo-medium.png \
	figures/git_branches.svg \
	figures/fig-vnc-commercial-route-reflector.txt \
	figures/fig_topologies_rs.txt \
	figures/git_branches.png \
	figures/fig-vnc-mesh.txt \
	figures/ospf_api_msgs1.png \
	figures/fig-vnc-redundant-route-reflectors.txt \
	figures/fig-vnc-commercial-route-reflector.png \
	figures/fig-vnc-gw.png \
	figures/fig_topologies_rs.png \
	figures/fig_topologies_full.txt \
	figures/fig-vnc-frr-route-reflector.txt \
	figures/fig-normal-processing.dia \
	figures/fig-vnc-redundant-route-reflectors.png \
	figures/fig-vnc-frr-route-reflector.dia \
	figures/fig_topologies_full.png \
	figures/fig-vnc-redundant-route-reflectors.dia \
	figures/fig-normal-processing.png \
	figures/fig-rs-processing.dia \
	figures/ospf_api_msgs2.png \
	figures/fig-vnc-gw.dia \
	figures/fig-rs-processing.txt \
	figures/frr-logo-icon.png \
	figures/ospf_api_architecture.png \
	figures/fig-vnc-gw.txt \
	figures/fig-rs-processing.png \
	figures/frr-icon.svg \
	figures/fig_topologies_rs.dia \
	figures/fig-vnc-frr-route-reflector.png \
	figures/fig-vnc-gw-rr.png \
	figures/fig-vnc-gw-rr.dia \
	figures/fig_topologies_full.dia \
	figures/frr-logo-small.png \
	figures/fig-vnc-mesh.png
