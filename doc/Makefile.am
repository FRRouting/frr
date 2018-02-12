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

FRR.pdf:
	$(MAKE) -C user latexpdf

developer.pdf:
	$(MAKE) -C developer latexpdf

FRR.html:
	$(MAKE) -C user html

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
	manpages/Makefile
