## Process this file with automake to produce Makefile.in.

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib
DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600

noinst_LIBRARIES = libospf6.a
sbin_PROGRAMS = ospf6d

libospf6_a_SOURCES = \
	ospf6_dump.c ospf6d.c ospf6_interface.c ospf6_network.c \
	ospf6_neighbor.c ospf6_message.c ospf6_lsa.c ospf6_spf.c \
	ospf6_route.c ospf6_zebra.c ospf6_ism.c ospf6_dbex.c \
	ospf6_lsdb.c ospf6_prefix.c ospf6_top.c ospf6_area.c ospf6_nsm.c \
	ospf6_routemap.c ospf6_proto.c \
	ospf6_hook.c ospf6_asbr.c ospf6_bintree.c ospf6_linklist.c \
	ospf6_abr.c ospf6_intra.c ospf6_damp.c

noinst_HEADERS = \
	ospf6_area.h ospf6_dump.h ospf6_interface.h ospf6_lsa.h \
	ospf6_message.h ospf6_neighbor.h ospf6_network.h ospf6_proto.h \
	ospf6_spf.h ospf6_route.h ospf6_types.h ospf6_zebra.h ospf6d.h \
	ospf6_ism.h ospf6_dbex.h ospf6_lsdb.h ospf6_prefix.h \
	ospf6_top.h ospf6_nsm.h ospf6_routemap.h \
        ospf6_hook.h ospf6_asbr.h ospf6_bintree.h ospf6_linklist.h \
	ospf6_abr.h ospf6_intra.h ospf6_damp.h

ospf6d_SOURCES = \
	ospf6_main.c $(libospf6_a_SOURCES)

ospf6d_LDADD = ../lib/libzebra.a

sysconf_DATA = ospf6d.conf.sample

EXTRA_DIST = $(sysconf_DATA)

install-sysconfDATA: $(sysconf_DATA)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(sysconfdir)
	@list='$(sysconf_DATA)'; for p in $$list; do \
	  if test -f $(srcdir)/$$p; then \
	    echo " $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $(srcdir)/$$p $(DESTDIR)$(sysconfdir)/$$p; \
	  else if test -f $$p; then \
	    echo " $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p"; \
	    $(INSTALL_SDATA) $$p $(DESTDIR)$(sysconfdir)/$$p; \
	  fi; fi; \
	done
