## Automake.am for OSPF API client

INCLUDES = @INCLUDES@ -I.. -I$(top_srcdir) -I$(top_srcdir)/lib

lib_LTLIBRARIES = libospfapiclient.la
libospfapiclient_la_LDFLAGS = -version 0:0:0

sbin_PROGRAMS = ospfclient

libospfapiclient_la_SOURCES = \
	ospf_apiclient.c

ospfapiheaderdir = $(pkgincludedir)/ospfapi

ospfapiheader_HEADERS = \
	ospf_apiclient.h

ospfclient_SOURCES = \
	ospfclient.c

ospfclient_LDADD = libospfapiclient.la \
	../ospfd/libospf.la ../lib/libzebra.la @LIBCAP@

ospfclient_CFLAGS = $(AM_CFLAGS) $(PICFLAGS)
ospfclient_LDFLAGS = $(AM_LDFLAGS) $(PILDFLAGS)

