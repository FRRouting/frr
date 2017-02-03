## Automake.am for OSPF API client

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)

lib_LTLIBRARIES = libfrrospfapiclient.la
libfrrospfapiclient_la_LDFLAGS = -version-info 0:0:0
libfrrospfapiclient_la_LIBADD = ../ospfd/libfrrospf.la ../lib/libfrr.la

sbin_PROGRAMS = ospfclient

libfrrospfapiclient_la_SOURCES = \
	ospf_apiclient.c

ospfapiheaderdir = $(pkgincludedir)/ospfapi

ospfapiheader_HEADERS = \
	ospf_apiclient.h

ospfclient_SOURCES = \
	ospfclient.c

ospfclient_LDADD = libfrrospfapiclient.la \
	../ospfd/libfrrospf.la ../lib/libfrr.la @LIBCAP@

ospfclient_CFLAGS = $(AM_CFLAGS)
ospfclient_LDFLAGS = $(AM_LDFLAGS)
