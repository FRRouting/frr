## Automake.am for OSPF API client

INCLUDES = -I../lib -I../

lib_LTLIBRARIES = libospfapiclient.la
sbin_PROGRAMS = ospfclient

libospfapiclient_la_SOURCES = \
	ospf_apiclient.c

ospfapiheaderdir = $(pkgincludedir)/ospfapi

ospfapiheader_HEADERS = \
	ospf_apiclient.h

ospfclient_SOURCES = \
	ospfclient.c

ospfclient_LDADD = libospfapiclient.la \
	-L../ospfd -lospf -L../lib -lzebra @LIBCAP@


