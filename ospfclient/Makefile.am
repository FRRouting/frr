## Automake.am for OSPF API client

INCLUDES = -I../lib -I../

lib_LIBRARIES = libospfapiclient.a
sbin_PROGRAMS = ospfclient

libospfapiclient_a_SOURCES = \
	ospf_apiclient.c

ospfapiheaderdir = $(includedir)/ospfapi

ospfapiheader_HEADERS = \
	ospf_apiclient.h

ospfclient_SOURCES = \
	ospfclient.c $(libospfapiclient_a_SOURCES)

ospfclient_LDADD = ../ospfd/libospf.a ../lib/libzebra.a


