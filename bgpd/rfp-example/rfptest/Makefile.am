#
# This file has been modified by LabN Consulting, L.L.C.
#
#
## Process this file with automake to produce Makefile.in.

if ENABLE_BGP_VNC
BGP_VNC_RFAPI_INC=-I$(top_srcdir)/bgpd/rfapi
BGP_VNC_RFP_LIBDIR=../librfp
BGP_VNC_RFP_INCDIR=$(BGP_VNC_RFP_LIBDIR)
BGP_VNC_RFP_LIB=$(BGP_VNC_RFP_LIBDIR)/librfp.a
BGP_VNC_RFP_INC=-I$(BGP_VNC_RFP_INCDIR)

rfptest_SOURCES =  \
	rfptest.c 

rfptest_INCLUDES = \
	rfptest.h 


RFPTEST_BIN = rfptest

else
BGP_VNC_RFAPI_INC=
BGP_VNC_RFAPI_SRC=
BGP_VNC_RFP_LIB=
BGP_VNC_RFP_INC=
RFPTEST_BIN=
endif

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/lib \
	-I$(top_builddir) -I$(top_builddir)/lib \
	$(BGP_VNC_RFAPI_INC) $(BGP_VNC_RFP_INC)

DEFS = @DEFS@ -DSYSCONFDIR=\"$(sysconfdir)/\"
INSTALL_SDATA=@INSTALL@ -m 600


AM_CFLAGS = $(PICFLAGS)
AM_LDFLAGS = $(PILDFLAGS)


noinst_HEADERS = \
	$(rfptest_INCLUDES)

noinst_LIBRARIES = 
sbin_PROGRAMS = $(RFPTEST_BIN)

examplesdir = $(exampledir)
 
rfptest_LDADD = $(top_builddir)/lib/libfrr.la $(BGP_VNC_RFP_LIB)
dist_examples_DATA = 
