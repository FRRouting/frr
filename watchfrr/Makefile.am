## Process this file with Automake to create Makefile.in

AM_CPPFLAGS = -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib
AM_CFLAGS = $(WERROR)

sbin_PROGRAMS = watchfrr

noinst_HEADERS = watchfrr.h

watchfrr_SOURCES = watchfrr.c watchfrr_vty.c
watchfrr_LDADD = ../lib/libfrr.la @LIBCAP@
