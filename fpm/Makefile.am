include ../common.am

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib $(Q_PROTOBUF_C_CLIENT_INCLUDES)

PROTOBUF_INCLUDES=-I$(top_srcdir)
PROTOBUF_PACKAGE = fpm

lib_LTLIBRARIES = libfpm_pb.la
libfpm_pb_la_LDFLAGS = -version-info 0:0:0

if HAVE_PROTOBUF
protobuf_srcs =

protobuf_srcs_nodist =				\
	fpm.pb-c.c
endif

libfpm_pb_la_SOURCES =				\
	fpm.h					\
	fpm_pb.h				\
	fpm_pb.c				\
	$(protobuf_srcs)

nodist_libfpm_pb_la_SOURCES = $(protobuf_srcs_nodist)

CLEANFILES = $(Q_CLEANFILES)

BUILT_SOURCES = $(Q_PROTOBUF_SRCS)
EXTRA_DIST = fpm.proto
