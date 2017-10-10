include ../common.am

AM_CPPFLAGS = -I.. -I$(top_srcdir) -I$(top_srcdir)/lib -I$(top_builddir)/lib $(Q_PROTOBUF_C_CLIENT_INCLUDES)

PROTOBUF_INCLUDES=-I$(top_srcdir)
PROTOBUF_PACKAGE = qpb

if HAVE_PROTOBUF

lib_LTLIBRARIES = libfrr_pb.la
libfrr_pb_la_LDFLAGS = -version-info 0:0:0

protobuf_srcs =					\
	qpb_allocator.c

protobuf_srcs_nodist =				\
	qpb.pb-c.c
endif

libfrr_pb_la_SOURCES =			\
	linear_allocator.h			\
	qpb.h					\
	qpb.c					\
	qpb_allocator.h				\
	$(protobuf_srcs)

nodist_libfrr_pb_la_SOURCES = $(protobuf_srcs_nodist)

CLEANFILES = $(Q_CLEANFILES)
BUILT_SOURCES = $(Q_PROTOBUF_SRCS)
EXTRA_DIST = qpb.proto
