##
## Configure template file for FRRouting.
## autoconf will generate configure script.
##
##  Copyright (c) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
##  Portions Copyright (c) 2003 Paul Jakma <paul@dishone.st>
##
AC_PREREQ(2.60)

AC_INIT(frr, 3.0.2, [https://github.com/frrouting/frr/issues])
PACKAGE_URL="https://frrouting.org/"
PACKAGE_FULLNAME="FRRouting"
AC_SUBST(PACKAGE_FULLNAME)

CONFIG_ARGS="$ac_configure_args"
AC_SUBST(CONFIG_ARGS)

AC_CONFIG_SRCDIR(lib/zebra.h)
AC_CONFIG_MACRO_DIR([m4])

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_BUILD()
AC_CANONICAL_HOST()
AC_CANONICAL_TARGET()

# Disable portability warnings -- our automake code (in particular
# common.am) uses some constructs specific to gmake.
AM_INIT_AUTOMAKE([1.12 -Wno-portability])
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS(config.h)

AC_PATH_PROG(PERL, perl)
PKG_PROG_PKG_CONFIG

dnl default is to match previous behavior
exampledir=${sysconfdir}
AC_ARG_ENABLE([exampledir],
	  AS_HELP_STRING([--enable-exampledir],
			 [specify alternate directory for examples]),
			 exampledir="$enableval",)
dnl XXX add --exampledir to autoconf standard directory list somehow
AC_SUBST(exampledir)

dnl default is to match previous behavior
pkgsrcrcdir=""
pkgsrcdir=""
AC_ARG_ENABLE([pkgsrcrcdir],
	  AS_HELP_STRING([--enable-pkgsrcrcdir],
			 [specify directory for rc.d scripts]),
			 pkgsrcrcdir="$enableval"; pkgsrcdir="pkgsrc",)
dnl XXX add --pkgsrcrcdir to autoconf standard directory list somehow
AC_SUBST(pkgsrcdir)
AC_SUBST(pkgsrcrcdir)

AC_ARG_WITH([moduledir], [AS_HELP_STRING([--with-moduledir=DIR], [module directory (${libdir}/frr/modules)])], [
	moduledir="$withval"
], [
	moduledir="\${libdir}/frr/modules"
])
AC_SUBST([moduledir], [$moduledir])

AC_ARG_ENABLE(tcmalloc,
	AS_HELP_STRING([--enable-tcmalloc], [Turn on tcmalloc]),
[case "${enableval}" in
  yes) tcmalloc_enabled=true
LIBS="$LIBS -ltcmalloc_minimal"
 ;;
  no)  tcmalloc_enabled=false ;;
  *) AC_MSG_ERROR(bad value ${enableval} for --enable-tcmalloc) ;;
esac],[tcmalloc_enabled=false])


dnl --------------------
dnl Check CC and friends
dnl --------------------
dnl note orig_cflags is also used further down
orig_cflags="$CFLAGS"
AC_LANG([C])
AC_PROG_CC
AC_PROG_CPP
AM_PROG_CC_C_O
dnl remove autoconf default "-g -O2"
CFLAGS="$orig_cflags"
AC_PROG_CC_C99

AC_PROG_EGREP
PKG_PROG_PKG_CONFIG

dnl autoconf 2.59 appears not to support AC_PROG_SED
dnl AC_PROG_SED
AC_CHECK_PROG([SED],[sed],[sed],[/bin/false])

dnl try and enable CFLAGS that are useful for Quagga
dnl - specifically, options to control warnings

AC_USE_SYSTEM_EXTENSIONS()
AC_DEFUN([AC_C_FLAG], [{
	AC_LANG_PUSH(C)
	ac_c_flag_save="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	AC_MSG_CHECKING([[whether $CC supports $1]])
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([[]])],
		[
			AC_MSG_RESULT([yes])
			m4_if([$3], [], [], [
				CFLAGS="$ac_c_flag_save"
				$3
			])
		], [
			CFLAGS="$ac_c_flag_save"
			AC_MSG_RESULT([no])
			$2
		])
	AC_LANG_POP(C)
	}])

dnl ICC won't bail on unknown options without -diag-error 10006
dnl need to do this first so we get useful results for the other options
AC_C_FLAG([-diag-error 10006])

dnl if the user specified any CFLAGS, we don't add "-g -Os/-O2" here
if test "z$orig_cflags" = "z"; then
  AC_C_FLAG([-g])
  AC_C_FLAG([-Os], [
    AC_C_FLAG([-O2])
  ])
fi

dnl always want these CFLAGS
AC_C_FLAG([-fno-omit-frame-pointer])
AC_C_FLAG([-Wall])
AC_C_FLAG([-Wextra])
AC_C_FLAG([-Wmissing-prototypes])
AC_C_FLAG([-Wmissing-declarations])
AC_C_FLAG([-Wpointer-arith])
AC_C_FLAG([-Wbad-function-cast])
AC_C_FLAG([-Wwrite-strings])
if test x"${enable_gcc_ultra_verbose}" = x"yes" ; then
  AC_C_FLAG([-Wcast-qual])
  AC_C_FLAG([-Wstrict-prototypes])
  AC_C_FLAG([-Wmissing-noreturn])
  AC_C_FLAG([-Wmissing-format-attribute])
  AC_C_FLAG([-Wunreachable-code])
  AC_C_FLAG([-Wpacked])
  AC_C_FLAG([-Wpadded])
else
  AC_C_FLAG([-Wno-unused-result])
fi
AC_C_FLAG([-Wno-unused-parameter])
AC_C_FLAG([-Wno-missing-field-initializers])

dnl ICC emits a broken warning for const char *x = a ? "b" : "c";
dnl for some reason the string consts get 'promoted' to char *,
dnl triggering a const to non-const conversion warning.
AC_C_FLAG([-diag-disable 3179])

if test x"${enable_werror}" = x"yes" ; then
  WERROR="-Werror"
fi
AC_SUBST(WERROR)

dnl need link on this one, not compile
AC_LANG_PUSH(C)
ac_ld_flag_save="$LDFLAGS"
LDFLAGS="$LDFLAGS -rdynamic"
AC_MSG_CHECKING([[whether linker supports -rdynamic]])
AC_LINK_IFELSE(
	[AC_LANG_PROGRAM([[]])],
	[AC_MSG_RESULT([yes])],
	[
		LDFLAGS="$ac_ld_flag_save"
		AC_MSG_RESULT([no])
	])
AC_LANG_POP(C)

dnl --------------
dnl Check programs
dnl --------------
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_CHECK_TOOL(AR, ar)

dnl -----------------
dnl System extensions
dnl -----------------
AC_GNU_SOURCE

dnl -------
dnl libtool
dnl -------
LT_INIT

dnl ----------------------
dnl Packages configuration
dnl ----------------------
AC_ARG_WITH(pkg-extra-version,
	AS_HELP_STRING([--with-pkg-extra-version=VER], [add extra version field, for packagers/distributions]),
	[EXTRAVERSION=$withval],)
AC_ARG_WITH(pkg-git-version,
	AS_HELP_STRING([--with-pkg-git-version], [add git information to MOTD and build version string]),
	[ test "x$withval" != "xno" && with_pkg_git_version="yes" ])
AC_ARG_ENABLE(vtysh,
  AS_HELP_STRING([--disable-vtysh], [do not build integrated vty shell for Quagga]))
AC_ARG_ENABLE(doc,
  AS_HELP_STRING([--disable-doc], [do not build docs]))
AC_ARG_ENABLE(zebra,
  AS_HELP_STRING([--disable-zebra], [do not build zebra daemon]))
AC_ARG_ENABLE(bgpd,
  AS_HELP_STRING([--disable-bgpd], [do not build bgpd]))
AC_ARG_ENABLE(ripd,
  AS_HELP_STRING([--disable-ripd], [do not build ripd]))
AC_ARG_ENABLE(ripngd,
  AS_HELP_STRING([--disable-ripngd], [do not build ripngd]))
AC_ARG_ENABLE(ospfd,
  AS_HELP_STRING([--disable-ospfd], [do not build ospfd]))
AC_ARG_ENABLE(ospf6d,
  AS_HELP_STRING([--disable-ospf6d], [do not build ospf6d]))
AC_ARG_ENABLE(ldpd,
  AS_HELP_STRING([--enable-ldpd], [build ldpd]))
AC_ARG_ENABLE(nhrpd,
  AS_HELP_STRING([--disable-nhrpd], [do not build nhrpd]))
AC_ARG_ENABLE(watchfrr,
  AS_HELP_STRING([--disable-watchfrr], [do not build watchfrr]))
AC_ARG_ENABLE(isisd,
  AS_HELP_STRING([--disable-isisd], [do not build isisd]))
AC_ARG_ENABLE(pimd,
  AS_HELP_STRING([--disable-pimd], [do not build pimd]))
AC_ARG_ENABLE(bgp-announce,
  AS_HELP_STRING([--disable-bgp-announce,], [turn off BGP route announcement]))
AC_ARG_ENABLE(bgp-vnc,
  AS_HELP_STRING([--disable-bgp-vnc],[turn off BGP VNC support]))
AC_ARG_WITH(rfp-path,
  AS_HELP_STRING([--with-rfp-path[=DIR]],[path to replaced stub RFP used with BGP VNC]))
AC_ARG_ENABLE(snmp,
  AS_HELP_STRING([--enable-snmp=ARG], [enable SNMP support (smux or agentx)]))
AC_ARG_WITH(libpam,
  AS_HELP_STRING([--with-libpam], [use libpam for PAM support in vtysh]))
AC_ARG_ENABLE(ospfapi,
  AS_HELP_STRING([--disable-ospfapi], [do not build OSPFAPI to access the OSPF LSA Database]))
AC_ARG_ENABLE(ospfclient,
  AS_HELP_STRING([--disable-ospfclient], [do not build OSPFAPI client for OSPFAPI,
                          (this is the default if --disable-ospfapi is set)]))
AC_ARG_ENABLE(multipath,
  AS_HELP_STRING([--enable-multipath=ARG], [enable multipath function, ARG must be digit]))
AC_ARG_ENABLE(user,
  AS_HELP_STRING([--enable-user=USER], [user to run FRR suite as (default frr)]))
AC_ARG_ENABLE(group,
  AS_HELP_STRING([--enable-group=GROUP], [group to run FRR suite as (default frr)]))
AC_ARG_ENABLE(vty_group,
  AS_HELP_STRING([--enable-vty-group=ARG], [set vty sockets to have specified group as owner]))
AC_ARG_ENABLE(configfile_mask,
  AS_HELP_STRING([--enable-configfile-mask=ARG], [set mask for config files]))
AC_ARG_ENABLE(logfile_mask,
  AS_HELP_STRING([--enable-logfile-mask=ARG], [set mask for log files]))
AC_ARG_ENABLE(shell_access,
  AS_HELP_STRING([--enable-shell-access], [Allow users to access shell/telnet/ssh]))
AC_ARG_ENABLE(rtadv,
  AS_HELP_STRING([--disable-rtadv], [disable IPV6 router advertisement feature]))
AC_ARG_ENABLE(irdp,
  AS_HELP_STRING([--enable-irdp], [enable IRDP server support in zebra]))
AC_ARG_ENABLE(capabilities,
  AS_HELP_STRING([--disable-capabilities], [disable using POSIX capabilities]))
AC_ARG_ENABLE(rusage,
  AS_HELP_STRING([--disable-rusage], [disable using getrusage]))
AC_ARG_ENABLE(gcc_ultra_verbose,
  AS_HELP_STRING([--enable-gcc-ultra-verbose], [enable ultra verbose GCC warnings]))
AC_ARG_ENABLE(linux24_tcp_md5,
  AS_HELP_STRING([--enable-linux24-tcp-md5], [enable support for old, Linux-2.4 RFC2385 patch]))
AC_ARG_ENABLE(backtrace,
  AS_HELP_STRING([--disable-backtrace,], [disable crash backtraces (default autodetect)]))
AC_ARG_ENABLE(time-check,
  AS_HELP_STRING([--disable-time-check], [disable slow thread warning messages]))
AC_ARG_ENABLE(pcreposix,
  AS_HELP_STRING([--enable-pcreposix], [enable using PCRE Posix libs for regex functions]))
AC_ARG_ENABLE(fpm,
  AS_HELP_STRING([--enable-fpm], [enable Forwarding Plane Manager support]))
AC_ARG_ENABLE(systemd,
  AS_HELP_STRING([--enable-systemd], [enable Systemd support]))
AC_ARG_ENABLE(poll,
  AS_HELP_STRING([--enable-poll], [enable usage of Poll instead of select]))
AC_ARG_ENABLE(werror,
  AS_HELP_STRING([--enable-werror], [enable -Werror (recommended for developers only)]))
AC_ARG_ENABLE(cumulus,
  AS_HELP_STRING([--enable-cumulus], [enable Cumulus Switch Special Extensions]))
AC_ARG_ENABLE(rr-semantics,
  AS_HELP_STRING([--disable-rr-semantics], [disable the v6 Route Replace semantics]))
AC_ARG_ENABLE([protobuf],
  AS_HELP_STRING([--enable-protobuf], [Enable experimental protobuf support]))
AC_ARG_ENABLE([oldvpn_commands],
  AS_HELP_STRING([--enable-oldvpn-commands], [Keep old vpn commands]))

AC_CHECK_HEADERS(json-c/json.h)
AC_CHECK_LIB(json-c, json_object_get, LIBS="$LIBS -ljson-c")
if test $ac_cv_lib_json_c_json_object_get = no; then
  AC_CHECK_LIB(json, json_object_get, LIBS="$LIBS -ljson")
  if test $ac_cv_lib_json_json_object_get = no; then
      AC_MSG_ERROR([lib json is needed to compile])
  fi
fi

AC_ARG_ENABLE([dev_build],
    AS_HELP_STRING([--enable-dev-build], [build for development]))

if test x"${enable_time_check}" != x"no" ; then
  if test x"${enable_time_check}" = x"yes" -o x"${enable_time_check}" = x ; then
    AC_DEFINE(CONSUMED_TIME_CHECK,5000000,Consumed Time Check)
  else
    AC_DEFINE_UNQUOTED(CONSUMED_TIME_CHECK,$enable_time_check,Consumed Time Check)
  fi
fi

case "${enable_systemd}" in
  "no") ;;
  "yes")
  AC_CHECK_LIB(systemd, sd_notify, LIBS="$LIBS -lsystemd")
  if test $ac_cv_lib_systemd_sd_notify = no; then
    AC_MSG_ERROR([enable systemd has been specified but systemd development env not found on your system])
  else
    AC_DEFINE(HAVE_SYSTEMD,,Compile systemd support in)
  fi
  ;;
  "*") ;;
esac

if test "${enable_rr_semantics}" != "no" ; then
  AC_DEFINE(HAVE_V6_RR_SEMANTICS,, Compile in v6 Route Replacement Semantics)
fi

if test "${enable_poll}" = "yes" ; then
  AC_DEFINE(HAVE_POLL_CALL,,Compile systemd support in)
fi

dnl ----------
dnl MPLS check
dnl ----------
AC_MSG_CHECKING(whether this OS has MPLS stack)
case "$host" in
  *-linux*)
      MPLS_METHOD="zebra_mpls_netlink.o"
      AC_MSG_RESULT(Linux MPLS)
  ;;
  *-openbsd*)
      MPLS_METHOD="zebra_mpls_openbsd.o"
      AC_MSG_RESULT(OpenBSD MPLS)
  ;;
  *)
      MPLS_METHOD="zebra_mpls_null.o"
      AC_MSG_RESULT(Unsupported kernel)
  ;;
esac
AC_SUBST(MPLS_METHOD)

if test "${enable_cumulus}" = "yes" ; then
  AC_DEFINE(HAVE_CUMULUS,,Compile Special Cumulus Code in)
  DFLT_NAME="datacenter"
else
  DFLT_NAME="traditional"
fi
AC_SUBST(DFLT_NAME)
AC_DEFINE_UNQUOTED(DFLT_NAME,["$DFLT_NAME"], Name of the configuration default set)

if test "${enable_shell_access}" = "yes"; then
   AC_DEFINE(HAVE_SHELL_ACCESS,,Allow user to use ssh/telnet/bash)
fi

AM_CONDITIONAL([FPM], [test "x$enable_fpm" = "xyes"])

if test "x${enable_dev_build}" = "xyes"; then
   AC_DEFINE(DEV_BUILD,,Build for development)
fi
AM_CONDITIONAL([DEV_BUILD], [test "x$enable_dev_build" = "xyes"])

#
# Logic for protobuf support.
#
if test "$enable_protobuf" = "yes"; then
   have_protobuf=yes

   # Check for protoc-c
   AC_CHECK_PROG([PROTOC_C], [protoc-c], [protoc-c], [/bin/false])
   if test "x$PROTOC_C" = "x/bin/false"; then
      have_protobuf=no
   else
      found_protobuf_c=no
      PKG_CHECK_MODULES([PROTOBUF_C], libprotobuf-c >= 0.14,
                     [found_protobuf_c=yes],
                     [AC_MSG_RESULT([pkg-config did not find libprotobuf-c])])

      if test "x$found_protobuf_c" = "xyes"; then
         LDFLAGS="$LDFLAGS $PROTOBUF_C_LIBS"
         CFLAGS="$CFLAGS $PROTOBUF_C_CFLAGS"
      else
        AC_CHECK_HEADER([google/protobuf-c/protobuf-c.h], [],
                        [have_protobuf=no; AC_MSG_RESULT([Couldn't find google/protobuf-c.h])])
      fi
   fi
fi

#
# Logic for old vpn commans support.
#
if test "$enable_oldvpn_commands" = "yes"; then
   AC_DEFINE(KEEP_OLD_VPN_COMMANDS,, [Define for compiling with old vpn commands])
fi

# Fail if the user explicity enabled protobuf support and we couldn't
# find the compiler or libraries.
if test "x$have_protobuf" = "xno" && test "x$enable_protobuf" = "xyes"; then
   AC_MSG_ERROR([Protobuf enabled explicitly but can't find libraries/tools])
fi

if test "x$have_protobuf" = "xyes"; then
   AC_DEFINE(HAVE_PROTOBUF,, protobuf)
fi

AM_CONDITIONAL([HAVE_PROTOBUF], [test "x$have_protobuf" = "xyes"])

#
# End of logic for protobuf support.
#

if test "${enable_linux24_tcp_md5}" = "yes"; then
  AC_DEFINE(HAVE_TCP_MD5_LINUX24,,Old Linux 2.4 TCP MD5 Signature Patch)
fi

AC_MSG_CHECKING(if zebra should be configurable to send Route Advertisements)
if test "${enable_rtadv}" != "no"; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_RTADV,,Enable IPv6 Routing Advertisement support)
else
  AC_MSG_RESULT(no)
fi

if test "${enable_irdp}" = "yes"; then
  AC_DEFINE(HAVE_IRDP,, IRDP )
fi

if test x"${enable_user}" = x"no"; then
  enable_user=""
else
  if test x"${enable_user}" = x"yes" || test x"${enable_user}" = x""; then
    enable_user="frr"
  fi
  AC_DEFINE_UNQUOTED(FRR_USER, "${enable_user}", frr User)
fi

if test x"${enable_group}" = x"no"; then
  enable_group=""
else
  if test x"${enable_group}" = x"yes" || test x"${enable_group}" = x""; then
    enable_group="frr"
  fi
  AC_DEFINE_UNQUOTED(FRR_GROUP, "${enable_group}", frr Group)
fi

if test x"${enable_vty_group}" = x"yes" ; then
  AC_MSG_ERROR([--enable-vty-group requires a group as argument, not yes])
elif test x"${enable_vty_group}" != x""; then
  if test x"${enable_vty_group}" != x"no"; then
    AC_DEFINE_UNQUOTED(VTY_GROUP, "${enable_vty_group}", VTY Sockets Group)
  fi
fi
AC_SUBST([enable_user])
AC_SUBST([enable_group])
AC_SUBST([enable_vty_group])

enable_configfile_mask=${enable_configfile_mask:-0600}
AC_DEFINE_UNQUOTED(CONFIGFILE_MASK, ${enable_configfile_mask}, Mask for config files)

enable_logfile_mask=${enable_logfile_mask:-0600}
AC_DEFINE_UNQUOTED(LOGFILE_MASK, ${enable_logfile_mask}, Mask for log files)

MPATH_NUM=1

case "${enable_multipath}" in
  0)
    MPATH_NUM=64
    ;;
  [[1-9]|[1-9][0-9]|[1-9][0-9][0-9]])
    MPATH_NUM="${enable_multipath}"
    ;;
  "")
    ;;
  *)           
    AC_MSG_FAILURE([Please specify digit to enable multipath ARG])
    ;;
esac

AC_DEFINE_UNQUOTED(MULTIPATH_NUM, $MPATH_NUM, Maximum number of paths for a route)

dnl -----------------------------------
dnl Add extra version string to package
dnl name, string and version fields.
dnl -----------------------------------
if test "x${EXTRAVERSION}" != "x" ; then
  VERSION="${VERSION}${EXTRAVERSION}"
  PACKAGE_VERSION="${PACKAGE_VERSION}${EXTRAVERSION}"
  AC_SUBST(PACKAGE_EXTRAVERSION, ["${EXTRAVERSION}"])
  PACKAGE_STRING="${PACKAGE_STRING}${EXTRAVERSION}"
fi

if test "x$with_pkg_git_version" = "xyes"; then
	if test -d "${srcdir}/.git"; then
		AC_DEFINE(GIT_VERSION, [1], [include git version info])
	else	with_pkg_git_version="no"
		AC_MSG_WARN([--with-pkg-git-version given, but this is not a git checkout])
	fi
fi
AM_CONDITIONAL([GIT_VERSION], [test "x$with_pkg_git_version" = "xyes"])

dnl ------------------------------------
dnl Check C keywords and standard  types
dnl ------------------------------------
AC_C_CONST
AC_C_INLINE
AC_C_VOLATILE
AC_HEADER_STDC
dnl AC_TYPE_PID_T
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

dnl -------------------------
dnl Check other header files.
dnl -------------------------
AC_CHECK_HEADERS([stropts.h sys/ksym.h \
	linux/version.h asm/types.h \
	sys/cdefs.h])

dnl Utility macro to avoid retyping includes all the time
m4_define([FRR_INCLUDES],
[#ifdef SUNOS_5
#define _XPG4_2
#define __EXTENSIONS__
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/types.h>
/* sys/conf.h depends on param.h on FBSD at least */
#include <sys/param.h>
/* Required for MAXSIG */
#include <signal.h>
#include <sys/socket.h>
#ifdef __APPLE__
# define __APPLE_USE_RFC_3542
#endif
#include <netinet/in.h>
#include <sys/time.h>
#include <time.h>
#include <net/if.h>
])dnl

dnl Same applies for HAVE_NET_IF_VAR_H, which HAVE_NETINET6_ND6_H and
dnl HAVE_NETINET_IN_VAR_H depend upon. But if_var.h depends on if.h, hence
dnl an additional round for it.

AC_CHECK_HEADERS([net/if_var.h], [], [], FRR_INCLUDES)

m4_define([FRR_INCLUDES],
FRR_INCLUDES
[#if HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif
])dnl

AC_CHECK_HEADERS([netinet/in_var.h \
	net/if_dl.h net/netopt.h \
	inet/nd.h netinet/ip_icmp.h \
	sys/sysctl.h sys/sockio.h kvm.h sys/conf.h],
	[], [], FRR_INCLUDES)

AC_CHECK_HEADERS([ucontext.h], [], [],
[#ifndef __USE_GNU
#define __USE_GNU
#endif /* __USE_GNU */
FRR_INCLUDES
])

m4_define([UCONTEXT_INCLUDES],
[#include <ucontext.h>])dnl

AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.uc_regs],
  [], [], [UCONTEXT_INCLUDES])
AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.regs],
  [AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.regs.nip],
   [], [], [UCONTEXT_INCLUDES])],
  [], [UCONTEXT_INCLUDES])
AC_CHECK_MEMBERS([ucontext_t.uc_mcontext.gregs],
  [], [], [UCONTEXT_INCLUDES])

m4_define([FRR_INCLUDES],
FRR_INCLUDES
[
#include <sys/un.h>
#include <netinet/in_systm.h>
#if HAVE_NETINET_IN_VAR_H
# include <netinet/in_var.h>
#endif
#if HAVE_NET_IF_DL_H
# include <net/if_dl.h>
#endif
#if HAVE_NET_NETOPT_H
# include <net/netopt.h>
#endif
#include <net/route.h>
#if HAVE_INET_ND_H
# include <inet/nd.h>
#endif
#include <arpa/inet.h>
/* Required for IDRP */
#if HAVE_NETINET_IP_ICMP_H
# include <netinet/ip_icmp.h>
#endif
])dnl

dnl V6 headers are checked below, after we check for v6

dnl Some systems (Solaris 2.x) require libnsl (Network Services Library)
case "$host" in
  [*-sunos5.[6-7]*] | [*-solaris2.[6-7]*])
      opsys=sol2-6
      AC_DEFINE(SUNOS_56, 1, SunOS 5.6 to 5.7)
      AC_DEFINE(SUNOS_5, 1, SunOS 5)
      AC_CHECK_LIB(xnet, main)
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  [*-sunos5.[8-9]] \
  | [*-sunos5.1[0-9]] \
  | [*-sunos5.1[0-9].[0-9]] \
  | [*-solaris2.[8-9]] \
  | [*-solaris2.1[0-9]] \
  | [*-solaris2.1[0-9].[0-9]])
      opsys=sol8
      AC_DEFINE(SUNOS_59, 1, [SunOS 5.8 up])
      AC_DEFINE(SUNOS_5, 1, [SunOS 5])
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      AC_CHECK_LIB(umem, main)
      AC_CHECK_FUNCS([printstack],
      	[AC_DEFINE([HAVE_PRINTSTACK],1,[Solaris printstack])
      	 AC_DEFINE([HAVE_STACK_TRACE],1,[Stack symbols decode functionality])
      	])
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  *-sunos5* | *-solaris2*)
      AC_DEFINE(SUNOS_5,,SunOS 5, Unknown SunOS)
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      CURSES=-lcurses
      SOLARIS="solaris"
  ;;
  *-linux*)
      opsys=gnu-linux
      AC_DEFINE(GNU_LINUX,,GNU Linux)
  ;;
  *-openbsd*)
      opsys=openbsd
      AC_DEFINE(OPEN_BSD,,OpenBSD)
  ;;
esac

AC_SYS_LARGEFILE

dnl ---------------------
dnl Integrated VTY option
dnl ---------------------
case "${enable_vtysh}" in
  "no") VTYSH="";;
  *)    VTYSH="vtysh";
         AC_DEFINE(VTYSH,,VTY shell)
dnl	 Vtysh uses libreadline, which looks for termcap functions at
dnl	 configure time.  We follow readlines search order.
dnl	 The required procedures are in libtermcap on NetBSD, in
dnl	 [TODO] on Linux, and in [TODO] on Solaris.
	 AC_CHECK_LIB(termcap, tputs, LIBREADLINE="$LIBREADLINE -ltermcap",
	   [AC_CHECK_LIB(tinfo, tputs, LIBREADLINE="$LIBREADLINE -ltinfo",
	     [AC_CHECK_LIB(curses, tputs, LIBREADLINE="$LIBREADLINE -lcurses",
	       [AC_CHECK_LIB(ncurses, tputs, 
	                     LIBREADLINE="$LIBREADLINE -lncurses")]
	      )]
	    )]
	  )
         AC_CHECK_LIB(readline, main, LIBREADLINE="-lreadline $LIBREADLINE",,
                      "$LIBREADLINE")
         if test $ac_cv_lib_readline_main = no; then
           AC_MSG_ERROR([vtysh needs libreadline but was not found and usable on your system.])
         fi
	 AC_CHECK_HEADER(readline/history.h)
	 if test $ac_cv_header_readline_history_h = no;then
           AC_MSG_ERROR([readline is too old to have readline/history.h, please update to the latest readline library.])
	 fi
	 AC_CHECK_LIB(readline, rl_completion_matches, 
	              LIBREADLINE="$LIBREADLINE",, "$LIBREADLINE")
         if test $ac_cv_lib_readline_rl_completion_matches = no; then
           AC_DEFINE(rl_completion_matches,completion_matches,Old readline)
	 fi
	 ;;
esac
AC_SUBST(LIBREADLINE)
AM_CONDITIONAL(VTYSH, test "x$VTYSH" = "xvtysh")

dnl ----------
dnl PAM module
dnl
dnl Quagga detects the PAM library it is built against by checking for a
dnl functional pam_misc.h (Linux-PAM) or openpam.h (OpenPAM) header. pam_misc.h
dnl is known to #include pam_appl.h, the standard header of a PAM library, and
dnl openpam.h doesn't do that, although depends on the header too. Hence a
dnl little assistance to AC_CHECK_HEADER is necessary for the proper detection
dnl of OpenPAM.
dnl ----------
if test "$with_libpam" = "yes"; then
  AC_CHECK_HEADER([security/pam_misc.h],
    [AC_DEFINE(HAVE_PAM_MISC_H,,Have pam_misc.h)
     AC_DEFINE(PAM_CONV_FUNC,misc_conv,Have misc_conv)
     pam_conv_func="misc_conv"
    ],
    [], FRR_INCLUDES)
  AC_CHECK_HEADER([security/openpam.h],
    [AC_DEFINE(HAVE_OPENPAM_H,,Have openpam.h)
     AC_DEFINE(PAM_CONV_FUNC,openpam_ttyconv,Have openpam_ttyconv)
     pam_conv_func="openpam_ttyconv"
    ],
    [], FRR_INCLUDES[#include <security/pam_appl.h>])
  if test -z "$ac_cv_header_security_pam_misc_h$ac_cv_header_security_openpam_h" ; then
    AC_MSG_WARN([*** pam support will not be built ***])
    with_libpam="no"
  fi
fi

if test "$with_libpam" = "yes"; then
dnl took this test from proftpds configure.in and suited to our needs
dnl -------------------------------------------------------------------------
dnl
dnl This next check looks funky due to a linker problem with some versions
dnl of the PAM library.  Prior to 0.72 release, the Linux PAM shared library
dnl omitted requiring libdl linking information. PAM-0.72 or better ships
dnl with RedHat 6.2 and Debian 2.2 or better.
AC_CHECK_LIB(pam, pam_start,
  [AC_CHECK_LIB(pam, $pam_conv_func,
    [AC_DEFINE(USE_PAM,,Use PAM for authentication)
     LIBPAM="-lpam"],
    [AC_DEFINE(USE_PAM,,Use PAM for authentication)
     LIBPAM="-lpam -lpam_misc"]
    )
  ],

  [AC_CHECK_LIB(pam, pam_end,
    [AC_CHECK_LIB(pam, $pam_conv_func,
      [AC_DEFINE(USE_PAM,,Use PAM for authentication)
       LIBPAM="-lpam -ldl"],
      [AC_DEFINE(USE_PAM,,Use PAM for authentication)
       LIBPAM="-lpam -ldl -lpam_misc"]
     )
  ],AC_MSG_WARN([*** pam support will not be built ***]),
  [-ldl])
  ]
)
fi
AC_SUBST(LIBPAM)

dnl -------------------------------
dnl Endian-ness check
dnl -------------------------------
AC_WORDS_BIGENDIAN

dnl -------------------------------
dnl check the size in byte of the C
dnl -------------------------------
dnl AC_CHECK_SIZEOF(char)
dnl AC_CHECK_SIZEOF(int)
dnl AC_CHECK_SIZEOF(short)
dnl AC_CHECK_SIZEOF(long)

dnl ----------------------------
dnl check existance of functions
dnl ----------------------------
AC_FUNC_FNMATCH
AC_FUNC_FORK
AC_FUNC_MKTIME
AC_FUNC_STAT

dnl -------------------------------
dnl bgpd needs pow() and hence libm
dnl -------------------------------
TMPLIBS="$LIBS"
AC_CHECK_HEADER([math.h],
  [AC_CHECK_LIB([m], [pow],
    [LIBM="-lm"
     LIBS="$LIBS $LIBM"
     AC_CHECK_FUNCS(pow,[],[LIBM=""])
    ])
])
if test x"$LIBM" = x ; then
  AC_MSG_WARN([Unable to find working pow function - bgpd may not link])
fi
LIBS="$TMPLIBS"
AC_SUBST(LIBM)

dnl ---------------
dnl other functions
dnl ---------------
AC_CHECK_FUNCS([ \
	strlcat strlcpy \
	getgrouplist])

AC_CHECK_HEADER([asm-generic/unistd.h],
                [AC_CHECK_DECL(__NR_setns,
                               AC_DEFINE(HAVE_NETNS,, Have netns),,
                               FRR_INCLUDES [#include <asm-generic/unistd.h>
                               ])
                 AC_CHECK_FUNCS(setns)]
               )

dnl ------------------------------------
dnl Determine routing get and set method
dnl ------------------------------------
AC_MSG_CHECKING(zebra between kernel interface method)
if test x"$opsys" = x"gnu-linux"; then
  AC_MSG_RESULT(netlink)
  RT_METHOD=rt_netlink.o
  KERNEL_METHOD=kernel_netlink.o
  AC_DEFINE(HAVE_NETLINK,,netlink)
  netlink=yes
  AC_CHECK_DECLS([IFLA_INFO_SLAVE_KIND], [], [], [#include <linux/if_link.h>])
else
  AC_MSG_RESULT(Route socket)
  KERNEL_METHOD="kernel_socket.o"
  RT_METHOD="rt_socket.o"
fi
AC_SUBST(RT_METHOD)
AC_SUBST(KERNEL_METHOD)
AM_CONDITIONAL([HAVE_NETLINK], [test "x$netlink" = "xyes"])

dnl --------------------------
dnl Determine IS-IS I/O method
dnl --------------------------
AC_DEFINE(ISIS_METHOD_PFPACKET,	1, [ constant value for isis method pfpacket ])
AC_DEFINE(ISIS_METHOD_DLPI,	2, [ constant value for isis method dlpi ])
AC_DEFINE(ISIS_METHOD_BPF,	3, [ constant value for isis method bpf ])
AC_CHECK_HEADER(net/bpf.h)
AC_CHECK_HEADER(sys/dlpi.h)
AC_MSG_CHECKING(zebra IS-IS I/O method)
if test x"$opsys" = x"gnu-linux"; then
  AC_MSG_RESULT(pfpacket)
  ISIS_METHOD_MACRO="ISIS_METHOD_PFPACKET"
elif test x"$opsys" = x"sol2-6" -o x"$opsys" = x"sol8"; then
  AC_MSG_RESULT(DLPI)
  ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
else
  if test $ac_cv_header_net_bpf_h = no; then
    if test $ac_cv_header_sys_dlpi_h = no; then
      AC_MSG_RESULT(none)
      AC_MSG_WARN([*** IS-IS support will not be built ***])
      ISISD=""
    else
      AC_MSG_RESULT(DLPI)
    fi
    ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
  else
    AC_MSG_RESULT(BPF)
    ISIS_METHOD_MACRO="ISIS_METHOD_BPF"
  fi
fi
AC_DEFINE_UNQUOTED(ISIS_METHOD, $ISIS_METHOD_MACRO, [ selected method for isis, == one of the constants ])

dnl ------------------------------------
dnl check for broken CMSG_FIRSTHDR macro
dnl ------------------------------------
AC_MSG_CHECKING(for broken CMSG_FIRSTHDR)
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#ifdef SUNOS_5
#define _XPG4_2
#define __EXTENSIONS__
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>

main()
{
  struct msghdr msg;
  char buf[4];

  msg.msg_control = buf;
  msg.msg_controllen = 0;

  if (CMSG_FIRSTHDR(&msg) != NULL)
    exit(0);
  exit (1);
}]])],[AC_MSG_RESULT(yes - using workaround) AC_DEFINE(HAVE_BROKEN_CMSG_FIRSTHDR,,Broken CMSG_FIRSTHDR)],
[AC_MSG_RESULT(no)],[AC_MSG_RESULT(no)])

dnl ------------------------------
dnl check kernel route read method
dnl ------------------------------
AC_CACHE_CHECK([route read method], [frr_cv_rtread_method],
[if test "x$netlink" = xyes; then
  frr_cv_rtread_method="netlink"
else
for frr_cv_rtread_method in /dev/ip /dev/null;
do
  test x`ls $frr_cv_rtread_method 2>/dev/null` = x"$frr_cv_rtread_method" && break
done
case $frr_cv_rtread_method in
  "/dev/ip")
                     case "$host" in
                       *-freebsd*)    frr_cv_rtread_method="sysctl";;
                       *)             frr_cv_rtread_method="getmsg";;
                     esac;;
	*)
                     frr_cv_rtread_method="sysctl";;
esac
fi])
RTREAD_METHOD=rtread_${frr_cv_rtread_method}.o
AC_SUBST(RTREAD_METHOD)

dnl -----------------------------
dnl check interface lookup method
dnl -----------------------------
IOCTL_METHOD=ioctl.o
AC_MSG_CHECKING(interface looking up method)
if test "$netlink" = yes; then
  AC_MSG_RESULT(netlink)
  IF_METHOD=if_netlink.o
elif test "$opsys" = "sol2-6";then
  AC_MSG_RESULT(Solaris GIF)
  IF_METHOD=if_ioctl.o
elif test "$opsys" = "sol8";then
  AC_MSG_RESULT(Solaris GLIF)
  IF_METHOD=if_ioctl_solaris.o
  IOCTL_METHOD=ioctl_solaris.o
elif test "$opsys" = "openbsd";then
  AC_MSG_RESULT(openbsd)
  IF_METHOD=if_ioctl.o
elif grep NET_RT_IFLIST /usr/include/sys/socket.h >/dev/null 2>&1; then
  AC_MSG_RESULT(sysctl)
    IF_METHOD=if_sysctl.o
    AC_DEFINE(HAVE_NET_RT_IFLIST,,NET_RT_IFLIST)
else
    AC_MSG_RESULT(ioctl)
    IF_METHOD=if_ioctl.o
fi
AC_SUBST(IF_METHOD)
AC_SUBST(IOCTL_METHOD)

dnl ---------------------------------------------------------------
dnl figure out how to specify an interface in multicast sockets API
dnl ---------------------------------------------------------------
AC_CHECK_MEMBERS([struct ip_mreqn.imr_ifindex], [], [], FRR_INCLUDES)

AC_CHECK_HEADERS([linux/mroute.h], [], [],[
	#include <sys/socket.h>
	#include <netinet/in.h>
	#define _LINUX_IN_H             /* For Linux <= 2.6.25 */
	#include <linux/types.h>
])

m4_define([FRR_INCLUDES],
FRR_INCLUDES
[#if HAVE_LINUX_MROUTE_H
# include <linux/mroute.h>
#endif
])dnl

AC_CHECK_HEADERS([netinet/ip_mroute.h], [], [],[
	#include <sys/socket.h>
	#include <sys/types.h>
	#include <netinet/in.h>
	#include <net/route.h>
])

m4_define([FRR_INCLUDES],
FRR_INCLUDES
[#if HAVE_NETINET_IP_MROUTE_H
# include <netinet/ip_mroute.h>
#endif
])dnl

AC_MSG_CHECKING([for BSD struct ip_mreq hack])
AC_TRY_COMPILE([#include <sys/param.h>],
[#if (defined(__FreeBSD__) && ((__FreeBSD_version >= 500022 && __FreeBSD_version < 700000) || (__FreeBSD_version < 500000 && __FreeBSD_version >= 440000))) || (defined(__NetBSD__) && defined(__NetBSD_Version__) && __NetBSD_Version__ >= 106010000) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__DragonFly__) || defined(__sun)
  return (0);
#else
  #error No support for BSD struct ip_mreq hack detected
#endif],[AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_BSD_STRUCT_IP_MREQ_HACK,,[Can pass ifindex in struct ip_mreq])],
AC_MSG_RESULT(no))

AC_MSG_CHECKING([for RFC3678 protocol-independed API])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>
], [struct group_req gr; int sock; setsockopt(sock, IPPROTO_IP, MCAST_JOIN_GROUP, (void*)&gr, sizeof(gr));
], [AC_MSG_RESULT(yes)
AC_DEFINE(HAVE_RFC3678,1,[Have RFC3678 protocol-independed API])],
AC_MSG_RESULT(no))

dnl ---------------------------------------------------------------
dnl figure out how to check link-state
dnl ---------------------------------------------------------------
AC_CHECK_HEADER( [net/if_media.h],
  [m4_define([LINK_DETECT_INCLUDES],
    FRR_INCLUDES
    [#include <net/if_media.h>
  ])
  AC_CHECK_MEMBERS( [struct ifmediareq.ifm_status],
    AC_DEFINE(HAVE_BSD_LINK_DETECT,,[BSD link-detect]),
    [], LINK_DETECT_INCLUDES)], 
  [],
  FRR_INCLUDES)

dnl ---------------------------------------------------------------
dnl Additional, newer way to check link-state using ifi_link_state.
dnl Not available in all BSD's when ifmediareq available
dnl ---------------------------------------------------------------
AC_CHECK_MEMBERS([struct if_data.ifi_link_state],
  AC_DEFINE(HAVE_BSD_IFI_LINK_STATE,,[BSD ifi_link_state available]),
  [], FRR_INCLUDES)

dnl ------------------------
dnl TCP_MD5SIG socket option
dnl ------------------------

AC_CHECK_HEADER([netinet/tcp.h], 
   [m4_define([MD5_INCLUDES],
      FRR_INCLUDES
      [#include <netinet/tcp.h>
    ])
    AC_CHECK_DECLS([TCP_MD5SIG], [], [], MD5_INCLUDES)],
   [],
   FRR_INCLUDES)
if test $ac_cv_have_decl_TCP_MD5SIG = no; then
  AC_CHECK_HEADER([linux/tcp.h],
       [m4_define([MD5_INCLUDES],
          FRR_INCLUDES
          [#include <linux/tcp.h>
        ])
       AC_CHECK_DECLS([TCP_MD5SIG], [], [], MD5_INCLUDES)])
fi

dnl -----------------------------
dnl check ipforward detect method
dnl -----------------------------
AC_CACHE_CHECK([ipforward method], [frr_cv_ipforward_method],
[if test x$cross_compiling = xyes; then
  if test x"$opsys" = x"gnu-linux"; then
    frr_cv_ipforward_method=/proc/net/snmp
  else
    frr_cv_ipforward_method=/dev/ip
  fi
else
  for frr_cv_ipforward_method in /proc/net/snmp /dev/ip /dev/null;
  do
    test x`ls $frr_cv_ipforward_method 2>/dev/null` = x"$frr_cv_ipforward_method" && break
  done
fi
case $frr_cv_ipforward_method in
  "/proc/net/snmp")  frr_cv_ipforward_method="proc";;
  "/dev/ip")         
                     case "$host" in
                       *-freebsd*)    frr_cv_ipforward_method="sysctl";;
                       *)             frr_cv_ipforward_method="solaris";;
                     esac;;
  *)                 frr_cv_ipforward_method="sysctl";;
esac])
IPFORWARD=ipforward_${frr_cv_ipforward_method}.o
AC_SUBST(IPFORWARD)

dnl ----------------------------------------------------------------------------
dnl figure out if domainname is available in the utsname struct (GNU extension).
dnl ----------------------------------------------------------------------------
AC_CHECK_MEMBERS([struct utsname.domainname], [], [], [#include <sys/utsname.h>])

dnl ----------
dnl IPv6 check
dnl ----------
AC_MSG_CHECKING(whether does this OS have IPv6 stack)
dnl ---------
dnl KAME IPv6
dnl ---------
  if grep WIDE /usr/include/netinet6/in6.h >/dev/null 2>&1; then
    AC_DEFINE(KAME,1,KAME IPv6)
    AC_MSG_RESULT(KAME)
dnl ------------------------------------
dnl Solaris 9, 10 and potentially higher
dnl ------------------------------------
  elif test x"$opsys" = x"sol8"; then
    AC_DEFINE(SOLARIS_IPV6, 1, Solaris IPv6)
    AC_MSG_RESULT(Solaris IPv6)
dnl ----------
dnl Linux IPv6
dnl ----------
  elif test x"$opsys" = x"gnu-linux"; then
    AC_DEFINE(LINUX_IPV6,1,Linux IPv6 stack)
    dnl Linux has a compilation problem with mixing
    dnl netinet/in.h and linux/in6.h they are not
    dnl compatible.  There has been discussion on
    dnl how to fix it but no real progress on implementation
    dnl when they fix it, remove this
    AC_DEFINE(IPV6_MINHOPCOUNT, 73, Linux ipv6 Min Hop Count)
    AC_MSG_RESULT(Linux IPv6)
  else
    AC_MSG_ERROR([Failed to detect IPv6 stack])
  fi

dnl ------------------
dnl IPv6 header checks
dnl ------------------
AC_CHECK_HEADERS([netinet6/in6.h netinet/in6_var.h \
	netinet6/in6_var.h netinet6/nd6.h], [], [],
	FRR_INCLUDES)

m4_define([FRR_INCLUDES],dnl
FRR_INCLUDES
[#if HAVE_NETINET6_IN6_H
#include <netinet6/in6.h>
#endif
#if HAVE_NETINET_IN6_VAR_H
#include <netinet/in6_var.h>
#endif
#include <netinet/icmp6.h>
#if HAVE_NETINET6_IN6_VAR_H
# include <netinet6/in6_var.h>
#endif
#if HAVE_NETINET6_ND6_H
# include <netinet6/nd6.h>
#endif
])dnl

dnl disable doc check
if test "${enable_doc}" = "no";then
  DOC=""
else
  DOC="doc"
fi

dnl --------------------
dnl Daemon disable check
dnl --------------------
if test "${enable_zebra}" = "no";then
  ZEBRA=""
else
  ZEBRA="zebra"
fi
AM_CONDITIONAL(ZEBRA, test "x$ZEBRA" = "xzebra")

if test "${enable_bgpd}" = "no";then
  BGPD=""
else
  BGPD="bgpd"
fi
AM_CONDITIONAL(BGPD, test "x$BGPD" = "xbgpd")

if test "${enable_ripd}" = "no";then
  RIPD=""
else
  RIPD="ripd"
fi
AM_CONDITIONAL(RIPD, test "x$RIPD" = "xripd")

if test "${enable_ospfd}" = "no";then
  OSPFD=""
else
  OSPFD="ospfd"
fi
AM_CONDITIONAL(OSPFD, test "x$OSPFD" = "xospfd")

if test "${enable_ldpd}" = "no";then
  LDPD=""
else
  AX_PROG_PERL_MODULES(XML::LibXML, , [
    if test -f "${srcdir}/ldpd/ldp_vty_cmds.c"; then
      AC_MSG_WARN([XML::LibXML perl module not found, using pregenerated ldp_vty_cmds.c])
    else
      AC_MSG_ERROR([XML::LibXML perl module not found and pregenerated ldp_vty_cmds.c missing])
    fi
  ])

  LDPD="ldpd"
  AC_DEFINE(HAVE_LDPD, 1, ldpd)
fi
AM_CONDITIONAL(LDPD, test "x$LDPD" = "xldpd")

NHRPD=""
if test "$opsys" = "gnu-linux"; then
  if test "${enable_nhrpd}" != "no"; then
    NHRPD="nhrpd"
  fi
else
  if test "${enable_nhrpd}" = "yes"; then
    AC_MSG_ERROR([nhrpd requires kernel APIs that are only present on Linux.])
  fi
fi
AM_CONDITIONAL(NHRPD, test "x$NHRPD" = "xnhrpd")

if test "${enable_watchfrr}" = "no";then
  WATCHFRR=""
else
  WATCHFRR="watchfrr"
fi
AM_CONDITIONAL(WATCHFRR, test "x$WATCHFRR" = "xwatchfrr")

OSPFCLIENT=""
if test "${enable_ospfapi}" != "no";then
    AC_DEFINE(SUPPORT_OSPF_API,,OSPFAPI)

  if test "${enable_ospfclient}" != "no";then
      OSPFCLIENT="ospfclient"
  fi
fi

AM_CONDITIONAL(OSPFCLIENT, test "x$OSPFCLIENT" = "xospfclient")

case "${enable_ripngd}" in
  "no" ) RIPNGD="";;
  *    ) RIPNGD="ripngd";;
esac
AM_CONDITIONAL(RIPNGD, test "x$RIPNGD" = "xripngd")

case "${enable_ospf6d}" in
  "no" ) OSPF6D="";;
  *    ) OSPF6D="ospf6d";;
esac
AM_CONDITIONAL(OSPF6D, test "x$OSPF6D" = "xospf6d")

case "${enable_isisd}" in
  "no" ) ISISD="";;
  *    ) ISISD="isisd";;
esac
AM_CONDITIONAL(ISISD, test "x$ISISD" = "xisisd")

case "${enable_pimd}" in
  "no" ) PIMD="";;
  *    ) PIMD="pimd";;
esac
AM_CONDITIONAL(PIMD, test "x$PIMD" = "xpimd")

if test "${enable_bgp_announce}" = "no";then
  AC_DEFINE(DISABLE_BGP_ANNOUNCE,1,Disable BGP installation to zebra)
else
  AC_DEFINE(DISABLE_BGP_ANNOUNCE,0,Disable BGP installation to zebra)
fi

if test "${with_rfp_path}" = "yes" || test x"${with_rfp_path}" = x""; then
  with_rfp_path="bgpd/rfp-example"
fi
if test "${with_rfp_path}" != "no"; then
  VNC_RFP_PATH="${with_rfp_path}"
  AC_SUBST(VNC_RFP_PATH)
fi

if test "${enable_bgp_vnc}" != "no";then
  AC_DEFINE(ENABLE_BGP_VNC,1,Enable BGP VNC support)
  RFPTEST="${with_rfp_path}/rfptest"
  LIBRFP="${with_rfp_path}/librfp"
  RFPINC="${with_rfp_path}/librfp"
else
  RFPTEST=
  LIBRFP=
  RFPINC="bgpd/rfp-example/librfp"
fi
# set 
AM_CONDITIONAL([ENABLE_BGP_VNC], [test x${enable_bgp_vnc} != xno])

AC_SUBST(DOC)
AC_SUBST(ZEBRA)
AC_SUBST(RFPTEST)
AC_SUBST(LIBRFP)
AC_SUBST(RFPINC)
AC_SUBST(BGPD)
AC_SUBST(RIPD)
AC_SUBST(RIPNGD)
AC_SUBST(OSPFD)
AC_SUBST(OSPF6D)
AC_SUBST(LDPD)
AC_SUBST(NHRPD)
AC_SUBST(WATCHFRR)
AC_SUBST(ISISD)
AC_SUBST(PIMD)
AC_SUBST(SOLARIS)
AC_SUBST(VTYSH)
AC_SUBST(CURSES)
AC_SUBST(OSPFCLIENT)
AC_SUBST(OSPFAPI)
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(resolv, res_init)

dnl ---------------------------
dnl check system has PCRE regexp
dnl ---------------------------
if test "x$enable_pcreposix" = "xyes"; then
  AC_CHECK_LIB(pcreposix, pcreposix_regexec, ,[enable_pcreposix=no
  AC_MSG_WARN([*** falling back to other regex library ***]) ])
fi
AC_SUBST(HAVE_LIBPCREPOSIX)

dnl ------------------
dnl check C-Ares library
dnl ------------------
if test "${NHRPD}" != ""; then
   PKG_CHECK_MODULES([CARES], [libcares])
fi


dnl ------------------
dnl check Net-SNMP library
dnl ------------------
if test "${enable_snmp}" != "" -a "${enable_snmp}" != "no"; then
   AC_PATH_TOOL([NETSNMP_CONFIG], [net-snmp-config], [no])
   if test x"$NETSNMP_CONFIG" = x"no"; then
      AC_MSG_ERROR([--enable-snmp given but unable to find net-snmp-config])
   fi
   SNMP_LIBS="`${NETSNMP_CONFIG} --agent-libs`"
   SNMP_CFLAGS="`${NETSNMP_CONFIG} --base-cflags`"
   AC_MSG_CHECKING([whether we can link to Net-SNMP])
   AC_LINK_IFELSE([AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])],[AC_MSG_RESULT(yes)],[
     AC_MSG_RESULT(no)
     AC_MSG_ERROR([--enable-snmp given but not usable])])
   case "${enable_snmp}" in
     yes)
      SNMP_METHOD=agentx
      ;;
     smux|agentx)
      SNMP_METHOD="${enable_snmp}"
      ;;
     *)
      AC_MSG_ERROR([--enable-snmp given with an unknown method (${enable_snmp}). Use smux or agentx])
      ;;
   esac
   AH_TEMPLATE([SNMP_SMUX], [Use SNMP SMUX to interface with snmpd])
   AH_TEMPLATE([SNMP_AGENTX], [Use SNMP AgentX to interface with snmpd])
   AC_DEFINE_UNQUOTED(AS_TR_CPP(SNMP_${SNMP_METHOD}),,SNMP method to interface with snmpd)
fi
AM_CONDITIONAL([SNMP], [test "x${SNMP_METHOD}" != "x"])
AC_SUBST(SNMP_LIBS)
AC_SUBST(SNMP_CFLAGS)

dnl ---------------
dnl dlopen & dlinfo
dnl ---------------
AC_SEARCH_LIBS(dlopen, [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen()])
])

AC_CHECK_HEADERS([link.h])

AC_MSG_CHECKING([for dlinfo(RTLD_DI_ORIGIN)])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#ifdef HAVE_LINK_H
#include <link.h>
#endif
#include <dlfcn.h>
]], [[
  char origin[1];
  dlinfo (NULL, RTLD_DI_ORIGIN, &origin);
]])], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_DLINFO_ORIGIN, 1, [Have dlinfo RTLD_DI_ORIGIN])
], [
  AC_MSG_RESULT(no)
])

AC_MSG_CHECKING([for dlinfo(RTLD_DI_LINKMAP)])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <stdlib.h>
#ifdef HAVE_LINK_H
#include <link.h>
#endif
#include <dlfcn.h>
]], [[
  struct link_map *lm = NULL;
  dlinfo (NULL, RTLD_DI_LINKMAP, &lm);
]])], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_DLINFO_LINKMAP, 1, [Have dlinfo RTLD_DI_LINKMAP])
], [
  AC_MSG_RESULT(no)
])


dnl ---------------------------
dnl sockaddr and netinet checks
dnl ---------------------------
AC_CHECK_TYPES([
	struct sockaddr_dl,
	struct vifctl, struct mfcctl, struct sioc_sg_req,
	vifi_t, struct sioc_vif_req, struct igmpmsg,
	struct ifaliasreq, struct if6_aliasreq, struct in6_aliasreq,
	struct nd_opt_adv_interval, struct rt_addrinfo,
	struct nd_opt_homeagent_info, struct nd_opt_adv_interval],
	[], [], FRR_INCLUDES)

AC_CHECK_MEMBERS([struct sockaddr.sa_len,
	struct sockaddr_in.sin_len, struct sockaddr_un.sun_len,
	struct sockaddr_dl.sdl_len,
	struct if6_aliasreq.ifra_lifetime,
	struct nd_opt_adv_interval.nd_opt_ai_type],
	[], [], FRR_INCLUDES)

dnl ---------------------------
dnl IRDP/pktinfo/icmphdr checks
dnl ---------------------------
AC_CHECK_TYPES([struct in_pktinfo], 
 [AC_CHECK_TYPES([struct icmphdr],
   [if test "${enable_irdp}" != "no"; then
      AC_DEFINE(HAVE_IRDP,, IRDP)
    fi],
   [if test "${enable_irdp}" = "yes"; then
      AC_MSG_ERROR(['IRDP requires in_pktinfo at the moment!'])
    fi], [FRR_INCLUDES])],
 [if test "${enable_irdp}" = "yes"; then
    AC_MSG_ERROR(['IRDP requires in_pktinfo at the moment!'])
  fi], [FRR_INCLUDES])

dnl -----------------------
dnl checking for IP_PKTINFO
dnl -----------------------
AC_MSG_CHECKING(for IP_PKTINFO)
AC_TRY_COMPILE([#include <netdb.h>], [
  int opt = IP_PKTINFO;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IP_PKTINFO, 1, [Have IP_PKTINFO])
], [
  AC_MSG_RESULT(no)
])

dnl ---------------------------
dnl checking for IP_RECVDSTADDR
dnl ---------------------------
AC_MSG_CHECKING(for IP_RECVDSTADDR)
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_RECVDSTADDR;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IP_RECVDSTADDR, 1, [Have IP_RECVDSTADDR])
], [
  AC_MSG_RESULT(no)
])

dnl ----------------------
dnl checking for IP_RECVIF
dnl ----------------------
AC_MSG_CHECKING(for IP_RECVIF)
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_RECVIF;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IP_RECVIF, 1, [Have IP_RECVIF])
], [
  AC_MSG_RESULT(no)
])

dnl ----------------------
dnl checking for SO_BINDANY
dnl ----------------------
AC_MSG_CHECKING(for SO_BINDANY)
AC_TRY_COMPILE([#include <sys/socket.h>], [
  int opt = SO_BINDANY;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_SO_BINDANY, 1, [Have SO_BINDANY])
], [
  AC_MSG_RESULT(no)
])

dnl ----------------------
dnl checking for IP_FREEBIND
dnl ----------------------
AC_MSG_CHECKING(for IP_FREEBIND)
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_FREEBIND;
], [
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_IP_FREEBIND, 1, [Have IP_FREEBIND])
], [
  AC_MSG_RESULT(no)
])

dnl --------------------------------------
dnl checking for clock_time monotonic struct and call
dnl --------------------------------------
AC_CHECK_DECL(CLOCK_MONOTONIC,
	[AC_CHECK_LIB(rt, clock_gettime, [LIBS="$LIBS -lrt"])
	 AC_DEFINE(HAVE_CLOCK_MONOTONIC,, Have monotonic clock)
], [AC_MSG_RESULT(no)], [FRR_INCLUDES])

dnl --------------------------------------
dnl checking for flex and bison
dnl --------------------------------------

AM_PROG_LEX
AC_MSG_CHECKING(version of flex)
quagga_ac_flex_version="$(eval $LEX -V | grep flex | head -n 1)"
quagga_ac_flex_version="${quagga_ac_flex_version##* }"
AC_MSG_RESULT([$quagga_ac_flex_version])
AX_COMPARE_VERSION([$quagga_ac_flex_version], [lt], [2.5.20], [
  LEX="$SHELL $missing_dir/missing flex"
  if test -f "${srcdir}/lib/command_lex.c" -a -f "${srcdir}/lib/command_lex.h"; then
    AC_MSG_WARN([using pregenerated flex output files])
  else
    AC_MSG_ERROR([flex failure and pregenerated files not included (probably a git build)])
  fi
  AC_SUBST([LEX_OUTPUT_ROOT], [lex.yy])
  AC_SUBST([LEXLIB], [''])
])

AC_PROG_YACC
dnl thanks GNU bison for this b*llshit...
AC_MSG_CHECKING(version of bison)
quagga_ac_bison_version="$(eval $YACC -V | grep bison | head -n 1)"
quagga_ac_bison_version="${quagga_ac_bison_version##* }"
quagga_ac_bison_missing="false"
case "x${quagga_ac_bison_version}" in
  x2.7*)
    BISON_OPENBRACE='"'
    BISON_CLOSEBRACE='"'
    BISON_VERBOSE=''
    AC_MSG_RESULT([$quagga_ac_bison_version - 2.7 or older])
    ;;
  x2.*|x1.*)
    AC_MSG_RESULT([$quagga_ac_bison_version])
    AC_MSG_WARN([installed bison is too old.  Please install GNU bison 2.7.x or newer.])
    quagga_ac_bison_missing="true"
    ;;
  x)
    AC_MSG_RESULT([none])
    AC_MSG_WARN([could not determine bison version.  Please install GNU bison 2.7.x or newer.])
    quagga_ac_bison_missing="true"
    ;;
  *)
    BISON_OPENBRACE='{'
    BISON_CLOSEBRACE='}'
    BISON_VERBOSE='-Dparse.error=verbose'
    AC_MSG_RESULT([$quagga_ac_bison_version - 3.0 or newer])
    ;;
esac
AC_SUBST(BISON_OPENBRACE)
AC_SUBST(BISON_CLOSEBRACE)
AC_SUBST(BISON_VERBOSE)

if $quagga_ac_bison_missing; then
  YACC="$SHELL $missing_dir/missing bison -y"
  if test -f "${srcdir}/lib/command_parse.c" -a -f "${srcdir}/lib/command_parse.h"; then
    AC_MSG_WARN([using pregenerated bison output files])
  else
    AC_MSG_ERROR([bison failure and pregenerated files not included (probably a git build)])
  fi
fi

dnl -------------------
dnl capabilities checks
dnl -------------------
if test "${enable_capabilities}" != "no"; then
  AC_MSG_CHECKING(whether prctl PR_SET_KEEPCAPS is available)
  AC_TRY_COMPILE([#include <sys/prctl.h>],[prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);],
    [AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_PR_SET_KEEPCAPS,,prctl)
     frr_ac_keepcaps="yes"],
     AC_MSG_RESULT(no)
  )
  if test x"${frr_ac_keepcaps}" = x"yes"; then
    AC_CHECK_HEADERS(sys/capability.h)
  fi
  if test x"${ac_cv_header_sys_capability_h}" = x"yes"; then
    AC_CHECK_LIB(cap, cap_init, 
      [AC_DEFINE(HAVE_LCAPS,1,Capabilities)
       LIBCAP="-lcap"
       frr_ac_lcaps="yes"]
    )
  else
    AC_CHECK_HEADERS(priv.h,
     [AC_MSG_CHECKING(Solaris style privileges are available)
      AC_TRY_COMPILE([#include <priv.h>],[getpflags(PRIV_AWARE);],
    	  [AC_MSG_RESULT(yes)
    	   AC_DEFINE(HAVE_SOLARIS_CAPABILITIES,1,getpflags)
    	   frr_ac_scaps="yes"],
    	   AC_MSG_RESULT(no)
      )
     ]
   )
  fi
  if test x"${frr_ac_scaps}" = x"yes" \
       -o x"${frr_ac_lcaps}" = x"yes"; then
    AC_DEFINE(HAVE_CAPABILITIES,1,capabilities)
  fi
fi
AC_SUBST(LIBCAP)

dnl ---------------------------
dnl check for glibc 'backtrace'
dnl --------------------------- 
if test x"${enable_backtrace}" != x"no" ; then
  backtrace_ok=no
  AC_CHECK_HEADER([execinfo.h], [
    AC_SEARCH_LIBS([backtrace], [execinfo], [
      AC_DEFINE(HAVE_GLIBC_BACKTRACE,,[Glibc backtrace])
      AC_DEFINE(HAVE_STACK_TRACE,,[Stack symbol decoding])
      backtrace_ok=yes
    ],, [-lm])
  ])

  if test x"${enable_backtrace}" = x"yes" -a x"${backtrace_ok}" = x"no"; then
    dnl user explicitly requested backtrace but we failed to find support
    AC_MSG_FAILURE([failed to find backtrace support])
  fi
fi

dnl -----------------------------------------
dnl check for malloc mallinfo struct and call
dnl this must try and link using LIBS, in
dnl order to check no alternative allocator
dnl has been specified, which might not provide
dnl mallinfo, e.g. such as Umem on Solaris.
dnl -----------------------------------------
AC_CHECK_HEADER([malloc.h],
 [AC_MSG_CHECKING(whether mallinfo is available)
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <malloc.h>]],
                        [[struct mallinfo ac_x; ac_x = mallinfo ();]])],
      [AC_MSG_RESULT(yes)
       AC_DEFINE(HAVE_MALLINFO,,mallinfo)],
       AC_MSG_RESULT(no)
  )
 ], [], FRR_INCLUDES)

dnl ----------
dnl configure date
dnl ----------
CONFDATE=`date '+%Y%m%d'`
AC_SUBST(CONFDATE)

dnl ------------------------------
dnl set paths for state directory
dnl ------------------------------
AC_MSG_CHECKING(directory to use for state file)
if test "${prefix}" = "NONE"; then
  frr_statedir_prefix="";
else
  frr_statedir_prefix=${prefix}
fi
if test "${localstatedir}" = '${prefix}/var'; then
  for FRR_STATE_DIR in ${frr_statedir_prefix}/var/run dnl
			${frr_statedir_prefix}/var/adm dnl
			${frr_statedir_prefix}/etc dnl
			/var/run	dnl
                        /var/adm	dnl
                        /etc		dnl
                        /dev/null;
  do
    test -d $FRR_STATE_DIR && break
  done
  frr_statedir=$FRR_STATE_DIR
else
  frr_statedir=${localstatedir}
fi
if test $frr_statedir = "/dev/null"; then
    AC_MSG_ERROR('STATE DIRECTORY NOT FOUND! FIX OR SPECIFY --localstatedir!')
fi
AC_MSG_RESULT(${frr_statedir})
AC_SUBST(frr_statedir)

AC_DEFINE_UNQUOTED(LDPD_SOCKET, "$frr_statedir/ldpd.sock",ldpd control socket)
AC_DEFINE_UNQUOTED(ZEBRA_SERV_PATH, "$frr_statedir/zserv.api",zebra api socket)
AC_DEFINE_UNQUOTED(DAEMON_VTY_DIR, "$frr_statedir",daemon vty directory)

dnl autoconf does this, but it does it too late...
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

dnl get the full path, recursing through variables...
vtysh_bin="$bindir/vtysh"
for I in 1 2 3 4 5 6 7 8 9 10; do
	eval vtysh_bin="\"$vtysh_bin\""
done
AC_DEFINE_UNQUOTED(VTYSH_BIN_PATH, "$vtysh_bin",path to vtysh binary)

CFG_SYSCONF="$sysconfdir"
CFG_SBIN="$sbindir"
CFG_STATE="$frr_statedir"
CFG_MODULE="$moduledir"
for I in 1 2 3 4 5 6 7 8 9 10; do
	eval CFG_SYSCONF="\"$CFG_SYSCONF\""
	eval CFG_SBIN="\"$CFG_SBIN\""
	eval CFG_STATE="\"$CFG_STATE\""
	eval CFG_MODULE="\"$CFG_MODULE\""
done
AC_SUBST(CFG_SYSCONF)
AC_SUBST(CFG_SBIN)
AC_SUBST(CFG_STATE)
AC_SUBST(CFG_MODULE)
AC_DEFINE_UNQUOTED(MODULE_PATH, "$CFG_MODULE", path to modules)

dnl ---------------------------
dnl Check htonl works correctly
dnl ---------------------------
AC_MSG_CHECKING(for working htonl)
AC_CACHE_VAL(ac_cv_htonl_works,
 [AC_LINK_IFELSE([AC_LANG_PROGRAM([FRR_INCLUDES],[htonl (0);])],
 		[ac_cv_htonl_works=yes], [ac_cv_htonl_works=no])
 ]
)
AC_MSG_RESULT($ac_cv_htonl_works)

AC_CONFIG_FILES([Makefile lib/Makefile qpb/Makefile zebra/Makefile ripd/Makefile 
	  ripngd/Makefile bgpd/Makefile ospfd/Makefile watchfrr/Makefile
	  ospf6d/Makefile ldpd/Makefile isisd/Makefile vtysh/Makefile
	  doc/Makefile ospfclient/Makefile tests/Makefile m4/Makefile
	  pimd/Makefile
	  nhrpd/Makefile
	  redhat/Makefile
	  tools/Makefile
	  debianpkg/Makefile
	  cumulus/Makefile
	  pkgsrc/Makefile
	  fpm/Makefile
	  redhat/frr.spec
	  debianpkg/changelog
	  snapcraft/Makefile
	  snapcraft/snapcraft.yaml
	  lib/version.h
	  tests/lib/cli/test_cli.refout
	  doc/defines.texi
	  doc/bgpd.8
	  doc/isisd.8
	  doc/ospf6d.8
	  doc/ospfclient.8
	  doc/ospfd.8
	  doc/ldpd.8
	  doc/ripd.8
	  doc/ripngd.8
	  doc/pimd.8
	  doc/nhrpd.8
	  doc/vtysh.1
	  doc/watchfrr.8
	  doc/zebra.8
	  doc/frr.1
	  pkgsrc/bgpd.sh pkgsrc/ospf6d.sh pkgsrc/ospfd.sh
	  pkgsrc/ripd.sh pkgsrc/ripngd.sh pkgsrc/zebra.sh])

if test "${enable_bgp_vnc}" != "no"; then
   if test "${with_rfp_path}" = "bgpd/rfp-example" ; then 
     AC_CONFIG_FILES([bgpd/rfp-example/rfptest/Makefile bgpd/rfp-example/librfp/Makefile])
   else
     AC_CONFIG_FILES([${with_rfp_path}/rfptest/Makefile ${with_rfp_path}/librfp/Makefile])
   fi
fi

AC_CONFIG_FILES([solaris/Makefile])

AC_CONFIG_FILES([vtysh/extract.pl],[chmod +x vtysh/extract.pl])

## Hack, but working solution to avoid rebuilding of quagga.info.
## It's already in CVS until texinfo 4.7 is more common.
AC_OUTPUT

echo "
FRRouting configuration
------------------------------
FRR version             : ${PACKAGE_VERSION}
host operating system   : ${host_os}
source code location    : ${srcdir}
compiler                : ${CC}
compiler flags          : ${CFLAGS}
make                    : ${MAKE-make}
linker flags            : ${LDFLAGS} ${LIBS} ${LIBCAP} ${LIBREADLINE} ${LIBM}
state file directory    : ${frr_statedir}
config file directory   : `eval echo \`echo ${sysconfdir}\``
example directory       : `eval echo \`echo ${exampledir}\``
module directory        : ${CFG_MODULE}
user to run as          : ${enable_user}
group to run as         : ${enable_group}
group for vty sockets   : ${enable_vty_group}
config file mask        : ${enable_configfile_mask}
log file mask           : ${enable_logfile_mask}
zebra protobuf enabled  : ${have_protobuf:-no}

The above user and group must have read/write access to the state file
directory and to the config files in the config file directory."
