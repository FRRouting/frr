##
## Configure template file for FRRouting.
## autoconf will generate configure script.
##
##  Copyright (c) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
##  Portions Copyright (c) 2003 Paul Jakma <paul@dishone.st>
##
AC_PREREQ(2.60)

AC_INIT(frr, 4.1-dev, [https://github.com/frrouting/frr/issues])
PACKAGE_URL="https://frrouting.org/"
AC_SUBST(PACKAGE_URL)
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

AS_IF([test "$host" != "$build"], [
  if test "$srcdir" = "."; then
    AC_MSG_ERROR([cross-compilation is only possible with builddir separate from srcdir.  create a separate directory and run as .../path-to-frr/configure.])
  fi
  test -d hosttools || mkdir hosttools
  abssrc="`cd \"${srcdir}\"; pwd`"

  AC_MSG_NOTICE([...])
  AC_MSG_NOTICE([... cross-compilation: creating hosttools directory and self-configuring for build platform tools])
  AC_MSG_NOTICE([... use HOST_CPPFLAGS / HOST_CFLAGS / HOST_LDFLAGS if neccessary])
  AC_MSG_NOTICE([...])

  ( CPPFLAGS="$HOST_CPPFLAGS"; \
    CFLAGS="$HOST_CFLAGS"; \
    LDFLAGS="$HOST_LDFLAGS"; \
    cd hosttools; "${abssrc}/configure" "--host=$build" "--build=$build" "--enable-clippy-only" "--disable-nhrpd" "--disable-vtysh"; )

  AC_MSG_NOTICE([...])
  AC_MSG_NOTICE([... cross-compilation: finished self-configuring for build platform tools])
  AC_MSG_NOTICE([...])

  build_clippy="false"
  HOSTTOOLS="hosttools/"
], [
  build_clippy="true"
  HOSTTOOLS=""
])
AC_SUBST(HOSTTOOLS)
AM_CONDITIONAL([BUILD_CLIPPY], [$build_clippy])

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
AC_ARG_ENABLE([pkgsrcrcdir],
	  AS_HELP_STRING([--enable-pkgsrcrcdir],
			 [specify directory for rc.d scripts]),
			 pkgsrcrcdir="$enableval",)
dnl XXX add --pkgsrcrcdir to autoconf standard directory list somehow
AC_SUBST(pkgsrcrcdir)
AM_CONDITIONAL([PKGSRC], [test "x$pkgsrcrcdir" != "x"])

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


dnl Thanks autoconf, but we don't want a default -g -O2.  We have our own
dnl flag determination logic.
CFLAGS="${CFLAGS:-}"

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
dnl NB: see C11 below

AC_PROG_EGREP
PKG_PROG_PKG_CONFIG

dnl autoconf 2.59 appears not to support AC_PROG_SED
dnl AC_PROG_SED
AC_CHECK_PROG([SED],[sed],[sed],[/bin/false])

dnl try and enable CFLAGS that are useful for FRR
dnl - specifically, options to control warnings

AC_USE_SYSTEM_EXTENSIONS
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

AC_DEFUN([AC_LINK_IFELSE_FLAGS], [{
	AC_LANG_PUSH(C)
	ac_cflags_save="$CFLAGS"
	ac_libs_save="$LIBS"
	CFLAGS="$CFLAGS $1"
	LIBS="$LIBS $2"
	AC_LINK_IFELSE(
		[$3],
		[
			AC_MSG_RESULT([yes])
			CFLAGS="$ac_cflags_save"
			LIBS="$ac_libs_save"
			$5
		], [
			AC_MSG_RESULT([no])
			CFLAGS="$ac_cflags_save"
			LIBS="$ac_libs_save"
			$4
		])
	AC_LANG_POP(C)
	}])

dnl ICC won't bail on unknown options without -diag-error 10006
dnl need to do this first so we get useful results for the other options
AC_C_FLAG([-diag-error 10006])

dnl AC_PROG_CC_C99 may change CC to include -std=gnu99 or something
ac_cc="$CC"
CC="${CC% -std=gnu99}"
CC="${CC% -std=c99}"

AC_C_FLAG([-std=gnu11], [CC="$ac_cc"], [CC="$CC -std=gnu11"])

dnl if the user has specified any CFLAGS, override our settings
if test "x${enable_dev_build}" = "xyes"; then
   AC_DEFINE(DEV_BUILD,,Build for development)
   if test "z$orig_cflags" = "z"; then
      AC_C_FLAG([-g3])
      AC_C_FLAG([-O0])
   fi
else
   if test "z$orig_cflags" = "z"; then
      AC_C_FLAG([-g])
      AC_C_FLAG([-Os], [
        AC_C_FLAG([-O2])
      ])
   fi
fi
AM_CONDITIONAL([DEV_BUILD], [test "x$enable_dev_build" = "xyes"])
AM_CONDITIONAL([SHARPD], [test "x$enable_dev_build" = "xyes"])

dnl always want these CFLAGS
AC_C_FLAG([-fno-omit-frame-pointer])
AC_C_FLAG([-funwind-tables])
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

dnl ----------
dnl Essentials
dnl ----------

AX_PTHREAD([
  CC="$PTHREAD_CC"
  CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
  LIBS="$PTHREAD_LIBS $LIBS"
], [
  AC_MSG_FAILURE([This FRR version needs pthreads])
])

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
AC_ARG_WITH(vtysh_pager,
	AS_HELP_STRING([--with-vtysh-pager=PAGER], [control what pager is compiled in as default]),
	VTYSH_PAGER=$withval, VTYSH_PAGER="more")
AC_ARG_ENABLE(vtysh,
  AS_HELP_STRING([--disable-vtysh], [do not build integrated vty shell for FRR]))
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
AC_ARG_ENABLE(eigrpd,
  AS_HELP_STRING([--disable-eigrpd], [do not build eigrpd]))
AC_ARG_ENABLE(babeld,
  AS_HELP_STRING([--disable-babeld], [do not build babeld]))
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
AC_ARG_ENABLE(zeromq,
  AS_HELP_STRING([--enable-zeromq], [enable ZeroMQ handler (libfrrzmq)]))
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
AC_ARG_ENABLE(realms,
  AS_HELP_STRING([--enable-realms], [enable REALMS support under Linux]))
AC_ARG_ENABLE(rtadv,
  AS_HELP_STRING([--disable-rtadv], [disable IPV6 router advertisement feature]))
AC_ARG_ENABLE(irdp,
  AS_HELP_STRING([--disable-irdp], [enable IRDP server support in zebra (default if supported)]))
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
AC_ARG_ENABLE(werror,
  AS_HELP_STRING([--enable-werror], [enable -Werror (recommended for developers only)]))
AC_ARG_ENABLE(cumulus,
  AS_HELP_STRING([--enable-cumulus], [enable Cumulus Switch Special Extensions]))
AC_ARG_ENABLE(datacenter,
  AS_HELP_STRING([--enable-datacenter], [enable Compilation for Data Center Extensions]))
AC_ARG_ENABLE(fuzzing,
  AS_HELP_STRING([--enable-fuzzing], [enable ability to fuzz various parts of FRR]))
AC_ARG_ENABLE(rr-semantics,
  AS_HELP_STRING([--disable-rr-semantics], [disable the v6 Route Replace semantics]))
AC_ARG_ENABLE([protobuf],
  AS_HELP_STRING([--enable-protobuf], [Enable experimental protobuf support]))
AC_ARG_ENABLE([oldvpn_commands],
  AS_HELP_STRING([--enable-oldvpn-commands], [Keep old vpn commands]))
AC_ARG_ENABLE(rpki,
  AS_HELP_STRING([--enable-rpki], [enable RPKI prefix validation support]))
AC_ARG_ENABLE([clippy-only],
  AS_HELP_STRING([--enable-clippy-only], [Only build clippy]))

AS_IF([test "${enable_clippy_only}" != "yes"], [
AC_CHECK_HEADERS(json-c/json.h)
AC_CHECK_LIB(json-c, json_object_get, LIBS="$LIBS -ljson-c", [], [-lm])
if test $ac_cv_lib_json_c_json_object_get = no; then
  AC_CHECK_LIB(json, json_object_get, LIBS="$LIBS -ljson")
  if test $ac_cv_lib_json_json_object_get = no; then
      AC_MSG_ERROR([lib json is needed to compile])
  fi
fi
])

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

if test "${enable_datacenter}" = "yes" ; then
  AC_DEFINE(HAVE_DATACENTER,,Compile extensions for a DataCenter)
  DFLT_NAME="datacenter"
else
  DFLT_NAME="traditional"
fi

if test "${enable_fuzzing}" = "yes" ; then
  AC_DEFINE(HANDLE_ZAPI_FUZZING,,Compile extensions to use with a fuzzer)
fi

if test "${enable_cumulus}" = "yes" ; then
  AC_DEFINE(HAVE_CUMULUS,,Compile Special Cumulus Code in)
fi

AC_SUBST(DFLT_NAME)
AC_DEFINE_UNQUOTED(DFLT_NAME,["$DFLT_NAME"], Name of the configuration default set)

if test "${enable_shell_access}" = "yes"; then
   AC_DEFINE(HAVE_SHELL_ACCESS,,Allow user to use ssh/telnet/bash)
fi

AM_CONDITIONAL([FPM], [test "x$enable_fpm" = "xyes"])

#
# Python for clippy
#
AS_IF([test "$host" = "$build"], [
  PYTHONCONFIG=""

  # ordering:
  # 1.  try python3, but respect the user's preference on which minor ver
  # 2.  try python, which might be py3 or py2 again on the user's preference
  # 3.  try python2 (can really only be 2.7 but eh)
  # 4.  try 3.5 > 3.4 > 3.3 > 3.2 > 2.7 through pkg-config (no user pref)
  #
  # (AX_PYTHON_DEVEL has no clue about py3 vs py2)
  # (AX_PYTHON does not do what we need)

  AC_CHECK_TOOLS([PYTHONCONFIG], [python3-config python-config python2-config])
  if test -n "$PYTHONCONFIG"; then
    PYTHON_CFLAGS="`\"${PYTHONCONFIG}\" --includes`"
    PYTHON_LIBS="`\"${PYTHONCONFIG}\" --libs`"

    AC_MSG_CHECKING([whether we found a working Python version])
    AC_LINK_IFELSE_FLAGS([$PYTHON_CFLAGS], [$PYTHON_LIBS], [AC_LANG_PROGRAM([
#include <Python.h>
#if PY_VERSION_HEX < 0x02070000
#error python too old
#endif
int main(void);
],
[
{
  Py_Initialize();
  return 0;
}
])], [
      PYTHONCONFIG=""
      unset PYTHON_LIBS
      unset PYTHON_CFLAGS
    ])
  fi

  if test -z "$PYTHONCONFIG"; then
    PKG_CHECK_MODULES([PYTHON], python-3.5, [], [
      PKG_CHECK_MODULES([PYTHON], python-3.4, [], [
        PKG_CHECK_MODULES([PYTHON], python-3.3, [], [
          PKG_CHECK_MODULES([PYTHON], python-3.2, [], [
            PKG_CHECK_MODULES([PYTHON], python-2.7, [], [
              AC_MSG_FAILURE([could not find python-config or pkg-config python, please install Python development files from libpython-dev or similar])
              ])])])])])


    AC_MSG_CHECKING([whether we found a working Python version])
    AC_LINK_IFELSE_FLAGS([$PYTHON_CFLAGS], [$PYTHON_LIBS], [AC_LANG_PROGRAM([
#include <Python.h>
#if PY_VERSION_HEX < 0x02070000
#error python too old
#endif
int main(void);
],
[
{
  Py_Initialize();
  return 0;
}
])], [
      AC_MSG_FAILURE([could not find python-config or pkg-config python, please install Python development files from libpython-dev or similar])
    ])
  fi
])
AC_SUBST(PYTHON_CFLAGS)
AC_SUBST(PYTHON_LIBS)

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

AC_DEFINE_UNQUOTED(VTYSH_PAGER, "$VTYSH_PAGER", [What pager to use])

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

ac_stdatomic_ok=false
AC_DEFINE(FRR_AUTOCONF_ATOMIC, 1, [did autoconf checks for atomic funcs])
AC_CHECK_HEADER([stdatomic.h],[

  AC_MSG_CHECKING([whether _Atomic qualifier works])
  AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <stdatomic.h>
int main(int argc, char **argv) {
  _Atomic int i = 0;
  return i;
}
]])], [
    AC_DEFINE(HAVE_STDATOMIC_H, 1, [found stdatomic.h])
    AC_MSG_RESULT([yes])
    ac_stdatomic_ok=true
  ], [
    AC_MSG_RESULT([no])
  ])
])

AS_IF([$ac_stdatomic_ok], [true], [
  AC_MSG_CHECKING([for __atomic_* builtins])
  AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main(int argc, char **argv) {
  volatile int i = 1;
  __atomic_store_n (&i, 0, __ATOMIC_RELEASE);
  return __atomic_load_n (&i, __ATOMIC_ACQUIRE);
}
]])], [
    AC_DEFINE(HAVE___ATOMIC, 1, [found __atomic builtins])
    AC_MSG_RESULT([yes])
  ], [
    AC_MSG_RESULT([no])

    dnl FreeBSD 9 has a broken stdatomic.h where _Atomic doesn't work
    AC_MSG_CHECKING([for __sync_* builtins])
    AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main(int argc, char **argv) {
  volatile int i = 1;
  __sync_fetch_and_sub (&i, 1);
  return __sync_val_compare_and_swap (&i, 0, 1);
}
]])], [
      AC_DEFINE(HAVE___SYNC, 1, [found __sync builtins])
      AC_MSG_RESULT([yes])

      AC_MSG_CHECKING([for __sync_swap builtin])
      AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main(int argc, char **argv) {
  volatile int i = 1;
  return __sync_swap (&i, 2);
}
]])], [
        AC_DEFINE(HAVE___SYNC_SWAP, 1, [found __sync_swap builtin])
        AC_MSG_RESULT([yes])
      ], [
        AC_MSG_RESULT([no])
      ])

    ], [
      AC_MSG_RESULT([no])
      AC_MSG_FAILURE([stdatomic.h unavailable and $CC has neither __atomic nor __sync builtins])
    ])
  ])
])

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

AC_MSG_CHECKING([which operating system interface to use])
case "$host_os" in
  sunos* | solaris2*)
    AC_MSG_RESULT([Solaris])

    AC_DEFINE(SUNOS_5, 1, [SunOS 5])
    AC_DEFINE(SOLARIS_IPV6, 1, Solaris IPv6)

    AC_CHECK_LIB(socket, main)
    AC_CHECK_LIB(nsl, main)
    AC_CHECK_LIB(umem, main)
    AC_CHECK_FUNCS([printstack], [
      AC_DEFINE([HAVE_PRINTSTACK],1,[Solaris printstack])
      AC_DEFINE([HAVE_STACK_TRACE],1,[Stack symbols decode functionality])
    ])
    CURSES=-lcurses
    SOLARIS="solaris"
    ;;
  linux*)
    AC_MSG_RESULT([Linux])

    AC_DEFINE(GNU_LINUX,,GNU Linux)
    AC_DEFINE(HAVE_NETLINK,,netlink)
    AC_DEFINE(LINUX_IPV6,1,Linux IPv6 stack)

    dnl Linux has a compilation problem with mixing
    dnl netinet/in.h and linux/in6.h they are not
    dnl compatible.  There has been discussion on
    dnl how to fix it but no real progress on implementation
    dnl when they fix it, remove this
    AC_DEFINE(IPV6_MINHOPCOUNT, 73, Linux ipv6 Min Hop Count)

    AC_CHECK_DECLS([IFLA_INFO_SLAVE_KIND], [], [], [#include <linux/if_link.h>])
    ;;
  openbsd*)
    AC_MSG_RESULT([OpenBSD])

    AC_DEFINE(OPEN_BSD,,OpenBSD)
    AC_DEFINE(KAME,1,KAME IPv6)
    AC_DEFINE(BSD_V6_SYSCTL,1,BSD v6 sysctl to turn on and off forwarding)

    if test "x${enable_pimd}" != "xno"; then
      case "$host_os" in
      openbsd6.0)
        ;;
      openbsd[6-9]*)
        AC_MSG_FAILURE([pimd cannot be enabled as PIM support has been removed from OpenBSD 6.1])
        ;;
      esac
    fi
    ;;
  *)
    AC_MSG_RESULT([BSD])

    AC_DEFINE(HAVE_NET_RT_IFLIST,,NET_RT_IFLIST)
    AC_DEFINE(KAME,1,KAME IPv6)
    AC_DEFINE(BSD_V6_SYSCTL,1,BSD v6 sysctl to turn on and off forwarding)
    ;;
esac
AM_CONDITIONAL(SOLARIS, test "${SOLARIS}" = "solaris")

AC_SYS_LARGEFILE

dnl ------------------------
dnl Integrated REALMS option
dnl ------------------------
if test "${enable_realms}" = "yes"; then
    case "$host_os" in
      linux*)
       AC_DEFINE(SUPPORT_REALMS,, Realms support)
       ;;
      *)
       echo "Sorry, only Linux has REALMS support"
       exit 1
       ;;
    esac
fi
AM_CONDITIONAL([SUPPORT_REALMS], [test "${enable_realms}" = "yes"])

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
dnl FRR detects the PAM library it is built against by checking for a
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

AC_CHECK_FUNCS([ppoll], [
  AC_DEFINE([HAVE_PPOLL], 1, [have Linux/BSD ppoll()])
])
AC_CHECK_FUNCS([pollts], [
  AC_DEFINE([HAVE_POLLTS], 1, [have NetBSD pollts()])
])

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

dnl --------------------------
dnl Determine IS-IS I/O method
dnl --------------------------
AC_DEFINE(ISIS_METHOD_PFPACKET,	1, [ constant value for isis method pfpacket ])
AC_DEFINE(ISIS_METHOD_DLPI,	2, [ constant value for isis method dlpi ])
AC_DEFINE(ISIS_METHOD_BPF,	3, [ constant value for isis method bpf ])
AC_CHECK_HEADER(net/bpf.h)
AC_CHECK_HEADER(sys/dlpi.h)
AC_MSG_CHECKING(zebra IS-IS I/O method)

case "$host_os" in
  linux*)
    AC_MSG_RESULT(pfpacket)
    ISIS_METHOD_MACRO="ISIS_METHOD_PFPACKET"
    ;;
  solaris* | sunos*)
    AC_MSG_RESULT(DLPI)
    ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
    ;;
  *)
    if test $ac_cv_header_net_bpf_h = no; then
      if test $ac_cv_header_sys_dlpi_h = no; then
        AC_MSG_RESULT(none)
        if test "${enable_isisd}" = yes; then
          AC_MSG_FAILURE([IS-IS support requested but no packet backend found])
        fi
        AC_MSG_WARN([*** IS-IS support will not be built ***])
        enable_isisd="no"
      else
        AC_MSG_RESULT(DLPI)
      fi
      ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
    else
      AC_MSG_RESULT(BPF)
      ISIS_METHOD_MACRO="ISIS_METHOD_BPF"
    fi
    ;;
esac
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

dnl ----------------------------------------------------------------------------
dnl figure out if domainname is available in the utsname struct (GNU extension).
dnl ----------------------------------------------------------------------------
AC_CHECK_MEMBERS([struct utsname.domainname], [], [], [#include <sys/utsname.h>])

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
AM_CONDITIONAL(ZEBRA, test "${enable_zebra}" != "no")

if test "${enable_bgpd}" = "no";then
  BGPD=""
else
  BGPD="bgpd"
fi
AM_CONDITIONAL(BGPD, test "x$BGPD" = "xbgpd")

AM_CONDITIONAL(RIPD, test "${enable_ripd}" != "no")
AM_CONDITIONAL(OSPFD, test "${enable_ospfd}" != "no")
AM_CONDITIONAL(LDPD, test "${enable_ldpd}" != "no")

AS_IF([test "${enable_ldpd}" != "no"], [
  AC_DEFINE(HAVE_LDPD, 1, ldpd)
])

NHRPD=""
case "$host_os" in
  linux*)
    if test "${enable_nhrpd}" != "no"; then
      NHRPD="nhrpd"
    fi
    ;;
  *)
    if test "${enable_nhrpd}" = "yes"; then
      AC_MSG_ERROR([nhrpd requires kernel APIs that are only present on Linux.])
    fi
    ;;
esac
AM_CONDITIONAL(NHRPD, test "x$NHRPD" = "xnhrpd")

AM_CONDITIONAL(EIGRPD, test "${enable_eigrpd}" != "no")

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
AM_CONDITIONAL(RIPNGD, test "${enable_ripngd}" != "no")
AM_CONDITIONAL(BABELD, test "${enable_babeld}" != "no")
AM_CONDITIONAL(OSPF6D, test "${enable_ospf6d}" != "no")
AM_CONDITIONAL(ISISD, test "${enable_isisd}" != "no")
AM_CONDITIONAL(PIMD, test "${enable_pimd}" != "no")

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
AC_SUBST(RFPTEST)
AC_SUBST(LIBRFP)
AC_SUBST(RFPINC)
AC_SUBST(BGPD)
AC_SUBST(SOLARIS)
AC_SUBST(VTYSH)
AC_SUBST(CURSES)
AC_CHECK_LIB(crypt, crypt, [],
		    [AC_CHECK_LIB(crypto, DES_crypt)])
AC_CHECK_LIB(resolv, res_init)

dnl ---------------------------
dnl check system has PCRE regexp
dnl ---------------------------
if test "x$enable_pcreposix" = "xyes"; then
  AC_CHECK_LIB(pcreposix, regexec, [], [
    AC_MSG_ERROR([--enable-pcreposix given but unable to find libpcreposix])
  ])
fi
AC_SUBST(HAVE_LIBPCREPOSIX)

dnl ------------------
dnl check C-Ares library
dnl ------------------
if test "${NHRPD}" != ""; then
  PKG_CHECK_MODULES([CARES], [libcares], , [
    AC_MSG_ERROR([trying to build nhrpd, but libcares not found. install c-ares and its -dev headers.])
  ])
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
   AC_LINK_IFELSE_FLAGS([$SNMP_CFLAGS], [$SNMP_LIBS], [AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])], [
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
dnl math
dnl ---------------
AC_SEARCH_LIBS([sqrt], [m])

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


AM_CONDITIONAL(SNMP, test "x$SNMP_METHOD" = "xagentx")

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

AC_CHECK_TYPES([struct in_pktinfo], [
  AC_CHECK_TYPES([struct icmphdr], [
    IRDP=true
  ], [
    IRDP=false
  ], [FRR_INCLUDES])
], [
  IRDP=false
], [FRR_INCLUDES])

case "${enable_irdp}" in
yes)
  $IRDP || AC_MSG_ERROR(['IRDP requires in_pktinfo at the moment!'])
  ;;
no)
  IRDP=false
  ;;
esac

AM_CONDITIONAL(IRDP, $IRDP)

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
dnl checking for be32dec existence or not
dnl --------------------------------------
AC_CHECK_DECLS([be32enc, be32dec], [], [],
	       [#include <sys/endian.h>])

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
frr_ac_flex_version="$(eval $LEX -V | grep flex | head -n 1)"
frr_ac_flex_version="${frr_ac_flex_version##* }"
AC_MSG_RESULT([$frr_ac_flex_version])
AX_COMPARE_VERSION([$frr_ac_flex_version], [lt], [2.5.20], [
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
frr_ac_bison_version="$(eval $YACC -V | grep bison | head -n 1)"
frr_ac_bison_version="${frr_ac_bison_version##* }"
frr_ac_bison_missing="false"
case "x${frr_ac_bison_version}" in
  x2.7*)
    BISON_OPENBRACE='"'
    BISON_CLOSEBRACE='"'
    BISON_VERBOSE=''
    AC_MSG_RESULT([$frr_ac_bison_version - 2.7 or older])
    ;;
  x2.*|x1.*)
    AC_MSG_RESULT([$frr_ac_bison_version])
    AC_MSG_WARN([installed bison is too old.  Please install GNU bison 2.7.x or newer.])
    frr_ac_bison_missing="true"
    ;;
  x)
    AC_MSG_RESULT([none])
    AC_MSG_WARN([could not determine bison version.  Please install GNU bison 2.7.x or newer.])
    frr_ac_bison_missing="true"
    ;;
  *)
    BISON_OPENBRACE='{'
    BISON_CLOSEBRACE='}'
    BISON_VERBOSE='-Dparse.error=verbose'
    AC_MSG_RESULT([$frr_ac_bison_version - 3.0 or newer])
    ;;
esac
AC_SUBST(BISON_OPENBRACE)
AC_SUBST(BISON_CLOSEBRACE)
AC_SUBST(BISON_VERBOSE)

if $frr_ac_bison_missing; then
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

dnl ------
dnl ZeroMQ
dnl ------
if test "x$enable_zeromq" != "xno"; then
  PKG_CHECK_MODULES(ZEROMQ, [libzmq >= 4.0.0], [
    AC_DEFINE(HAVE_ZEROMQ, 1, [Enable ZeroMQ support])
    ZEROMQ=true
  ], [
    if test "x$enable_zeromq" = "xyes"; then
      AC_MSG_ERROR([configuration specifies --enable-zeromq but libzmq was not found])
    fi
  ])
fi
AM_CONDITIONAL([ZEROMQ], test "x$ZEROMQ" = "xtrue")

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

dnl ------------------------------------
dnl Enable RPKI and add librtr to libs
dnl ------------------------------------
if test "${enable_rpki}" = "yes"; then
  PKG_CHECK_MODULES(RTRLIB,[rtrlib >= 0.5.0],
      [AC_DEFINE(HAVE_RPKI,1,Enable RPKI prefix validation for BGP)
      RPKI=true],
      [RPKI=false
      AC_MSG_ERROR([rtrlib was not found on your system or is too old.])]
  )
fi
AM_CONDITIONAL([RPKI], test "x$RPKI" = "xtrue")

dnl ------------------------------------------
dnl Check whether rtrlib was build with ssh support
dnl ------------------------------------------
AC_MSG_CHECKING([whether the RTR Library is compiled with SSH])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include "rtrlib/rtrlib.h"]],
			[[struct tr_ssh_config config;]])],
	[AC_MSG_RESULT(yes)
	AC_DEFINE(FOUND_SSH,,found_ssh)],
	AC_MSG_RESULT(no)
)

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

AC_CONFIG_FILES([Makefile
	  bgpd/Makefile
	  vtysh/Makefile
	  doc/Makefile tests/Makefile
	  bgpd/rfp-example/rfptest/Makefile bgpd/rfp-example/librfp/Makefile
	  redhat/frr.spec
	  debianpkg/Makefile
	  debianpkg/changelog
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
	  doc/eigrpd.8
	  doc/ripngd.8
	  doc/pimd.8
	  doc/mtracebis.8
	  doc/nhrpd.8
	  doc/vtysh.1
	  doc/watchfrr.8
	  doc/zebra.8
	  doc/frr.1
	  doc/frr-args.8
	  pkgsrc/bgpd.sh pkgsrc/ospf6d.sh pkgsrc/ospfd.sh
	  pkgsrc/ripd.sh pkgsrc/ripngd.sh pkgsrc/zebra.sh
	  pkgsrc/eigrpd.sh])

if test "${enable_bgp_vnc}" != "no"; then
   if test "${with_rfp_path}" != "bgpd/rfp-example" ; then
      AC_CONFIG_FILES([${with_rfp_path}/rfptest/Makefile ${with_rfp_path}/librfp/Makefile])
   fi
fi

AC_CONFIG_FILES([solaris/Makefile])

AC_CONFIG_FILES([vtysh/extract.pl],[chmod +x vtysh/extract.pl])

AC_CONFIG_COMMANDS([lib/route_types.h], [
	dst="${ac_abs_top_builddir}/lib/route_types.h"
	${PERL} "${ac_abs_top_srcdir}/lib/route_types.pl" \
		< "${ac_abs_top_srcdir}/lib/route_types.txt" \
		> "${dst}.tmp"
	test -f "${dst}" \
		&& diff "${dst}.tmp" "${dst}" >/dev/null 2>/dev/null \
		&& rm "${dst}.tmp" \
		|| mv "${dst}.tmp" "${dst}"
], [
	PERL="$PERL"
])

AS_IF([test "x$with_pkg_git_version" = "xyes"], [
    AC_CONFIG_COMMANDS([lib/gitversion.h], [
	dst="${ac_abs_top_builddir}/lib/gitversion.h"
	${PERL} "${ac_abs_top_srcdir}/lib/gitversion.pl" \
		"${ac_abs_top_srcdir}" \
		> "${dst}.tmp"
	test -f "${dst}" \
		&& diff "${dst}.tmp" "${dst}" >/dev/null 2>/dev/null \
		&& rm "${dst}.tmp" \
		|| mv "${dst}.tmp" "${dst}"
    ], [
	PERL="$PERL"
    ])
])

## Hack, but working solution to avoid rebuilding of frr.info.
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
