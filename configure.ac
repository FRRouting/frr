##
## Configure template file for FRRouting.
## autoconf will generate a configure script.
##
##  Copyright (c) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
##  Portions Copyright (c) 2003 Paul Jakma <paul@dishone.st>
##
AC_PREREQ([2.60])

AC_INIT([frr], [7.3-dev], [https://github.com/frrouting/frr/issues])
PACKAGE_URL="https://frrouting.org/"
AC_SUBST([PACKAGE_URL])
PACKAGE_FULLNAME="FRRouting"
AC_SUBST([PACKAGE_FULLNAME])

CONFIG_ARGS="`echo $ac_configure_args | sed -e \"s% '[[A-Z]]*FLAGS=[[^']]\+'%%g\"`"
AC_SUBST([CONFIG_ARGS])

AC_CONFIG_SRCDIR([lib/zebra.h])
AC_CONFIG_MACRO_DIR([m4])

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_BUILD()
AC_CANONICAL_HOST()

hosttools_clippy="false"
build_clippy="true"

dnl case 1: external clippy
if test -n "$with_clippy" -a "$with_clippy" != "no" -a "$with_clippy" != "yes"; then
  if test "$enable_clippy_only" == "yes"; then
    AC_MSG_ERROR([--enable-clippy-only does not make sense with --with-clippy])
  fi

  CLIPPY="$with_clippy"
  build_clippy="false"
  if test ! -x "$with_clippy"; then
    AC_MSG_ERROR([clippy tool ($with_clippy) is not executable])
  fi

dnl case 2: cross-compiling internal clippy
elif test "$host" != "$build"; then
  if test "$srcdir" = "."; then
    AC_MSG_ERROR([cross-compilation is only possible with builddir separate from srcdir or by building clippy separately and using the --with-clippy option.  create a separate directory and run as .../path-to-frr/configure.])
  fi
  test -d hosttools || mkdir hosttools
  abssrc="`cd \"${srcdir}\"; pwd`"

  AC_MSG_NOTICE([...])
  AC_MSG_NOTICE([... cross-compilation: creating hosttools directory and self-configuring for build platform tools])
  AC_MSG_NOTICE([... use HOST_CPPFLAGS / HOST_CFLAGS / HOST_LDFLAGS if neccessary])
  AC_MSG_NOTICE([...])

  (
    for var in $ac_precious_vars; do
      dnl special cases
      case "$var" in
      YACC|YFLAGS) continue;;
      PYTHON*)     retain=true;;
      *)           retain=false;
      esac

      eval "hostvar=\"\${HOST_$var}\""
      eval "targetvar=\"\${$var}\""
      if test -n "$hostvar"; then
        eval "$var='$hostvar'"
        _AS_ECHO_LOG([host $var='$hostvar'])
      elif $retain; then
        _AS_ECHO_LOG([host retain $var='$targetvar'])
      else
        eval "unset $var"
        _AS_ECHO_LOG([host unset $var])
      fi
    done
    cd hosttools
    "${abssrc}/configure" "--host=$build" "--build=$build" "--enable-clippy-only" "--disable-nhrpd" "--disable-vtysh"
  ) || exit 1

  AC_MSG_NOTICE([...])
  AC_MSG_NOTICE([... cross-compilation: finished self-configuring for build platform tools])
  AC_MSG_NOTICE([...])

  build_clippy="false"
  hosttools_clippy="true"
  CLIPPY="hosttools/lib/clippy"

dnl case 3: normal build internal clippy
else
  CLIPPY="lib/clippy\$(EXEEXT)"
fi
AC_SUBST([CLIPPY])
AM_CONDITIONAL([BUILD_CLIPPY], [$build_clippy])
AM_CONDITIONAL([HOSTTOOLS_CLIPPY], [$hosttools_clippy])
AM_CONDITIONAL([ONLY_CLIPPY], [test "$enable_clippy_only" = "yes"])

# Disable portability warnings -- our automake code (in particular
# common.am) uses some constructs specific to gmake.
AM_INIT_AUTOMAKE([1.12 -Wno-portability foreign])
m4_ifndef([AM_SILENT_RULES], [m4_define([AM_SILENT_RULES],[])])
AM_SILENT_RULES([yes])
AC_CONFIG_HEADERS([config.h])

AC_PATH_PROG([PERL], [perl])
PKG_PROG_PKG_CONFIG

dnl default is to match previous behavior
exampledir=${sysconfdir}
AC_ARG_ENABLE([exampledir],
	  AS_HELP_STRING([--enable-exampledir],
			 [specify alternate directory for examples]),
			 exampledir="$enableval",)
dnl XXX add --exampledir to autoconf standard directory list somehow
AC_SUBST([exampledir])

dnl default is to match previous behavior
pkgsrcrcdir=""
AC_ARG_ENABLE([pkgsrcrcdir],
	  AS_HELP_STRING([--enable-pkgsrcrcdir],
			 [specify directory for rc.d scripts]),
			 pkgsrcrcdir="$enableval",)
dnl XXX add --pkgsrcrcdir to autoconf standard directory list somehow
AC_SUBST([pkgsrcrcdir])
AM_CONDITIONAL([PKGSRC], [test "x$pkgsrcrcdir" != "x"])

AC_ARG_WITH([moduledir], [AS_HELP_STRING([--with-moduledir=DIR], [module directory (${libdir}/frr/modules)])], [
	moduledir="$withval"
], [
	moduledir="\${libdir}/frr/modules"
])
AC_SUBST([moduledir], [$moduledir])


AC_ARG_WITH([yangmodelsdir], [AS_HELP_STRING([--with-yangmodelsdir=DIR], [yang models directory (${datarootdir}/yang)])], [
	yangmodelsdir="$withval"
], [
	yangmodelsdir="\${datarootdir}/yang"
])
AC_SUBST([yangmodelsdir])

AC_ARG_ENABLE(tcmalloc,
	AS_HELP_STRING([--enable-tcmalloc], [Turn on tcmalloc]),
[case "${enableval}" in
  yes) tcmalloc_enabled=true
LIBS="$LIBS -ltcmalloc_minimal"
 ;;
  no)  tcmalloc_enabled=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-tcmalloc]) ;;
esac],[tcmalloc_enabled=false])


dnl Thanks autoconf, but we don't want a default -g -O2.  We have our own
dnl flag determination logic.
CFLAGS="${CFLAGS:-}"

dnl --------------------
dnl Check CC and friends
dnl --------------------
dnl note orig_cflags is also used further down
orig_cflags="$CFLAGS"
orig_cxxflags="$CXXFLAGS"
AC_LANG([C])
AC_PROG_CC
AC_PROG_CPP
AC_PROG_CXX
AM_PROG_CC_C_O
dnl remove autoconf default "-g -O2"
CFLAGS="$orig_cflags"
CXXFLAGS="$orig_cxxflags"
AC_PROG_CC_C99
dnl NB: see C11 below

PKG_PROG_PKG_CONFIG

dnl it's 2019, sed is sed.
SED=sed
AC_SUBST([SED])

dnl try and enable CFLAGS that are useful for FRR
dnl - specifically, options to control warnings

AC_USE_SYSTEM_EXTENSIONS
AC_DEFUN([AC_C_FLAG], [{
    m4_pushdef([cachename],[m4_translit([frr_cv_$1],[ =-+],[____])])
    AC_CACHE_CHECK([[whether $CC supports $1]], cachename, [
	AC_LANG_PUSH([C])
	ac_c_flag_save="$CFLAGS"
	CFLAGS="$CFLAGS $1"
	AC_COMPILE_IFELSE(
		[AC_LANG_PROGRAM([[]])],
		[
			cachename=yes
		], [
			cachename=no
		])
	CFLAGS="$ac_c_flag_save"
	AC_LANG_POP([C])
    ])
    if test "${cachename}" = yes; then
	m4_if([$3], [], [CFLAGS="$CFLAGS $1"], [$3])
    else
	:
	$2
    fi
    m4_popdef([cachename])
}])

AC_DEFUN([AC_LINK_IFELSE_FLAGS], [{
	AC_LANG_PUSH([C])
	ac_cflags_save="$CFLAGS"
	ac_libs_save="$LIBS"
	CFLAGS="$CFLAGS $1"
	LIBS="$LIBS $2"
	AC_LINK_IFELSE(
		[$3],
		[
			CFLAGS="$ac_cflags_save"
			LIBS="$ac_libs_save"
			m4_default([$5], [
				AC_MSG_RESULT([yes])
			])
		], [
			CFLAGS="$ac_cflags_save"
			LIBS="$ac_libs_save"
			m4_default([$4], [
				AC_MSG_RESULT([no])
			])
		])
	AC_LANG_POP([C])
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
if test "x${enable_gcov}" = "xyes"; then
   if test "z$orig_cflags" = "z"; then
      AC_C_FLAG([-coverage])
      AC_C_FLAG([-O0])
   fi

   LDFLAGS="${LDFLAGS} -lgcov"
elif test "x${enable_dev_build}" = "xyes"; then
   AC_DEFINE([DEV_BUILD], [1], [Build for development])
   if test "z$orig_cflags" = "z"; then
      AC_C_FLAG([-g3])
      AC_C_FLAG([-O0])
   fi
   if test "x${enable_lua}" = "xyes"; then
      AX_PROG_LUA([5.3])
      AX_LUA_HEADERS
      AX_LUA_LIBS([
         AC_DEFINE([HAVE_LUA], [1], [Have support for Lua interpreter])
         LIBS="$LIBS $LUA_LIB"
      ])
   fi
else
   if test "x${enable_lua}" = "xyes"; then
      AC_MSG_ERROR([Lua is not meant to be built/used outside of development at this time])
   fi
   if test "z$orig_cflags" = "z"; then
      AC_C_FLAG([-g])
      AC_C_FLAG([-O2])
   fi
fi
AM_CONDITIONAL([DEV_BUILD], [test "x$enable_dev_build" = "xyes"])

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
  AC_C_FLAG([-Wshadow])
else
  AC_C_FLAG([-Wno-unused-result])
fi
AC_C_FLAG([-Wno-unused-parameter])
AC_C_FLAG([-Wno-missing-field-initializers])

AC_C_FLAG([-Wc++-compat], [], [CXX_COMPAT_CFLAGS="-Wc++-compat"])
AC_SUBST([CXX_COMPAT_CFLAGS])

dnl ICC emits a broken warning for const char *x = a ? "b" : "c";
dnl for some reason the string consts get 'promoted' to char *,
dnl triggering a const to non-const conversion warning.
AC_C_FLAG([-diag-disable 3179])

if test x"${enable_werror}" = x"yes" ; then
  WERROR="-Werror"
fi
AC_SUBST([WERROR])

SAN_FLAGS=""
if test "$enable_address_sanitizer" = "yes"; then
  AC_C_FLAG([-fsanitize=address], [
    AC_MSG_ERROR([$CC does not support Address Sanitizer.])
  ], [
    SAN_FLAGS="$SAN_FLAGS -fsanitize=address"
  ])
fi
if test "$enable_thread_sanitizer" = "yes"; then
  AC_C_FLAG([-fsanitize=thread], [
    AC_MSG_ERROR([$CC does not support Thread Sanitizer.])
  ], [
    SAN_FLAGS="$SAN_FLAGS -fsanitize=thread"
  ])
fi
if test "$enable_memory_sanitizer" = "yes"; then
  AC_C_FLAG([-fsanitize=memory -fPIE -pie], [
    AC_MSG_ERROR([$CC does not support Memory Sanitizer.])
  ], [
    SAN_FLAGS="-fsanitize=memory -fPIE -pie"
  ])
fi
AC_SUBST([SAN_FLAGS])

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

AC_SEARCH_LIBS([pthread_condattr_setclock], [],
		[frr_cv_pthread_condattr_setclock=yes],
		[frr_cv_pthread_condattr_setclock=no])
if test "$frr_cv_pthread_condattr_setclock" = yes; then
  AC_DEFINE([HAVE_PTHREAD_CONDATTR_SETCLOCK], [1], [Have pthread.h pthread_condattr_setclock])
fi

dnl --------------
dnl Check programs
dnl --------------
AC_PROG_INSTALL
AC_PROG_LN_S
AC_CHECK_TOOL([AR], [ar])

dnl -------
dnl libtool
dnl -------
AC_ARG_ENABLE([static-bin],
  AS_HELP_STRING([--enable-static-bin], [link binaries statically]))
LT_INIT
_LT_CONFIG_LIBTOOL([
  patch -N -i "${srcdir}/m4/libtool-whole-archive.patch" libtool >&AS_MESSAGE_LOG_FD || \
    AC_MSG_WARN([Could not patch libtool for static linking support.  Loading modules into a statically linked daemon will fail.])
])
if test "$enable_static_bin" = "yes"; then
  AC_LDFLAGS="-static"
  if test "$enable_static" != "yes"; then
    AC_MSG_ERROR([The --enable-static-bin option must be combined with --enable-static.])
  fi
fi
if test "$enable_shared" != "yes"; then
  AC_MSG_ERROR([FRR cannot be built with --disable-shared.  If you want statically linked daemons, use --enable-shared --enable-static --enable-static-bin])
fi
AC_SUBST([AC_LDFLAGS])
AM_CONDITIONAL([STATIC_BIN], [test "x$enable_static_bin" = "xyes"])

dnl $AR and $RANLIB are set by LT_INIT above
AC_MSG_CHECKING([whether $AR supports D option])
if $AR crD conftest.a >/dev/null 2>/dev/null; then
  AC_MSG_RESULT([yes])
  dnl ARFLAGS is for automake, AR_FLAGS for libtool m-(
  ARFLAGS="crD"
  AR_FLAGS="crD"
else
  AC_MSG_RESULT([no])
  ARFLAGS="cru"
  AR_FLAGS="cru"
fi
AC_SUBST([ARFLAGS])
AC_SUBST([AR_FLAGS])

AC_MSG_CHECKING([whether $RANLIB supports D option])
if $RANLIB -D conftest.a >conftest.err 2>&1; then
  if grep -q -- '-D' conftest.err; then
    AC_MSG_RESULT([no])
  else
    AC_MSG_RESULT([yes])
    RANLIB="$RANLIB -D"
  fi
else
  AC_MSG_RESULT([no])
fi
AC_SUBST([RANLIB])

test -f conftest.err && rm conftest.err
test -f conftest.a && rm conftest.a

dnl ----------------------
dnl Packages configuration
dnl ----------------------
if test -f config.version; then
  . ./config.version
elif test -f "${srcdir}/config.version"; then
  . "${srcdir}/config.version"
fi
AC_ARG_WITH([pkg-extra-version],
  AS_HELP_STRING([--with-pkg-extra-version=VER], [add extra version field, for packagers/distributions]), [
  if test "$withval" = "no"; then
    EXTRAVERSION=
  else
    EXTRAVERSION=$withval
  fi
], [])
AC_ARG_WITH([pkg-git-version],
	AS_HELP_STRING([--with-pkg-git-version], [add git information to MOTD and build version string]),
	[ test "x$withval" != "xno" && with_pkg_git_version="yes" ])
AC_ARG_WITH([clippy],
  AS_HELP_STRING([--with-clippy=PATH], [use external clippy helper program]))
AC_ARG_WITH([vtysh_pager],
	AS_HELP_STRING([--with-vtysh-pager=PAGER], [control what pager is compiled in as default]),
	VTYSH_PAGER=$withval, VTYSH_PAGER="more")
AC_ARG_ENABLE([vtysh],
  AS_HELP_STRING([--disable-vtysh], [do not build integrated vty shell for FRR]))
AC_ARG_ENABLE([doc],
  AS_HELP_STRING([--disable-doc], [do not build docs]))
AC_ARG_ENABLE([doc-html],
  AS_HELP_STRING([--enable-doc-html], [build HTML docs]))
AC_ARG_ENABLE([zebra],
  AS_HELP_STRING([--disable-zebra], [do not build zebra daemon]))
AC_ARG_ENABLE([bgpd],
  AS_HELP_STRING([--disable-bgpd], [do not build bgpd]))
AC_ARG_ENABLE([ripd],
  AS_HELP_STRING([--disable-ripd], [do not build ripd]))
AC_ARG_ENABLE([ripngd],
  AS_HELP_STRING([--disable-ripngd], [do not build ripngd]))
AC_ARG_ENABLE([ospfd],
  AS_HELP_STRING([--disable-ospfd], [do not build ospfd]))
AC_ARG_ENABLE([ospf6d],
  AS_HELP_STRING([--disable-ospf6d], [do not build ospf6d]))
AC_ARG_ENABLE([ldpd],
  AS_HELP_STRING([--disable-ldpd], [do not build ldpd]))
AC_ARG_ENABLE([nhrpd],
  AS_HELP_STRING([--disable-nhrpd], [do not build nhrpd]))
AC_ARG_ENABLE([eigrpd],
  AS_HELP_STRING([--disable-eigrpd], [do not build eigrpd]))
AC_ARG_ENABLE([babeld],
  AS_HELP_STRING([--disable-babeld], [do not build babeld]))
AC_ARG_ENABLE([watchfrr],
  AS_HELP_STRING([--disable-watchfrr], [do not build watchfrr]))
AC_ARG_ENABLE([isisd],
  AS_HELP_STRING([--disable-isisd], [do not build isisd]))
AC_ARG_ENABLE([pimd],
  AS_HELP_STRING([--disable-pimd], [do not build pimd]))
AC_ARG_ENABLE([pbrd],
  AS_HELP_STRING([--disable-pbrd], [do not build pbrd]))
AC_ARG_ENABLE([sharpd],
  AS_HELP_STRING([--enable-sharpd], [build sharpd]))
AC_ARG_ENABLE([staticd],
  AS_HELP_STRING([--disable-staticd], [do not build staticd]))
AC_ARG_ENABLE([fabricd],
  AS_HELP_STRING([--disable-fabricd], [do not build fabricd]))
AC_ARG_ENABLE([vrrpd],
  AS_HELP_STRING([--disable-vrrpd], [do not build vrrpd]))
AC_ARG_ENABLE([bgp-announce],
  AS_HELP_STRING([--disable-bgp-announce,], [turn off BGP route announcement]))
AC_ARG_ENABLE([bgp-vnc],
  AS_HELP_STRING([--disable-bgp-vnc],[turn off BGP VNC support]))
AC_ARG_ENABLE([bgp-bmp],
  AS_HELP_STRING([--disable-bgp-bmp],[turn off BGP BMP support]))
AC_ARG_ENABLE([snmp],
  AS_HELP_STRING([--enable-snmp], [enable SNMP support for agentx]))
AC_ARG_ENABLE([config_rollbacks],
  AS_HELP_STRING([--enable-config-rollbacks], [enable configuration rollbacks (requires sqlite3)]))
AC_ARG_ENABLE([confd],
  AS_HELP_STRING([--enable-confd=ARG], [enable confd integration]))
AC_ARG_ENABLE([sysrepo],
  AS_HELP_STRING([--enable-sysrepo], [enable sysrepo integration]))
AC_ARG_ENABLE([grpc],
  AS_HELP_STRING([--enable-grpc], [enable the gRPC northbound plugin]))
AC_ARG_ENABLE([zeromq],
  AS_HELP_STRING([--enable-zeromq], [enable ZeroMQ handler (libfrrzmq)]))
AC_ARG_WITH([libpam],
  AS_HELP_STRING([--with-libpam], [use libpam for PAM support in vtysh]))
AC_ARG_ENABLE([ospfapi],
  AS_HELP_STRING([--disable-ospfapi], [do not build OSPFAPI to access the OSPF LSA Database]))
AC_ARG_ENABLE([ospfclient],
  AS_HELP_STRING([--disable-ospfclient], [do not build OSPFAPI client for OSPFAPI,
                          (this is the default if --disable-ospfapi is set)]))
AC_ARG_ENABLE([multipath],
  AS_HELP_STRING([--enable-multipath=ARG], [enable multipath function, ARG must be digit]))
AC_ARG_ENABLE([user],
  AS_HELP_STRING([--enable-user=USER], [user to run FRR suite as (default frr)]))
AC_ARG_ENABLE([group],
  AS_HELP_STRING([--enable-group=GROUP], [group to run FRR suite as (default frr)]))
AC_ARG_ENABLE([vty_group],
  AS_HELP_STRING([--enable-vty-group=ARG], [set vty sockets to have specified group as owner]))
AC_ARG_ENABLE([configfile_mask],
  AS_HELP_STRING([--enable-configfile-mask=ARG], [set mask for config files]))
AC_ARG_ENABLE([logfile_mask],
  AS_HELP_STRING([--enable-logfile-mask=ARG], [set mask for log files]))
AC_ARG_ENABLE([shell_access],
  AS_HELP_STRING([--enable-shell-access], [Allow users to access shell/telnet/ssh]))
AC_ARG_ENABLE([realms],
  AS_HELP_STRING([--enable-realms], [enable REALMS support under Linux]))
AC_ARG_ENABLE([rtadv],
  AS_HELP_STRING([--disable-rtadv], [disable IPV6 router advertisement feature]))
AC_ARG_ENABLE([irdp],
  AS_HELP_STRING([--disable-irdp], [enable IRDP server support in zebra (default if supported)]))
AC_ARG_ENABLE([capabilities],
  AS_HELP_STRING([--disable-capabilities], [disable using POSIX capabilities]))
AC_ARG_ENABLE([rusage],
  AS_HELP_STRING([--disable-rusage], [disable using getrusage]))
AC_ARG_ENABLE([gcc_ultra_verbose],
  AS_HELP_STRING([--enable-gcc-ultra-verbose], [enable ultra verbose GCC warnings]))
AC_ARG_ENABLE([backtrace],
  AS_HELP_STRING([--disable-backtrace,], [disable crash backtraces (default autodetect)]))
AC_ARG_ENABLE([time-check],
  AS_HELP_STRING([--disable-time-check], [disable slow thread warning messages]))
AC_ARG_ENABLE([cpu-time],
  AS_HELP_STRING([--disable-cpu-time], [disable cpu usage data gathering]))
AC_ARG_ENABLE([pcreposix],
  AS_HELP_STRING([--enable-pcreposix], [enable using PCRE Posix libs for regex functions]))
AC_ARG_ENABLE([fpm],
  AS_HELP_STRING([--enable-fpm], [enable Forwarding Plane Manager support]))
AC_ARG_ENABLE([systemd],
  AS_HELP_STRING([--enable-systemd], [enable Systemd support]))
AC_ARG_ENABLE([werror],
  AS_HELP_STRING([--enable-werror], [enable -Werror (recommended for developers only)]))
AC_ARG_ENABLE([cumulus],
  AS_HELP_STRING([--enable-cumulus], [enable Cumulus Switch Special Extensions]))
AC_ARG_ENABLE([datacenter],
  AS_HELP_STRING([--enable-datacenter], [enable Compilation for Data Center Extensions]))
AC_ARG_ENABLE([fuzzing],
  AS_HELP_STRING([--enable-fuzzing], [enable ability to fuzz various parts of FRR]))
AC_ARG_ENABLE([netlink_fuzzing],
  AS_HELP_STRING([--enable-netlink-fuzzing], [enable ability to fuzz netlink listening socket in zebra]))
AC_ARG_ENABLE([rr-semantics],
  AS_HELP_STRING([--disable-rr-semantics], [disable the v6 Route Replace semantics]))
AC_ARG_ENABLE([protobuf],
  AS_HELP_STRING([--enable-protobuf], [Enable experimental protobuf support]))
AC_ARG_ENABLE([oldvpn_commands],
  AS_HELP_STRING([--enable-oldvpn-commands], [Keep old vpn commands]))
AC_ARG_ENABLE([rpki],
  AS_HELP_STRING([--enable-rpki], [enable RPKI prefix validation support]))
AC_ARG_ENABLE([clippy-only],
  AS_HELP_STRING([--enable-clippy-only], [Only build clippy]))
AC_ARG_ENABLE([numeric_version],
  AS_HELP_STRING([--enable-numeric-version], [Only numeric digits allowed in version (for Alpine)]))
AC_ARG_ENABLE([gcov],
  AS_HELP_STRING([--enable-gcov], [Add code coverage information]))
AC_ARG_ENABLE([bfdd],
  AS_HELP_STRING([--disable-bfdd], [do not build bfdd]))
AC_ARG_ENABLE([address-sanitizer],
  AS_HELP_STRING([--enable-address-sanitizer], [enable AddressSanitizer support for detecting a wide variety of memory allocation and deallocation errors]))
AC_ARG_ENABLE([thread-sanitizer],
  AS_HELP_STRING([--enable-thread-sanitizer], [enable ThreadSanitizer support for detecting data races]))
AC_ARG_ENABLE([memory-sanitizer],
  AS_HELP_STRING([--enable-memory-sanitizer], [enable MemorySanitizer support for detecting uninitialized memory reads]))
AC_ARG_WITH([crypto],
  AS_HELP_STRING([--with-crypto=<internal|openssl>], [choose between different implementations of cryptographic functions(default value is --with-crypto=internal)]))

#if openssl, else use the internal
AS_IF([test x"${with_crypto}" = x"openssl"], [
AC_CHECK_LIB([crypto], [EVP_DigestInit], [LIBS="$LIBS -lcrypto"], [], [])
if test $ac_cv_lib_crypto_EVP_DigestInit = no; then
  AC_MSG_ERROR([build with openssl has been specified but openssl library was not found on your system])
else
  AC_DEFINE([CRYPTO_OPENSSL], [1], [Compile with openssl support])
fi
], [test x"${with_crypto}" = x"internal" || test x"${with_crypto}" = x"" ], [AC_DEFINE([CRYPTO_INTERNAL], [1], [Compile with internal cryptographic implementation])
], [AC_MSG_ERROR([Unknown value for --with-crypto])]
)

AS_IF([test "${enable_clippy_only}" != "yes"], [
AC_CHECK_HEADERS([json-c/json.h])
AC_CHECK_LIB([json-c], [json_object_get], [LIBS="$LIBS -ljson-c"], [], [-lm])
if test "$ac_cv_lib_json_c_json_object_get" = no; then
  AC_CHECK_LIB([json], [json_object_get], [LIBS="$LIBS -ljson"])
  if test "$ac_cv_lib_json_json_object_get" = no; then
      AC_MSG_ERROR([libjson is needed to compile])
  fi
fi
])

AC_ARG_ENABLE([dev_build],
    AS_HELP_STRING([--enable-dev-build], [build for development]))

AC_ARG_ENABLE([lua],
    AS_HELP_STRING([--enable-lua], [Build Lua scripting]))

if test x"${enable_time_check}" != x"no" ; then
  if test x"${enable_time_check}" = x"yes" -o x"${enable_time_check}" = x ; then
    AC_DEFINE([CONSUMED_TIME_CHECK], [5000000], [Consumed Time Check])
  else
    AC_DEFINE_UNQUOTED([CONSUMED_TIME_CHECK], [$enable_time_check], [Consumed Time Check])
  fi
fi

case "${enable_cpu_time}" in
  "no")
  AC_DEFINE([EXCLUDE_CPU_TIME], [1], [Exclude getrusage data gathering])
  ;;
  "*")
  ;;
esac

case "${enable_systemd}" in
  "no") ;;
  "yes")
  AC_CHECK_LIB([systemd], [sd_notify], [LIBS="$LIBS -lsystemd"])
  if test $ac_cv_lib_systemd_sd_notify = no; then
    AC_MSG_ERROR([enable systemd has been specified but systemd development env not found on your system])
  else
    AC_DEFINE([HAVE_SYSTEMD], [1], [Compile systemd support in])
  fi
  ;;
  "*") ;;
esac

if test "${enable_rr_semantics}" != "no" ; then
  AC_DEFINE([HAVE_V6_RR_SEMANTICS], [1], [Compile in v6 Route Replacement Semantics])
fi

if test "${enable_datacenter}" = "yes" ; then
  AC_DEFINE([HAVE_DATACENTER], [1], [Compile extensions for a DataCenter])
  DFLT_NAME="datacenter"
else
  DFLT_NAME="traditional"
fi

if test "${enable_fuzzing}" = "yes" ; then
  AC_DEFINE([HANDLE_ZAPI_FUZZING], [1], [Compile extensions to use with a fuzzer])
fi

if test "${enable_netlink_fuzzing}" = "yes" ; then
  AC_DEFINE([HANDLE_NETLINK_FUZZING], [1], [Compile extensions to use with a fuzzer for netlink])
fi

if test "${enable_cumulus}" = "yes" ; then
  AC_DEFINE([HAVE_CUMULUS], [1], [Compile Special Cumulus Code in])
fi

AC_SUBST([DFLT_NAME])
AC_DEFINE_UNQUOTED([DFLT_NAME], ["$DFLT_NAME"], [Name of the configuration default set])

if test "${enable_shell_access}" = "yes"; then
   AC_DEFINE([HAVE_SHELL_ACCESS], [1], [Allow user to use ssh/telnet/bash, be aware this is considered insecure])
fi

#
# Python for clippy
#

AS_IF([test "$host" = "$build"], [
  FRR_PYTHON_DEV
], [
  FRR_PYTHON
])

FRR_PYTHON_MODULES([pytest])

if test "${enable_doc}" != "no"; then
  FRR_PYTHON_MODULES([sphinx], , [
    if test "${enable_doc}" = "yes"; then
      AC_MSG_ERROR([Documentation was explicitly requested with --enable-doc but sphinx is not available for $PYTHON. Please disable docs or install sphinx.])
    fi
  ])
fi
AM_CONDITIONAL([DOC], [test "${enable_doc}" != "no" -a "$frr_py_mod_sphinx" != "false"])
AM_CONDITIONAL([DOC_HTML], [test "${enable_doc_html}" = "yes"])

FRR_PYTHON_MOD_EXEC([sphinx], [--version], [
  PYSPHINX="-m sphinx"
], [
  PYSPHINX="-c 'import sys; from sphinx import main; sys.exit(main(sys.argv))'"
])
AC_SUBST([PYSPHINX])

#
# Logic for old vpn commands support.
#
if test "$enable_oldvpn_commands" = "yes"; then
   AC_DEFINE([KEEP_OLD_VPN_COMMANDS], [1], [Define for compiling with old vpn commands])
fi

#
# End of logic for protobuf support.
#

AC_MSG_CHECKING([if zebra should be configurable to send Route Advertisements])
if test "${enable_rtadv}" != "no"; then
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_RTADV], [1], [Enable IPv6 Routing Advertisement support])
else
  AC_MSG_RESULT([no])
fi

if test x"${enable_user}" = x"no"; then
  enable_user=""
else
  if test x"${enable_user}" = x"yes" || test x"${enable_user}" = x""; then
    enable_user="frr"
  fi
  AC_DEFINE_UNQUOTED([FRR_USER], ["${enable_user}"], [frr User])
fi

if test x"${enable_group}" = x"no"; then
  enable_group=""
else
  if test x"${enable_group}" = x"yes" || test x"${enable_group}" = x""; then
    enable_group="frr"
  fi
  AC_DEFINE_UNQUOTED([FRR_GROUP], ["${enable_group}"], [frr Group])
fi

if test x"${enable_vty_group}" = x"yes" ; then
  AC_MSG_ERROR([--enable-vty-group requires a group as argument, not yes])
elif test x"${enable_vty_group}" != x""; then
  if test x"${enable_vty_group}" != x"no"; then
    AC_DEFINE_UNQUOTED([VTY_GROUP], ["${enable_vty_group}"], [VTY Sockets Group])
  fi
fi
AC_SUBST([enable_user])
AC_SUBST([enable_group])
AC_SUBST([enable_vty_group])

enable_configfile_mask=${enable_configfile_mask:-0600}
AC_DEFINE_UNQUOTED([CONFIGFILE_MASK], [${enable_configfile_mask}], [Mask for config files])

enable_logfile_mask=${enable_logfile_mask:-0600}
AC_DEFINE_UNQUOTED([LOGFILE_MASK], [${enable_logfile_mask}], [Mask for log files])

MPATH_NUM=16

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

AC_DEFINE_UNQUOTED([MULTIPATH_NUM], [$MPATH_NUM], [Maximum number of paths for a route])

AC_DEFINE_UNQUOTED([VTYSH_PAGER], ["$VTYSH_PAGER"], [What pager to use])

dnl --------------------
dnl Enable code coverage
dnl --------------------
AM_CONDITIONAL([HAVE_GCOV], [test '!' "$enable_gcov" = no])

dnl ------------------------------------
dnl Alpine only accepts numeric versions
dnl ------------------------------------
if test "x${enable_numeric_version}" != "x" ; then
  VERSION="`echo ${VERSION} | tr -c -d '[[.0-9]]'`"
  PACKAGE_VERSION="`echo ${PACKAGE_VERSION} | tr -c -d '[[.0-9]]'`"
fi

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
AC_SUBST([EXTRAVERSION])

if test "x$with_pkg_git_version" = "xyes"; then
	if test -d "${srcdir}/.git"; then
		AC_DEFINE([GIT_VERSION], [1], [include git version info])
	else	with_pkg_git_version="no"
		AC_MSG_WARN([--with-pkg-git-version given, but this is not a git checkout])
	fi
fi
AM_CONDITIONAL([GIT_VERSION], [test "x$with_pkg_git_version" = "xyes"])

AC_CHECK_TOOL([OBJCOPY], [objcopy], [:])
if test "x${OBJCOPY}" != "x:"; then
  AC_CACHE_CHECK([for .interp value to use], [frr_cv_interp], [
    frr_cv_interp=""
    AC_LINK_IFELSE([AC_LANG_SOURCE([[int main() { return 0; }]])], [
      if $OBJCOPY -j.interp -Obinary conftest conftest.interp; then
        frr_cv_interp="`xargs -0 echo < conftest.interp`"
      fi
      test -f conftest.interp && rm conftest.interp
    ])
  ])
fi
if test -n "$frr_cv_interp"; then
  AC_DEFINE_UNQUOTED([INTERP], ["$frr_cv_interp"], [.interp value])
fi

dnl -------------------------
dnl Check other header files.
dnl -------------------------
AC_CHECK_HEADERS([stropts.h sys/ksym.h \
	linux/version.h asm/types.h])

ac_stdatomic_ok=false
AC_DEFINE([FRR_AUTOCONF_ATOMIC], [1], [did autoconf checks for atomic funcs])
AC_CHECK_HEADER([stdatomic.h],[

  AC_MSG_CHECKING([whether _Atomic qualifier works])
  AC_LINK_IFELSE([AC_LANG_SOURCE([[
#include <stdatomic.h>
int main(int argc, char **argv) {
  _Atomic int i = 0;
  return i;
}
]])], [
    AC_DEFINE([HAVE_STDATOMIC_H], [1], [found stdatomic.h])
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
    AC_DEFINE([HAVE___ATOMIC], [1], [found __atomic builtins])
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
      AC_DEFINE([HAVE___SYNC], [1], [found __sync builtins])
      AC_MSG_RESULT([yes])

      AC_MSG_CHECKING([for __sync_swap builtin])
      AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main(int argc, char **argv) {
  volatile int i = 1;
  return __sync_swap (&i, 2);
}
]])], [
        AC_DEFINE([HAVE___SYNC_SWAP], 1, [found __sync_swap builtin])
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

AC_CHECK_HEADERS([pthread_np.h],,, [
#include <pthread.h>
])
AC_CHECK_FUNCS([pthread_setname_np pthread_set_name_np])

needsync=true

AS_IF([$needsync], [
  dnl Linux
  AC_MSG_CHECKING([for Linux futex() support])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <linux/futex.h>

int main(void);
],
[
{
  return syscall(SYS_futex, NULL, FUTEX_WAIT, 0, NULL, NULL, 0);
}
])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_SYNC_LINUX_FUTEX,,Have Linux futex support)
    needsync=false
  ], [
    AC_MSG_RESULT([no])
  ])
])

AS_IF([$needsync], [
  dnl FreeBSD
  AC_MSG_CHECKING([for FreeBSD _umtx_op() support])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/umtx.h>
int main(void);
],
[
{
  return _umtx_op(NULL, UMTX_OP_WAIT_UINT, 0, NULL, NULL);
}
])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_SYNC_UMTX_OP,,Have FreeBSD _umtx_op() support)
    needsync=false
  ], [
    AC_MSG_RESULT([no])
  ])
])

AS_IF([$needsync], [
  dnl OpenBSD patch (not upstream at the time of writing this)
  dnl https://marc.info/?l=openbsd-tech&m=147299508409549&w=2
  AC_MSG_CHECKING([for OpenBSD futex() support])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([
#include <sys/futex.h>
int main(void);
],
[
{
  return futex(NULL, FUTEX_WAIT, 0, NULL, NULL, 0);
}
])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_SYNC_OPENBSD_FUTEX,,Have OpenBSD futex support)
    needsync=false
  ], [
    AC_MSG_RESULT([no])
  ])
])

dnl Utility macro to avoid retyping includes all the time
m4_define([FRR_INCLUDES],
[#ifdef SUNOS_5
#define _POSIX_C_SOURCE 200809L
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

AC_CHECK_HEADERS([net/if_var.h], [], [], [FRR_INCLUDES])

m4_define([FRR_INCLUDES],
FRR_INCLUDES
[#if HAVE_NET_IF_VAR_H
# include <net/if_var.h>
#endif
])dnl

AC_CHECK_HEADERS([netinet/in_var.h \
	net/if_dl.h net/netopt.h \
	inet/nd.h netinet/ip_icmp.h \
	sys/sysctl.h sys/sockio.h sys/conf.h],
	[], [], [FRR_INCLUDES])

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

    AC_DEFINE([SUNOS_5], [1], [SunOS 5])
    AC_DEFINE([SOLARIS_IPV6], [1], Solaris IPv6)
    AC_DEFINE([_POSIX_C_SOURCE], [200809L], [enable POSIX.1-2008 and XPG7/SUSv4])

    AC_CHECK_LIB([socket], [main])
    AC_CHECK_LIB([nsl], [main])
    AC_CHECK_LIB([umem], [main])
    SOLARIS="solaris"
    AC_MSG_WARN([--Solaris support is being considered for deprecation, please let us know if you are still using this--])
    ;;
  linux*)
    AC_MSG_RESULT([Linux])

    AC_DEFINE([GNU_LINUX], [1], [GNU Linux])
    AC_DEFINE([HAVE_NETLINK], [1], [netlink])
    AC_DEFINE([LINUX_IPV6], [1], [Linux IPv6 stack])

    dnl Linux has a compilation problem with mixing
    dnl netinet/in.h and linux/in6.h they are not
    dnl compatible.  There has been discussion on
    dnl how to fix it but no real progress on implementation
    dnl when they fix it, remove this
    AC_DEFINE([IPV6_MINHOPCOUNT], [73], [Linux ipv6 Min Hop Count])
    ;;
  openbsd*)
    AC_MSG_RESULT([OpenBSD])

    AC_DEFINE([OPEN_BSD], [1], [OpenBSD])
    AC_DEFINE([KAME], [1], [KAME IPv6])
    AC_DEFINE([BSD_V6_SYSCTL], [1], [BSD v6 sysctl to turn on and off forwarding])

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

    AC_DEFINE([HAVE_NET_RT_IFLIST], [1], [NET_RT_IFLIST])
    AC_DEFINE([KAME], [1], [KAME IPv6])
    AC_DEFINE([BSD_V6_SYSCTL], [1], [BSD v6 sysctl to turn on and off forwarding])
    ;;
esac
AM_CONDITIONAL([SOLARIS], [test "${SOLARIS}" = "solaris"])

AC_SYS_LARGEFILE

dnl ------------------------
dnl Integrated REALMS option
dnl ------------------------
if test "${enable_realms}" = "yes"; then
    case "$host_os" in
      linux*)
       AC_DEFINE([SUPPORT_REALMS], [1], [Realms support])
       ;;
      *)
       echo "Sorry, only Linux has REALMS support"
       exit 1
       ;;
    esac
fi

dnl -------------------------------
dnl Endian-ness check
dnl -------------------------------
AC_WORDS_BIGENDIAN

dnl ---------------
dnl other functions
dnl ---------------
AC_CHECK_FUNCS([ \
	strlcat strlcpy \
	getgrouplist])

dnl ##########################################################################
dnl LARGE if block spans a lot of "configure"!
if test "${enable_clippy_only}" != "yes"; then
dnl ##########################################################################

#
# Logic for protobuf support.
#
if test "$enable_protobuf" = "yes"; then
  # Check for protoc & protoc-c

  # protoc is not required, it's only for a "be nice" helper target
  AC_CHECK_PROGS([PROTOC], [protoc], [/bin/false])

  AC_CHECK_PROGS([PROTOC_C], [protoc-c], [/bin/false])
  if test "$PROTOC_C" = "/bin/false"; then
    AC_MSG_FAILURE([protobuf requested but protoc-c not found.  Install protobuf-c.])
  fi

  PKG_CHECK_MODULES([PROTOBUF_C], [libprotobuf-c >= 0.14],, [
    AC_MSG_FAILURE([protobuf requested but libprotobuf-c not found.  Install protobuf-c.])
  ])
  AC_CHECK_HEADER([google/protobuf-c/protobuf-c.h], [], [
    AC_MSG_FAILURE([protobuf requested but protobuf-c.h not found.  Install protobuf-c.])
  ])

  AC_DEFINE([HAVE_PROTOBUF], [1], [protobuf])
fi


dnl ---------------------
dnl Integrated VTY option
dnl ---------------------
case "${enable_vtysh}" in
"no")
  VTYSH="";;
*)
  VTYSH="vtysh";
  AC_DEFINE([VTYSH], [1], [VTY shell])

  prev_libs="$LIBS"
  AC_CHECK_LIB([readline], [main], [
    LIBREADLINE="-lreadline"
  ], [
    dnl readline failed - it might be incorrectly linked and missing its
    dnl termcap/tinfo/curses dependency.  see if we can fix that...
    AC_SEARCH_LIBS([tputs], [termcap tinfo curses ncurses], [
      LIBREADLINE="$ac_cv_search_tputs"
    ], [
      AC_MSG_ERROR([libreadline (needed for vtysh) not found and/or missing dependencies])
    ])

    dnl re-try with the lib we found above
    unset ac_cv_lib_readline_main
    AC_CHECK_LIB([readline], [main], [
      LIBREADLINE="-lreadline $LIBREADLINE"
    ], [
      AC_MSG_ERROR([libreadline (needed for vtysh) not found and/or missing dependencies])
    ], [$LIBREADLINE])
  ], [])
  LIBS="$prev_libs"

  AC_CHECK_HEADER([readline/history.h])
  if test $ac_cv_header_readline_history_h = no;then
    AC_MSG_ERROR([readline is too old to have readline/history.h, please update to the latest readline library.])
  fi
  AC_CHECK_LIB([readline], [rl_completion_matches], [true], [], [$LIBREADLINE])
  if test $ac_cv_lib_readline_rl_completion_matches = no; then
    AC_DEFINE([rl_completion_matches], [completion_matches], [Old readline])
  fi
  AC_CHECK_LIB([readline], [append_history], [frr_cv_append_history=yes], [frr_cv_append_history=no], [$LIBREADLINE])
  if test "$frr_cv_append_history" = yes; then
    AC_DEFINE([HAVE_APPEND_HISTORY], [1], [Have history.h append_history])
  fi
  ;;
esac
AC_SUBST([LIBREADLINE])

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
    [AC_DEFINE([HAVE_PAM_MISC_H], [1], [Have pam_misc.h])
     AC_DEFINE([PAM_CONV_FUNC], [misc_conv], [Have misc_conv])
     pam_conv_func="misc_conv"
    ],
    [], FRR_INCLUDES)
  AC_CHECK_HEADER([security/openpam.h],
    [AC_DEFINE([HAVE_OPENPAM_H], [1], [Have openpam.h])
     AC_DEFINE([PAM_CONV_FUNC], [openpam_ttyconv], [Have openpam_ttyconv])
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
AC_CHECK_LIB([pam], [pam_start],
  [AC_CHECK_LIB([pam], [$pam_conv_func],
    [AC_DEFINE([USE_PAM], [1], [Use PAM for authentication])
     LIBPAM="-lpam"],
    [AC_DEFINE([USE_PAM], [1], [Use PAM for authentication])
     LIBPAM="-lpam -lpam_misc"]
    )
  ],

  [AC_CHECK_LIB([pam], [pam_end],
    [AC_CHECK_LIB([pam], [$pam_conv_func],
      [AC_DEFINE([USE_PAM], [1], [Use PAM for authentication])
       LIBPAM="-lpam -ldl"],
      [AC_DEFINE([USE_PAM], [1], [Use PAM for authentication])
       LIBPAM="-lpam -ldl -lpam_misc"]
     )
  ],AC_MSG_WARN([*** pam support will not be built ***]),
  [-ldl])
  ]
)
fi
AC_SUBST([LIBPAM])

dnl -------------------------------
dnl bgpd needs pow() and hence libm
dnl -------------------------------
TMPLIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS([pow], [m], [
  LIBM="$LIBS"
], [
  AC_MSG_WARN([Unable to find working pow function - bgpd may not link])
])
LIBS="$TMPLIBS"
AC_SUBST([LIBM])

AC_CHECK_FUNCS([ppoll], [
  AC_DEFINE([HAVE_PPOLL], [1], [have Linux/BSD ppoll()])
])
AC_CHECK_FUNCS([pollts], [
  AC_DEFINE([HAVE_POLLTS], [1], [have NetBSD pollts()])
])

AC_CHECK_HEADER([asm-generic/unistd.h],
                [AC_CHECK_DECL(__NR_setns,
                               AC_DEFINE([HAVE_NETNS], [1], [Have netns]),,
                               FRR_INCLUDES [#include <asm-generic/unistd.h>
                               ])
                 AC_CHECK_FUNCS([setns])]
               )

dnl --------------------------
dnl Determine IS-IS I/O method
dnl --------------------------
AC_DEFINE([ISIS_METHOD_PFPACKET], [1], [constant value for isis method pfpacket])
AC_DEFINE([ISIS_METHOD_DLPI], [2], [constant value for isis method dlpi])
AC_DEFINE([ISIS_METHOD_BPF], [3], [constant value for isis method bpf])
AC_CHECK_HEADER([net/bpf.h])
AC_CHECK_HEADER([sys/dlpi.h])
AC_MSG_CHECKING([zebra IS-IS I/O method])

case "$host_os" in
  linux*)
    AC_MSG_RESULT([pfpacket])
    ISIS_METHOD_MACRO="ISIS_METHOD_PFPACKET"
    ;;
  solaris* | sunos*)
    AC_MSG_RESULT([DLPI])
    ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
    ;;
  *)
    if test $ac_cv_header_net_bpf_h = no; then
      if test $ac_cv_header_sys_dlpi_h = no; then
        AC_MSG_RESULT([none])
        if test "${enable_isisd}" = yes -o "${enable_fabricd}" = yes; then
          AC_MSG_FAILURE([IS-IS support requested but no packet backend found])
        fi
        AC_MSG_WARN([*** IS-IS support will not be built ***])
        enable_isisd="no"
        enable_fabricd="no"
      else
        AC_MSG_RESULT([DLPI])
      fi
      ISIS_METHOD_MACRO="ISIS_METHOD_DLPI"
    else
      AC_MSG_RESULT([BPF])
      ISIS_METHOD_MACRO="ISIS_METHOD_BPF"
    fi
    ;;
esac
AC_DEFINE_UNQUOTED([ISIS_METHOD], [$ISIS_METHOD_MACRO], [selected method for isis, == one of the constants])

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
#endif],[AC_MSG_RESULT([yes])
AC_DEFINE([HAVE_BSD_STRUCT_IP_MREQ_HACK], [1], [Can pass ifindex in struct ip_mreq])],
AC_MSG_RESULT([no]))

AC_MSG_CHECKING([for RFC3678 protocol-independed API])
AC_TRY_COMPILE([
#include <sys/types.h>
#include <netinet/in.h>
], [struct group_req gr; int sock; setsockopt(sock, IPPROTO_IP, MCAST_JOIN_GROUP, (void*)&gr, sizeof(gr));
], [AC_MSG_RESULT([yes])
AC_DEFINE([HAVE_RFC3678], [1], [Have RFC3678 protocol-independed API])],
AC_MSG_RESULT([no]))

dnl ---------------------------------------------------------------
dnl figure out how to check link-state
dnl ---------------------------------------------------------------
AC_CHECK_HEADER([net/if_media.h],
  [m4_define([LINK_DETECT_INCLUDES],
    FRR_INCLUDES
    [#include <net/if_media.h>
  ])
  AC_CHECK_MEMBERS([struct ifmediareq.ifm_status],
    AC_DEFINE([HAVE_BSD_LINK_DETECT], [1], [BSD link-detect]),
    [], LINK_DETECT_INCLUDES)], 
  [],
  FRR_INCLUDES)

dnl ---------------------------------------------------------------
dnl Additional, newer way to check link-state using ifi_link_state.
dnl Not available in all BSD's when ifmediareq available
dnl ---------------------------------------------------------------
AC_CHECK_MEMBERS([struct if_data.ifi_link_state],
  AC_DEFINE([HAVE_BSD_IFI_LINK_STATE], [1], [BSD ifi_link_state available]),
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

AC_SUBST([SOLARIS])
AC_CHECK_LIB([crypt], [crypt], [],
		    [AC_CHECK_LIB([crypto], [DES_crypt])])
AC_CHECK_LIB([resolv], [res_init])

dnl ---------------------------
dnl check system has PCRE regexp
dnl ---------------------------
if test "x$enable_pcreposix" = "xyes"; then
  AC_CHECK_LIB([pcreposix], [regexec], [], [
    AC_MSG_ERROR([--enable-pcreposix given but unable to find libpcreposix])
  ])
fi
AC_SUBST([HAVE_LIBPCREPOSIX])

dnl ##########################################################################
dnl test "${enable_clippy_only}" != "yes"
fi
dnl END OF LARGE if block
dnl ##########################################################################

dnl ------------------
dnl check C-Ares library
dnl ------------------
PKG_CHECK_MODULES([CARES], [libcares], [
  c_ares_found=true
],[
  c_ares_found=false
])
AM_CONDITIONAL([CARES], [$c_ares_found])


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

dnl --------------------
dnl Daemon disable check
dnl --------------------

AS_IF([test "${enable_ldpd}" != "no"], [
  AC_DEFINE([HAVE_LDPD], [1], [ldpd])
])

if test "$enable_bfdd" = "no"; then
  AC_DEFINE([HAVE_BFDD], [0], [bfdd])
  BFDD=""
else
  AC_DEFINE([HAVE_BFDD], [1], [bfdd])
  BFDD="bfdd"

  case $host_os in
    linux*)
      AC_DEFINE([BFD_LINUX], [1], [bfdd])
      ;;

    *)
      AC_DEFINE([BFD_BSD], [1], [bfdd])
      ;;
  esac
fi

if test "$ac_cv_lib_json_c_json_object_get" = no -a "x$BFDD" = "xbfdd"; then
  AC_MSG_ERROR(["you must use json-c library to use bfdd"])
fi

NHRPD=""
case "$host_os" in
  linux*)
    case "${enable_nhrpd}" in
      no)
        ;;
      yes)
	if test "${enable_clippy_only}" != "yes"; then
        if test "$c_ares_found" != "true" ; then
          AC_MSG_ERROR([nhrpd requires libcares.  Please install c-ares and its -dev headers.])
        fi
	fi
        NHRPD="nhrpd"
        ;;
      *)
        if test "$c_ares_found" = "true" ; then
          NHRPD="nhrpd"
        fi
        ;;
    esac
    ;;
  *)
    if test "${enable_nhrpd}" = "yes"; then
      AC_MSG_ERROR([nhrpd requires kernel APIs that are only present on Linux.])
    fi
    ;;
esac

if test "${enable_watchfrr}" = "no";then
  WATCHFRR=""
else
  WATCHFRR="watchfrr"
fi

OSPFCLIENT=""
if test "${enable_ospfapi}" != "no";then
    AC_DEFINE([SUPPORT_OSPF_API], [1], [OSPFAPI])

  if test "${enable_ospfclient}" != "no";then
      OSPFCLIENT="ospfclient"
  fi
fi

if test "${enable_bgp_announce}" = "no";then
  AC_DEFINE([DISABLE_BGP_ANNOUNCE], [1], [Disable BGP installation to zebra])
else
  AC_DEFINE([DISABLE_BGP_ANNOUNCE], [0], [Disable BGP installation to zebra])
fi

if test "${enable_bgp_vnc}" != "no";then
  AC_DEFINE([ENABLE_BGP_VNC], [1], [Enable BGP VNC support])
fi

bgpd_bmp=false
case "${enable_bmp}" in
  no)
    ;;
  yes)
    if test "$c_ares_found" != "true" ; then
      AC_MSG_ERROR([BMP support requires libcares.  Please install c-ares and its -dev headers.])
    fi
    bgpd_bmp=true
    ;;
  *)
    if test "$c_ares_found" = "true" ; then
      bgpd_bmp=true
    fi
    ;;
esac

dnl ##########################################################################
dnl LARGE if block
if test "${enable_clippy_only}" != "yes"; then
dnl ##########################################################################

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
   # net-snmp lists all of its own dependencies.  we absolutely do not want that
   # among other things we avoid a GPL vs. OpenSSL license conflict here
   for removelib in crypto ssl sensors pci wrap; do
     SNMP_LIBS="`echo $SNMP_LIBS | sed -e 's/\(^\|\s\)-l'$removelib'\b/ /g' -e 's/\(^\|\s\)\([^\s]*\/\)\?lib'$removelib'\.[^\s]\+\b/ /g'`"
   done
   AC_MSG_CHECKING([whether we can link to Net-SNMP])
   AC_LINK_IFELSE_FLAGS([$SNMP_CFLAGS], [$SNMP_LIBS], [AC_LANG_PROGRAM([
int main(void);
],
[
{
  return 0;
}
])], [
     AC_MSG_RESULT([no])
     AC_MSG_ERROR([--enable-snmp given but not usable])])
   case "${enable_snmp}" in
     yes)
      SNMP_METHOD=agentx
      ;;
     agentx)
      SNMP_METHOD="${enable_snmp}"
      ;;
     *)
      AC_MSG_ERROR([--enable-snmp given with an unknown method (${enable_snmp}). Use yes or agentx])
      ;;
   esac
   AH_TEMPLATE([SNMP_AGENTX], [Use SNMP AgentX to interface with snmpd])
   AC_DEFINE_UNQUOTED(AS_TR_CPP(SNMP_${SNMP_METHOD}),,[SNMP method to interface with snmpd])
fi
AC_SUBST([SNMP_LIBS])
AC_SUBST([SNMP_CFLAGS])

dnl ---------------
dnl libyang
dnl ---------------
PKG_CHECK_MODULES([LIBYANG], [libyang >= 0.16.105], , [
  AC_MSG_ERROR([libyang (>= 0.16.105) was not found on your system.])
])
ac_cflags_save="$CFLAGS"
CFLAGS="$CFLAGS $LIBYANG_CFLAGS"
AC_CHECK_MEMBER([struct lyd_node.priv], [], [
  AC_MSG_ERROR([m4_normalize([
    libyang needs to be compiled with ENABLE_LYD_PRIV=ON.
    Instructions for this are included in the build documentation for your platform at http://docs.frrouting.org/projects/dev-guide/en/latest/building.html])
  ])
], [[#include <libyang/libyang.h>]])
CFLAGS="$ac_cflags_save"

dnl ---------------
dnl configuration rollbacks
dnl ---------------
SQLITE3=false
if test "$enable_config_rollbacks" = "yes"; then
  PKG_CHECK_MODULES([SQLITE3], [sqlite3], [
    AC_DEFINE([HAVE_CONFIG_ROLLBACKS], [1], [Enable configuration rollbacks])
    AC_DEFINE([HAVE_SQLITE3], [1], [Enable sqlite3 database])
    SQLITE3=true
  ], [
    AC_MSG_ERROR([--enable-config-rollbacks given but sqlite3 was not found on your system.])
  ])
fi

dnl ---------------
dnl confd
dnl ---------------
if test "$enable_confd" != "" -a "$enable_confd" != "no"; then
   AC_CHECK_PROG([CONFD], [confd], [confd], [/bin/false], "${enable_confd}/bin")
   if test "x$CONFD" = "x/bin/false"; then
      AC_MSG_ERROR([confd was not found on your system.])]
   fi
   CONFD_CFLAGS="-I${enable_confd}/include -L${enable_confd}/lib"
   AC_SUBST([CONFD_CFLAGS])
   CONFD_LIBS="-lconfd"
   AC_SUBST([CONFD_LIBS])
   AC_DEFINE([HAVE_CONFD], [1], [Enable confd integration])
fi

dnl ---------------
dnl sysrepo
dnl ---------------
if test "$enable_sysrepo" = "yes"; then
  PKG_CHECK_MODULES([SYSREPO], [libsysrepo],
      [AC_DEFINE([HAVE_SYSREPO], [1], [Enable sysrepo integration])
      SYSREPO=true],
      [SYSREPO=false
      AC_MSG_ERROR([sysrepo was not found on your system.])]
  )
fi

dnl ---------------
dnl gRPC
dnl ---------------
if test "$enable_grpc" = "yes"; then
  PKG_CHECK_MODULES([GRPC], [grpc grpc++ protobuf], [
    AC_CHECK_PROGS([PROTOC], [protoc], [/bin/false])
    if test "$PROTOC" = "/bin/false"; then
      AC_MSG_FAILURE([grpc requested but protoc not found.])
    fi

    AC_DEFINE([HAVE_GRPC], [1], [Enable the gRPC northbound plugin])
    GRPC=true
  ], [
    GRPC=false
    AC_MSG_ERROR([grpc/grpc++ were not found on your system.])
  ])
fi

dnl ------
dnl ZeroMQ
dnl ------
if test "x$enable_zeromq" != "xno"; then
  PKG_CHECK_MODULES([ZEROMQ], [libzmq >= 4.0.0], [
    AC_DEFINE([HAVE_ZEROMQ], [1], [Enable ZeroMQ support])
    ZEROMQ=true
  ], [
    if test "x$enable_zeromq" = "xyes"; then
      AC_MSG_ERROR([configuration specifies --enable-zeromq but libzmq was not found])
    fi
  ])
fi

dnl ------------------------------------
dnl Enable RPKI and add librtr to libs
dnl ------------------------------------
if test "${enable_rpki}" = "yes"; then
  PKG_CHECK_MODULES([RTRLIB], [rtrlib >= 0.5.0],
      [RPKI=true],
      [RPKI=false
      AC_MSG_ERROR([rtrlib was not found on your system or is too old.])]
  )
fi

dnl ------------------------------------------
dnl Check whether rtrlib was build with ssh support
dnl ------------------------------------------
AC_MSG_CHECKING([whether the RTR Library is compiled with SSH])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include "rtrlib/rtrlib.h"]],
			[[struct tr_ssh_config config;]])],
	[AC_MSG_RESULT([yes])
	AC_DEFINE([FOUND_SSH], [1], [found_ssh])],
	AC_MSG_RESULT([no])
)

dnl ---------------
dnl dlopen & dlinfo
dnl ---------------
AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_ERROR([unable to find the dlopen()])
])

AC_CHECK_HEADERS([link.h])

AC_CACHE_CHECK([for dlinfo(RTLD_DI_ORIGIN)], [frr_cv_rtld_di_origin], [
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
    frr_cv_rtld_di_origin=yes
  ], [
    frr_cv_rtld_di_origin=no
  ])
])
if test "$frr_cv_rtld_di_origin" = yes; then
  AC_DEFINE([HAVE_DLINFO_ORIGIN], [1], [Have dlinfo RTLD_DI_ORIGIN])
fi

AC_CACHE_CHECK([for dlinfo(RTLD_DI_LINKMAP)], [frr_cv_rtld_di_linkmap], [
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
    frr_cv_rtld_di_linkmap=yes
  ], [
    frr_cv_rtld_di_linkmap=no
  ])
])
if test "$frr_cv_rtld_di_linkmap" = yes; then
  AC_DEFINE([HAVE_DLINFO_LINKMAP], [1], [Have dlinfo RTLD_DI_LINKMAP])
fi

dnl ##########################################################################
dnl test "${enable_clippy_only}" != "yes"
fi
dnl END OF LARGE if block
dnl ##########################################################################

dnl ---------------------------
dnl sockaddr and netinet checks
dnl ---------------------------
AC_CHECK_TYPES([
	struct sockaddr_dl,
	struct vifctl, struct mfcctl, struct sioc_sg_req,
	vifi_t, struct sioc_vif_req, struct igmpmsg,
	struct ifaliasreq, struct if6_aliasreq, struct in6_aliasreq,
	struct nd_opt_adv_interval,
	struct nd_opt_homeagent_info, struct nd_opt_adv_interval,
	struct nd_opt_rdnss, struct nd_opt_dnssl],
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


dnl -----------------------
dnl checking for IP_PKTINFO
dnl -----------------------
AC_MSG_CHECKING([for IP_PKTINFO])
AC_TRY_COMPILE([#include <netdb.h>], [
  int opt = IP_PKTINFO;
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_IP_PKTINFO], [1], [Have IP_PKTINFO])
], [
  AC_MSG_RESULT([no])
])

dnl ---------------------------
dnl checking for IP_RECVDSTADDR
dnl ---------------------------
AC_MSG_CHECKING([for IP_RECVDSTADDR])
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_RECVDSTADDR;
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_IP_RECVDSTADDR], [1], [Have IP_RECVDSTADDR])
], [
  AC_MSG_RESULT([no])
])

dnl ----------------------
dnl checking for IP_RECVIF
dnl ----------------------
AC_MSG_CHECKING([for IP_RECVIF])
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_RECVIF;
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_IP_RECVIF], [1], [Have IP_RECVIF])
], [
  AC_MSG_RESULT([no])
])

dnl ----------------------
dnl checking for SO_BINDANY
dnl ----------------------
AC_MSG_CHECKING([for SO_BINDANY])
AC_TRY_COMPILE([#include <sys/socket.h>], [
  int opt = SO_BINDANY;
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_SO_BINDANY], [1], [Have SO_BINDANY])
], [
  AC_MSG_RESULT([no])
])

dnl ----------------------
dnl checking for IP_FREEBIND
dnl ----------------------
AC_MSG_CHECKING([for IP_FREEBIND])
AC_TRY_COMPILE([#include <netinet/in.h>], [
  int opt = IP_FREEBIND;
], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_IP_FREEBIND], [1], [Have IP_FREEBIND])
], [
  AC_MSG_RESULT([no])
])

dnl --------------------------------------
dnl checking for be32dec existence or not
dnl --------------------------------------
AC_CHECK_DECLS([be32enc, be32dec], [], [],
	       [#include <sys/endian.h>])

dnl --------------------------------------
dnl checking for clock_time monotonic struct and call
dnl --------------------------------------
AC_CHECK_DECL([CLOCK_MONOTONIC],
	[AC_CHECK_LIB([rt], [clock_gettime], [LIBS="$LIBS -lrt"])
	 AC_DEFINE([HAVE_CLOCK_MONOTONIC], [1], [Have monotonic clock])
], [AC_MSG_RESULT([no])], [FRR_INCLUDES])

dnl --------------------------------------
dnl checking for flex and bison
dnl --------------------------------------

AM_PROG_LEX
AC_MSG_CHECKING([version of flex])
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
AC_MSG_CHECKING([version of bison])
frr_ac_bison_version="$(eval $YACC -V | grep bison | head -n 1)"
frr_ac_bison_version="${frr_ac_bison_version##* }"
frr_ac_bison_missing="false"
case "x${frr_ac_bison_version}x" in
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
  x3.[012][^0-9]*)
    BISON_OPENBRACE='{'
    BISON_CLOSEBRACE='}'
    BISON_VERBOSE='-Dparse.error=verbose'
    AC_MSG_RESULT([$frr_ac_bison_version - 3.0 to 3.2])
    ;;
  *)
    BISON_OPENBRACE='{'
    BISON_CLOSEBRACE='}'
    BISON_VERBOSE='-Dparse.error=verbose -Wno-yacc'
    AC_MSG_RESULT([$frr_ac_bison_version - 3.3 or newer])
    ;;
esac
AC_SUBST([BISON_OPENBRACE])
AC_SUBST([BISON_CLOSEBRACE])
AC_SUBST([BISON_VERBOSE])

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
  AC_MSG_CHECKING([whether prctl PR_SET_KEEPCAPS is available])
  AC_TRY_COMPILE([#include <sys/prctl.h>], [prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);],
    [AC_MSG_RESULT([yes])
     AC_DEFINE([HAVE_PR_SET_KEEPCAPS], [1], [prctl])
     frr_ac_keepcaps="yes"],
     AC_MSG_RESULT([no])
  )
  if test x"${frr_ac_keepcaps}" = x"yes"; then
    AC_CHECK_HEADERS([sys/capability.h])
  fi
  if test x"${ac_cv_header_sys_capability_h}" = x"yes"; then
    AC_CHECK_LIB([cap], [cap_init], 
      [AC_DEFINE([HAVE_LCAPS], [1], [Capabilities])
       LIBCAP="-lcap"
       frr_ac_lcaps="yes"]
    )
  else
    AC_CHECK_HEADERS([priv.h],
     [AC_MSG_CHECKING([Solaris style privileges are available])
      AC_TRY_COMPILE([#include <priv.h>], [getpflags(PRIV_AWARE);],
    	  [AC_MSG_RESULT([yes])
    	   AC_DEFINE([HAVE_SOLARIS_CAPABILITIES], [1], [getpflags])
    	   frr_ac_scaps="yes"],
    	   AC_MSG_RESULT(no)
      )
     ]
   )
  fi
  if test x"${frr_ac_scaps}" = x"yes" \
       -o x"${frr_ac_lcaps}" = x"yes"; then
    AC_DEFINE([HAVE_CAPABILITIES], [1], [capabilities])
  fi

  case "$host_os" in
  linux*)
    if test "${enable_clippy_only}" != "yes"; then
    if test "$frr_ac_lcaps" != "yes"; then
      AC_MSG_ERROR([libcap and/or its headers were not found.  Running FRR without libcap support built in causes a huge performance penalty.])
    fi
    fi
    ;;
  esac
else
  case "$host_os" in
  linux*)
    AC_MSG_WARN([Running FRR without libcap support built in causes a huge performance penalty.])
    ;;
  esac
fi
AC_SUBST([LIBCAP])

dnl ---------------------------
dnl check for glibc 'backtrace'
dnl --------------------------- 
if test x"${enable_backtrace}" != x"no" ; then
  backtrace_ok=no
  PKG_CHECK_MODULES([UNWIND], [libunwind], [
    AC_DEFINE([HAVE_LIBUNWIND], [1], [libunwind])
    backtrace_ok=yes
  ], [
    case "$host_os" in
    sunos* | solaris2*)
      AC_CHECK_FUNCS([printstack], [
        AC_DEFINE([HAVE_PRINTSTACK], [1], [Solaris printstack])
        backtrace_ok=yes
      ])
      ;;
    esac
    if test "$backtrace_ok" = no; then
      AC_CHECK_HEADER([execinfo.h], [
        AC_SEARCH_LIBS([backtrace], [execinfo], [
          AC_DEFINE([HAVE_GLIBC_BACKTRACE], [1], [Glibc backtrace])
          backtrace_ok=yes
        ],, [-lm])
      ])
    fi
  ])

  if test x"${enable_backtrace}" = x"yes" -a x"${backtrace_ok}" = x"no"; then
    dnl user explicitly requested backtrace but we failed to find support
    AC_MSG_FAILURE([failed to find backtrace or libunwind support])
  fi
fi

dnl -----------------------------------------
dnl check for malloc mallinfo struct and call
dnl this must try and link using LIBS, in
dnl order to check no alternative allocator
dnl has been specified, which might not provide
dnl mallinfo, e.g. such as Umem on Solaris.
dnl -----------------------------------------
AC_CHECK_HEADERS([malloc.h malloc_np.h malloc/malloc.h],,, [FRR_INCLUDES])

AC_CACHE_CHECK([whether mallinfo is available], [frr_cv_mallinfo], [
  AC_LINK_IFELSE([AC_LANG_PROGRAM([FRR_INCLUDES [
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_NP_H
#include <malloc_np.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
]], [[
struct mallinfo ac_x; ac_x = mallinfo ();
]])], [
    frr_cv_mallinfo=yes
  ], [
    frr_cv_mallinfo=no
  ])
])
if test "$frr_cv_mallinfo" = yes; then
  AC_DEFINE([HAVE_MALLINFO], [1], [mallinfo])
fi

AC_MSG_CHECKING([whether malloc_usable_size is available])
AC_LINK_IFELSE([AC_LANG_PROGRAM([FRR_INCLUDES [
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
]], [[
size_t ac_x; ac_x = malloc_usable_size(NULL);
]])], [
  AC_MSG_RESULT([yes])
  AC_DEFINE([HAVE_MALLOC_USABLE_SIZE], [1], [malloc_usable_size])
], [
  AC_MSG_RESULT([no])

  AC_MSG_CHECKING([whether malloc_size is available])
  AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
]], [[
size_t ac_x; ac_x = malloc_size(NULL);
]])], [
    AC_MSG_RESULT([yes])
    AC_DEFINE([HAVE_MALLOC_SIZE], [1], [malloc_size])
  ], [
    AC_MSG_RESULT([no])
  ])
])

dnl ----------
dnl configure date
dnl ----------
dev_version=`echo $VERSION | grep dev`
#don't expire deprecated code in non 'dev' branch
if test "${dev_version}" = ""; then
   CONFDATE=0
else
   CONFDATE=`date '+%Y%m%d'`
fi
AC_SUBST([CONFDATE])

dnl ------------------------------
dnl set paths for state directory
dnl ------------------------------
AC_MSG_CHECKING([directory to use for state file])
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
    AC_MSG_ERROR([STATE DIRECTORY NOT FOUND! FIX OR SPECIFY --localstatedir!])
fi
AC_MSG_RESULT([${frr_statedir}])
AC_SUBST([frr_statedir])

AC_DEFINE_UNQUOTED([LDPD_SOCKET], ["$frr_statedir%s%s/ldpd.sock"], [ldpd control socket])
AC_DEFINE_UNQUOTED([ZEBRA_SERV_PATH], ["$frr_statedir%s%s/zserv.api"], [zebra api socket])
AC_DEFINE_UNQUOTED([BFDD_CONTROL_SOCKET], ["$frr_statedir%s%s/bfdd.sock"], [bfdd control socket])
AC_DEFINE_UNQUOTED([DAEMON_VTY_DIR], ["$frr_statedir%s%s"], [daemon vty directory])
AC_DEFINE_UNQUOTED([DAEMON_DB_DIR], ["$frr_statedir"], [daemon database directory])

dnl autoconf does this, but it does it too late...
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

dnl get the full path, recursing through variables...
vtysh_bin="$bindir/vtysh"
for I in 1 2 3 4 5 6 7 8 9 10; do
	eval vtysh_bin="\"$vtysh_bin\""
done
AC_DEFINE_UNQUOTED([VTYSH_BIN_PATH], ["$vtysh_bin"], [path to vtysh binary])
AC_SUBST([vtysh_bin])

CFG_SYSCONF="$sysconfdir"
CFG_SBIN="$sbindir"
CFG_STATE="$frr_statedir"
CFG_MODULE="$moduledir"
CFG_YANGMODELS="$yangmodelsdir"
for I in 1 2 3 4 5 6 7 8 9 10; do
	eval CFG_SYSCONF="\"$CFG_SYSCONF\""
	eval CFG_SBIN="\"$CFG_SBIN\""
	eval CFG_STATE="\"$CFG_STATE\""
	eval CFG_MODULE="\"$CFG_MODULE\""
	eval CFG_YANGMODELS="\"$CFG_YANGMODELS\""
done
AC_SUBST([CFG_SYSCONF])
AC_SUBST([CFG_SBIN])
AC_SUBST([CFG_STATE])
AC_SUBST([CFG_MODULE])
AC_SUBST([CFG_YANGMODELS])
AC_DEFINE_UNQUOTED([MODULE_PATH], ["$CFG_MODULE"], [path to modules])
AC_DEFINE_UNQUOTED([YANG_MODELS_PATH], ["$CFG_YANGMODELS"], [path to YANG data models])
AC_DEFINE_UNQUOTED([WATCHFRR_SH_PATH], ["${CFG_SBIN%/}/watchfrr.sh"], [path to watchfrr.sh])

dnl various features
AM_CONDITIONAL([SUPPORT_REALMS], [test "${enable_realms}" = "yes"])
AM_CONDITIONAL([ENABLE_BGP_VNC], [test x${enable_bgp_vnc} != xno])
AM_CONDITIONAL([BGP_BMP], [$bgpd_bmp])
dnl northbound
AM_CONDITIONAL([SQLITE3], [$SQLITE3])
AM_CONDITIONAL([CONFD], [test "x$enable_confd" != "x"])
AM_CONDITIONAL([SYSREPO], [test "x$enable_sysrepo" = "xyes"])
AM_CONDITIONAL([GRPC], [test "x$enable_grpc" = "xyes"])
AM_CONDITIONAL([ZEROMQ], [test "x$ZEROMQ" = "xtrue"])
dnl plugins
AM_CONDITIONAL([RPKI], [test "x$RPKI" = "xtrue"])
AM_CONDITIONAL([SNMP], [test "x$SNMP_METHOD" = "xagentx"])
AM_CONDITIONAL([IRDP], [$IRDP])
AM_CONDITIONAL([FPM], [test "x$enable_fpm" = "xyes"])
AM_CONDITIONAL([HAVE_PROTOBUF], [test "x$enable_protobuf" = "xyes"])
dnl daemons
AM_CONDITIONAL([VTYSH], [test "x$VTYSH" = "xvtysh"])
AM_CONDITIONAL([ZEBRA], [test "${enable_zebra}" != "no"])
AM_CONDITIONAL([BGPD], [test "x${enable_bgpd}" != "no"])
AM_CONDITIONAL([RIPD], [test "${enable_ripd}" != "no"])
AM_CONDITIONAL([OSPFD], [test "${enable_ospfd}" != "no"])
AM_CONDITIONAL([LDPD], [test "${enable_ldpd}" != "no"])
AM_CONDITIONAL([BFDD], [test "x$BFDD" = "xbfdd"])
AM_CONDITIONAL([NHRPD], [test "x$NHRPD" = "xnhrpd"])
AM_CONDITIONAL([EIGRPD], [test "${enable_eigrpd}" != "no"])
AM_CONDITIONAL([WATCHFRR], [test "x$WATCHFRR" = "xwatchfrr"])
AM_CONDITIONAL([OSPFCLIENT], [test "x$OSPFCLIENT" = "xospfclient"])
AM_CONDITIONAL([RIPNGD], [test "${enable_ripngd}" != "no"])
AM_CONDITIONAL([BABELD], [test "${enable_babeld}" != "no"])
AM_CONDITIONAL([OSPF6D], [test "${enable_ospf6d}" != "no"])
AM_CONDITIONAL([ISISD], [test "${enable_isisd}" != "no"])
AM_CONDITIONAL([PIMD], [test "${enable_pimd}" != "no"])
AM_CONDITIONAL([PBRD], [test "${enable_pbrd}" != "no"])
AM_CONDITIONAL([SHARPD], [test "${enable_sharpd}" = "yes"])
AM_CONDITIONAL([STATICD], [test "${enable_staticd}" != "no"])
AM_CONDITIONAL([FABRICD], [test "${enable_fabricd}" != "no"])
AM_CONDITIONAL([VRRPD], [test "${enable_vrrpd}" != "no"])

AC_CONFIG_FILES([Makefile],[sed -e 's/^#AUTODERP# //' -i Makefile])

AC_CONFIG_FILES([
	  config.version
	  changelog-auto
	  redhat/frr.spec
	  solaris/Makefile
	  alpine/APKBUILD
	  snapcraft/snapcraft.yaml
	  lib/version.h
	  tests/lib/cli/test_cli.refout
	  pkgsrc/bgpd.sh pkgsrc/ospf6d.sh pkgsrc/ospfd.sh
	  pkgsrc/ripd.sh pkgsrc/ripngd.sh pkgsrc/zebra.sh
	  pkgsrc/eigrpd.sh])

AC_CONFIG_FILES([vtysh/extract.pl], [chmod +x vtysh/extract.pl])
AC_CONFIG_FILES([tools/frr], [chmod +x tools/frr])
AC_CONFIG_FILES([tools/watchfrr.sh], [chmod +x tools/watchfrr.sh])
AC_CONFIG_FILES([tools/frrinit.sh], [chmod +x tools/frrinit.sh])
AC_CONFIG_FILES([tools/frrcommon.sh])

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
compiler flags          : ${CFLAGS} ${SAN_FLAGS}
make                    : ${MAKE-make}
linker flags            : ${LDFLAGS} ${SAN_FLAGS} ${LIBS} ${LIBCAP} ${LIBREADLINE} ${LIBM}
state file directory    : ${frr_statedir}
config file directory   : `eval echo \`echo ${sysconfdir}\``
example directory       : `eval echo \`echo ${exampledir}\``
module directory        : ${CFG_MODULE}
user to run as          : ${enable_user}
group to run as         : ${enable_group}
group for vty sockets   : ${enable_vty_group}
config file mask        : ${enable_configfile_mask}
log file mask           : ${enable_logfile_mask}
zebra protobuf enabled  : ${enable_protobuf:-no}

The above user and group must have read/write access to the state file
directory and to the config files in the config file directory."

if test "${enable_doc}" != "no" -a "$frr_py_mod_sphinx" = false; then
  AC_MSG_WARN([sphinx is missing but required to build documentation])
fi
if test "$frr_py_mod_pytest" = false; then
  AC_MSG_WARN([pytest is missing, unit tests cannot be performed])
fi
