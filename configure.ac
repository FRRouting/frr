##
## Configure template file for Quagga.
## autoconf will generate configure script.
##
##  Copyright (c) 1996, 97, 98, 99, 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
##  Portions Copyright (c) 2003 Paul Jakma <paul@dishone.st>
##
AC_PREREQ(2.53)

AC_INIT(quagga, 0.96.4, [bug-zebra@gnu.org])
AC_CONFIG_SRCDIR(lib/zebra.h)
AM_INIT_AUTOMAKE()
AM_CONFIG_HEADER(config.h)

dnl -----------------------------------
dnl Get hostname and other information.
dnl -----------------------------------
AC_CANONICAL_HOST

dnl ------------
dnl Check CFLAGS
dnl ------------
AC_ARG_WITH(cflags,
[  --with-cflags           Set CFLAGS for use in compilation.])
if test "x$with_cflags" != "x" ; then
  CFLAGS="$with_cflags" ; cflags_specified=yes ;
elif test -n "$CFLAGS" ; then
  cflags_specified=yes ;
fi

dnl --------
dnl Check CC
dnl --------
AC_PROG_CC

dnl -----------------------------------------
dnl If CLFAGS doesn\'t exist set default value
dnl -----------------------------------------
if test "x$cflags_specified" = "x" ; then
  CFLAGS="$CFLAGS -Wall"
fi

dnl --------------
dnl Check programs
dnl --------------
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_CHECK_TOOL(AR, ar)
AC_CHECK_TOOL(RANLIB, ranlib, :)

dnl ---------
dnl AIX check
dnl ---------
AC_AIX

dnl ----------------------
dnl Packages configuration
dnl ----------------------
AC_ARG_ENABLE(vtysh,
[  --enable-vtysh,       Make integrated vty shell for Quagga])
AC_ARG_ENABLE(ipv6,
[  --disable-ipv6          turn off IPv6 related features and daemons])
AC_ARG_ENABLE(zebra,
[  --disable-zebra         do not build zebra daemon])
AC_ARG_ENABLE(bgpd,
[  --disable-bgpd          do not build bgpd])
AC_ARG_ENABLE(ripd,
[  --disable-ripd          do not build ripd])
AC_ARG_ENABLE(ripngd,
[  --disable-ripngd        do not build ripngd])
AC_ARG_ENABLE(ospfd,
[  --disable-ospfd         do not build ospfd])
AC_ARG_ENABLE(ospf6d,
[  --disable-ospf6d        do not build ospf6d])
AC_ARG_ENABLE(bgp-announce,
[  --disable-bgp-announce, turn off BGP route announcement])
AC_ARG_ENABLE(netlink,
[  --enable-netlink        force to use Linux netlink interface])
AC_ARG_ENABLE(broken-aliases,
[  --enable-broken-aliases enable aliases as distinct interfaces for Linux 2.2.X])
AC_ARG_ENABLE(snmp,
[  --enable-snmp           enable SNMP support])
AC_ARG_WITH(libpam,
[  --with-libpam           use libpam for PAM support in vtysh])
AC_ARG_ENABLE(tcp-zebra,
[  --enable-tcp-zebra      enable TCP/IP socket connection between zebra and protocol daemon])
dnl Temporary option until OSPF NSSA implementation complete
AC_ARG_ENABLE(nssa,
[  --enable-nssa           enable OSPF NSSA option])
AC_ARG_ENABLE(opaque-lsa,
[  --enable-opaque-lsa     enable OSPF Opaque-LSA with OSPFAPI support (RFC2370)])
AC_ARG_ENABLE(ospfapi,
[  --disable-ospfapi       do not build OSPFAPI to access the OSPF LSA Database, 
                          (this is the default if --enable-opaque-lsa is not set)])
AC_ARG_ENABLE(ospfclient,
[  --disable-ospfclient    do not build OSPFAPI client for OSPFAPI, 
                          (this is the default if --disable-ospfapi is set)])
AC_ARG_ENABLE(ospf-te,
[  --enable-ospf-te        enable Traffic Engineering Extension to OSPF])
AC_ARG_ENABLE(multipath,
[  --enable-multipath=ARG  enable multipath function, ARG must be digit])
AC_ARG_ENABLE(quagga_user,
[  --enable-user=ARG       user to run Quagga suite as (default quagga)])
AC_ARG_ENABLE(quagga_group,
[  --enable-group=ARG      group to run Quagga suite as (default quagga)])
AC_ARG_ENABLE(vty_group,
[  --enable-vty-group=ARG      set vty sockets to have specified group as owner])

AC_ARG_ENABLE(rtadv,
[  --enable-rtadv         enable IPV6 router advertisement feature])

if test "${enable_broken_aliases}" = "yes"; then
  if test "${enable_netlink}" = "yes"
  then
    echo "Sorry, you can't use netlink with broken aliases"
    exit 1
  fi
  AC_DEFINE(HAVE_BROKEN_ALIASES,,Broken Alias)
  enable_netlink=no
fi

if test "${enable_tcp_zebra}" = "yes"; then
  AC_DEFINE(HAVE_TCP_ZEBRA,,Use TCP for zebra communication)
fi

if test "${enable_nssa}" = "yes"; then
  AC_DEFINE(HAVE_NSSA,,OSPF NSSA)
fi

if test "${enable_opaque_lsa}" = "yes"; then
  AC_DEFINE(HAVE_OPAQUE_LSA,,OSPF Opaque LSA)
fi

if test "${enable_ospf_te}" = "yes"; then
  AC_DEFINE(HAVE_OPAQUE_LSA,,OSPF Opaque LSA)
  AC_DEFINE(HAVE_OSPF_TE,,OSPF TE)
fi

AC_MSG_CHECKING(Should zebra's RTADV be used)
if test "${enable_rtadv}" = "yes"; then
  AC_MSG_RESULT(yes)
  AC_DEFINE(HAVE_RTADV,,Enable zebra IPv6 Routing Advertisements)
else
  AC_MSG_RESULT(no)
fi

if test "${enable_user}" = "yes" || test x"${enable_user}" = x""; then
  enable_user="quagga"
elif test "${enable_user}" = "no"; then
  enable_user="root"
fi
AC_DEFINE_UNQUOTED(QUAGGA_USER, "${enable_user}", Quagga User)

if test "${enable_group}" = "yes" || test x"${enable_group}" = x""; then
  enable_group="quagga"
elif test "${enable_group}" = "no"; then
  enable_group="root"
fi
AC_DEFINE_UNQUOTED(QUAGGA_GROUP, "${enable_group}", Quagga Group)

if test x"${enable_vty_group}" = x"yes" ; then
  AC_MSG_ERROR([--enable-vty-group requires a group as argument, not yes])
elif test x"${enable_vty_group}" != x""; then
  if test x"${enable_vty_group}" != x"no"; then
    AC_DEFINE_UNQUOTED(VTY_GROUP, "${enable_vty_group}", VTY Sockets Group)
  fi
fi

changequote(, )dnl

MULTIPATH_NUM=1

case "${enable_multipath}" in
  [0-9]|[1-9][0-9])
    MULTIPATH_NUM="${enable_multipath}"
    ;;
  "")
    ;;
  *)           
    echo "Please specify digit to --enable-multipath ARG."
    exit 1
    ;;
esac

changequote([, ])dnl

AC_SUBST(MULTIPATH_NUM)

dnl -------------------
dnl Check header files.
dnl -------------------
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h stropts.h sys/conf.h sys/ksym.h sys/time.h \
                 sys/times.h sys/select.h sys/sysctl.h sys/sockio.h \
                 sys/types.h linux/version.h kvm.h netdb.h asm/types.h \
                 libutil.h limits.h])

AC_CHECK_HEADERS([sys/socket.h netinet/in_systm.h netinet/in.h \
		 net/if_dl.hnet/netopt.h inet/nd.h net/route.h \
		 net/if.h net/if_var.h netinet/in_var.h])

if test "x${enable_ipv6}" = "xyes"; then
AC_CHECK_HEADERS([netinet6/in6.h netinet/in6_var.h netinet/icmp6.h \
		 netinet6/in6_var.h netinet6/nd6.h])
fi
dnl if enable_ipv6

dnl check some types
AC_C_CONST
dnl AC_TYPE_PID_T
AC_TYPE_SIGNAL

dnl Some systems (Solaris 2.x) require libnsl (Network Services Library)
case "$host" in
  *-sunos5.6* | *-solaris2.6*)
      opsys=sol2-6
      AC_DEFINE(SUNOS_5,,SunOS 5)
      AC_CHECK_LIB(xnet, main)
      CURSES=-lcurses
  ;;
  *-sunos5* | *-solaris2*)
      AC_DEFINE(SUNOS_5,,SunOS 5)
      AC_CHECK_LIB(socket, main)
      AC_CHECK_LIB(nsl, main)
      CURSES=-lcurses
  ;;
  *-linux-*)
      opsys=gnu-linux
      AC_DEFINE(GNU_LINUX,,GNU Linux)
  ;;
  *-nec-sysv4*)
      AC_CHECK_LIB(nsl, gethostbyname)
      AC_CHECK_LIB(socket, socket)
  ;;
  *-freebsd3.2)
      AC_DEFINE(FREEBSD_32,,FreeBSD 3.2)
  ;;
  *-openbsd*)
      opsys=openbsd
      AC_DEFINE(OPEN_BSD,,OpenBSD)
  ;;
  *-bsdi*)
      opsys=bsdi
      OTHER_METHOD="mtu_kvm.o"
      AC_CHECK_LIB(kvm, main)
  ;;
  *-irix6.5)
      opsys=irix
      AC_DEFINE(IRIX_65,,IRIX 6.5)
  ;;
esac

dnl ---------------------
dnl Integrated VTY option
dnl ---------------------
case "${enable_vtysh}" in
  "yes") VTYSH="vtysh";
         AC_DEFINE(VTYSH,,VTY shell)
	 AC_CHECK_LIB(tinfo, tputs, , AC_CHECK_LIB(ncurses, tputs))
         AC_CHECK_LIB(readline, main)
         if test $ac_cv_lib_readline_main = no; then
           AC_MSG_ERROR([vtysh needs libreadline but was not found on your system.])
         fi
	 AC_CHECK_HEADER(readline/history.h)
	 if test $ac_cv_header_readline_history_h = no;then
           AC_MSG_ERROR([readline is too old to have readline/history.h, please update to the latest readline library.])
	 fi
	 AC_CHECK_LIB(readline, rl_completion_matches)
         if test $ac_cv_lib_readline_rl_completion_matches = no; then
           AC_DEFINE(rl_completion_matches,completion_matches,Old readline)
	 fi
	 ;;
  "no" ) VTYSH="";;
  *    ) ;;
esac

dnl ----------
dnl PAM module
dnl ----------
if test "$with_libpam" = "yes"; then
  AC_CHECK_HEADER(security/pam_misc.h)
  if test "$ac_cv_header_security_pam_misc_h" = yes; then
    AC_DEFINE(HAVE_PAM_MISC_H,,Have pam_misc.h)
    AC_DEFINE(PAM_CONV_FUNC,misc_conv,Have misc_conv)
    pam_conv_func="misc_conv"
  fi
  AC_CHECK_HEADER(security/openpam.h)
  if test "$ac_cv_header_security_openpam_h" = yes; then
    AC_DEFINE(HAVE_OPENPAM_H,,Have openpam.h)
    AC_DEFINE(PAM_CONV_FUNC,openpam_ttyconv,Have openpam_ttyconv)
    pam_conv_func="openpam_ttyconv"
  fi
  if test -z "$ac_cv_header_security_pam_misc_h$ac_cv_header_security_openpam_h" ; then
    AC_MSG_WARN([*** pam support will not be built ***])
    with_libpam="no"
  fi
fi

if test "$with_libpam" = "yes"; then
dnl took this test from proftpd's configure.in and suited to our needs
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
AC_CHECK_FUNCS(memset memcpy strerror inet_aton daemon snprintf vsnprintf \
               strlcat strlcpy if_nametoindex if_indextoname getifaddrs \
	       fcntl)
AC_CHECK_FUNCS(setproctitle, ,
  [AC_CHECK_LIB(util, setproctitle, 
     [LIBS="$LIBS -lutil"
      AC_DEFINE(HAVE_SETPROCTITLE,, Have setproctitle)
     ]
   )
  ]
)

dnl ------------------------------------
dnl Determine routing get and set method
dnl ------------------------------------
AC_MSG_CHECKING(zebra between kernel interface method)
if test x"$opsys" = x"gnu-linux"; then
  if test "${enable_netlink}" = "yes";then
    AC_MSG_RESULT(netlink)
    RT_METHOD=rt_netlink.o
    AC_DEFINE(HAVE_NETLINK,,netlink)
    netlink=yes
  elif test "${enable_netlink}" = "no"; then
    AC_MSG_RESULT(ioctl)
    RT_METHOD=rt_ioctl.o
    netlink=no
  else
    AC_MSG_RESULT(netlink)
    RT_METHOD=rt_netlink.o
    AC_DEFINE(HAVE_NETLINK,,netlink)
    netlink=yes
  fi
else
  if test "$opsys" = "sol2-6";then
    AC_MSG_RESULT(solaris)
    KERNEL_METHOD="kernel_socket.o"
    RT_METHOD="rt_socket.o"
  elif test "$opsys" = "irix" ; then
    AC_MSG_RESULT(irix)
    KERNEL_METHOD="kernel_socket.o"
    RT_METHOD="rt_socket.o"
  else
    AC_TRY_RUN([#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

main ()
{
  int ac_sock;

  ac_sock = socket (AF_ROUTE, SOCK_RAW, 0);
  if (ac_sock < 0 && errno == EINVAL)
    exit (1);
  exit (0);
}],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)],
  [RT_METHOD=rt_ioctl.o
   AC_MSG_RESULT(ioctl)],
  [KERNEL_METHOD=kernel_socket.o
   RT_METHOD=rt_socket.o
   AC_MSG_RESULT(socket)])
  fi
fi
AC_SUBST(RT_METHOD)
AC_SUBST(KERNEL_METHOD)
AC_SUBST(OTHER_METHOD)

dnl ------------------------------
dnl check kernel route read method
dnl ------------------------------
AC_CACHE_CHECK(route read method check, zebra_rtread,
[if test "$netlink" = yes; then
  RTREAD_METHOD="rtread_netlink.o"
  zebra_rtread="netlink"
else
for zebra_rtread in /proc/net/route /dev/ip /dev/null;
do
  test x`ls $zebra_rtread 2>/dev/null` = x"$zebra_rtread" && break
done
case $zebra_rtread in
  "/proc/net/route") RTREAD_METHOD="rtread_proc.o"
                     zebra_rtread="proc";;
  "/dev/ip")
                     case "$host" in
                       *-freebsd*)    RTREAD_METHOD=rtread_sysctl.o
                                      zebra_rtread="sysctl";;
                       *)             RTREAD_METHOD="rtread_getmsg.o"
                                      zebra_rtread="getmsg";;
                     esac;;
  *)                 RTREAD_METHOD="rtread_sysctl.o"
                     zebra_rtread="sysctl";;
esac
fi])
AC_SUBST(RTREAD_METHOD)

dnl -----------------------------
dnl check interface lookup method
dnl -----------------------------
AC_MSG_CHECKING(interface looking up method)
if test "$netlink" = yes; then
  AC_MSG_RESULT(netlink)
  IF_METHOD=if_netlink.o
else
  if test "$opsys" = "sol2-6";then
    AC_MSG_RESULT(solaris)
    IF_METHOD=if_ioctl.o
  elif test "$opsys" = "irix" ; then
    AC_MSG_RESULT(irix)
     IF_METHOD=if_ioctl.o
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
fi
AC_SUBST(IF_METHOD)

dnl -----------------------
dnl check proc file system.
dnl -----------------------
if test -r /proc/net/dev; then
  AC_DEFINE(HAVE_PROC_NET_DEV,,/proc/net/dev)
  IF_PROC=if_proc.o
fi

if test -r /proc/net/if_inet6; then
  AC_DEFINE(HAVE_PROC_NET_IF_INET6,,/proc/net/if_inet6)
  IF_PROC=if_proc.o
fi
AC_SUBST(IF_PROC)

dnl -----------------------------
dnl check ipforward detect method
dnl -----------------------------
AC_CACHE_CHECK(ipforward method check, zebra_ipforward_path,
[for zebra_ipforward_path in /proc/net/snmp /dev/ip /dev/null;
do
  test x`ls $zebra_ipforward_path 2>/dev/null` = x"$zebra_ipforward_path" && break
done
case $zebra_ipforward_path in
  "/proc/net/snmp")  IPFORWARD=ipforward_proc.o
                     zebra_ipforward_path="proc";;
  "/dev/ip")         
                     case "$host" in
                       *-nec-sysv4*)  IPFORWARD=ipforward_ews.o
                                      zebra_ipforward_path="ews";;
                       *-freebsd*)    IPFORWARD=ipforward_sysctl.o
                                      zebra_ipforward_path="sysctl";;
                       *)             IPFORWARD=ipforward_solaris.o
                                      zebra_ipforward_path="solaris";;
                     esac;;
  *)                 IPFORWARD=ipforward_sysctl.o
                     zebra_ipforward_path="sysctl";;
esac])
AC_SUBST(IPFORWARD)

AC_CHECK_FUNCS(getaddrinfo, [have_getaddrinfo=yes], [have_getaddrinfo=no])

dnl ----------
dnl IPv6 check
dnl ----------
AC_MSG_CHECKING(whether does this OS have IPv6 stack)
if test "${enable_ipv6}" = "no"; then
  AC_MSG_RESULT(disabled)
else
dnl ----------
dnl INRIA IPv6
dnl ----------
  if grep IPV6_INRIA_VERSION /usr/include/netinet/in.h >/dev/null 2>&1; then
    zebra_cv_ipv6=yes
    AC_DEFINE(HAVE_IPV6,1,INRIA IPv6)
    AC_DEFINE(INRIA_IPV6,1,INRIA IPv6)
    RIPNGD="ripngd"
    OSPF6D="ospf6d"
    LIB_IPV6=""
    AC_MSG_RESULT(INRIA IPv6)
dnl ---------
dnl KAME IPv6
dnl ---------
  elif grep WIDE /usr/include/netinet6/in6.h >/dev/null 2>&1; then
    zebra_cv_ipv6=yes
    AC_DEFINE(HAVE_IPV6,1,KAME IPv6)
    AC_DEFINE(KAME,1,KAME IPv6)
    RIPNGD="ripngd"
    OSPF6D="ospf6d"
    if test -d /usr/local/v6/lib -a -f /usr/local/v6/lib/libinet6.a; then
      LIB_IPV6="-L/usr/local/v6/lib -linet6"
    fi
    AC_MSG_RESULT(KAME)
dnl -------------------------
dnl MUSICA IPv6
dnl  default host check
dnl  It is not used by Kheops
dnl -------------------------
  elif grep MUSICA /usr/include6/netinet6/in6.h >/dev/null 2>&1; then
    zebra_cv_ipv6=yes
    AC_DEFINE(HAVE_IPV6,1,Musicia IPv6)
    AC_DEFINE(MUSICA,1,Musica IPv6 stack)
    AC_DEFINE(KAME,1,KAME IPv6 stack)
    RIPNGD="ripngd"
    OSPF6D="ospf6d"
    if test -d /usr/local/v6/lib -a -f /usr/local/v6/lib/libinet6.a; then
      LIB_IPV6="-L/usr/local/v6/lib -linet6"
    fi
    AC_MSG_RESULT(MUSICA)
dnl ---------
dnl NRL check
dnl ---------
  elif grep NRL /usr/include/netinet6/in6.h >/dev/null 2>&1; then
    zebra_cv_ipv6=yes
    AC_DEFINE(HAVE_IPV6,1,NRL IPv6)
    AC_DEFINE(NRL,1,NRL)
    RIPNGD="ripngd"
    OSPF6D="ospf6d"
    if test x"$opsys" = x"bsdi";then
      AC_DEFINE(BSDI_NRL,,BSDI)
      AC_MSG_RESULT(BSDI_NRL)
    else
      AC_MSG_RESULT(NRL)
    fi
dnl ----------
dnl Linux IPv6
dnl ----------
  elif test "${enable_ipv6}" = "yes"; then
    AC_EGREP_CPP(yes, [
      #include <linux/version.h>
      /* 2.1.128 or later */
      #if LINUX_VERSION_CODE >= 0x020180
      yes
      #endif],
      [zebra_cv_ipv6=yes
       zebra_cv_linux_ipv6=yes
       AC_MSG_RESULT(Linux IPv6)])
  else
    if test x`ls /proc/net/ipv6_route 2>/dev/null` = x"/proc/net/ipv6_route"
     then
      zebra_cv_ipv6=yes
      zebra_cv_linux_ipv6=yes
      AC_MSG_RESULT(Linux IPv6)
    fi
  fi

  if test "$zebra_cv_linux_ipv6" = "yes";then
    AC_MSG_CHECKING(for GNU libc >= 2.1)
    AC_DEFINE(HAVE_IPV6,1,Linux IPv6)
    AC_EGREP_CPP(yes, [
#include <features.h>
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 1
  yes
#endif], 
      [glibc=yes
       AC_DEFINE(LINUX_IPV6,1,Linux IPv6 stack)
       AC_MSG_RESULT(yes)], 
      AC_MSG_RESULT(no)
    )
    RIPNGD="ripngd"
    OSPF6D="ospf6d"
    if test "$glibc" != "yes"; then
      INCLUDES="-I/usr/inet6/include"
      if test x`ls /usr/inet6/lib/libinet6.a 2>/dev/null` != x;then
         LIB_IPV6="-L/usr/inet6/lib -linet6"
      fi
    fi
  fi

dnl -----------------------
dnl Set IPv6 related values
dnl -----------------------
  LIBS="$LIB_IPV6 $LIBS"
  AC_SUBST(LIB_IPV6)

  if test x"$RIPNGD" = x""; then
    AC_MSG_RESULT(IPv4 only)
  fi
fi

dnl --------------------
dnl Daemon disable check
dnl --------------------
if test "${enable_zebra}" = "no";then
  ZEBRA=""
else
  ZEBRA="zebra"
fi

if test "${enable_bgpd}" = "no";then
  BGPD=""
else
  BGPD="bgpd"
fi

if test "${enable_ripd}" = "no";then
  RIPD=""
else
  RIPD="ripd"
fi

if test "${enable_ospfd}" = "no";then
  OSPFD=""
else
  OSPFD="ospfd"
fi

OSPFCLIENT=""
if test "${enable_opaque_lsa}" = "yes"; then
  if test "${enable_ospfapi}" != "no";then
    AC_DEFINE(SUPPORT_OSPF_API,,OSPFAPI)

    if test "${enable_ospfclient}" != "no";then
      OSPFCLIENT="ospfclient"
    fi
  fi

fi

case "${enable_ripngd}" in
  "yes") RIPNGD="ripngd";;
  "no" ) RIPNGD="";;
  *    ) ;;
esac

case "${enable_ospf6d}" in
  "yes") OSPF6D="ospf6d";;
  "no" ) OSPF6D="";;
  *    ) ;;
esac

if test "${enable_bgp_announce}" = "no";then
  AC_DEFINE(DISABLE_BGP_ANNOUNCE,,Disable BGP installation to zebra)
fi

AC_SUBST(ZEBRA)
AC_SUBST(BGPD)
AC_SUBST(RIPD)
AC_SUBST(RIPNGD)
AC_SUBST(OSPFD)
AC_SUBST(OSPF6D)
AC_SUBST(VTYSH)
AC_SUBST(INCLUDES)
AC_SUBST(CURSES)
AC_SUBST(OSPFCLIENT)
AC_SUBST(OSPFAPI)
AC_CHECK_LIB(c, inet_ntop, [AC_DEFINE(HAVE_INET_NTOP,,inet_ntop)])
AC_CHECK_LIB(c, inet_pton, [AC_DEFINE(HAVE_INET_PTON,,inet_pton)])
AC_CHECK_LIB(crypt, crypt)
AC_CHECK_LIB(resolv, res_init)
AC_CHECK_LIB(m, main)

dnl ---------------------------------------------------
dnl BSD/OS 4.1 define inet_XtoY function as __inet_XtoY
dnl ---------------------------------------------------
AC_CHECK_FUNC(__inet_ntop, AC_DEFINE(HAVE_INET_NTOP,,__inet_ntop))
AC_CHECK_FUNC(__inet_pton, AC_DEFINE(HAVE_INET_PTON,,__inet_pton))
AC_CHECK_FUNC(__inet_aton, AC_DEFINE(HAVE_INET_ATON,,__inet_aton))

dnl ---------------------------
dnl check system has GNU regexp
dnl ---------------------------
dnl AC_MSG_CHECKING(whether system has GNU regex)
AC_CHECK_LIB(c, regexec,
[AC_DEFINE(HAVE_GNU_REGEX,,GNU regexp library)
 LIB_REGEX=""],
[LIB_REGEX="regex.o"])
AC_SUBST(LIB_REGEX)

dnl ------------------
dnl check SNMP library
dnl ------------------
if test "${enable_snmp}" = "yes";then
dnl  AC_CHECK_LIB(snmp, asn_parse_int, HAVE_SNMP=yes)
  if test "${HAVE_SNMP}" = ""; then
    old_libs="${LIBS}"
    LIBS="-L/usr/lib"
    unset ac_cv_lib_snmp_asn_parse_int
    AC_CHECK_LIB(crypto, main, NEED_CRYPTO=yes, )
    if test "${NEED_CRYPTO}" = ""; then
      AC_CHECK_LIB(netsnmp, asn_parse_int, [HAVE_NETSNMP=yes; HAVE_SNMP=yes ])
    else
      AC_CHECK_LIB(netsnmp, asn_parse_int, [HAVE_NETSNMP=yes; HAVE_SNMP=yes; NEED_CRYPTO=yes;LIBS="$LIBS -lcrypto" ],,"-lcrypto")
    fi
    LIBS="${old_libs}"
  fi
  if test "${HAVE_SNMP}" = ""; then
    old_libs="${LIBS}"
    LIBS="-L/usr/lib"
    unset ac_cv_lib_snmp_asn_parse_int
    AC_CHECK_LIB(snmp, asn_parse_int, HAVE_SNMP=yes, )
    if test "${HAVE_SNMP}" = ""; then
      unset ac_cv_lib_snmp_asn_parse_int
      AC_CHECK_LIB(crypto, main, NEED_CRYPTO=yes, )
      if test "${NEED_CRYPTO}" = "yes"; then 
        AC_CHECK_LIB(snmp, asn_parse_int, [HAVE_SNMP=yes; NEED_CRYPTO=yes; LIBS="$LIBS -lcrypto" ],,"-lcrypto")
      fi
    fi
    LIBS="${old_libs}"
  fi

  if test "${HAVE_SNMP}" = ""; then
    old_libs="${LIBS}"
    LIBS="-L/usr/local/lib"
    unset ac_cv_lib_snmp_asn_parse_int
    AC_CHECK_LIB(snmp, asn_parse_int, HAVE_SNMP=yes)
    if test "${HAVE_SNMP}" = ""; then
      unset ac_cv_lib_snmp_asn_parse_int
      AC_CHECK_LIB(crypto, main, NEED_CRYPTO=yes, )
      if test "${NEED_CRYPTO}" = "yes"; then
        AC_CHECK_LIB(snmp, asn_parse_int, [HAVE_SNMP=yes; NEED_CRYPTO=yes; LIBS="$LIBS -lcrypto" ],,"-lcrypto")
      fi
    fi
    LIBS="${old_libs}"
  fi

  if test "${HAVE_SNMP}" = "yes"; then
    for ac_snmp in /usr/include/net-snmp/library/asn1.h /usr/include/ucd-snmp/asn1.h /usr/local/include/ucd-snmp/asn1.h /dev/null
    do
      test -f "${ac_snmp}" && break
    done

    case ${ac_snmp} in
      /usr/include/net-snmp/*)
                  AC_DEFINE(HAVE_SNMP,,SNMP)
		  AC_DEFINE(HAVE_NETSNMP,,SNMP)
                  AC_DEFINE(UCD_COMPATIBLE,,SNMP)
                  CFLAGS="${CFLAGS} -I/usr/include/net-snmp -I/usr/include/net-snmp/library"
		  if test "${HAVE_NETSNMP}" = "yes"; then
		        LIBS="${LIBS} -lnetsnmp"
		  else
			LIBS="${LIBS} -lsnmp"
		  fi
                  ;;
      /usr/include/ucd-snmp/*) 
                  AC_DEFINE(HAVE_SNMP,,SNMP)
                  CFLAGS="${CFLAGS} -I/usr/include/ucd-snmp"
    		  LIBS="${LIBS} -lsnmp"
                  ;;
      /usr/local/include/ucd-snmp/*) 
                  AC_DEFINE(HAVE_SNMP,,SNMP)
  	          CFLAGS="${CFLAGS} -I/usr/local/include/ucd-snmp"
  		  LIBS="${LIBS} -L/usr/local/lib -lsnmp"
                  ;;
    esac
    if test "${NEED_CRYPTO}" = "yes"; then
      LIBS="${LIBS} -lcrypto"
    fi
  fi
fi

dnl ----------------------------
dnl check sa_len of sockaddr
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr has a sa_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
],[static struct sockaddr ac_i;int ac_j = sizeof (ac_i.sa_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SA_LEN,,sa_len)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check sin_len of sockaddr_in
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr_in has a sin_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in ac_i;int ac_j = sizeof (ac_i.sin_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN_LEN,,sin_len)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check sun_len of sockaddr_un
dnl ----------------------------
AC_MSG_CHECKING(whether struct sockaddr_un has a sun_len field)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/un.h>
],[static struct sockaddr_un ac_i;int ac_j = sizeof (ac_i.sun_len);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SUN_LEN,,sun_len)],
 AC_MSG_RESULT(no))

dnl -----------------------------------
dnl check sin6_scope_id of sockaddr_in6
dnl -----------------------------------
if test "$zebra_cv_ipv6" = yes; then
  AC_MSG_CHECKING(whether struct sockaddr_in6 has a sin6_scope_id field)
  AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet/in.h>
],[static struct sockaddr_in6 ac_i;int ac_j = sizeof (ac_i.sin6_scope_id);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SIN6_SCOPE_ID,,scope id)],
 AC_MSG_RESULT(no))
fi

dnl ----------------------------
dnl check socklen_t exist or not
dnl ----------------------------
AC_MSG_CHECKING(whther socklen_t is defined)
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
],[socklen_t ac_x;],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SOCKLEN_T,,socklen_t)],
 AC_MSG_RESULT(no))

dnl ------------------------
dnl check struct sockaddr_dl
dnl ------------------------
AC_MSG_CHECKING(whether struct sockaddr_dl exist)
AC_EGREP_HEADER(sockaddr_dl,
net/if_dl.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_SOCKADDR_DL,,sockaddr_dl)],
 AC_MSG_RESULT(no))

dnl --------------------------
dnl check structure ifaliasreq
dnl --------------------------
AC_MSG_CHECKING(whether struct ifaliasreq exist)
AC_EGREP_HEADER(ifaliasreq,
net/if.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_IFALIASREQ,,ifaliasreq)],
 AC_MSG_RESULT(no))

dnl ----------------------------
dnl check structure in6_aliasreq
dnl ----------------------------
AC_MSG_CHECKING(whether struct in6_aliasreq exist)
AC_EGREP_HEADER(in6_aliasreq,
netinet6/in6_var.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_IN6_ALIASREQ,,in6_aliasreq)],
 AC_MSG_RESULT(no))

dnl -----------------------------------
dnl check ifra_lifetime of in6_aliasreq
dnl -----------------------------------
AC_MSG_CHECKING(whether in6_aliasreq.ifra_lifetime exist)
AC_TRY_COMPILE([#include <sys/types.h>
#include <netinet6/in6_var.h>
],[static struct if6_aliasreq ac_i;int ac_j = sizeof (ac_i.ifra_lifetime);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_IFRA_LIFETIME,,Have in6_aliasreq.ifra_lifetime)],
 AC_MSG_RESULT(no))

dnl ---------------------------
dnl check structure rt_addrinfo
dnl ---------------------------
AC_MSG_CHECKING(whether struct rt_addrinfo exist)
AC_EGREP_HEADER(rt_addrinfo,
net/route.h,
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_RT_ADDRINFO,,rt_addrinfo)],
 AC_MSG_RESULT(no))

dnl --------------------------
dnl check structure in_pktinfo
dnl --------------------------
AC_MSG_CHECKING(whether struct in_pktinfo exist)
AC_TRY_COMPILE([#include <netinet/in.h>
],[struct in_pktinfo ac_x;],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_INPKTINFO,,in_pktinfo)],
 AC_MSG_RESULT(no))

dnl --------------------------------------
dnl checking for getrusage struct and call
dnl --------------------------------------
AC_MSG_CHECKING(whether getrusage is available)
AC_TRY_COMPILE([#include <sys/resource.h>
],[struct rusage ac_x; getrusage (RUSAGE_SELF, &ac_x);],
[AC_MSG_RESULT(yes)
 AC_DEFINE(HAVE_RUSAGE,,rusage)],
 AC_MSG_RESULT(no))

dnl -------------------
dnl capabilities checks
dnl -------------------
AC_MSG_CHECKING(whether prctl PR_SET_KEEPCAPS is available)
AC_TRY_COMPILE([#include <sys/prctl.h>],[prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);],
  [AC_MSG_RESULT(yes)
   AC_DEFINE(HAVE_PR_SET_KEEPCAPS,,prctl)
   quagga_ac_keepcaps="yes"],
   AC_MSG_RESULT(no)
)
if test x"${quagga_ac_keepcaps}" = x"yes"; then
  AC_CHECK_HEADERS(sys/capability.h)
fi
if test x"${ac_cv_header_sys_capability_h}" = x"yes"; then
  AC_CHECK_LIB(cap, cap_init, 
    [AC_DEFINE(HAVE_LCAPS,1,Capabilities)
     LIBCAP="-lcap"
    ]
  )
fi
AC_SUBST(LIBCAP)

dnl ---------------------------
dnl check for glibc 'backtrace'
dnl --------------------------- 
if test "${glibc}" = "yes"; then
   AC_CHECK_HEADER(execinfo.h)
fi
if test x"${ac_cv_header_execinfo_h}" = x"yes"; then
  AC_CHECK_FUNC(backtrace,
    [AC_DEFINE(HAVE_GLIBC_BACKTRACE,,Glibc backtrace)]
  )
fi

dnl ----------
dnl configure date
dnl ----------
CONFDATE=`date '+%Y%m%d'`
AC_SUBST(CONFDATE)

dnl ------------------------------
dnl set paths for state directory
dnl ------------------------------
if test "${prefix}" = "NONE"; then
  quagga_statedir_prefix="";
else
  quagga_statedir_prefix=${prefix}
fi
if test "${localstatedir}" = '${prefix}/var'; then
  AC_CACHE_CHECK(state directory,ac_statedir,
  [for QUAGGA_STATE_DIR in ${quagga_statedir_prefix}/var/run dnl
			${quagga_statedir_prefix}/var/adm dnl
			${quagga_statedir_prefix}/etc dnl
			/var/run	dnl
                        /var/adm	dnl
                        /etc		dnl
                        /dev/null;
  do
    test -d $QUAGGA_STATE_DIR && break
  done
  quagga_statedir=$QUAGGA_STATE_DIR])
else
  quagga_statedir=${localstatedir}
  AC_MSG_CHECKING(directory to use for state file)
  AC_MSG_RESULT(${quagga_statedir})
fi
if test $quagga_statedir = "/dev/null"; then
    AC_MSG_ERROR('STATE DIRECTORY NOT FOUND! FIX OR SPECIFY --localstatedir!')
fi

AC_DEFINE_UNQUOTED(PATH_ZEBRA_PID, "$quagga_statedir/zebra.pid",zebra PID)
AC_DEFINE_UNQUOTED(PATH_RIPD_PID, "$quagga_statedir/ripd.pid",ripd PID)
AC_DEFINE_UNQUOTED(PATH_RIPNGD_PID, "$quagga_statedir/ripngd.pid",ripngd PID)
AC_DEFINE_UNQUOTED(PATH_BGPD_PID, "$quagga_statedir/bgpd.pid",bgpd PID)
AC_DEFINE_UNQUOTED(PATH_OSPFD_PID, "$quagga_statedir/ospfd.pid",ospfd PID)
AC_DEFINE_UNQUOTED(PATH_OSPF6D_PID, "$quagga_statedir/ospf6d.pid",ospf6d PID)
AC_DEFINE_UNQUOTED(ZEBRA_SERV_PATH, "$quagga_statedir/zserv.api",zebra api socket)
AC_DEFINE_UNQUOTED(ZEBRA_VTYSH_PATH, "$quagga_statedir/zebra.vty",zebra vty socket)
AC_DEFINE_UNQUOTED(RIP_VTYSH_PATH, "$quagga_statedir/ripd.vty",rip vty socket)
AC_DEFINE_UNQUOTED(RIPNG_VTYSH_PATH, "$quagga_statedir/ripngd.vty",ripng vty socket)
AC_DEFINE_UNQUOTED(BGP_VTYSH_PATH, "$quagga_statedir/bgpd.vty",bgpd vty socket)
AC_DEFINE_UNQUOTED(OSPF_VTYSH_PATH, "$quagga_statedir/ospfd.vty",ospfd vty socket)
AC_DEFINE_UNQUOTED(OSPF6_VTYSH_PATH, "$quagga_statedir/ospf6d.vty",ospf6d vty socket)

dnl ---------------------------
dnl Check htonl works correctly
dnl ---------------------------
AC_MSG_CHECKING(for working htonl)
AC_CACHE_VAL(ac_cv_htonl_works, [
AC_TRY_LINK([#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif],
[htonl (0);],
ac_cv_htonl_works=yes,
ac_cv_htonl_works=no)])
AC_MSG_RESULT($ac_cv_htonl_works)

AC_OUTPUT(Makefile lib/Makefile zebra/Makefile ripd/Makefile 
	  ripngd/Makefile bgpd/Makefile ospfd/Makefile 
	  ospf6d/Makefile vtysh/Makefile doc/Makefile 
	  ospfclient/Makefile
	  redhat/quagga.spec
	  lib/version.h)

echo "
zebra configuration
-------------------
quagga version           : ${PACKAGE_VERSION}
host operationg system  : ${host_os}
source code location    : ${srcdir}
compiler                : ${CC}
compiler flags          : ${CFLAGS}
linker flags            : ${LDFLAGS} ${LIBS}
state file directory    : ${quagga_statedir}
config file directory   : `eval echo \`echo ${sysconfdir}\``
user to run as		: ${enable_user}
group to run as		: ${enable_group}
group for vty sockets	: ${enable_vty_group}

The above user and group must have read/write access to the state file
directory and to the config files in the config file directory.
"
