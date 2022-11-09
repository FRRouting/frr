dnl FRR Python autoconf magic
dnl 2019 David Lamparter for NetDEF, Inc.
dnl SPDX-License-Identifier: GPL-2.0-or-later

dnl the _ at the beginning will be cut off (to support the empty version string)
m4_define_default([_FRR_PY_VERS], [_3 _3.10 _3.9 _3.8 _3.7 _3.6 _3.5 _3.4 _3.3 _3.2 _ _2 _2.7])

dnl check basic interpreter properties (py2/py3)
dnl doubles as simple check whether the interpreter actually works
dnl also swaps in the full path to the interpreter
dnl arg1: if-true, arg2: if-false
AC_DEFUN([_FRR_PYTHON_INTERP], [dnl
AC_ARG_VAR([PYTHON], [Python interpreter to use])dnl
  AC_MSG_CHECKING([python interpreter $PYTHON])
  AC_RUN_LOG(["$PYTHON" -c 'import sys; open("conftest.pyver", "w").write(sys.executable or ""); sys.exit(not (sys.version_info.major == 2 and sys.version_info.minor >= 7))'])
  py2=$ac_status
  _py2_full="`cat conftest.pyver 2>/dev/null`"
  rm -f "conftest.pyver" >/dev/null 2>/dev/null

  AC_RUN_LOG(["$PYTHON" -c 'import sys; open("conftest.pyver", "w").write(sys.executable or ""); sys.exit(not ((sys.version_info.major == 3 and sys.version_info.minor >= 2) or sys.version_info.major > 3))'])
  py3=$ac_status
  _py3_full="`cat conftest.pyver 2>/dev/null`"
  rm -f "conftest.pyver" >/dev/null 2>/dev/null

  case "p${py2}p${py3}" in
  p0p1) frr_cv_python=python2
        _python_full="$_py2_full" ;;
  p1p0) frr_cv_python=python3
        _python_full="$_py3_full" ;;
  *)    frr_cv_python=none ;;
  esac

  if test "$frr_cv_python" = none; then
    AC_MSG_RESULT([not working])
    $2
  else
    test -n "$_python_full" -a -x "$_python_full" && PYTHON="$_python_full"
    AC_MSG_RESULT([$PYTHON ($frr_cv_python)])
    $1
  fi

  dnl return value
  test "$frr_cv_python" != none
])

dnl check whether $PYTHON has modules available
dnl arg1: list of modules (space separated)
dnl arg2: if all true, arg3: if any missing
dnl also sets frr_py_mod_<name> to "true" or "false"
AC_DEFUN([FRR_PYTHON_MODULES], [
  result=true
  for pymod in $1; do
    AC_MSG_CHECKING([whether $PYTHON module $pymod is available])
    AC_RUN_LOG(["$PYTHON" -c "import $pymod"])
    sane="`echo \"$pymod\" | tr -c '[a-zA-Z0-9\n]' '_'`"
    if test "$ac_status" -eq 0; then
      AC_MSG_RESULT([yes])
      eval frr_py_mod_$sane=true
    else
      AC_MSG_RESULT([no])
      eval frr_py_mod_$sane=false
      result=false
    fi
  done
  if $result; then
    m4_default([$2], [:])
  else
    m4_default([$3], [:])
  fi
  $result
])

dnl check whether $PYTHON has modules available
dnl arg1: list of modules (space separated)
dnl arg2: command line parameters for executing
dnl arg3: if all true, arg4: if any missing
dnl also sets frr_py_modexec_<name> to "true" or "false"
AC_DEFUN([FRR_PYTHON_MOD_EXEC], [
  result=true
  for pymod in $1; do
    AC_MSG_CHECKING([whether $PYTHON module $pymod is executable])
    AC_RUN_LOG(["$PYTHON" -m "$pymod" $2 > /dev/null])
    sane="`echo \"$pymod\" | tr -c '[a-zA-Z0-9\n]' '_'`"
    if test "$ac_status" -eq 0; then
      AC_MSG_RESULT([yes])
      eval frr_py_modexec_$sane=true
    else
      AC_MSG_RESULT([no])
      eval frr_py_modexec_$sane=false
      result=false
    fi
  done
  if $result; then
    m4_default([$3], [:])
  else
    m4_default([$4], [:])
  fi
  $result
])

dnl check whether we can build & link python bits
dnl input: PYTHON_CFLAGS and PYTHON_LIBS
AC_DEFUN([_FRR_PYTHON_DEVENV], [
  result=true
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
    # some python installs are missing the zlib dependency...
    PYTHON_LIBS="${PYTHON_LIBS} -lz"
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
      result=false
      AC_MSG_RESULT([no])
    ], [:])
  ], [:])

  if $result; then
    AC_LINK_IFELSE_FLAGS([$PYTHON_CFLAGS], [$PYTHON_LIBS], [AC_LANG_PROGRAM([
#include <Python.h>
#if PY_VERSION_HEX != $1
#error python version mismatch
#endif
int main(void);
],
[
{
  Py_Initialize();
  return 0;
}
])], [
      result=false
      AC_MSG_RESULT([version mismatch])
    ], [
      AC_MSG_RESULT([yes])
    ])
  fi

  if $result; then
    m4_default([$2], [:])
  else
    m4_default([$3], [
      unset PYTHON_LIBS
      unset PYTHON_CFLAGS
    ])
  fi
])

AC_DEFUN([_FRR_PYTHON_GETDEV], [dnl
AC_REQUIRE([PKG_PROG_PKG_CONFIG])dnl

  py_abi="`   \"$1\" -c \"import sys; print(getattr(sys, 'abiflags', ''))\"`"
  py_hex="`   \"$1\" -c \"import sys; print(hex(sys.hexversion))\"`"
  py_ldver="` \"$1\" -c \"import sysconfig; print(sysconfig.get_config_var('LDVERSION') or '')\"`"
  py_ver="`   \"$1\" -c \"import sysconfig; print(sysconfig.get_config_var('VERSION') or '')\"`"
  py_bindir="`\"$1\" -c \"import sysconfig; print(sysconfig.get_config_var('BINDIR') or '')\"`"
  test -z "$py_bindir" || py_bindir="$py_bindir/"
  echo "py_abi=${py_abi} py_ldver=${py_ldver} py_ver=${py_ver} py_bindir=${py_bindir}" >&AS_MESSAGE_LOG_FD

  py_found=false

  for tryver in "${py_ldver}" "${py_ver}"; do
    pycfg="${py_bindir}python${tryver}-config"
    AC_MSG_CHECKING([whether ${pycfg} is available])
    if "$pycfg" --configdir >/dev/null 2>/dev/null; then
      AC_MSG_RESULT([yes])

      PYTHON_CFLAGS="`\"$pycfg\" --includes`"
      minor_ver=${py_ver#*\.}
      if test $((minor_ver)) -gt 7; then
        PYTHON_LIBS="`\"$pycfg\" --ldflags --embed`"
      else
        PYTHON_LIBS="`\"$pycfg\" --ldflags`"
      fi

      AC_MSG_CHECKING([whether ${pycfg} provides a working build environment])
      _FRR_PYTHON_DEVENV([$py_hex], [
        py_found=true
        break
      ])
    else
      AC_MSG_RESULT([no])
    fi

    pkg_failed=no
    AC_MSG_CHECKING([whether pkg-config python-${tryver} is available])
    unset PYTHON_CFLAGS
    unset PYTHON_LIBS
    pkg="python-${tryver}-embed"
    pkg="${pkg%-}"
    _PKG_CONFIG([PYTHON_CFLAGS], [cflags], [${pkg}])
    _PKG_CONFIG([PYTHON_LIBS], [libs], [${pkg}])
    if test $pkg_failed = no; then
      AC_MSG_RESULT([yes])

      PYTHON_CFLAGS=$pkg_cv_PYTHON_CFLAGS
      PYTHON_LIBS=$pkg_cv_PYTHON_LIBS

      AC_MSG_CHECKING([whether pkg-config python-${tryver} provides a working build environment])
      _FRR_PYTHON_DEVENV([$py_hex], [
        py_found=true
        break
      ])
    else
      AC_MSG_RESULT([no])
    fi
  done

  if $py_found; then
    m4_default([$2], [:])
  else
    unset PYTHON_CFLAGS
    unset PYTHON_LIBS
    m4_default([$3], [:])
  fi
])

dnl just find python without checking headers/libs
AC_DEFUN([FRR_PYTHON], [
  dnl user override
  if test "x$PYTHON" != "x"; then
    _FRR_PYTHON_INTERP([], [
      AC_MSG_ERROR([PYTHON ($PYTHON) explicitly specified but not working])
    ])
  else
    for frr_pyver in _FRR_PY_VERS; do
      PYTHON="python${frr_pyver#_}"
      _FRR_PYTHON_INTERP([break])
      PYTHON=":"
    done
    if test "$PYTHON" = ":"; then
      AC_MSG_ERROR([no working python version found])
    fi
  fi
  AC_SUBST([PYTHON])
])

dnl find python with checking headers/libs
AC_DEFUN([FRR_PYTHON_DEV], [dnl
AC_ARG_VAR([PYTHON_CFLAGS], [C compiler flags for Python])dnl
AC_ARG_VAR([PYTHON_LIBS], [linker flags for Python])dnl

  dnl user override
  if test "x$PYTHON" != "x"; then
    _FRR_PYTHON_INTERP([], [
      AC_MSG_ERROR([PYTHON ($PYTHON) explicitly specified but not working])
    ])
    _FRR_PYTHON_GETDEV([$PYTHON], [], [
      AC_MSG_ERROR([PYTHON ($PYTHON) explicitly specified but development environment not working])
    ])
  else
    for frr_pyver in _FRR_PY_VERS; do
      PYTHON="python${frr_pyver#_}"
      _FRR_PYTHON_INTERP([
        _FRR_PYTHON_GETDEV([$PYTHON], [
          break
        ])
      ])
      PYTHON=":"
    done
    if test "$PYTHON" = ":"; then
      AC_MSG_ERROR([no working python version found])
    fi
  fi

  AC_SUBST([PYTHON_CFLAGS])
  AC_SUBST([PYTHON_LIBS])
  AC_SUBST([PYTHON])
])
