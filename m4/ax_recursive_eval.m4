# SPDX-License-Identifier: GPL-2.0-or-later WITH Autoconf-exception-2.0
#
# ===========================================================================
#    https://www.gnu.org/software/autoconf-archive/ax_recursive_eval.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_RECURSIVE_EVAL(VALUE, RESULT)
#
# DESCRIPTION
#
#   Interpolate the VALUE in loop until it doesn't change, and set the
#   result to $RESULT.  This version has a recursion limit (10).
#
# LICENSE
#
#   Copyright (c) 2008 Alexandre Duret-Lutz <adl@gnu.org>
#   Copyright (c) 2024 David Lamparter <equinox@opensourcerouting.org>

AC_DEFUN([AX_RECURSIVE_EVAL],
[_lcl_receval="$1"
$2=`(test "x$prefix" = xNONE && prefix="$ac_default_prefix"
     test "x$exec_prefix" = xNONE && exec_prefix="${prefix}"
     _lcl_receval_old=''
     for _rec_limit in 1 2 3 4 5 6 7 8 9 10; do
       test "[$]_lcl_receval_old" = "[$]_lcl_receval" && break
       _lcl_receval_old="[$]_lcl_receval"
       eval _lcl_receval="\"[$]_lcl_receval\""
     done
     echo "[$]_lcl_receval")`])
