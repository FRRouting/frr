# Portability macros for glibc argz.                    -*- Autoconf -*-
# Written by Gary V. Vaughan <gary@gnu.org>

# Copyright (C) 2004  Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
# 02111-1307, USA.

# serial 1

AC_DEFUN([gl_FUNC_ARGZ],
[gl_PREREQ_ARGZ

AC_CHECK_HEADERS([argz.h], [], [], [AC_INCLUDES_DEFAULT])

AC_CHECK_TYPES([error_t],
  [],
  [AC_DEFINE([error_t], [int],
   [Define to a type to use for `error_t' if it is not otherwise available.])],
  [#if defined(HAVE_ARGZ_H)
#  include <argz.h>
#endif])

ARGZ_H=
AC_CHECK_FUNCS([argz_append argz_create_sep argz_insert argz_next \
	argz_stringify], [], [ARGZ_H=argz.h; AC_LIBOBJ([argz])])
AC_SUBST([ARGZ_H])
])

# Prerequisites of lib/argz.c.
AC_DEFUN([gl_PREREQ_ARGZ], [:])
