# ltversion.m4 -- version numbers			-*- Autoconf -*-
# @configure_input@

# serial @MACRO_SERIAL@
# This file is part of GNU Libtool

m4_define([LT_PACKAGE_VERSION], [1.5.6])
m4_define([LT_PACKAGE_REVISION], [1.5.6])

AC_DEFUN([LTVERSION_VERSION],
[macro_version='1.5.6'
macro_revision='6'
_LT_DECL(, macro_version, 0, [Which release of libtool.m4 was used?])
_LT_DECL(, macro_revision, 0)
])
