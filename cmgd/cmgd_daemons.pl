#!/usr/bin/perl
##
## generate daemons list and help strings
##
## Copyright (C) 2020 NFWare Inc.
##
## This file is part of FRR.
##
## FRR is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 2, or (at your option) any
## later version.
##
## FRR is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with FRR; see the file COPYING; if not, write to the Free
## Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
## 02110-1301, USA.
##

use strict;

my @daemons_list = ();
my @daemons_str = ();

foreach (@ARGV) {
	push (@daemons_list, $_);
	push (@daemons_str, "For the $_ daemon\\n");
}

print "#define DAEMONS_LIST \"<" . join('|', @daemons_list) . ">\"\n";
print "#define DAEMONS_STR \"" . join('', @daemons_str) . "\"\n";
