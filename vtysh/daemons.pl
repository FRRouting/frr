#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later
##
## generate daemons list and help strings
##
## Copyright (C) 2020 NFWare Inc.

use strict;

my @daemons_list = ();
my @daemons_str = ();

foreach (@ARGV) {
	push (@daemons_list, $_);
	push (@daemons_str, "For the $_ daemon\\n");
}

print "#define DAEMONS_LIST \"<" . join('|', @daemons_list) . ">\"\n";
print "#define DAEMONS_STR \"" . join('', @daemons_str) . "\"\n";
