#!/usr/bin/perl
while (<STDIN>) {
	$_ =~ s/DEFINE_MTYPE\([^,]+,\s*([^,]+)\s*,.*\)/DECLARE_MTYPE\($1\)/;
	$_ =~ s/DEFINE_MGROUP\(([^,]+),.*\)/DECLARE_MGROUP\($1\)/;
	print $_;
}
