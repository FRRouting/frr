#!/usr/bin/perl
##
## Parse a XML file containing a tree-like representation of Quagga CLI
## commands and generate a file with:
##
## - a DEFUN function for each command;
## - an initialization function.
##
##
## Copyright (C) 2012 Renato Westphal <renatow@digistar.com.br>
## This file is part of GNU Zebra.
##
## GNU Zebra is free software; you can redistribute it and/or modify it
## under the terms of the GNU General Public License as published by the
## Free Software Foundation; either version 2, or (at your option) any
## later version.
##
## GNU Zebra is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with GNU Zebra; see the file COPYING.  If not, write to the Free
## Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
## 02111-1307, USA.
##

use strict;
use warnings;
use Getopt::Std;
use vars qw($opt_d);
use File::Basename qw(fileparse);
use XML::LibXML;

%::input_strs = (
		"ifname"		=> "IFNAME",
		"word"			=> "WORD",
		"line"			=> ".LINE",
		"ipv4"			=> "A.B.C.D",
		"ipv4m"			=> "A.B.C.D/M",
		"ipv6"			=> "X:X::X:X",
		"ipv6m"			=> "X:X::X:X/M",
		"mtu"			=> "<1500-9180>",
		# BGP specific
		"rd"			=> "ASN:nn_or_IP-address:nn",
		"asn"			=> "<1-4294967295>",
		"community"		=> "AA:NN",
		"clist"			=> "<1-500>",
		# LDP specific
		"disc_time"		=> "<1-65535>",
		"session_time"		=> "<15-65535>",
		"pwid"			=> "<1-4294967295>",
		"hops"			=> "<1-254>"
		);

# parse options node and store the corresponding information
# into a global hash of hashes
sub parse_options {
	my $xml_node = $_[0];
	my @cmdstr;

	my $options_name = $xml_node->findvalue('./@name');
	if (not $options_name) {
		die('error: "options" node without "name" attribute');
	}

	# initialize hash
	$::options{$options_name}{'cmdstr'} = "";
	$::options{$options_name}{'help'} = "";

	my @children = $xml_node->getChildnodes();
	foreach my $child(@children) {
		# skip comments, random text, etc
		if ($child->getType() != XML_ELEMENT_NODE) {
			next;
		}

		# check for error/special conditions
		if ($child->getName() ne "option") {
			die('error: invalid node type: "' . $child->getName() . '"');
		}

		my $name = $child->findvalue('./@name');
		my $input = $child->findvalue('./@input');
		my $help = $child->findvalue('./@help');
		if ($input) {
			$name = $::input_strs{$input};
		}

		push (@cmdstr, $name);
		$::options{$options_name}{'help'} .= "\n       \"" . $help . "\\n\"";
	}
	$::options{$options_name}{'cmdstr'} = "(" . join('|', @cmdstr) . ")";
}

# given a subtree, replace all the corresponding include nodes by
# this subtree
sub subtree_replace_includes {
	my $subtree = $_[0];

	my $subtree_name = $subtree->findvalue('./@name');
	if (not $subtree_name) {
		die("subtree without \"name\" attribute");
	}

	my $query = "//include[\@subtree='$subtree_name']";
	foreach my $include_node($::xml->findnodes($query)) {
		my @children = $subtree->getChildnodes();
		foreach my $child(reverse @children) {
			my $include_node_parent = $include_node->getParentNode();
			$include_node_parent->insertAfter($child->cloneNode(1),
					$include_node);
		}
		$include_node->unbindNode();
	}
	$subtree->unbindNode();
}

# generate arguments for a given command
sub generate_arguments {
	my @nodes = @_;
	my $arguments;
	my $no_args = 1;
	my $argc = 0;

	$arguments .= "  struct vty_arg *args[] =\n";
	$arguments .= "    {\n";
	for (my $i = 0; $i < @nodes; $i++) {
		my %node = %{$nodes[$i]};
		my $arg_value;

		if (not $node{'arg'}) {
			next;
		}
		$no_args = 0;

		# for input and select nodes, the value of the argument is an
		# argv[] element. for the other types of nodes, the value of the
		# argument is the name of the node
		if ($node{'input'} or $node{'type'} eq "select") {
			$arg_value = "argv[" . $argc++ . "]";
		} else {
			$arg_value = '"' . $node{'name'} . '"';
		}

		if ($node{'input'} and $node{'input'} eq "line") {
			# arguments of the type 'line' may have multiple spaces (i.e
			# they don't fit into a single argv[] element).	to properly
			# handle these arguments, we need to provide direct access
			# to the argv[] array and the argc variable.
			my $argc_str = "argc" . (($argc > 1) ? " - " . ($argc - 1) : "");
			my $argv_str = "argv" . (($argc > 1) ? " + " . ($argc - 1) : "");
			$arguments .= "      &(struct vty_arg) { "
				. ".name = \"" . $node{'arg'} . "\", "
				. ".argc = $argc_str, "
				. ".argv = $argv_str },\n";
		} else {
			# common case - each argument has a name and a single value
			$arguments .= "      &(struct vty_arg) { "
				. ".name = \"" . $node{'arg'} . "\", "
				. ".value = " . $arg_value . " },\n";
		}
	}
	$arguments .= "      NULL\n";
	$arguments .= "    };\n";

	# handle special case
	if ($no_args) {
		return "  struct vty_arg *args[] = { NULL };\n";
	}

	return $arguments;
}

# generate C code
sub generate_code {
	my @nodes = @_;
	my $funcname = '';
	my $cmdstr = '';
	my $cmdname = '';
	my $helpstr = '';
	my $function = '';

	for (my $i = 0; $i < @nodes; $i++) {
		my %node = %{$nodes[$i]};
		if ($node{'input'}) {
			$funcname .= $node{'input'} . " ";
			$cmdstr .= $::input_strs{$node{'input'}} . " ";
			$helpstr .= "\n       \"" . $node{'help'} . "\\n\"";
		} elsif ($node{'type'} eq "select") {
			my $options_name = $node{'options'};
			$funcname .= $options_name . " ";
			$cmdstr .= $::options{$options_name}{'cmdstr'} . " ";
			$helpstr .= $::options{$options_name}{'help'};
		} else {
			$funcname .= $node{'name'} . " ";
			$cmdstr .= $node{'name'} . " ";
			$helpstr .= "\n       \"" . $node{'help'} . "\\n\"";
		}

		# update the command string
		if ($node{'function'} ne "inherited") {
			$function = $node{'function'};
		}
	}

	# rtrim
	$funcname =~ s/\s+$//;
	$cmdstr =~ s/\s+$//;
	# lowercase
	$funcname = lc($funcname);
	# replace " " by "_"
	$funcname =~ tr/ /_/;
	# replace "-" by "_"
	$funcname =~ tr/-/_/;
	# add prefix
	$funcname = $::cmdprefix . '_' . $funcname;

	# generate DEFUN
	$cmdname = $funcname . "_cmd";

	# don't generate same command more than once
	if ($::commands{$cmdname}) {
		return $cmdname;
	}
	$::commands{$cmdname} = "1";

	print STDOUT "DEFUN (" . $funcname . ",\n"
		   . "       " . $cmdname . ",\n"
		   . "       \"" . $cmdstr . "\","
		   . $helpstr . ")\n"
		   . "{\n"
		   . generate_arguments(@nodes)
		   . "  return " . $function . " (vty, args);\n"
		   . "}\n\n";

	return $cmdname;
}

# parse tree node (recursive function)
sub parse_tree {
	# get args
	my $xml_node = $_[0];
	my @nodes = @{$_[1]};
	my $tree_name = $_[2];

	# hash containing all the node attributes
	my %node;
	$node{'type'} = $xml_node->getName();

	# check for error/special conditions
	if ($node{'type'} eq "tree") {
		goto end;
	}
	if ($node{'type'} eq "include") {
		die('error: can not include "'
				. $xml_node->findvalue('./@subtree') . '"');
	}
	if (not $node{'type'} ~~ [qw(option select)]) {
		die('error: invalid node type: "' . $node{'type'} . '"');
	}
	if ($node{'type'} eq "select") {
		my $options_name = $xml_node->findvalue('./@options');
		if (not $options_name) {
			die('error: "select" node without "name" attribute');
		}
		if (not $::options{$options_name}) {
			die('error: can not find options');
		}
		$node{'options'} = $options_name;
	}

	# get node attributes
	$node{'name'} = $xml_node->findvalue('./@name');
	$node{'input'} = $xml_node->findvalue('./@input');
	$node{'arg'} = $xml_node->findvalue('./@arg');
	$node{'help'} = $xml_node->findvalue('./@help');
	$node{'function'} = $xml_node->findvalue('./@function');
	$node{'ifdef'} = $xml_node->findvalue('./@ifdef');

	# push node to stack
	push (@nodes, \%node);

	# generate C code
	if ($node{'function'}) {
		my $cmdname = generate_code(@nodes);
		push (@{$::trees{$tree_name}}, [0, $cmdname, 0]);
	}

	if ($node{'ifdef'}) {
		push (@{$::trees{$tree_name}}, [$node{'ifdef'}, 0, 0]);
	}

end:
	# recursively process child nodes
	my @children = $xml_node->getChildnodes();
	foreach my $child(@children) {
		# skip comments, random text, etc
		if ($child->getType() != XML_ELEMENT_NODE) {
			next;
		}
		parse_tree($child, \@nodes, $tree_name);
	}

	if ($node{'ifdef'}) {
		push (@{$::trees{$tree_name}}, [0, 0, $node{'ifdef'}]);
	}
}

sub parse_node {
	# get args
	my $xml_node = $_[0];

	my $node_name = $xml_node->findvalue('./@name');
	if (not $node_name) {
		die('missing the "name" attribute');
	}

	my $install = $xml_node->findvalue('./@install');
	my $config_write = $xml_node->findvalue('./@config_write');
	if ($install and $install eq "1") {
		print "  install_node (&" .lc( $node_name) . "_node, " . $config_write . ");\n";
	}

	my $install_default = $xml_node->findvalue('./@install_default');
	if ($install_default and $install_default eq "1") {
  		print "  install_default (" . $node_name . "_NODE);\n";
	}

	my @children = $xml_node->getChildnodes();
	foreach my $child(@children) {
		# skip comments, random text, etc
		if ($child->getType() != XML_ELEMENT_NODE) {
			next;
		}

		if ($child->getName() ne "include") {
			die('error: invalid node type: "' . $child->getName() . '"');
		}
		my $tree_name = $child->findvalue('./@tree');
		if (not $tree_name) {
			die('missing the "tree" attribute');
		}

		foreach my $entry (@{$::trees{$tree_name}}) {
			my ($ifdef, $cmdname, $endif) = @{$entry};

			if ($ifdef) {
				print ("#ifdef " . $ifdef . "\n");
			}

			if ($cmdname) {
				print "  install_element (" . $node_name . "_NODE, &" . $cmdname . ");\n";
			}

			if ($endif) {
				print ("#endif /* " . $endif . " */\n");
			}
		}
	}
}

# parse command-line arguments
if (not getopts('d')) {
	die("Usage: xml2cli.pl [-d] FILE\n");
}
my $file = shift;

# initialize the XML parser
my $parser = new XML::LibXML;
$parser->keep_blanks(0);

# parse XML file
$::xml = $parser->parse_file($file);
my $xmlroot = $::xml->getDocumentElement();
if ($xmlroot->getName() ne "file") {
	die('XML root element name must be "file"');
}

# read file attributes
my $init_function = $xmlroot->findvalue('./@init');
if (not $init_function) {
	die('missing the "init" attribute in the "file" node');
}
$::cmdprefix = $xmlroot->findvalue('./@cmdprefix');
if (not $::cmdprefix) {
	die('missing the "cmdprefix" attribute in the "file" node');
}
my $header = $xmlroot->findvalue('./@header');
if (not $header) {
	die('missing the "header" attribute in the "file" node');
}

# generate source header
print STDOUT "/* Auto-generated from " . fileparse($file) . ". */\n"
	   . "/* Do not edit! */\n\n"
	   . "#include <zebra.h>\n\n"
	   . "#include \"command.h\"\n"
	   . "#include \"vty.h\"\n"
	   . "#include \"$header\"\n\n";

# Parse options
foreach my $options($::xml->findnodes("/file/options")) {
	parse_options($options);
}

# replace include nodes by the corresponding subtrees
foreach my $subtree(reverse $::xml->findnodes("/file/subtree")) {
	subtree_replace_includes($subtree);
}

# Parse trees
foreach my $tree($::xml->findnodes("/file/tree")) {
	my @nodes = ();
	my $tree_name = $tree->findvalue('./@name');
	parse_tree($tree, \@nodes, $tree_name);
}

# install function header
print STDOUT "void\n"
	   . $init_function . " (void)\n"
	   . "{\n";

# Parse nodes
foreach my $node($::xml->findnodes("/file/node")) {
	parse_node($node);
}

# closing braces for the install function
print STDOUT "}";

# print to stderr the expanded XML file if the debug flag (-d) is given
if ($opt_d) {
	print STDERR $::xml->toString(1);
}
