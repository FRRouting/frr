// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * CLI/command dummy handling tester
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 */

#include <zebra.h>

#include "prefix.h"
#include "common_cli.h"

DUMMY_DEFUN(cmd0, "arg ipv4 A.B.C.D");
DUMMY_DEFUN(cmd1, "arg ipv4m A.B.C.D/M");
DUMMY_DEFUN(cmd2, "arg ipv6 X:X::X:X$foo");
DUMMY_DEFUN(cmd3, "arg ipv6m X:X::X:X/M");
DUMMY_DEFUN(cmd4, "arg range (5-15)");
DUMMY_DEFUN(cmd5, "pat a < a|b>");
DUMMY_DEFUN(cmd6, "pat b  <a|b A.B.C.D$bar>");
DUMMY_DEFUN(cmd7, "pat c <a | b|c> A.B.C.D");
DUMMY_DEFUN(cmd8, "pat d {  foo A.B.C.D$foo|bar   X:X::X:X$bar| baz } [final]");
DUMMY_DEFUN(cmd9, "pat e [ WORD ]");
DUMMY_DEFUN(cmd10, "pat f [key]");
DUMMY_DEFUN(cmd11, "alt a WORD");
DUMMY_DEFUN(cmd12, "alt a A.B.C.D");
DUMMY_DEFUN(cmd13, "alt a X:X::X:X");
DUMMY_DEFUN(cmd14,
	    "pat g {  foo A.B.C.D$foo|foo|bar   X:X::X:X$bar| baz } [final]");
DUMMY_DEFUN(cmd15, "no pat g ![ WORD ]");
DUMMY_DEFUN(cmd16, "[no] pat h {foo ![A.B.C.D$foo]|bar X:X::X:X$bar} final");

#include "tests/lib/cli/test_cli_clippy.c"

DEFPY(magic_test, magic_test_cmd,
	"magic (0-100) {ipv4net A.B.C.D/M|X:X::X:X$ipv6}",
	"1\n2\n3\n4\n5\n")
{
	vty_out(vty, "def: %s\n", self->string);
	vty_out(vty, "num: %ld\n", magic);
	vty_out(vty, "ipv4: %pFX\n", ipv4net);
	vty_out(vty, "ipv6: %pI6\n", &ipv6);
	return CMD_SUCCESS;
}

void test_init(int argc, char **argv)
{
	size_t repeat = argc > 1 ? strtoul(argv[1], NULL, 0) : 223;

	install_element(ENABLE_NODE, &cmd0_cmd);
	install_element(ENABLE_NODE, &cmd1_cmd);
	install_element(ENABLE_NODE, &cmd2_cmd);
	install_element(ENABLE_NODE, &cmd3_cmd);
	install_element(ENABLE_NODE, &cmd4_cmd);
	install_element(ENABLE_NODE, &cmd5_cmd);
	install_element(ENABLE_NODE, &cmd6_cmd);
	install_element(ENABLE_NODE, &cmd7_cmd);
	install_element(ENABLE_NODE, &cmd8_cmd);
	install_element(ENABLE_NODE, &cmd9_cmd);
	install_element(ENABLE_NODE, &cmd10_cmd);
	install_element(ENABLE_NODE, &cmd11_cmd);
	install_element(ENABLE_NODE, &cmd12_cmd);
	install_element(ENABLE_NODE, &cmd13_cmd);
	for (size_t i = 0; i < repeat; i++) {
		uninstall_element(ENABLE_NODE, &cmd5_cmd);
		install_element(ENABLE_NODE, &cmd5_cmd);
	}
	for (size_t i = 0; i < repeat; i++) {
		uninstall_element(ENABLE_NODE, &cmd13_cmd);
		install_element(ENABLE_NODE, &cmd13_cmd);
	}
	install_element(ENABLE_NODE, &cmd14_cmd);
	install_element(ENABLE_NODE, &cmd15_cmd);
	install_element(ENABLE_NODE, &cmd16_cmd);
	install_element(ENABLE_NODE, &magic_test_cmd);
}
