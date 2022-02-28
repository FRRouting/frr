/*
 * CLI/command dummy handling tester
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "zlog.h"
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

DECLARE_DEBUGFLAG(TEST);
DECLARE_DEBUGFLAG(TEST2);
DECLARE_DEBUGFLAG_COMBO(TCOMBO);
DECLARE_DEBUGFLAG_PARAMS(TPAR, (int arg));

#define _dbg_TPAR(...) _dbg_TPAR

DEFINE_DEBUGFLAG(TEST, "test", "TEST debug flag\n");
DEFINE_DEBUGFLAG(TEST2, "test2", "TEST2 debug flag\n");
DEFINE_DEBUGFLAG_COMBO(TCOMBO, TEST, TEST2);
DEFINE_DEBUGFLAG_PARAMS(TPAR, "tpar", (int arg));

bool _dbg_filter_TPAR(int arg)
{
	return arg < 10;
}

DEFPY(debug_test, debug_test_cmd,
      "debug log (0-20)$testval TESTMSG",
      DEBUG_STR
      "logging test\n"
      "integer parameter\n"
      "text parameter\n")
{
	dbg(TEST, "TEST: %ld, %s", testval, testmsg);
	dbg(TEST2, "TEST2: %ld, %s", testval, testmsg);
	dbg(TCOMBO, "TCOMBO: %ld, %s", testval, testmsg);
	dbg(TPAR(testval), "TPAR: %ld, %s", testval, testmsg);
	return CMD_SUCCESS;
}

/*
DEFUN(debug_test_ctl, debug_test_ctl_cmd,
      "[no] debug test",
      NO_STR
      DEBUG_STR
      "TEST flag\n")
{
	return zlog_debugflag_cli(_dbg_TEST, vty, argc, argv);
}

DEFUN(debug_test2_ctl, debug_test2_ctl_cmd,
      "[no] debug test2",
      NO_STR
      DEBUG_STR
      "TEST2 flag\n")
{
	return zlog_debugflag_cli(_dbg_TEST2, vty, argc, argv);
}
*/

DEFUN(debug_tpar_ctl, debug_tpar_ctl_cmd,
      "[no] debug tpar",
      NO_STR
      DEBUG_STR
      "TPAR flag\n")
{
	return zlog_debugflag_cli(_dbg_TPAR, vty, argc, argv);
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
	
	install_element(ENABLE_NODE, &debug_test_cmd);
//	install_element(ENABLE_NODE, &debug_test_ctl_cmd);
//	install_element(ENABLE_NODE, &debug_test2_ctl_cmd);
	install_element(ENABLE_NODE, &debug_tpar_ctl_cmd);
}
