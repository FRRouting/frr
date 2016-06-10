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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "common-cli.h"

DUMMY_DEFUN(cmd0,  "arg ipv4 A.B.C.D");
DUMMY_DEFUN(cmd1,  "arg ipv4m A.B.C.D/M");
DUMMY_DEFUN(cmd2,  "arg ipv6 X:X::X:X");
DUMMY_DEFUN(cmd3,  "arg ipv6m X:X::X:X/M");
DUMMY_DEFUN(cmd4,  "arg range <5-15>");
DUMMY_DEFUN(cmd5,  "pat a ( a|b)");
DUMMY_DEFUN(cmd6,  "pat b  (a|)");
DUMMY_DEFUN(cmd7,  "pat c (a | b|c) A.B.C.D");
DUMMY_DEFUN(cmd8,  "pat d {  foo A.B.C.D|bar   X:X::X:X| baz }");
DUMMY_DEFUN(cmd9,  "pat e [ WORD ]");
DUMMY_DEFUN(cmd10, "pat f [key]");
DUMMY_DEFUN(cmd11, "alt a WORD");
DUMMY_DEFUN(cmd12, "alt a A.B.C.D");
DUMMY_DEFUN(cmd13, "alt a X:X::X:X");

void test_init(void)
{
  install_element (ENABLE_NODE, &cmd0_cmd);
  install_element (ENABLE_NODE, &cmd1_cmd);
  install_element (ENABLE_NODE, &cmd2_cmd);
  install_element (ENABLE_NODE, &cmd3_cmd);
  install_element (ENABLE_NODE, &cmd4_cmd);
  install_element (ENABLE_NODE, &cmd5_cmd);
  install_element (ENABLE_NODE, &cmd6_cmd);
  install_element (ENABLE_NODE, &cmd7_cmd);
  install_element (ENABLE_NODE, &cmd8_cmd);
  install_element (ENABLE_NODE, &cmd9_cmd);
  install_element (ENABLE_NODE, &cmd10_cmd);
  install_element (ENABLE_NODE, &cmd11_cmd);
  install_element (ENABLE_NODE, &cmd12_cmd);
  install_element (ENABLE_NODE, &cmd13_cmd);
}
