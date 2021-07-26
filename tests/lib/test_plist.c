/*
 * Simple prefix list querying tool
 *
 * Copyright (C) 2021 by David Lamparter,
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

#include "lib/plist.h"
#include "lib/filter.h"
#include "tests/lib/cli/common_cli.h"

static const struct frr_yang_module_info *const my_yang_modules[] = {
	&frr_filter_info,
	NULL,
};

__attribute__((_CONSTRUCTOR(2000)))
static void test_yang_modules_set(void)
{
	test_yang_modules = my_yang_modules;
}

void test_init(int argc, char **argv)
{
	prefix_list_init();
	filter_cli_init();

	/* nothing else to do here, giving stand-alone access to the prefix
	 * list code's "debug prefix-list ..." command is the only purpose of
	 * this "test".
	 */
}
