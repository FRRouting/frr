// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Simple prefix list querying tool
 *
 * Copyright (C) 2021 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
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
