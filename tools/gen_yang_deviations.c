/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define REALLY_NEED_PLAIN_GETOPT 1

#include <zebra.h>

#include <unistd.h>

#include "yang.h"
#include "northbound.h"

static void __attribute__((noreturn)) usage(int status)
{
	fprintf(stderr, "usage: gen_yang_deviations [-h] MODULE\n");
	exit(status);
}

static int generate_yang_deviation(const struct lysc_node *snode, void *arg)
{
	char xpath[XPATH_MAXLEN];

	yang_snode_get_path(snode, YANG_PATH_SCHEMA, xpath, sizeof(xpath));

	printf("  deviation \"%s\" {\n", xpath);
	printf("    deviate not-supported;\n");
	printf("  }\n\n");

	return YANG_ITER_CONTINUE;
}

int main(int argc, char *argv[])
{
	struct yang_module *module;
	int opt;

	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
		case 'h':
			usage(EXIT_SUCCESS);
			/* NOTREACHED */
		default:
			usage(EXIT_FAILURE);
			/* NOTREACHED */
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage(EXIT_FAILURE);

	yang_init(false, false);

	/* Load YANG module. */
	module = yang_module_load(argv[0]);

	/* Generate deviations. */
	yang_snodes_iterate(module->info, generate_yang_deviation, 0, NULL);

	/* Cleanup and exit. */
	yang_terminate();

	return 0;
}
