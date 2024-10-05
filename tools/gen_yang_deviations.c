// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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
	module = yang_module_load(argv[0], NULL);

	/* Generate deviations. */
	yang_snodes_iterate(module->info, generate_yang_deviation, 0, NULL);

	/* Cleanup and exit. */
	yang_terminate();

	return 0;
}
