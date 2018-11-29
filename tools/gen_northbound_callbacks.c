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
	fprintf(stderr, "usage: gen_northbound_callbacks [-h] MODULE\n");
	exit(status);
}

static struct nb_callback_info {
	int operation;
	bool optional;
	char return_type[32];
	char return_value[32];
	char arguments[128];
} nb_callbacks[] = {
	{
		.operation = NB_OP_CREATE,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource",
	},
	{
		.operation = NB_OP_MODIFY,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"enum nb_event event, const struct lyd_node *dnode, union nb_resource *resource",
	},
	{
		.operation = NB_OP_DELETE,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"enum nb_event event, const struct lyd_node *dnode",
	},
	{
		.operation = NB_OP_MOVE,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"enum nb_event event, const struct lyd_node *dnode",
	},
	{
		.operation = NB_OP_APPLY_FINISH,
		.optional = true,
		.return_type = "void ",
		.return_value = "",
		.arguments = "const struct lyd_node *dnode",
	},
	{
		.operation = NB_OP_GET_ELEM,
		.return_type = "struct yang_data *",
		.return_value = "NULL",
		.arguments = "const char *xpath, const void *list_entry",
	},
	{
		.operation = NB_OP_GET_NEXT,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments =
			"const void *parent_list_entry, const void *list_entry",
	},
	{
		.operation = NB_OP_GET_KEYS,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"const void *list_entry, struct yang_list_keys *keys",
	},
	{
		.operation = NB_OP_LOOKUP_ENTRY,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments =
			"const void *parent_list_entry, const struct yang_list_keys *keys",
	},
	{
		.operation = NB_OP_RPC,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments =
			"const char *xpath, const struct list *input, struct list *output",
	},
	{
		/* sentinel */
		.operation = -1,
	},
};

static void replace_hyphens_by_underscores(char *str)
{
	char *p;

	p = str;
	while ((p = strchr(p, '-')) != NULL)
		*p++ = '_';
}

static void generate_callback_name(struct lys_node *snode,
				   enum nb_operation operation, char *buffer,
				   size_t size)
{
	struct list *snodes;
	struct listnode *ln;

	snodes = list_new();
	for (; snode; snode = lys_parent(snode)) {
		/* Skip schema-only snodes. */
		if (CHECK_FLAG(snode->nodetype, LYS_USES | LYS_CHOICE | LYS_CASE
							| LYS_INPUT
							| LYS_OUTPUT))
			continue;

		listnode_add_head(snodes, snode);
	}

	memset(buffer, 0, size);
	for (ALL_LIST_ELEMENTS_RO(snodes, ln, snode)) {
		strlcat(buffer, snode->name, size);
		strlcat(buffer, "_", size);
	}
	strlcat(buffer, nb_operation_name(operation), size);
	list_delete(&snodes);

	replace_hyphens_by_underscores(buffer);
}

static int generate_callbacks(const struct lys_node *snode, void *arg)
{
	bool first = true;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
	case LYS_NOTIF:
	case LYS_RPC:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	for (struct nb_callback_info *cb = &nb_callbacks[0];
	     cb->operation != -1; cb++) {
		char cb_name[BUFSIZ];

		if (cb->optional
		    || !nb_operation_is_valid(cb->operation, snode))
			continue;

		if (first) {
			char xpath[XPATH_MAXLEN];

			yang_snode_get_path(snode, YANG_PATH_DATA, xpath,
					    sizeof(xpath));

			printf("/*\n"
			       " * XPath: %s\n"
			       " */\n",
			       xpath);
			first = false;
		}

		generate_callback_name((struct lys_node *)snode, cb->operation,
				       cb_name, sizeof(cb_name));
		printf("static %s%s(%s)\n"
		       "{\n"
		       "\t/* TODO: implement me. */\n"
		       "\treturn %s;\n"
		       "}\n\n",
		       nb_callbacks[cb->operation].return_type, cb_name,
		       nb_callbacks[cb->operation].arguments,
		       nb_callbacks[cb->operation].return_value);
	}

	return YANG_ITER_CONTINUE;
}

static int generate_nb_nodes(const struct lys_node *snode, void *arg)
{
	bool first = true;

	switch (snode->nodetype) {
	case LYS_CONTAINER:
	case LYS_LEAF:
	case LYS_LEAFLIST:
	case LYS_LIST:
	case LYS_NOTIF:
	case LYS_RPC:
		break;
	default:
		return YANG_ITER_CONTINUE;
	}

	for (struct nb_callback_info *cb = &nb_callbacks[0];
	     cb->operation != -1; cb++) {
		char cb_name[BUFSIZ];

		if (cb->optional
		    || !nb_operation_is_valid(cb->operation, snode))
			continue;

		if (first) {
			char xpath[XPATH_MAXLEN];

			yang_snode_get_path(snode, YANG_PATH_DATA, xpath,
					    sizeof(xpath));

			printf("\t\t{\n"
			       "\t\t\t.xpath = \"%s\",\n",
			       xpath);
			first = false;
		}

		generate_callback_name((struct lys_node *)snode, cb->operation,
				       cb_name, sizeof(cb_name));
		printf("\t\t\t.cbs.%s = %s,\n",
		       nb_operation_name(cb->operation), cb_name);
	}

	if (!first)
		printf("\t\t},\n");

	return YANG_ITER_CONTINUE;
}

int main(int argc, char *argv[])
{
	struct yang_module *module;
	char module_name_underscores[64];
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

	yang_init();

	/* Load all FRR native models to ensure all augmentations are loaded. */
	yang_module_load_all();
	module = yang_module_find(argv[0]);
	if (!module)
		/* Non-native FRR module (e.g. modules from unit tests). */
		module = yang_module_load(argv[0]);

	/* Create a nb_node for all YANG schema nodes. */
	nb_nodes_create();

	/* Generate callback functions. */
	yang_snodes_iterate_module(module->info, generate_callbacks, 0, NULL);

	strlcpy(module_name_underscores, module->name,
		sizeof(module_name_underscores));
	replace_hyphens_by_underscores(module_name_underscores);

	/* Generate frr_yang_module_info array. */
	printf("/* clang-format off */\n"
	       "const struct frr_yang_module_info %s_info = {\n"
	       "\t.name = \"%s\",\n"
	       "\t.nodes = {\n",
	       module_name_underscores, module->name);
	yang_snodes_iterate_module(module->info, generate_nb_nodes, 0, NULL);
	printf("\t\t{\n"
	       "\t\t\t.xpath = NULL,\n"
	       "\t\t},\n");
	printf("\t}\n"
	       "};\n");

	/* Cleanup and exit. */
	nb_nodes_delete();
	yang_terminate();

	return 0;
}
