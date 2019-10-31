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

static bool static_cbs;

static void __attribute__((noreturn)) usage(int status)
{
	extern const char *__progname;
	fprintf(stderr, "usage: %s [-h] [-s] [-p path] MODULE\n", __progname);
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
		.operation = NB_OP_DESTROY,
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

static void generate_prototype(const struct nb_callback_info *ncinfo,
			      const char *cb_name)
{
	printf("%s%s(%s);\n", ncinfo->return_type, cb_name, ncinfo->arguments);
}

static int generate_prototypes(const struct lys_node *snode, void *arg)
{
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

		generate_callback_name((struct lys_node *)snode, cb->operation,
				       cb_name, sizeof(cb_name));
		generate_prototype(cb, cb_name);
	}

	return YANG_ITER_CONTINUE;
}

static void generate_callback(const struct nb_callback_info *ncinfo,
			      const char *cb_name)
{
	printf("%s%s%s(%s)\n{\n", static_cbs ? "static " : "",
	       ncinfo->return_type, cb_name, ncinfo->arguments);

	switch (ncinfo->operation) {
	case NB_OP_CREATE:
	case NB_OP_MODIFY:
	case NB_OP_DESTROY:
	case NB_OP_MOVE:
		printf("\tswitch (event) {\n"
		       "\tcase NB_EV_VALIDATE:\n"
		       "\tcase NB_EV_PREPARE:\n"
		       "\tcase NB_EV_ABORT:\n"
		       "\tcase NB_EV_APPLY:\n"
		       "\t\t/* TODO: implement me. */\n"
		       "\t\tbreak;\n"
		       "\t}\n\n"
		       );
		break;

	default:
		printf("\t/* TODO: implement me. */\n");
		break;
	}

	printf("\treturn %s;\n}\n\n", ncinfo->return_value);
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
		generate_callback(cb, cb_name);
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
			printf("\t\t\t.cbs = {\n");
			first = false;
		}

		generate_callback_name((struct lys_node *)snode, cb->operation,
				       cb_name, sizeof(cb_name));
		printf("\t\t\t\t.%s = %s,\n", nb_operation_name(cb->operation),
		       cb_name);
	}

	if (!first) {
		printf("\t\t\t}\n");
		printf("\t\t},\n");
	}

	return YANG_ITER_CONTINUE;
}

int main(int argc, char *argv[])
{
	const char *search_path = NULL;
	struct yang_module *module;
	char module_name_underscores[64];
	struct stat st;
	int opt;

	while ((opt = getopt(argc, argv, "hp:s")) != -1) {
		switch (opt) {
		case 'h':
			usage(EXIT_SUCCESS);
			/* NOTREACHED */
		case 'p':
			if (stat(optarg, &st) == -1) {
				fprintf(stderr,
				    "error: invalid search path '%s': %s\n",
				    optarg, strerror(errno));
				exit(EXIT_FAILURE);
			}
			if (S_ISDIR(st.st_mode) == 0) {
				fprintf(stderr,
				    "error: search path is not directory");
				exit(EXIT_FAILURE);
			}

			search_path = optarg;
			break;
		case 's':
			static_cbs = true;
			break;
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

	if (search_path)
		ly_ctx_set_searchdir(ly_native_ctx, search_path);

	/* Load all FRR native models to ensure all augmentations are loaded. */
	yang_module_load_all();
	module = yang_module_find(argv[0]);
	if (!module)
		/* Non-native FRR module (e.g. modules from unit tests). */
		module = yang_module_load(argv[0]);

	/* Create a nb_node for all YANG schema nodes. */
	nb_nodes_create();

	/* Generate callback prototypes. */
	if (!static_cbs) {
		printf("/* prototypes */\n");
		yang_snodes_iterate_module(module->info, generate_prototypes, 0,
					   NULL);
		printf("\n");
	}

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
