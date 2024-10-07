// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
 */

#define REALLY_NEED_PLAIN_GETOPT 1

#include <zebra.h>
#include <sys/stat.h>

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
	bool need_config_write;
	char return_type[32];
	char return_value[32];
	char arguments[128];
} nb_callbacks[] = {
	{
		.operation = NB_CB_CREATE,
		.need_config_write = true,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_create_args *args",
	},
	{
		.operation = NB_CB_MODIFY,
		.need_config_write = true,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_modify_args *args",
	},
	{
		.operation = NB_CB_DESTROY,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_destroy_args *args",
	},
	{
		.operation = NB_CB_MOVE,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_move_args *args",
	},
	{
		.operation = NB_CB_APPLY_FINISH,
		.optional = true,
		.return_type = "void ",
		.return_value = "",
		.arguments = "struct nb_cb_apply_finish_args *args",
	},
	{
		.operation = NB_CB_GET_ELEM,
		.return_type = "struct yang_data *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_get_elem_args *args",
	},
	{
		.operation = NB_CB_GET_NEXT,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_get_next_args *args",
	},
	{
		.operation = NB_CB_GET_KEYS,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_get_keys_args *args",
	},
	{
		.operation = NB_CB_LOOKUP_ENTRY,
		.return_type = "const void *",
		.return_value = "NULL",
		.arguments = "struct nb_cb_lookup_entry_args *args",
	},
	{
		.operation = NB_CB_RPC,
		.return_type = "int ",
		.return_value = "NB_OK",
		.arguments = "struct nb_cb_rpc_args *args",
	},
	{
		/* sentinel */
		.operation = -1,
	},
};

/*
 * Special-purpose info block for the cli-config-write callback. This
 * is different enough from the config-oriented callbacks that it doesn't
 * really fit in the array above.
 */
static struct nb_callback_info nb_config_write = {
	.return_type = "void ",
	.arguments = "struct vty *vty, const struct lyd_node *dnode, bool show_defaults",
};

static void replace_hyphens_by_underscores(char *str)
{
	char *p;

	p = str;
	while ((p = strchr(p, '-')) != NULL)
		*p++ = '_';
}

static void generate_callback_name(const struct lysc_node *snode,
				   enum nb_cb_operation operation, char *buffer,
				   size_t size)
{
	struct list *snodes;
	struct listnode *ln;

	snodes = list_new();
	for (; snode; snode = snode->parent) {
		/* Skip schema-only snodes. */
		if (CHECK_FLAG(snode->nodetype, LYS_USES | LYS_CHOICE | LYS_CASE
							| LYS_INPUT
							| LYS_OUTPUT))
			continue;

		listnode_add_head(snodes, (void *)snode);
	}

	memset(buffer, 0, size);
	for (ALL_LIST_ELEMENTS_RO(snodes, ln, snode)) {
		strlcat(buffer, snode->name, size);
		strlcat(buffer, "_", size);
	}
	strlcat(buffer, nb_cb_operation_name(operation), size);
	list_delete(&snodes);

	replace_hyphens_by_underscores(buffer);
}

static void generate_config_write_cb_name(const struct lysc_node *snode,
					  char *buffer, size_t size)
{
	struct list *snodes;
	struct listnode *ln;

	buffer[0] = '\0';

	snodes = list_new();
	for (; snode; snode = snode->parent) {
		/* Skip schema-only snodes. */
		if (CHECK_FLAG(snode->nodetype, LYS_USES | LYS_CHOICE | LYS_CASE
							| LYS_INPUT
							| LYS_OUTPUT))
			continue;

		listnode_add_head(snodes, (void *)snode);
	}

	for (ALL_LIST_ELEMENTS_RO(snodes, ln, snode)) {
		strlcat(buffer, snode->name, size);
		strlcat(buffer, "_", size);
	}

	strlcat(buffer, "cli_write", size);

	list_delete(&snodes);

	replace_hyphens_by_underscores(buffer);
}

static void generate_prototype(const struct nb_callback_info *ncinfo,
			      const char *cb_name)
{
	printf("%s%s(%s);\n", ncinfo->return_type, cb_name, ncinfo->arguments);
}

static void generate_config_write_prototype(const struct nb_callback_info *ncinfo,
					    const char *cb_name)
{
	printf("%s%s(%s);\n", ncinfo->return_type, cb_name, ncinfo->arguments);
}

static int generate_prototypes(const struct lysc_node *snode, void *arg)
{
	bool need_config_write = true;

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
		    || !nb_cb_operation_is_valid(cb->operation, snode))
			continue;

		generate_callback_name(snode, cb->operation, cb_name,
				       sizeof(cb_name));
		generate_prototype(cb, cb_name);

		if (cb->need_config_write && need_config_write) {
			generate_config_write_cb_name(snode, cb_name,
						      sizeof(cb_name));
			generate_config_write_prototype(&nb_config_write,
							cb_name);

			need_config_write = false;
		}
	}

	return YANG_ITER_CONTINUE;
}

static void generate_callback(const struct nb_callback_info *ncinfo,
			      const char *cb_name)
{
	printf("%s%s%s(%s)\n{\n", static_cbs ? "static " : "",
	       ncinfo->return_type, cb_name, ncinfo->arguments);

	switch (ncinfo->operation) {
	case NB_CB_CREATE:
	case NB_CB_MODIFY:
	case NB_CB_DESTROY:
	case NB_CB_MOVE:
		printf("\tswitch (args->event) {\n"
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

static void generate_config_write_callback(const struct nb_callback_info *ncinfo,
					   const char *cb_name)
{
	printf("%s%s%s(%s)\n{\n", static_cbs ? "static " : "",
	       ncinfo->return_type, cb_name, ncinfo->arguments);

	/* Add a comment, since these callbacks may not all be needed. */
	printf("\t/* TODO: this cli callback is optional; the cli output may not need to be done at each node. */\n");

	printf("}\n\n");
}

static int generate_callbacks(const struct lysc_node *snode, void *arg)
{
	bool first = true;
	bool need_config_write = true;

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
		    || !nb_cb_operation_is_valid(cb->operation, snode))
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

		generate_callback_name(snode, cb->operation, cb_name,
				       sizeof(cb_name));
		generate_callback(cb, cb_name);

		if (cb->need_config_write && need_config_write) {
			generate_config_write_cb_name(snode, cb_name,
						      sizeof(cb_name));
			generate_config_write_callback(&nb_config_write,
						       cb_name);

			need_config_write = false;
		}
	}

	return YANG_ITER_CONTINUE;
}

static int generate_nb_nodes(const struct lysc_node *snode, void *arg)
{
	bool first = true;
	char cb_name[BUFSIZ];
	char xpath[XPATH_MAXLEN];
	bool config_pass = *(bool *)arg;
	bool need_config_write = true;

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

	/* We generate two types of structs currently; behavior is a little
	 * different between the types.
	 */
	for (struct nb_callback_info *cb = &nb_callbacks[0];
	     cb->operation != -1; cb++) {

		if (cb->optional
		    || !nb_cb_operation_is_valid(cb->operation, snode))
			continue;

		if (config_pass) {
			if (first) {
				yang_snode_get_path(snode, YANG_PATH_DATA, xpath,
						    sizeof(xpath));

				printf("\t\t{\n"
				       "\t\t\t.xpath = \"%s\",\n",
				       xpath);
				printf("\t\t\t.cbs = {\n");
				first = false;
			}

			generate_callback_name(snode, cb->operation, cb_name,
					       sizeof(cb_name));
			printf("\t\t\t\t.%s = %s,\n",
			       nb_cb_operation_name(cb->operation),
			       cb_name);
		} else if (cb->need_config_write && need_config_write) {
			if (first) {
				yang_snode_get_path(snode,
						    YANG_PATH_DATA,
						    xpath,
						    sizeof(xpath));

				printf("\t\t{\n"
				       "\t\t\t.xpath = \"%s\",\n",
				       xpath);
				printf("\t\t\t.cbs = {\n");
				first = false;
			}

			generate_config_write_cb_name(snode, cb_name,
						      sizeof(cb_name));
			printf("\t\t\t\t.cli_show = %s,\n", cb_name);

			need_config_write = false;
		}
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
	bool config_pass;

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

	yang_init(false, true, false);

	if (search_path)
		ly_ctx_set_searchdir(ly_native_ctx, search_path);

	/* Load all FRR native models to ensure all augmentations are loaded. */
	yang_module_load_all();

	module = yang_module_find(argv[0]);
	if (!module)
		/* Non-native FRR module (e.g. modules from unit tests). */
		module = yang_module_load(argv[0], NULL);

	yang_init_loading_complete();

	/* Create a nb_node for all YANG schema nodes. */
	nb_nodes_create();

	/* Emit bare-bones license line (and fool the checkpatch regex
	 * that triggers a warning).
	 */
	printf("// SPDX-" "License-Identifier: GPL-2.0-or-later\n\n");

	/* Generate callback prototypes. */
	if (!static_cbs) {
		printf("/* prototypes */\n");
		yang_snodes_iterate(module->info, generate_prototypes, 0, NULL);
		printf("\n");
	}

	/* Generate callback functions. */
	yang_snodes_iterate(module->info, generate_callbacks, 0, NULL);

	strlcpy(module_name_underscores, module->name,
		sizeof(module_name_underscores));
	replace_hyphens_by_underscores(module_name_underscores);

	/*
	 * We're going to generate two structs here, two arrays of callbacks:
	 * first one with config-handling callbacks, then a second struct with
	 * config-output-oriented callbacks.
	 */

	/* Generate frr_yang_module_info array, with config-handling callbacks */
	config_pass = true;
	printf("/* clang-format off */\n"
	       "const struct frr_yang_module_info %s_nb_info = {\n"
	       "\t.name = \"%s\",\n"
	       "\t.nodes = {\n",
	       module_name_underscores, module->name);
	yang_snodes_iterate(module->info, generate_nb_nodes, 0, &config_pass);

	/* Emit terminator element */
	printf("\t\t{\n"
	       "\t\t\t.xpath = NULL,\n"
	       "\t\t},\n");
	printf("\t}\n"
	       "};\n");

	/* Generate second array, with output-oriented callbacks. */
	config_pass = false;
	printf("\n/* clang-format off */\n"
	       "const struct frr_yang_module_info %s_cli_info = {\n"
	       "\t.name = \"%s\",\n"
	       "\t.nodes = {\n",
	       module_name_underscores, module->name);
	yang_snodes_iterate(module->info, generate_nb_nodes, 0, &config_pass);

	/* Emit terminator element */
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
