/*
 * Zebra Tracker CLI
 *
 * Copyright 2022 6WIND S.A.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA.
 */

#include <zebra.h>
/* rib.h is needed because it contains DECLARE_MGROUP(ZEBRA); */
#include "zebra/rib.h"

#include "lib/command.h"
#include "lib/northbound_cli.h"
#include "zebra/zebra_tracker.h"
#include "zebra/zebra_tracker_clippy.c"

DEFINE_MTYPE_STATIC(ZEBRA, TRACKER_FILE, "Tracker File");

static struct list *zebra_tracker_file_master = NULL;

struct zebra_tracker_file *zebra_tracker_file_get(const char *name)
{
	struct zebra_tracker_file *tracker_file;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(zebra_tracker_file_master, node,
				  tracker_file)) {
		if (strncmp(name, tracker_file->name,
			    sizeof(tracker_file->name))
		    == 0)
			return tracker_file;
	}

	return NULL;
}

struct zebra_tracker_file *zebra_tracker_file_new(const char *name)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);
	if (tracker_file)
		return tracker_file;

	tracker_file =
		XCALLOC(MTYPE_TRACKER_FILE, sizeof(struct zebra_tracker_file));

	snprintf(tracker_file->name, sizeof(tracker_file->name), "%s", name);

	listnode_add(zebra_tracker_file_master, tracker_file);

	return tracker_file;
}

void zebra_tracker_file_free(const char *name)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	if (!tracker_file)
		return;

	listnode_delete(zebra_tracker_file_master, tracker_file);

	zlog_info("Tracker file name %s deleted", tracker_file->name);

	XFREE(MTYPE_TRACKER_FILE, tracker_file);
}

struct zebra_tracker_file *zebra_tracker_filepath_set(const char *name,
						      const char *filepath)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	snprintf(tracker_file->path, sizeof(tracker_file->path), "%s",
		 filepath);

	return tracker_file;
}


void zebra_tracker_filepath_unset(const char *name)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	tracker_file->path[0] = '\0';
}

struct zebra_tracker_file *
zebra_tracker_filepattern_set(const char *name, const char *filepattern)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	snprintf(tracker_file->pattern, sizeof(tracker_file->pattern), "%s",
		 filepattern);

	return tracker_file;
}

void zebra_tracker_filepattern_unset(const char *name)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	tracker_file->pattern[0] = '\0';
}

void zebra_tracker_filepattern_exact_set(const char *name, bool exact)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	tracker_file->exact_pattern = exact;
}

void zebra_tracker_fileexists_set(const char *name, bool condition_file_exists)
{
	struct zebra_tracker_file *tracker_file;

	tracker_file = zebra_tracker_file_get(name);

	tracker_file->condition_file_exists = condition_file_exists;
}


/* Tracker node structure. */
static int tracker_config_write(struct vty *vty);
static struct cmd_node trackerfile_node = {
	.name = "tracker-file",
	.node = TRACKERFILE_NODE,
	.prompt = "%s(config-tracker-file)# ",
	.config_write = tracker_config_write,
};

DEFPY_YANG_NOSH(tracker_file, trackerfile_cmd, "tracker NAME$name file",
		"Tracker configuration\n"
		"Tracker name\n"
		"Track a file")
{
	char xpath[XPATH_MAXLEN];
	int rv;

	if (strlen(name) > TRACKER_NAME_SIZE) {
		vty_out(vty, "Tracker name %s is too long\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath),
		 "/frr-zebra-tracker:trackers/tracker[name='%s']", name);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	rv = nb_cli_apply_changes(vty, NULL);
	if (rv == CMD_SUCCESS)
		VTY_PUSH_XPATH(TRACKERFILE_NODE, xpath);

	return rv;
}

DEFPY_YANG_NOSH(no_tracker_file, no_trackerfile_cmd,
		"no tracker NAME$name [file]",
		"Tracker configuration\n"
		"Tracker name\n"
		"Track a file")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath),
		 "/frr-zebra-tracker:trackers/tracker[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(tracker_file_path, tracker_file_path_cmd, "path PATH",
	   "Absolute file path\n"
	   "Absolute file path\n")
{
	if (strlen(path) > PATH_MAX) {
		vty_out(vty, "Pattern %s is too long\n", path);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (path[0] != '/') {
		vty_out(vty,
			"The file path is not an absolute path starting by '/'\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./filepath", NB_OP_MODIFY, path);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_tracker_file_path, no_tracker_file_path_cmd, "no path [PATH]",
	   NO_STR
	   "Absolute file path\n"
	   "Absolute file path\n")
{
	nb_cli_enqueue_change(vty, "./filepath", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}


DEFPY_YANG(tracker_file_condition_pattern, tracker_file_condition_pattern_cmd,
	   "condition pattern PATTERN [exact]",
	   "Condition for the tracker to be up\n"
	   "Pattern must match for the tracker to be up\n"
	   "Pattern\n"
	   "Exact match\n")
{
	if (strlen(pattern) > TRACKER_FILEPATTERN_SIZE) {
		vty_out(vty, "Pattern %s is too long\n", pattern);
		return CMD_WARNING_CONFIG_FAILED;
	}

	nb_cli_enqueue_change(vty, "./filepattern", NB_OP_MODIFY, pattern);


	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "exact"))
		nb_cli_enqueue_change(vty, "./filepattern-exact", NB_OP_CREATE,
				      NULL);
	else
		nb_cli_enqueue_change(vty, "./filepattern-exact", NB_OP_DESTROY,
				      NULL);

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(tracker_file_condition_exist, tracker_file_condition_exist_cmd,
	   "condition exist",
	   "Condition for the tracker to be up\n"
	   "File must exist for the tracker to be up\n")
{
	nb_cli_enqueue_change(vty, "./fileexists", NB_OP_CREATE, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(no_tracker_file_condition, no_tracker_file_condition_cmd,
	   "no condition [exist|pattern [NAME] [exact]]",
	   NO_STR
	   "Condition for the tracker to be up\n"
	   "File must exist for the tracker to be up\n"
	   "Pattern must match for the tracker to be up\n"
	   "Pattern\n"
	   "Exact match\n")
{
	if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "exact"))
		/* only delete the exact statement */
		nb_cli_enqueue_change(vty, "./filepattern-exact", NB_OP_DESTROY,
				      NULL);
	else if (argv[argc - 1]->arg && strmatch(argv[argc - 1]->text, "exist"))
		nb_cli_enqueue_change(vty, "./fileexists", NB_OP_DESTROY, NULL);
	else if (argv[argc - 1]->arg
		 && strmatch(argv[argc - 1]->text, "pattern")) {
		nb_cli_enqueue_change(vty, "./filepattern", NB_OP_DESTROY,
				      NULL);
		nb_cli_enqueue_change(vty, "./filepattern-exact", NB_OP_DESTROY,
				      NULL);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static int tracker_config_write(struct vty *vty)
{
	struct lyd_node *dnode;
	int written = 0;

	dnode = yang_dnode_get(running_config->dnode,
			       "/frr-zebra-tracker:trackers");
	if (dnode) {
		nb_cli_show_dnode_cmds(vty, dnode, false);
		written = 1;
	}

	return written;
}

void cli_show_tracker(struct vty *vty, const struct lyd_node *dnode,
		      bool show_defaults __attribute__((__unused__)))
{
	vty_out(vty, "tracker %s file\n",
		yang_dnode_get_string(dnode, "./name"));

	if (yang_dnode_exists(dnode, "./filepath"))
		vty_out(vty, " path %s\n",
			yang_dnode_get_string(dnode, "./filepath"));

	if (yang_dnode_exists(dnode, "./fileexists"))
		vty_out(vty, " condition exist\n");

	if (yang_dnode_exists(dnode, "./filepattern"))
		vty_out(vty, " condition pattern %s%s\n",
			yang_dnode_get_string(dnode, "./filepattern"),
			yang_dnode_exists(dnode, "./filepattern-exact")
				? " exact"
				: "");
}

/* Initialization of tracker vector. */
void zebra_tracker_init(void)
{
	zebra_tracker_file_master = list_new();

	/* CLI commands. */
	install_node(&trackerfile_node);

	install_default(TRACKERFILE_NODE);

	install_element(CONFIG_NODE, &trackerfile_cmd);
	install_element(CONFIG_NODE, &no_trackerfile_cmd);

	install_element(TRACKERFILE_NODE, &tracker_file_path_cmd);
	install_element(TRACKERFILE_NODE, &no_tracker_file_path_cmd);
	install_element(TRACKERFILE_NODE, &tracker_file_condition_pattern_cmd);
	install_element(TRACKERFILE_NODE, &tracker_file_condition_exist_cmd);
	install_element(TRACKERFILE_NODE, &no_tracker_file_condition_cmd);
}
