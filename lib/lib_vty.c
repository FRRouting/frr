// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Assorted library VTY commands
 *
 * Copyright (C) 1998 Kunihiro Ishiguro
 * Copyright (C) 2016-2017  David Lamparter for NetDEF, Inc.
 */

#include <zebra.h>
/* malloc.h is generally obsolete, however GNU Libc mallinfo wants it. */
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif
#include <dlfcn.h>
#ifdef HAVE_LINK_H
#include <link.h>
#endif

#include "log.h"
#include "memory.h"
#include "module.h"
#include "defaults.h"
#include "lib_vty.h"
#include "northbound_cli.h"

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

#if defined(HAVE_MALLINFO2) || defined(HAVE_MALLINFO)
static int show_memory_mallinfo(struct vty *vty)
{
#if defined(HAVE_MALLINFO2)
	struct mallinfo2 minfo = mallinfo2();
#elif defined(HAVE_MALLINFO)
	struct mallinfo minfo = mallinfo();
#endif
	char buf[MTYPE_MEMSTR_LEN];

	vty_out(vty, "System allocator statistics:\n");
	vty_out(vty, "  Total heap allocated:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.arena));
	vty_out(vty, "  Holding block headers: %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.hblkhd));
	vty_out(vty, "  Used small blocks:     %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.usmblks));
	vty_out(vty, "  Used ordinary blocks:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.uordblks));
	vty_out(vty, "  Free small blocks:     %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.fsmblks));
	vty_out(vty, "  Free ordinary blocks:  %s\n",
		mtype_memstr(buf, MTYPE_MEMSTR_LEN, minfo.fordblks));
	vty_out(vty, "  Ordinary blocks:       %ld\n",
		(unsigned long)minfo.ordblks);
	vty_out(vty, "  Small blocks:          %ld\n",
		(unsigned long)minfo.smblks);
	vty_out(vty, "  Holding blocks:        %ld\n",
		(unsigned long)minfo.hblks);
	vty_out(vty, "(see system documentation for 'mallinfo' for meaning)\n");
	return 1;
}
#endif /* HAVE_MALLINFO */

static int qmem_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct vty *vty = arg;
	if (!mt) {
		vty_out(vty, "--- qmem %s ---\n", mg->name);
		vty_out(vty, "%-30s: %8s %-8s%s %8s %9s\n",
			"Type", "Current#", "  Size",
#ifdef HAVE_MALLOC_USABLE_SIZE
			"     Total",
#else
			"",
#endif
			"Max#",
#ifdef HAVE_MALLOC_USABLE_SIZE
			"MaxBytes"
#else
			""
#endif
			);
	} else {
		if (mt->n_max != 0) {
			char size[32];
			snprintf(size, sizeof(size), "%6zu", mt->size);
#ifdef HAVE_MALLOC_USABLE_SIZE
#define TSTR " %9zu"
#define TARG , mt->total
#define TARG2 , mt->max_size
#else
#define TSTR ""
#define TARG
#define TARG2
#endif
			vty_out(vty, "%-30s: %8zu %-8s"TSTR" %8zu"TSTR"\n",
				mt->name,
				mt->n_alloc,
				mt->size == 0 ? ""
					      : mt->size == SIZE_VAR
							? "variable"
							: size
				TARG,
				mt->n_max
				TARG2);
		}
	}
	return 0;
}


DEFUN_NOSH (show_memory,
	    show_memory_cmd,
	    "show memory",
	    "Show running system information\n"
	    "Memory statistics\n")
{
#ifdef HAVE_MALLINFO
	show_memory_mallinfo(vty);
#endif /* HAVE_MALLINFO */

	qmem_walk(qmem_walker, vty);
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_modules,
	    show_modules_cmd,
	    "show modules",
	    "Show running system information\n"
	    "Loaded modules\n")
{
	struct frrmod_runtime *plug = frrmod_list;

	vty_out(vty, "%-12s %-25s %s\n\n", "Module Name", "Version",
		"Description");
	while (plug) {
		const struct frrmod_info *i = plug->info;

		vty_out(vty, "%-12s %-25s %s\n", i->name, i->version,
			i->description);
		if (plug->dl_handle) {
#ifdef HAVE_DLINFO_ORIGIN
			char origin[MAXPATHLEN] = "";
			dlinfo(plug->dl_handle, RTLD_DI_ORIGIN, &origin);
#ifdef HAVE_DLINFO_LINKMAP
			const char *name;
			struct link_map *lm = NULL;
			dlinfo(plug->dl_handle, RTLD_DI_LINKMAP, &lm);
			if (lm) {
				name = strrchr(lm->l_name, '/');
				name = name ? name + 1 : lm->l_name;
				vty_out(vty, "\tfrom: %s/%s\n", origin, name);
			}
#else
			vty_out(vty, "\tfrom: %s \n", origin, plug->load_name);
#endif
#else
			vty_out(vty, "\tfrom: %s\n", plug->load_name);
#endif
		}
		plug = plug->next;
	}

	vty_out(vty, "pid: %u\n", (uint32_t)(getpid()));

	return CMD_SUCCESS;
}

DEFUN (frr_defaults,
       frr_defaults_cmd,
       "frr defaults PROFILE...",
       "FRRouting global parameters\n"
       "set of configuration defaults used\n"
       "profile string\n")
{
	char *profile = argv_concat(argv, argc, 2);
	int rv = CMD_SUCCESS;

	if (!frr_defaults_profile_valid(profile)) {
		vty_out(vty, "%% WARNING: profile %s is not known in this version\n",
			profile);
		rv = CMD_WARNING;
	}
	frr_defaults_profile_set(profile);
	XFREE(MTYPE_TMP, profile);
	return rv;
}

DEFUN (frr_version,
       frr_version_cmd,
       "frr version VERSION...",
       "FRRouting global parameters\n"
       "version configuration was written by\n"
       "version string\n")
{
	char *version = argv_concat(argv, argc, 2);

	frr_defaults_version_set(version);
	XFREE(MTYPE_TMP, version);
	return CMD_SUCCESS;
}

static struct call_back {
	time_t readin_time;

	void (*start_config)(void);
	void (*end_config)(void);
} callback;


DEFUN_NOSH(start_config, start_config_cmd, "XFRR_start_configuration",
	   "The Beginning of Configuration\n")
{
	callback.readin_time = monotime(NULL);

	vty->pending_allowed = 1;

	if (callback.start_config)
		(*callback.start_config)();

	return CMD_SUCCESS;
}

DEFUN_NOSH(end_config, end_config_cmd, "XFRR_end_configuration",
	   "The End of Configuration\n")
{
	time_t readin_time;
	char readin_time_str[MONOTIME_STRLEN];
	int ret;

	readin_time = monotime(NULL);
	readin_time -= callback.readin_time;

	frrtime_to_interval(readin_time, readin_time_str,
			    sizeof(readin_time_str));

	vty->pending_allowed = 0;
	ret = nb_cli_pending_commit_check(vty);

	zlog_info("Configuration Read in Took: %s", readin_time_str);

	if (vty_mgmt_fe_enabled())
		vty_mgmt_send_commit_config(vty, false, false);

	if (callback.end_config)
		(*callback.end_config)();

	return ret;
}

void cmd_init_config_callbacks(void (*start_config_cb)(void),
			       void (*end_config_cb)(void))
{
	callback.start_config = start_config_cb;
	callback.end_config = end_config_cb;
}


static void defaults_autocomplete(vector comps, struct cmd_token *token)
{
	const char **p;

	for (p = frr_defaults_profiles; *p; p++)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, *p));
}

static const struct cmd_variable_handler default_var_handlers[] = {
	{.tokenname = "PROFILE", .completions = defaults_autocomplete},
	{.completions = NULL},
};

void lib_cmd_init(void)
{
	cmd_variable_handler_register(default_var_handlers);

	install_element(CONFIG_NODE, &frr_defaults_cmd);
	install_element(CONFIG_NODE, &frr_version_cmd);

	install_element(VIEW_NODE, &show_memory_cmd);
	install_element(VIEW_NODE, &show_modules_cmd);

	install_element(CONFIG_NODE, &start_config_cmd);
	install_element(CONFIG_NODE, &end_config_cmd);
}

/* Stats querying from users */
/* Return a pointer to a human friendly string describing
 * the byte count passed in. E.g:
 * "0 bytes", "2048 bytes", "110kB", "500MiB", "11GiB", etc.
 * Up to 4 significant figures will be given.
 * The pointer returned may be NULL (indicating an error)
 * or point to the given buffer, or point to static storage.
 */
const char *mtype_memstr(char *buf, size_t len, unsigned long bytes)
{
	unsigned int m, k;

	/* easy cases */
	if (!bytes)
		return "0 bytes";
	if (bytes == 1)
		return "1 byte";

	/*
	 * When we pass the 2gb barrier mallinfo() can no longer report
	 * correct data so it just does something odd...
	 * Reporting like Terrabytes of data.  Which makes users...
	 * edgy.. yes edgy that's the term for it.
	 * So let's just give up gracefully
	 */
	if (bytes > 0x7fffffff)
		return "> 2GB";

	m = bytes >> 20;
	k = bytes >> 10;

	if (m > 10) {
		if (bytes & (1 << 19))
			m++;
		snprintf(buf, len, "%d MiB", m);
	} else if (k > 10) {
		if (bytes & (1 << 9))
			k++;
		snprintf(buf, len, "%d KiB", k);
	} else
		snprintf(buf, len, "%ld bytes", bytes);

	return buf;
}
