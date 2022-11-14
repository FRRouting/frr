/*
 * Copyright (c) 2021-22  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include "zebra.h"

#include "zlog.h"
#include "command.h"

static int zdf_cmp(const struct zlog_debugflag_plain *a,
		   const struct zlog_debugflag_plain *b)
{
	return strcmp(a->cli_name, b->cli_name);
}

DECLARE_RBTREE_UNIQ(zlog_debugflags, struct zlog_debugflag_plain, zdf_item,
		    zdf_cmp);
DECLARE_LIST(zlog_debugflag_combos, struct zlog_debugflag_comboitem, item);

static bool zlog_debug_cmd_installed;

static struct zlog_debugflags_head zlog_debugflags[1] = {
	INIT_RBTREE_UNIQ(zlog_debugflags[1]),
};

void zlog_debugflag_plain_register(struct zlog_debugflag_plain *zdf)
{
	zlog_debugflag_combos_init(zdf->combos);
	zlog_debugflags_add(zlog_debugflags, zdf);

	if (zlog_debug_cmd_installed && zdf->cmd) {
		_install_element(ENABLE_NODE, zdf->cmd);
		_install_element(CONFIG_NODE, zdf->cmd);
	}
}

void zlog_debugflag_combo_register(struct zlog_debugflag_combo *zdf)
{
	size_t i;

	for (i = 0; i < zdf->combo_size; i++) {
		struct zlog_debugflag_comboitem *item = &zdf->combo_arr[i];

		item->combo = zdf;
		zlog_debugflag_combos_add_tail(item->flag->combos, item);
	}
}

/*
 * CLI integration
 */

int zlog_debugflag_cli(struct zlog_debugflag_plain *zdf, struct vty *vty,
			int argc, struct cmd_token *argv[])
{
	bool no;
	uint32_t bit, prev;
	int change;

	assert(argc > 0);

	no = !strcmp(argv[0]->text, "no");
	bit = (vty->node == ENABLE_NODE) ? LOGMSG_FLAG_EPHEMERAL
					 : LOGMSG_FLAG_PERSISTENT;

	if (no) {
		prev = atomic_fetch_and_explicit(&zdf->common.fl_enable, ~bit,
						 memory_order_relaxed);
		change = (prev & bit) ? -1 : 0;
	} else {
		prev = atomic_fetch_or_explicit(&zdf->common.fl_enable, bit,
						memory_order_relaxed);
		change = (prev & bit) ? 0 : 1;
	}

	if (!change)
		return CMD_SUCCESS;

	if (zdf->enable)
		zdf->enable(change > 0);

	struct zlog_debugflag_comboitem *item;

	frr_each (zlog_debugflag_combos, zdf->combos, item) {
		struct zlog_debugflag_combo *combo = item->combo;

		if (change == -1) {
			assert(combo->enable_counter > 0);

			combo->enable_counter += change;
			if (combo->enable_counter)
				continue;

			atomic_fetch_and_explicit(&combo->common.fl_enable,
						  ~LOGMSG_FLAG_EPHEMERAL,
						  memory_order_relaxed);
		} else {
			combo->enable_counter += change;
			if (combo->enable_counter > 1)
				continue;

			atomic_fetch_or_explicit(&combo->common.fl_enable,
						 LOGMSG_FLAG_EPHEMERAL,
						 memory_order_relaxed);
		}
	}

	return CMD_SUCCESS;
}

static int zlog_debug_write_config(struct vty *vty)
{
	struct zlog_debugflag_plain *zdf;
	int write = 0;

	frr_each (zlog_debugflags, zlog_debugflags, zdf) {
		uint32_t bits = atomic_load_explicit(&zdf->common.fl_enable,
						     memory_order_relaxed);

		if (bits & LOGMSG_FLAG_PERSISTENT) {
			vty_out(vty, "debug %s\n", zdf->cli_name);
			write++;
		}
	}

	return write;
}

/* XXX: rename to "show debugging" in CLI after that is no longer blocked
 * by individual daemon show commands
 */
DEFUN_NOSH(show_debugflags,
	   show_debugflags_cmd,
	   "show debugflags",
	   SHOW_STR
	   "Show list and state of debug flags\n")
{
	struct zlog_debugflag_plain *zdf;

	vty_out(vty, "debug flags:\n\n");

	frr_each (zlog_debugflags, zlog_debugflags, zdf) {
		uint32_t bits = atomic_load_explicit(&zdf->common.fl_enable,
						     memory_order_relaxed);
		bool persist = bits & LOGMSG_FLAG_PERSISTENT;
		bool ephem = bits & LOGMSG_FLAG_EPHEMERAL;
		const char *text;

		if (persist && ephem)
			text = "enabled in config and temporarily";
		else if (persist)
			text = "enabled in configuration";
		else if (ephem)
			text = "enabled temporarily";
		else
			text = "disabled";

		vty_out(vty, "debug %-30s  %s\n", zdf->cli_name, text);
	}

	return CMD_SUCCESS;
}

/* node only used for config write */
static struct cmd_node zlog_debug_node = {
	.node = LIB_DEBUG_NODE,
	.config_write = zlog_debug_write_config,
};

void zlog_debug_init_cmd(void)
{
	struct zlog_debugflag_plain *zdf;

	install_node(&zlog_debug_node);

	frr_each (zlog_debugflags, zlog_debugflags, zdf) {
		if (!zdf->cmd)
			continue;

		_install_element(ENABLE_NODE, zdf->cmd);
		_install_element(CONFIG_NODE, zdf->cmd);
	}

	install_element(VIEW_NODE, &show_debugflags_cmd);

	/* module load may happen after this, which may cause more debug flags
	 * to be registered.  call install_element() directly for them.
	 */
	zlog_debug_cmd_installed = true;
}
