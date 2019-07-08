/**
 * bfd_tracking.c: BFD tracking file
 *
 * Copyright 2019 6WIND S.A.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>
#include "json.h"
#include "lib/version.h"
#include "hook.h"
#include "memory.h"
#include "hash.h"
#include "libfrr.h"
#include "command.h"
#include "vty.h"
#include "jhash.h"
#include "vrf.h"
#include "log.h"
#include <string.h>
#include "northbound_cli.h"

#include "bfd.h"
#include "bfd_tracking.h"

#ifndef VTYSH_EXTRACT_PL
#include "bfdd/bfd_tracking_clippy.c"
#endif

DEFINE_MTYPE_STATIC(BFDD, BFD_TRACKING, "Tracking Information");
DEFINE_MTYPE_STATIC(BFDD, BFD_LABEL, "BFD Label");

static int bfd_tracking_call_notify_filename(const struct bfd_session *bs);

static int bfd_tracking_call_set_notify_string(const struct bfd_session *bs,
					       const char *notify_string);


static int bfd_tracking_call_set_label_string(const struct bfd_session *pm,
					      const char *label_string);

static int bfd_tracking_call_release_session(const struct bfd_session *bs);

static int bfd_tracking_call_new_session(const struct bfd_session *bs);

static int bfd_tracking_call_display(struct vty *vty,
				     const char *notify_string);

static int bfd_tracking_call_show_extra_info(const struct bfd_session *bs,
					     struct vty *vty, struct json_object *jo);

static int bfd_tracking_call_display_label(struct vty *vty,
					   const char *label_string);

static int bfd_tracking_init(struct thread_master *t);

static int bfd_tracking_module_init(void)
{
	hook_register(frr_late_init, bfd_tracking_init);
	hook_register(bfd_tracking_notify_filename,
		      bfd_tracking_call_notify_filename);
	hook_register(bfd_tracking_new_session,
		      bfd_tracking_call_new_session);
	hook_register(bfd_tracking_release_session,
		      bfd_tracking_call_release_session);
	hook_register(bfd_tracking_show_notify_string,
		      bfd_tracking_call_display);
	hook_register(bfd_tracking_set_notify_string,
		      bfd_tracking_call_set_notify_string);
	hook_register(bfd_tracking_set_label_string,
		      bfd_tracking_call_set_label_string);
	hook_register(bfd_tracking_show_extra_info,
		      bfd_tracking_call_show_extra_info);
	hook_register(bfd_tracking_show_label_string,
		      bfd_tracking_call_display_label);
	return 0;
}

FRR_MODULE_SETUP(
		 .name = "bfd_tracking",
		 .version = FRR_VERSION,
		 .description = "bfd tracking module",
		 .init = bfd_tracking_module_init
		 );

struct hash *bfd_tracking_list;

struct bfd_tracking_ctx {
	struct bfd_key key;
	union sockunion gateway;
	union sockunion alternate;
	char notify_path[PATH_MAX];
	char *label;
};

static struct bfd_tracking_ctx *bfd_tracking_lookup_from_bs(const struct bfd_session *bs)
{
	struct bfd_tracking_ctx ctx;

	memset(&ctx, 0, sizeof(struct bfd_tracking_ctx));
	memcpy(&ctx.key, &bs->key, sizeof(struct bfd_key));
	return hash_lookup(bfd_tracking_list, &ctx);
}

static void *bfd_tracking_alloc(void *arg)
{
	struct hash *ctx_to_allocate;

	ctx_to_allocate = XCALLOC(MTYPE_BFD_TRACKING,
				  sizeof(struct bfd_tracking_ctx));
	if (!ctx_to_allocate)
		return NULL;
	memcpy(ctx_to_allocate, arg, sizeof(struct bfd_tracking_ctx));
	return ctx_to_allocate;
}

static int bfd_tracking_notify_update_status(char *path, int status)
{
	FILE *fp;

	fp = fopen(path, "w+");
	if (!fp) {
		zlog_info("%s: could not open %s",
			  __func__, path);
		return -1;
	}
	fprintf(fp, "%d", status);
	fclose(fp);
	return 1;
}

static int bfd_tracking_call_notify_filename(const struct bfd_session *bs)
{
	struct bfd_tracking_ctx *ctx;
	int status = 0;
	int ret;
	char buf[INET6_ADDRSTRLEN];

	ctx = bfd_tracking_lookup_from_bs(bs);
	if (!ctx)
		return 0;
	if (bs->ses_state == PTM_BFD_UP)
		status = 0;
	else if ((bs->ses_state == PTM_BFD_DOWN) ||
		 (bs->ses_state == PTM_BFD_INIT))
		status = 1;
	else
		/* case init state or admin down
		 * or other
		 */
		return 0;
	if (!ctx->notify_path[0])
		return 0;
	ret = bfd_tracking_notify_update_status(ctx->notify_path, status);
	if (ret > 0) {
		inet_ntop(ctx->key.family, &ctx->key.peer, buf,
			  sizeof(buf));
		zlog_info("tracker %s, notifying %s to %s",
			  buf, bs->ses_state == PTM_BFD_UP ?
			  "UP" : "DOWN", ctx->notify_path);
	}
	return ret;
}

static int bfd_tracking_notify_call(const char *pathname,
				   struct vty *vty)
{
	char tmp_name[PATH_MAX] = "";

	if (!pathname) {
		nb_cli_enqueue_change(vty, "./notify-string",
				      NB_OP_DESTROY, NULL);
	} else {
		/* relevant pathname */
		if (!realpath(pathname, tmp_name) && errno != ENOENT) {
			vty_out(vty, "Invalid pathname for %s: %s\n",
				pathname, safe_strerror(errno));
			return CMD_WARNING_CONFIG_FAILED;
		}
		nb_cli_enqueue_change(vty, "./notify-string",
				      NB_OP_MODIFY, tmp_name);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG(
	bfd_tracking_descr, bfd_tracking_descr_cmd,
	"[no] label [<NAME$name>]",
	NO_STR
	"Configure tracking name description\n"
	"Description field\n")
{
	if (no || !name)
		nb_cli_enqueue_change(vty, "./label", NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, "./label", NB_OP_MODIFY, name);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (bfd_tracking_notify,
	    bfd_tracking_notify_cmd,
	    "[no] notify [<NAME$path>]",
	    NO_STR
	    "Define notification path name to notify changes to\n"
	    "Filename with absolute path\n")
{
	if (no)
		return bfd_tracking_notify_call(NULL, vty);
	return bfd_tracking_notify_call(path, vty);
}

static int bfd_tracking_call_release_session(const struct bfd_session *bs)
{
	struct bfd_tracking_ctx *ctx;

	ctx = bfd_tracking_lookup_from_bs(bs);
	if (!ctx)
		return 0;
	if (ctx->notify_path[0])
		bfd_tracking_notify_update_status(ctx->notify_path, 0);
	hash_release(bfd_tracking_list, &ctx);
	return 1;
}

static int bfd_tracking_call_new_session(const struct bfd_session *bs)
{
	struct bfd_tracking_ctx ctx;

	if (!bs)
		return 0;
	memset(&ctx, 0, sizeof(struct bfd_tracking_ctx));
	memcpy(&ctx.key, &bs->key, sizeof(struct bfd_key));

	hash_get(bfd_tracking_list, &ctx,
		 bfd_tracking_alloc);
	return 1;
}


static int bfd_tracking_call_set_notify_string(const struct bfd_session *bs,
					       const char *notify_string)
{
	struct bfd_tracking_ctx *ctx;

	ctx = bfd_tracking_lookup_from_bs(bs);
	if (!ctx)
		return 0;
	if (notify_string)
		snprintf(ctx->notify_path, sizeof(ctx->notify_path), "%s", notify_string);
	else
		memset(ctx->notify_path, 0, sizeof(ctx->notify_path));
	return 1;
}

static int bfd_tracking_call_set_label_string(const struct bfd_session *bs,
					      const char *label_string)
{
	struct bfd_tracking_ctx *ctx;

	ctx = bfd_tracking_lookup_from_bs(bs);
	if (!ctx)
		return 0;
	if (ctx->label)
		XFREE(MTYPE_BFD_LABEL, ctx->label);
	ctx->label = NULL;
	if (label_string)
		ctx->label = XSTRDUP(MTYPE_BFD_LABEL, label_string);
	return 1;
}

static int bfd_tracking_call_show_extra_info(const struct bfd_session *bs,
					     struct vty *vty, struct json_object *jo)
{
	struct bfd_tracking_ctx *ctx;

	ctx = bfd_tracking_lookup_from_bs(bs);
	if (!ctx)
		return 0;
	if (vty) {
		if (ctx->notify_path[0])
			vty_out(vty, "\t\tNotification-string: %s\n",
				ctx->notify_path);
		if (ctx->label)
			vty_out(vty, "\t\tLabel: %s\n",
				ctx->label);
	}
	if (jo) {
		if (ctx->notify_path[0])
			json_object_string_add(jo, "notification-string",
					       ctx->notify_path);
		if (ctx->label)
			json_object_string_add(jo, "label",
					       ctx->label);
	}
	return 1;
}

static int bfd_tracking_call_display(struct vty *vty,
				     const char *notify_string)
{
	if (notify_string) {
		if (vty)
			vty_out(vty, "  notify %s\n",
				notify_string);
	}
	return 1;
}

static int bfd_tracking_call_display_label(struct vty *vty,
					   const char *label_string)
{
	if (label_string) {
		if (vty)
			vty_out(vty, "  label %s\n",
				label_string);
	}
	return 1;
}

static unsigned int bfd_tracking_hash_key(const void *arg)
{
	const struct bfd_tracking_ctx *ctx = arg;

	return jhash(&ctx->key, sizeof(struct bfd_key), 0);
}

static bool bfd_tracking_hash_cmp(const void *n1, const void *n2)
{
	const struct bfd_tracking_ctx *a1 = n1;
	const struct bfd_tracking_ctx *a2 = n2;

	if (memcmp(&a1->key.peer, &a2->key.peer, sizeof(union sockunion)))
		return false;
	if (memcmp(&a1->key.local, &a2->key.local,  sizeof(union sockunion)))
		return false;
	if (memcmp(&a1->key.ifname, &a2->key.ifname, MAXNAMELEN))
		return false;
	if (memcmp(&a1->key.vrfname, &a2->key.vrfname, MAXNAMELEN))
		return false;
	return true;
}

static int bfd_tracking_init(struct thread_master *t)
{
	bfd_tracking_list = hash_create_size(8, bfd_tracking_hash_key,
						  bfd_tracking_hash_cmp,
						  "Tracking Hash");

	install_element(BFD_PEER_NODE, &bfd_tracking_notify_cmd);
	install_element(BFD_PEER_NODE, &bfd_tracking_descr_cmd);
	return 0;
}
