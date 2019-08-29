/**
 * pm_tracking.c: PM tracking file
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

#include "pm_memory.h"
#include "pm.h"
#include "pm_tracking.h"

#ifndef VTYSH_EXTRACT_PL
#include "pmd/pm_tracking_clippy.c"
#endif

DEFINE_MTYPE_STATIC(PMD, PM_TRACKING, "Tracking Information");
DEFINE_MTYPE_STATIC(PMD, PM_TRACK_LABEL, "Tracking Label Information");

static int pm_tracking_call_update_param(struct pm_session *pm);

static int pm_tracking_call_notify_filename(struct pm_session *pm);

static int pm_tracking_call_write_config(struct pm_session *pm,
					 struct vty *vty);

static int pm_tracking_call_release_session(struct pm_session *pm);

static int pm_tracking_call_new_session(struct pm_session *pm);

static int pm_tracking_call_get_dest_address(struct pm_session *pm,
					     union sockunion *peer);

static int pm_tracking_call_get_gateway_address(struct pm_session *pm,
						union sockunion *gw);

static int pm_tracking_call_display(struct pm_session *pm,
				    struct vty *vty,
				    struct json_object *jo);

static int pm_tracking_init(struct thread_master *t);

static int pm_tracking_module_init(void)
{
	hook_register(frr_late_init, pm_tracking_init);
	hook_register(pm_tracking_update_param,
		      pm_tracking_call_update_param);
	hook_register(pm_tracking_notify_filename,
		      pm_tracking_call_notify_filename);
	hook_register(pm_tracking_write_config,
		      pm_tracking_call_write_config);
	hook_register(pm_tracking_new_session,
		      pm_tracking_call_new_session);
	hook_register(pm_tracking_release_session,
		      pm_tracking_call_release_session);
	hook_register(pm_tracking_get_dest_address,
		      pm_tracking_call_get_dest_address);
	hook_register(pm_tracking_get_gateway_address,
		      pm_tracking_call_get_gateway_address);
	hook_register(pm_tracking_display,
		      pm_tracking_call_display);
	return 0;
}

FRR_MODULE_SETUP(
		 .name = "pm_tracking",
		 .version = FRR_VERSION,
		 .description = "pm tracking module",
		 .init = pm_tracking_module_init
		 );

struct hash *pm_tracking_list;

struct pm_tracking_ctx {
	struct pm_session_key key;
	union sockunion gateway;
	union sockunion alternate;
	char notify_path[PATH_MAX];
	char *label;
};

static struct pm_tracking_ctx *pm_tracking_lookup_from_pm(struct pm_session *pm)
{
	struct pm_tracking_ctx ctx;

	memset(&ctx, 0, sizeof(struct pm_tracking_ctx));
	memcpy(&ctx.key, &pm->key, sizeof(struct pm_session_key));
	return hash_lookup(pm_tracking_list, &ctx);
}

static int pm_tracking_call_write_config(struct pm_session *pm, struct vty *vty)
{
	char buf[SU_ADDRSTRLEN];
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (sockunion_family(&ctx->gateway) == AF_INET ||
	    sockunion_family(&ctx->gateway) == AF_INET6) {
		vty_out(vty, "  gateway %s\n",
			sockunion2str(&ctx->gateway,
					   buf, sizeof(buf)));
	}
	if (ctx->notify_path[0]) {
		vty_out(vty, "  notify %s\n",
			ctx->notify_path);
	}
	if (sockunion_family(&ctx->alternate) == AF_INET ||
	    sockunion_family(&ctx->alternate) == AF_INET6) {
		vty_out(vty, "  alternate %s\n",
			sockunion2str(&ctx->alternate,
					   buf, sizeof(buf)));
	}
	if (ctx->label) {
		vty_out(vty, "  label %s\n",
			ctx->label);
	}
	return 1;
}

static void *pm_tracking_alloc(void *arg)
{
	struct hash *ctx_to_allocate;

	ctx_to_allocate = XCALLOC(MTYPE_PM_TRACKING,
				  sizeof(struct pm_tracking_ctx));
	if (!ctx_to_allocate)
		return NULL;
	memcpy(ctx_to_allocate, arg, sizeof(struct pm_tracking_ctx));
	return ctx_to_allocate;
}

static int pm_tracking_call_update_param(struct pm_session *pm)
{
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	/* overwrite params */
	if ((sockunion_family(&ctx->gateway) == AF_INET) ||
	    (sockunion_family(&ctx->gateway) == AF_INET6))
		memcpy(&pm->nh, &ctx->gateway,
		       sizeof(union sockunion));
	return 1;
}

static int pm_tracking_notify_update_status(char *path, int status)
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

static int pm_tracking_call_notify_filename(struct pm_session *pm)
{
	struct pm_tracking_ctx *ctx;
	int status = 0;
	int ret;
	char buf[SU_ADDRSTRLEN];

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (pm->ses_state == PM_UP)
		status = 0;
	else if ((pm->ses_state == PM_DOWN) ||
		 (pm->ses_state == PM_INIT))
		status = 1;
	else
		/* case init state or admin down
		 * or other
		 */
		return 0;
	if (!ctx->notify_path[0])
		return 0;
	ret = pm_tracking_notify_update_status(ctx->notify_path, status);
	if (ret > 0) {
		sockunion2str(&ctx->key.peer, buf, sizeof(buf)),
			zlog_info("tracker %s, notifying %s to %s",
				  buf, pm->ses_state == PM_UP ?
				  "UP" : "DOWN", ctx->notify_path);
	}
	return ret;
}

static int pm_tracking_alternate_call(struct pm_session *pm,
				      const char *alt,
				      struct vty *vty)
{
	struct pm_tracking_ctx *ctx;
	union sockunion alternate;
	int ret;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (alt) {
		ret = str2sockunion(alt, &alternate);
		if (ret != 0) {
			vty_out(vty,
				"%% invalid source address %s. cancel\n",
				alt);
			return CMD_WARNING_CONFIG_FAILED;
		}
		memcpy(&ctx->alternate, &alternate,
		       sizeof(union sockunion));
	} else {
		memset(&ctx->alternate, 0,
		       sizeof(union sockunion));
	}
	return CMD_SUCCESS;
}

DEFPY (pm_tracking_alternate,
       pm_tracking_alternate_cmd,
       "[no$no] alternate <A.B.C.D|X:X::X:X>$alternate",
       NO_STR
       "Define alternate destination IP address\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);
	if (no)
		return pm_tracking_alternate_call(pm, NULL, vty);
	return pm_tracking_alternate_call(pm, alternate_str, vty);
}

static int pm_tracking_gateway_call(struct pm_session *pm,
				    const char *gw,
				    struct vty *vty)
{
	struct pm_tracking_ctx *ctx;
	union sockunion gateway;
	int ret;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (gw) {
		ret = str2sockunion(gw, &gateway);
		if (ret != 0) {
			vty_out(vty,
				"%% invalid source address %s. cancel\n",
				gw);
			return CMD_WARNING_CONFIG_FAILED;
		}
		memcpy(&ctx->gateway, &gateway,
		       sizeof(union sockunion));
	} else {
		memset(&ctx->gateway, 0,
		       sizeof(union sockunion));
	}
	return CMD_SUCCESS;
}

DEFPY (pm_tracking_gateway_ip,
       pm_tracking_gateway_ip_cmd,
       "[no$no] gateway <A.B.C.D|X:X::X:X>$gw",
       NO_STR
       "Define gateway to send packet to\n"
       "IPv4 address\n"
       "IPv6 address\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);
	if (no)
		return pm_tracking_gateway_call(pm, NULL, vty);
	return pm_tracking_gateway_call(pm, gw_str, vty);
}

static int pm_tracking_label_call(struct pm_session *pm,
				  const char *label,
				  struct vty *vty)
{
	static struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return CMD_WARNING_CONFIG_FAILED;

	if (ctx->label)
		XFREE(MTYPE_PM_TRACK_LABEL, ctx->label);
	if (label)
		ctx->label = XSTRDUP(MTYPE_PM_TRACK_LABEL, label);
	else
		ctx->label = NULL;
	return CMD_SUCCESS;
}

static int pm_tracking_notify_call(struct pm_session *pm,
				   const char *pathname,
				   struct vty *vty)
{
	static struct pm_tracking_ctx *ctx;
	char tmp_name[PATH_MAX] = "";

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return CMD_WARNING_CONFIG_FAILED;

	/* relevant pathname */
	if (!realpath(pathname, tmp_name) && errno != ENOENT) {
		vty_out(vty, "Invalid pathname for %s: %s\n",
			pathname, safe_strerror(errno));
		return CMD_WARNING_CONFIG_FAILED;
	}
	snprintf(ctx->notify_path, sizeof(ctx->notify_path), "%s", tmp_name);
	return CMD_SUCCESS;
}

DEFPY(
      pm_tracking_label, pm_tracking_label_cmd,
      "[no] label [<NAME$name>]",
	NO_STR
	"Configure tracking name description\n"
	"Description field\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);
	if (no)
		return pm_tracking_label_call(pm, NULL, vty);
	return pm_tracking_label_call(pm, name, vty);
}

DEFPY (pm_tracking_notify,
       pm_tracking_notify_cmd,
       "[no$no] notify WORD$path",
       NO_STR
       "Define notification path name to notify changes to\n"
       "Full file name with path\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);
	if (no)
		return pm_tracking_notify_call(pm, NULL, vty);
	return pm_tracking_notify_call(pm, path, vty);
}

static int pm_tracking_call_release_session(struct pm_session *pm)
{
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (ctx->notify_path[0])
		pm_tracking_notify_update_status(ctx->notify_path, 0);
	if (ctx->label)
		XFREE(MTYPE_PM_TRACK_LABEL, ctx->label);
	ctx->label = NULL;
	hash_release(pm_tracking_list, &ctx);
	return 1;
}

static int pm_tracking_call_new_session(struct pm_session *pm)
{
	struct pm_tracking_ctx ctx;

	if (!pm)
		return 0;
	memset(&ctx, 0, sizeof(struct pm_tracking_ctx));
	memcpy(&ctx.key, &pm->key, sizeof(struct pm_session_key));

	hash_get(pm_tracking_list, &ctx,
		 pm_tracking_alloc);
	return 1;
}

static int pm_tracking_call_get_dest_address(struct pm_session *pm,
					     union sockunion *peer)
{
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (sockunion_family(&ctx->alternate) == AF_INET ||
	    sockunion_family(&ctx->alternate) == AF_INET6) {
		memcpy(peer, &ctx->alternate,
		       sizeof(union sockunion));
		return 1;
	}
	return 0;
}

static int pm_tracking_call_get_gateway_address(struct pm_session *pm,
						union sockunion *gw)
{
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;
	if (sockunion_family(&ctx->gateway) == AF_INET ||
	    sockunion_family(&ctx->gateway) == AF_INET6) {
		memcpy(gw, &ctx->gateway,
		       sizeof(union sockunion));
		return 1;
	}
	return 0;
}

static int pm_tracking_call_display(struct pm_session *pm,
				    struct vty *vty,
				    struct json_object *jo)
{
	char buf[SU_ADDRSTRLEN];
	struct pm_tracking_ctx *ctx;

	ctx = pm_tracking_lookup_from_pm(pm);
	if (!ctx)
		return 0;

	if (sockunion_family(&ctx->gateway) == AF_INET ||
	    sockunion_family(&ctx->gateway) == AF_INET6) {
		sockunion2str(&ctx->gateway,
			      buf, sizeof(buf));
		if (vty)
			vty_out(vty, "\tnext-hop %s\n", buf);
		if (jo)
			json_object_string_add(jo, "next-hop",
					    buf);
	}
	if (ctx->notify_path[0]) {
		if (vty)
			vty_out(vty, "\tnotify %s\n",
				ctx->notify_path);
		if (jo)
			json_object_string_add(jo, "notify-path",
					       ctx->notify_path);
	}
	if (sockunion_family(&ctx->alternate) == AF_INET ||
	    sockunion_family(&ctx->alternate) == AF_INET6) {
		sockunion2str(&ctx->alternate,
			      buf, sizeof(buf));
		if (vty)
			vty_out(vty, "\toverride dst-ip %s\n", buf);
		if (jo)
			json_object_string_add(jo, "dst-ip",
					    buf);
	}
	if (ctx->label) {
		if (vty)
			vty_out(vty, "\tlabel %s\n", ctx->label);
		if (jo)
			json_object_string_add(jo, "label",
					       ctx->label);
	}
	return 1;
}

static unsigned int pm_tracking_hash_key(const void *arg)
{
	const struct pm_tracking_ctx *ctx = arg;

	return jhash(&ctx->key, sizeof(struct pm_session_key), 0);
}

static bool pm_tracking_hash_cmp(const void *n1, const void *n2)
{
	const struct pm_tracking_ctx *a1 = n1;
	const struct pm_tracking_ctx *a2 = n2;

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

static int pm_tracking_init(struct thread_master *t)
{
	pm_tracking_list = hash_create_size(8, pm_tracking_hash_key,
						  pm_tracking_hash_cmp,
						  "Tracking Hash");

	install_element(PM_SESSION_NODE, &pm_tracking_gateway_ip_cmd);
	install_element(PM_SESSION_NODE, &pm_tracking_notify_cmd);
	install_element(PM_SESSION_NODE, &pm_tracking_alternate_cmd);
	install_element(PM_SESSION_NODE, &pm_tracking_label_cmd);
	return 0;
}
