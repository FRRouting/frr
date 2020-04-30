/**
 * zebra_nhrp.c: nhrp 6wind detector file
 *
 * Copyright 2020 6WIND S.A.
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

#ifdef HAVE_NETNS
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <sched.h>
#endif
#include <dirent.h>

#include "json.h"
#include "lib/version.h"
#include "hook.h"
#include "memory.h"
#include "hash.h"
#include "libfrr.h"
#include "command.h"
#include "vty.h"
#include "jhash.h"
#include "ns.h"
#include "vrf.h"
#include "log.h"
#include "resolver.h"
#include <string.h>

#include "zebra/rib.h"
#include "zebra/zapi_msg.h"
#include "zebra/interface.h"
#include "zebra/zebra_router.h"
#include "zebra/debug.h"
#include "zebra/zebra_vrf.h"

#include "zebra/zebra_nhrp.h"
#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_nhrp_clippy.c"
#endif

/* control socket */
struct zebra_nhrp_header {
	uint32_t iface_idx;
	uint16_t packet_length; /* size of the whole packet */
	uint16_t strip_size;    /* size of the non copy data */
	uint16_t protocol_type;
	uint16_t vrfid;
}zebra_nhrp_header_t;

struct zebra_nhrp_ctx {
	struct interface *ifp; /* backpointer and key */
	bool nhrp_6wind_notify[AFI_MAX];
	bool nflog_notify[AFI_MAX];
	bool nhrp_6wind_notify_differ[AFI_MAX];
	int nflog_group;
	int disable_redirect_ipv6;
	int disable_redirect_ipv6_differ;
	int disable_redirect_ipv6_retry;
	struct thread *zebra_nhrp_retry_thread;
	int retry[AFI_MAX];
};

#define ZEBRA_GRE_NHRP_6WIND_PORT 36344

#define ZEBRA_FASTPATH_CONFIG "/var/run/fast-path/conf"

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_NHRP, "Gre Nhrp Notify Information");

/* api routines */
static int zebra_nhrp_6wind_init(struct thread_master *t);
static int zebra_nhrp_6wind_write_config(struct vty *vty);
static int zebra_nhrp_6wind_write_config_iface(struct vty *vty, struct interface *ifp);
static int zebra_nhrp_6wind_nflog_configure(int nflog_group, struct zebra_vrf *zvrf);
static int zebra_nhrp_6wind_if_delete_hook(struct interface *ifp);
static int zebra_nhrp_6wind_if_new_hook(struct interface *ifp);
static int zebra_nhrp_6wind_redirect_set(struct interface *ifp, int family, int on);

/* internal */
static int zebra_nhrp_configure(bool nhrp_6wind, bool is_ipv4,
				bool on, struct interface *ifp,
				int nflog_group);
static int zebra_nhrp_6wind_connection(bool on, uint16_t port);
static int zebra_nhrp_call_only(const char *script, vrf_id_t vrf_id,
				char *buf_response, int len_buf);
static int zebra_nhrp_6wind_notify_differ(struct thread *thread);
static int zebra_nhrp_call_redirect(struct interface *ifp, int on);
static bool zebra_nhrp_6wind_action_ctx(struct zebra_nhrp_ctx *ctx);

/* vty */
#define GRE_NHRP_STR	  "Nhrp Notification Mecanism\n"
#define GRE_NHRP_6WIND_STR "Nhrp 6wind fast-path notification\n"
#define IP_STR		"IP information\n"
#define IPV6_STR	"IPv6 information\n"
#define AFI_STR		IP_STR IPV6_STR

static afi_t cmd_to_afi(const char *tok)
{
	return strcmp(tok, "ipv6") == 0 ? AFI_IP6 : AFI_IP;
}

static const char *afi_to_cmd(afi_t afi)
{
	if (afi == AFI_IP6)
		return "ipv6";
	return "ip";
}

struct hash *zebra_nhrp_list;
static int zebra_nhrp_6wind_port;
int zebra_nhrp_6wind_fd;
struct thread *zebra_nhrp_log_thread;
static struct thread *zebra_nhrp_fastpath_thread;

#define NHRP_RETRY_MAX 5

static uint32_t zebra_nhrp_hash_key(const void *arg)
{
	const struct zebra_nhrp_ctx *ctx = arg;

	return jhash(&ctx->ifp->name, sizeof(ctx->ifp->name), 0);
}

static bool zebra_nhrp_hash_cmp(const void *n1, const void *n2)
{
	const struct zebra_nhrp_ctx *a1 = n1;
	const struct zebra_nhrp_ctx *a2 = n2;

	if (a1->ifp != a2->ifp)
		return false;
	return true;
}

bool zebra_nhrp_fastpath_configured;
static int zebra_nhrp_fastpath_count_unconfigured;
static int zebra_nhrp_fastpath_count_ok;
static int zebra_nhrp_fastpath_count_nok;
static bool zebra_nhrp_6wind_fpn_available;

static int zebra_nhrp_fastpath_restart_walker(struct hash_bucket *b, void *data)
{
	struct zebra_nhrp_ctx *ctx = (struct zebra_nhrp_ctx *)b->data;
	afi_t i;
	int relaunch;

	for (i = 0; i < AFI_MAX; i++) {
		if (ctx->nhrp_6wind_notify[i] && !ctx->nhrp_6wind_notify_differ[i]) {
			ctx->nhrp_6wind_notify_differ[i] = true;
			ctx->retry[i] = 0;
		}
	}
	if (ctx->disable_redirect_ipv6) {
		ctx->disable_redirect_ipv6_differ = 1;
		ctx->disable_redirect_ipv6_retry = 0;
	}

	/* as fast path restarted, (re)send the commands */
	relaunch = zebra_nhrp_6wind_action_ctx(ctx);
	if (relaunch) {
		if (ctx->zebra_nhrp_retry_thread)
			THREAD_OFF(ctx->zebra_nhrp_retry_thread);
		thread_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ctx, 1, &ctx->zebra_nhrp_retry_thread);
	}
	return HASHWALK_CONTINUE;
}

static int zebra_nhrp_6wind_configure_fastpath(uint16_t port)
{
	char retstr[100];
	char buf[100];
	int ret;

	memset(retstr, 0, sizeof(retstr));
	/* fp-cli nhrp-port <port> <vrfid> */
	snprintf(buf, sizeof(buf), "/usr/bin/fp-cli nhrp-port %d 2>&1",
		 port);
	ret = zebra_nhrp_call_only(buf, VRF_DEFAULT, retstr, 0);
	if (ret && strlen(retstr))
		return -1;
	return 0;
}

static void zebra_nhrp_fastpath_handle_result(bool result)
{
	if (result) {
		zebra_nhrp_fastpath_count_ok++;
		/* if status changed, updatethe nhrp 6wind
		 * per interface commands
		 */
		if (!zebra_nhrp_6wind_fpn_available) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s(): fast-path is up", __func__);
			/* reconnect */
			if (zebra_nhrp_6wind_port) {
				zebra_nhrp_6wind_configure_listen_port(zebra_nhrp_6wind_port);
				zebra_nhrp_6wind_configure_fastpath(zebra_nhrp_6wind_port);
			}
			hash_walk(zebra_nhrp_list, zebra_nhrp_fastpath_restart_walker, NULL);
			zebra_nhrp_6wind_fpn_available = true;
		}
	} else {
		zebra_nhrp_fastpath_count_nok++;
		if (zebra_nhrp_6wind_fpn_available) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s(): fast-path is down", __func__);
			zebra_nhrp_6wind_fpn_available = false;
			if (zebra_nhrp_6wind_port) {
				zebra_nhrp_6wind_configure_fastpath(0);
				zebra_nhrp_6wind_configure_listen_port(0);
			}
		}
	}
}

static int zebra_nhrp_fastpath_monitor(struct thread *thread)
{
	DIR *fpdir;
	int fd = -1, orig, ret = 0;
	struct interface *ifp;

	frr_with_privs(&zserv_privs) {
		fpdir = opendir(ZEBRA_FASTPATH_CONFIG);
	}
	if (fpdir == NULL) {
		zebra_nhrp_fastpath_count_unconfigured++;
		goto end;
	}
	zebra_nhrp_fastpath_configured = true;

	/* no need to go further if 6wind fast path not enabled */
	if (!zebra_nhrp_6wind_port) {
		goto end;
	}
	/* continous monitoring */
	if (zebra_nhrp_6wind_access(&fd, &orig) < 0) {
		zebra_nhrp_fastpath_count_unconfigured++;
		goto end;
	}
	/* fast path is on current netns, then lookup fpn0 directly */
	if ( fd < 0) {
		ifp = if_lookup_by_name("fpn0", VRF_DEFAULT);
		if (ifp && if_is_running(ifp))
			zebra_nhrp_fastpath_handle_result(true);
		else
			zebra_nhrp_fastpath_handle_result(false);
		goto end;
	}
	/* if failure to monitor fastpath with netlink */
	if (zebra_nhrp_netlink_fastpath_parse(fd, orig, &ret) < 0) {
		goto end;
	}
	if (ret)
		zebra_nhrp_fastpath_handle_result(true);
	else
		zebra_nhrp_fastpath_handle_result(false);
 end:
	if (fpdir)
		closedir(fpdir);
	if (fd >= 0)
		close(fd);
	thread_add_timer(zrouter.master, zebra_nhrp_fastpath_monitor,
			 NULL, 5, &zebra_nhrp_fastpath_thread);
	return 0;
}

static void zebra_nhrp_fastpath_init(void)
{
	zebra_nhrp_fastpath_configured = false;

	thread_add_timer(zrouter.master, zebra_nhrp_fastpath_monitor,
			 NULL, 0, &zebra_nhrp_fastpath_thread);

}


static void zebra_nhrp_list_init(void)
{
	if (!zebra_nhrp_list)
		zebra_nhrp_list = hash_create_size(8, zebra_nhrp_hash_key,
						   zebra_nhrp_hash_cmp,
						   "Nhrp Hash");
	return;
}

static void zebra_nhrp_flush_entry(struct zebra_nhrp_ctx *ctx)
{
	afi_t afi;

	if (ctx->zebra_nhrp_retry_thread) {
		THREAD_OFF(ctx->zebra_nhrp_retry_thread);
		ctx->zebra_nhrp_retry_thread = NULL;
	}
	ctx->zebra_nhrp_retry_thread = NULL;
	for (afi = 0; afi < AFI_MAX; afi++) {
		if (ctx->nhrp_6wind_notify[afi]) {
			zebra_nhrp_configure(true, afi == AFI_IP ? true : false,
					     false, ctx->ifp, ctx->nflog_group);
			ctx->nhrp_6wind_notify[afi] = false;
			ctx->nhrp_6wind_notify_differ[afi] = false;
		}
		if (ctx->nflog_notify[afi]) {
			zebra_nhrp_configure(false, afi == AFI_IP ? true : false,
					     false, ctx->ifp, ctx->nflog_group);
			ctx->nflog_notify[afi] = false;
		}
	}
	if (ctx->disable_redirect_ipv6) {
		zebra_nhrp_call_redirect(ctx->ifp, 0);
		ctx->disable_redirect_ipv6 = 0;
		ctx->disable_redirect_ipv6_differ = 0;
	}
}

static void zebra_nhrp_list_remove(struct hash_bucket *backet, void *ctxt)
{
	struct zebra_nhrp_ctx *ctx;

	ctx = (struct zebra_nhrp_ctx *)backet->data;
	if (!ctx)
		return;
	zebra_nhrp_flush_entry(ctx);
	hash_release(zebra_nhrp_list, ctx);
	XFREE(MTYPE_ZEBRA_NHRP, ctx);
}

static int zebra_nhrp_6wind_end(void)
{
	if (!zebra_nhrp_list)
		return 0;

	zebra_nhrp_6wind_connection(false, (uint16_t)0);

	hash_iterate(zebra_nhrp_list,
		     zebra_nhrp_list_remove, NULL);
	hash_clean(zebra_nhrp_list, NULL);
	return 1;
}

static int zebra_nhrp_6wind_module_init(void)
{
	hook_register(frr_late_init, zebra_nhrp_6wind_init);
	hook_register(zebra_nflog_configure,
		      zebra_nhrp_6wind_nflog_configure);
	hook_register(zebra_if_config_wr,
		      zebra_nhrp_6wind_write_config_iface);
	hook_register(zebra_vty_config_write,
		      zebra_nhrp_6wind_write_config);
	hook_register(if_add, zebra_nhrp_6wind_if_new_hook);
	hook_register(if_del, zebra_nhrp_6wind_if_delete_hook);
	hook_register(frr_fini, zebra_nhrp_6wind_end);
	hook_register(zebra_redirect_set,
		      zebra_nhrp_6wind_redirect_set);
	return 0;
}

FRR_MODULE_SETUP(
		 .name = "zebra_gre_nhrp_6wind",
		 .version = FRR_VERSION,
		 .description = "gre nhrp 6wind module",
		 .init = zebra_nhrp_6wind_module_init
		 );

static struct zebra_nhrp_ctx *zebra_nhrp_lookup(struct interface *ifp)
{
	struct zebra_nhrp_ctx ctx;

	memset(&ctx, 0, sizeof(struct zebra_nhrp_ctx));
	ctx.ifp = ifp;
	return hash_lookup(zebra_nhrp_list, &ctx);
}

static void *zebra_nhrp_alloc(void *arg)
{
	void *ctx_to_allocate;

	ctx_to_allocate = XCALLOC(MTYPE_ZEBRA_NHRP,
				  sizeof(struct zebra_nhrp_ctx));
	if (!ctx_to_allocate)
		return NULL;
	memcpy(ctx_to_allocate, arg, sizeof(struct zebra_nhrp_ctx));
	return ctx_to_allocate;
}

struct zebra_vrf_nflog_ctx {
	vrf_id_t vrf_id;
	int nflog_group;
};

static void zebra_nhrp_update_nfgroup(int nflog_group,
				      struct zebra_nhrp_ctx *ctxt)
{
	afi_t afi;

	if (nflog_group == ctxt->nflog_group)
		return;
	for (afi = 0; afi < AFI_MAX; afi++) {
		/* suppress */
		if (ctxt->nflog_notify[afi])
			zebra_nhrp_configure(false, afi == AFI_IP ? true : false,
					     false, ctxt->ifp, ctxt->nflog_group);
	}
	ctxt->nflog_group = nflog_group;
	if (!nflog_group)
		return;
	for (afi = 0; afi < AFI_MAX; afi++) {
		/* readd */
		if (ctxt->nflog_notify[afi])
			zebra_nhrp_configure(false, afi == AFI_IP ? true : false,
					     true, ctxt->ifp, ctxt->nflog_group);
	}
}

static int zebra_nhrp_6wind_nflog_walker(struct hash_bucket *b, void *data)
{
	struct zebra_vrf_nflog_ctx *nflog = (struct zebra_vrf_nflog_ctx *)data;
	struct zebra_nhrp_ctx *ctxt = (struct zebra_nhrp_ctx *)b->data;

	if (!ctxt->ifp || !nflog)
		return HASHWALK_CONTINUE;
	if (ctxt->ifp->vrf_id != nflog->vrf_id)
		return HASHWALK_CONTINUE;
	/* update nflog group */
	if (ctxt->nflog_group == nflog->nflog_group)
		return HASHWALK_CONTINUE;
	zebra_nhrp_update_nfgroup(nflog->nflog_group,
				  ctxt);
	return HASHWALK_CONTINUE;
}

static int zebra_nhrp_call_redirect(struct interface *ifp, int on)
{
	char buf[200], vrfstr[100];
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (!vrf)
		return -1;
	memset(vrfstr, 0, sizeof(vrfstr));
	if (vrf->vrf_id != VRF_DEFAULT)
		snprintf(vrfstr, sizeof(vrfstr), "ip netns exec %s ", vrf->name);
	/* a retry mechanism should be put in place */
	snprintf(buf, sizeof(buf), "%sip6tables %s OUTPUT -o %s -p icmpv6 --icmpv6-type redirect -j DROP",
		 vrfstr, on ? "-A" : "-D", ifp->name);
	return zebra_nhrp_call_only(buf, ifp->vrf_id, NULL, 0);
}


static int zebra_nhrp_6wind_redirect_set(struct interface *ifp, int family,
					 int on)
{
	int ret = 0;
	struct zebra_nhrp_ctx *ctx;

	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return 0;

	if (family != AF_INET6)
		return 0;

	if ((!on &&ctx->disable_redirect_ipv6) ||
	    (on && !ctx->disable_redirect_ipv6))
		return 0;
	ctx->disable_redirect_ipv6 = !on;

	if (ifp->ifindex == IFINDEX_INTERNAL && on) {
		ctx->disable_redirect_ipv6_differ = on;
		return 0;
	}
	/* a retry mechanism should be put in place */
	ret = zebra_nhrp_call_redirect(ifp, ctx->disable_redirect_ipv6);
	if (ret && ctx->disable_redirect_ipv6) {
		ctx->disable_redirect_ipv6_differ = on;
		if (ctx->zebra_nhrp_retry_thread)
			thread_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
					 ctx, 1, &ctx->zebra_nhrp_retry_thread);
	}
	return 1;
}

static int zebra_nhrp_6wind_nflog_configure(int nflog_group,
					    struct zebra_vrf *zvrf)
{
	struct zebra_vrf_nflog_ctx ctx;

	if (!zvrf->vrf)
		return 0;

	ctx.vrf_id = zvrf->vrf->vrf_id;
	ctx.nflog_group = nflog_group;

	hash_walk(zebra_nhrp_list, zebra_nhrp_6wind_nflog_walker, &ctx);
	return 1;
}

static int zebra_nhrp_6wind_write_config(struct vty *vty)
{
	if (zebra_nhrp_6wind_port) {
		vty_out(vty, "nhrp 6wind %u\n", zebra_nhrp_6wind_port);
		return 1;
	}
	return 0;
}

static int zebra_nhrp_6wind_write_config_iface(struct vty *vty, struct interface *ifp)
{
	struct zebra_nhrp_ctx *ctx;
	const char *aficmd;
	int ret = 0;
	afi_t afi;

	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return ret;
	for (afi = 0; afi < AFI_MAX; afi++) {
		aficmd = afi_to_cmd(afi);

		if (ctx->nhrp_6wind_notify[afi]) {
			vty_out(vty, " %s nhrp 6wind\n",
				aficmd);
			ret++;
		}
		if (ctx->nflog_notify[afi]) {
			vty_out(vty, " %s nhrp nflog\n", aficmd);
			ret++;
		}
	}
	return ret;
}

static bool zebra_nhrp_6wind_action_ctx(struct zebra_nhrp_ctx *ctx)
{
	int relaunch = 0;
	afi_t i;
	int ret;

	for (i = 0; i < AFI_MAX; i++) {
		if (ctx->nhrp_6wind_notify_differ[i]) {
			ctx->retry[i]++;
			ret = zebra_nhrp_configure(true, i == AFI_IP ? true : false,
						   true, ctx->ifp, ctx->nflog_group);
			if (ret) {
				if (ctx->retry[i] == NHRP_RETRY_MAX) {
					zlog_debug("%s(): failed to configure nhrp 6wind for afi %d, if %s",
						   __func__, i, ctx->ifp->name);
					ctx->retry[i] = 0;
					continue;
				}
				relaunch = 1;
			} else {
				ctx->nhrp_6wind_notify_differ[i] = false;
				ctx->retry[i] = 0;
			}
		}
	}
	if (ctx->disable_redirect_ipv6_differ) {
		/* a retry mechanism should be put in place */
		ctx->disable_redirect_ipv6_retry++;
		ret = zebra_nhrp_call_redirect(ctx->ifp, ctx->disable_redirect_ipv6);
		if (ret) {
			if (ctx->disable_redirect_ipv6_retry == NHRP_RETRY_MAX) {
				zlog_debug("%s(): failed to configure nhrp redirect for if %s",
					   __func__, ctx->ifp->name);
				ctx->disable_redirect_ipv6_retry = 0;
				goto end_function;
			}
			relaunch = 1;
		}
	}
 end_function:
	return relaunch;
}

static int zebra_nhrp_6wind_notify_differ(struct thread *thread)
{
	struct zebra_nhrp_ctx *ctx = THREAD_ARG(thread);
	int relaunch;

	relaunch = zebra_nhrp_6wind_action_ctx(ctx);
	if (relaunch) {
		if (ctx->zebra_nhrp_retry_thread)
			THREAD_OFF(ctx->zebra_nhrp_retry_thread);
		thread_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ctx, 1, &ctx->zebra_nhrp_retry_thread);
	} else {
		ctx->zebra_nhrp_retry_thread = NULL;
	}
	return 0;
}

static int zebra_nhrp_6wind_if_new_hook(struct interface *ifp)
{
	struct zebra_nhrp_ctx ctx;
	struct zebra_nhrp_ctx *ptr;
	int i, ret = 0;
	bool replay = false;

	memset(&ctx, 0, sizeof(struct zebra_nhrp_ctx));
	ctx.ifp = ifp;
	zebra_nhrp_list_init();
	ptr = hash_lookup(zebra_nhrp_list, &ctx);
	if (!ptr) {
		ctx.disable_redirect_ipv6 = 0;
		for (i = 0; i < AFI_MAX; i++) {
			ctx.nhrp_6wind_notify[i] = false;
			ctx.nflog_notify[i] = false;
			ctx.nhrp_6wind_notify_differ[i] = false;
		}
		ptr = hash_get(zebra_nhrp_list, &ctx,
			       zebra_nhrp_alloc);
	}
	/* XXX no retry mechanism at this point */
	if (ifp->ifindex != IFINDEX_INTERNAL) {
		for (i = 0; i < AFI_MAX; i++) {
			if (ptr->nhrp_6wind_notify_differ[i])
				ret = zebra_nhrp_configure(true, i == AFI_IP ? true : false,
						     true, ifp, ptr->nflog_group);
			if (ret && ptr->nhrp_6wind_notify[i]) {
				ptr->nhrp_6wind_notify_differ[i] = ptr->nhrp_6wind_notify[i];
				replay = true;
			}
		}
		if (ptr->disable_redirect_ipv6_differ)
			ret = zebra_nhrp_call_redirect(ifp, ptr->disable_redirect_ipv6);
		if (ret && ptr->disable_redirect_ipv6)
			replay = true;
	}
	if (replay)
		thread_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ptr, 1, &ptr->zebra_nhrp_retry_thread);
	return 1;
}

static int zebra_nhrp_6wind_if_delete_hook(struct interface *ifp)
{
	struct zebra_nhrp_ctx *ctx;

	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return 0;

	zebra_nhrp_flush_entry(ctx);
	hash_release(zebra_nhrp_list, ctx);
	XFREE(MTYPE_ZEBRA_NHRP, ctx);
	return 0;
}

int zebra_nhrp_6wind_log_recv(struct thread *t)
{
	int fd = THREAD_FD(t);
	char buf[ZEBRA_GRE_NHRP_6WIND_RCV_BUF];
	unsigned int len;
	struct zebra_nhrp_header *ctxt;
	ifindex_t iface_idx;
	uint32_t packet_length;
	uint32_t strip_size;
	uint32_t protocol_type;
	uint8_t *data;
	vrf_id_t vrf_id;
	struct interface *ifp;

	zebra_nhrp_log_thread = NULL;
	thread_add_read(zrouter.master, zebra_nhrp_6wind_log_recv,
			NULL, fd,
			&zebra_nhrp_log_thread);

	len = read(fd, buf, ZEBRA_GRE_NHRP_6WIND_RCV_BUF);
	if (len <= 0) {
		zlog_err("%s(): len negative. retry", __func__);
		return 0;
	}
	ctxt = (struct zebra_nhrp_header *)buf;
	packet_length = ntohs(ctxt->packet_length);
	strip_size = ntohs(ctxt->strip_size);
	if (len != sizeof(struct zebra_nhrp_header) + packet_length - strip_size) {
		zlog_err("%s(): %u bytes received on nhrp 6wind port, expected %u",
			 __func__, len,
			 (unsigned int)(sizeof(struct zebra_nhrp_header) +
					packet_length - strip_size));
		return 0;
	}
	iface_idx = (ifindex_t)ntohl(ctxt->iface_idx);
	vrf_id = (vrf_id_t)(ctxt->vrfid);
	protocol_type = ntohs(ctxt->protocol_type);
	data = (uint8_t *)(ctxt + 1);
	ifp = if_lookup_by_index(iface_idx, vrf_id);
	if (!ifp) {
		zlog_err("%s(): unknown interface idx %u vrf_id %u",
			 __func__, iface_idx, vrf_id);
		return 0;
	}
	zsend_nflog_notify(ZEBRA_NFLOG_TRAFFIC_INDICATION, ifp,
			   protocol_type, data,
			   packet_length - strip_size);
	return 0;
}

static int zebra_nhrp_call_only(const char *script, vrf_id_t vrf_id,
				char *buf_response, int len_buf)
{
	FILE *fp;
	char *current_str = NULL;

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		zlog_debug("NHRP : %s", script);

	vrf_switch_to_netns(vrf_id);

	fp = popen(script, "r");

	if (!fp) {
		zlog_err("NHRP: error calling %s", script);
		vrf_switchback_to_initial();
		return -1;
	}
	if (buf_response) {
		buf_response[0] = '\0';
		do {
			current_str = fgets(buf_response, len_buf, fp);
		} while (current_str != NULL);
		if (strlen(buf_response)) {
			if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
				zlog_debug("NHRP : %s", buf_response);
			return -1;
		}
	}
	vrf_switchback_to_initial();

	pclose(fp);

	return 0;
}

static int zebra_nhrp_6wind_connection(bool on, uint16_t port)
{
	int ret = 0;

	if (!on) {
		ret = zebra_nhrp_6wind_configure_listen_port(0);
		zebra_nhrp_6wind_port = 0;
	} else {
		ret = zebra_nhrp_6wind_configure_listen_port(port);
		zebra_nhrp_6wind_port = port;
	}
	if (ret < 0)
		return ret;

	zebra_nhrp_6wind_configure_fastpath(on ? port : 0);
	return 0;
}

static int zebra_nhrp_configure(bool nhrp_6wind, bool is_ipv4,
				bool on, struct interface *ifp,
				int nflog_group)
{
	char buf[500], buf2[100], buf3[110], buf4_ipv4[100], buf4_ipv6[100], buf5_vrf[55];
	struct vrf *vrf = NULL;
	char buf_vrf[1000];
	char retstr[100];
	int ret;

	memset(buf5_vrf, 0, sizeof(buf5_vrf));
	/* iptables : /sbin/iptables  -A FORWARD -i gre5 -o gre5 -j NFLOG
	 *      --nflog-group 6 --nflog-threshold 10
	 * ip6tables : /sbin/iptables  -A FORWARD -i gre5 -o gre5 -j NFLOG
	 *      --nflog-group 6 --nflog-threshold 10
	 */
	vrf = vrf_lookup_by_id(ifp->vrf_id);
	if (!vrf)
		return -1;
	if (!nhrp_6wind) {
		snprintf(buf3, sizeof(buf3), " %s%s%s",
			 "-m hashlimit --hashlimit-name nflog",
			 ifp->name,
			 " --hashlimit-upto 4/minute --hashlimit-burst 1");
		snprintf(buf4_ipv4, sizeof(buf4_ipv4), "%s %s",
			 " --hashlimit-mode srcip,dstip --hashlimit-srcmask 24",
			 "--hashlimit-dstmask 24");
		snprintf(buf4_ipv6, sizeof(buf4_ipv6), "%s %s",
			 " --hashlimit-mode srcip,dstip --hashlimit-srcmask 64",
			 "--hashlimit-dstmask 64");
		snprintf(buf2, sizeof(buf2), "--nflog-threshold 10");

		if (vrf->vrf_id != VRF_DEFAULT)
			snprintf(buf5_vrf, sizeof(buf5_vrf), "ip netns exec %s ", vrf->name);
		snprintf(buf, sizeof(buf), "%s%s %s FORWARD -i %s -o %s %s %u %s%s%s",
			 buf5_vrf,
			 is_ipv4 ? "/sbin/iptables" : "/sbin/ip6tables",
			 on ? "-A" : "-D",
			 ifp->name, ifp->name,
			 "-j NFLOG --nflog-group",
			 nflog_group,
			 buf2, buf3, is_ipv4 ? buf4_ipv4 : buf4_ipv6);
	} else {
		uint32_t vrid = 0;

		if (vrf->vrf_id != VRF_DEFAULT) {
			snprintf(buf, sizeof(buf), "/usr/bin/vrfctl list vrfname %s",
				 vrf->name);
			memset(buf_vrf, 0, sizeof(buf_vrf));
			zebra_nhrp_call_only(buf, ifp->vrf_id, buf_vrf, sizeof(buf_vrf));
			if (memcmp(buf_vrf, "vrf", 3) == 0)
				vrid = atoi(&buf_vrf[3]);
			else {
				zlog_err("%s(): could not retrieve id from vrf %s (%s)",
					 __func__, vrf->name, buf_vrf);
				return -1;
			}
		}
		snprintf(buf, sizeof(buf), "/usr/bin/fp-cli nhrp-iface-set %s %s %s %u 2>&1",
			 ifp->name,
			 is_ipv4 ? "ipv4" : "ipv6",
			 on ? "on" : "off",
			 vrid);
	}
	memset(retstr, 0, sizeof(retstr));
	ret = zebra_nhrp_call_only(buf, ifp->vrf_id, retstr, sizeof(retstr));
	if (ret && strlen(retstr))
		return -1;
	return 0;
}

DEFPY (iface_nhrp_6wind_onoff,
       iface_nhrp_6wind_onoff_cmd,
       "[no$no] <ip$ipv4|ipv6$ipv6> nhrp 6wind",
       NO_STR
       AFI_STR
       GRE_NHRP_STR
       GRE_NHRP_6WIND_STR)
{
	struct zebra_nhrp_ctx *ctx;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	bool action_to_set = true;
	afi_t afi;
	int ret = -1;

	if (ipv4)
		afi = cmd_to_afi(ipv4);
	else
		afi = cmd_to_afi(ipv6);
	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return CMD_WARNING;
	if (no) {
		action_to_set = false;
	}
	if (action_to_set == ctx->nhrp_6wind_notify[afi])
		return CMD_SUCCESS;
	ctx->nhrp_6wind_notify[afi] = action_to_set;
	/* will be triggered by if_new_hook() */
	if (ifp->ifindex == IFINDEX_INTERNAL && action_to_set) {
		ctx->nhrp_6wind_notify_differ[afi] = ctx->nhrp_6wind_notify[afi];
		return CMD_SUCCESS;
	}
	/* a retry mechanism should be put in place */
	ret = zebra_nhrp_configure(true, ipv4 ? true : false,
				   action_to_set, ctx->ifp,
				   ctx->nflog_group);
	if (ret && ctx->nhrp_6wind_notify[afi]) {
		ctx->nhrp_6wind_notify_differ[afi] = ctx->nhrp_6wind_notify[afi];
		thread_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ctx, 1, &ctx->zebra_nhrp_retry_thread);
	}
	return CMD_SUCCESS;
}

DEFPY (iface_nflog_onoff,
       iface_nflog_onoff_cmd,
       "[no$no] <ip$ipv4|ipv6$ipv6> nhrp nflog",
       NO_STR
       AFI_STR
       GRE_NHRP_STR
       "Netfilter log notification\n")
{
	struct zebra_nhrp_ctx *ctx;
	VTY_DECLVAR_CONTEXT(interface, ifp);
	bool action_to_set = true;
	afi_t afi;

	if (ipv4)
		afi = cmd_to_afi(ipv4);
	else
		afi = cmd_to_afi(ipv6);

	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return CMD_WARNING;
	if (no)
		action_to_set = false;
	if (action_to_set == ctx->nflog_notify[afi])
		return CMD_SUCCESS;
	ctx->nflog_notify[afi] = action_to_set;
	/* call */
	zebra_nhrp_configure(false, ipv4 ? true : false, action_to_set,
			     ifp, ctx->nflog_group);
	return CMD_SUCCESS;
}

DEFPY(zebra_nhrp_6wind_connect, zebra_nhrp_6wind_connect_cmd,
      "[no$no] nhrp 6wind [(1-65535)$port]",
      NO_STR
      GRE_NHRP_STR
      GRE_NHRP_6WIND_STR
      "Port number to connect to\n")
{
	int ret;

	if (no) {
		/* close */
		zebra_nhrp_6wind_connection(false, (uint16_t)0);
		zebra_nhrp_6wind_port = 0;
		return CMD_SUCCESS;
	}
	if (port == zebra_nhrp_6wind_port)
		return CMD_SUCCESS;
	ret = zebra_nhrp_6wind_connection(true, (uint16_t)port);
	if (ret < 0) {
		vty_out(vty, "Failed to connect to Fast-Path with port %ld\r\n", port);
		return CMD_WARNING;
	}
	zebra_nhrp_6wind_port = port;
	return CMD_SUCCESS;
}

DEFPY(show_zebra_nhrp,
      show_zebra_nhrp_cmd,
      "show zebra nhrp",
      SHOW_STR
      ZEBRA_STR
      GRE_NHRP_STR)
{
	vty_out(vty, "Fast-Path is %s\n",zebra_nhrp_6wind_fpn_available ?
		"on" : "off");
	vty_out(vty, "\tFastPath Not Configured Count : %u",
		zebra_nhrp_fastpath_count_unconfigured);
	vty_out(vty, "\tFastPath Down Count : %u\n",
		zebra_nhrp_fastpath_count_nok);
	vty_out(vty, "\tFastPath Up Count : %u\n",
		zebra_nhrp_fastpath_count_ok);

	return CMD_SUCCESS;
}

static int zebra_nhrp_6wind_init(struct thread_master *t)
{
	zebra_nhrp_list_init();
	zebra_nhrp_fastpath_init();
	zebra_nhrp_6wind_fd = -1;
	zebra_nhrp_6wind_port = 0;
	zebra_nhrp_6wind_fpn_available = false;
	install_element(INTERFACE_NODE, &iface_nflog_onoff_cmd);
	install_element(INTERFACE_NODE, &iface_nhrp_6wind_onoff_cmd);
	install_element(CONFIG_NODE, &zebra_nhrp_6wind_connect_cmd);
	install_element(VIEW_NODE, &show_zebra_nhrp_cmd);
	return 0;
}
