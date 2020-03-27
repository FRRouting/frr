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
#include <fcntl.h>

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

#define ZEBRA_GRE_NHRP_6WIND_PORT 36344
#define ZEBRA_GRE_NHRP_6WIND_ADDRESS "127.0.0.1"

#define ZEBRA_GRE_NHRP_6WIND_RCV_BUF 500

DEFINE_MTYPE_STATIC(ZEBRA, ZEBRA_NHRP, "Gre Nhrp Notify Information");

/* api routines */
static int zebra_nhrp_6wind_nflog_configure(int nflog_group, struct zebra_vrf *zvrf);
static int zebra_nhrp_6wind_if_delete_hook(struct interface *ifp);
static int zebra_nhrp_6wind_if_new_hook(struct interface *ifp);
static int zebra_nhrp_6wind_redirect_set(struct interface *ifp, int family, int on);

/* internal */
static int zebra_nhrp_configure(bool nhrp_6wind, bool is_ipv4,
				bool on, struct interface *ifp,
				int nflog_group);
static int zebra_nhrp_call_only(const char *script, vrf_id_t vrf_id,
				char *buf_response, int len_buf);
static void zebra_nhrp_6wind_notify_differ(struct event *event);
static int zebra_nhrp_call_redirect(struct interface *ifp, int on);

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
/* New network namespace (lo, device, names sockets, etc) */
#endif

#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = EINVAL;
	return -1;
#endif
}
#endif /* !HAVE_SETNS */

struct hash *zebra_nhrp_list;
static int zebra_nhrp_6wind_fd;
static struct event *zebra_nhrp_log_event;

#define NHRP_RETRY_MAX 5

struct zebra_nhrp_ctx {
	struct interface *ifp; /* backpointer and key */
	bool nhrp_6wind_notify[AFI_MAX];
	bool nflog_notify[AFI_MAX];
	bool nhrp_6wind_notify_differ[AFI_MAX];
	int nflog_group;
	int disable_redirect_ipv6;
	int disable_redirect_ipv6_differ;
	int disable_redirect_ipv6_retry;
	struct event *zebra_nhrp_retry_event;
	int retry[AFI_MAX];
};

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

	if (ctx->zebra_nhrp_retry_event) {
		EVENT_OFF(ctx->zebra_nhrp_retry_event);
		ctx->zebra_nhrp_retry_event = NULL;
	}
	ctx->zebra_nhrp_retry_event = NULL;
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

static void zebra_nhrp_6wind_hook_init(void)
{
	hook_register(zebra_nflog_configure, zebra_nhrp_6wind_nflog_configure);
	hook_register(if_add, zebra_nhrp_6wind_if_new_hook);
	hook_register(if_del, zebra_nhrp_6wind_if_delete_hook);
	hook_register(frr_fini, zebra_nhrp_6wind_end);
	hook_register(zebra_redirect_set, zebra_nhrp_6wind_redirect_set);
}

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
	if (ctxt->ifp->vrf->vrf_id != nflog->vrf_id)
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
	char buf[200], vrfstr[100], retstr[100];
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(ifp->vrf->vrf_id);
	if (!vrf)
		return -1;
	memset(vrfstr, 0, sizeof(vrfstr));
	if (vrf->vrf_id != VRF_DEFAULT)
		snprintf(vrfstr, sizeof(vrfstr), "ip netns exec %s ", vrf->name);
	/* a retry mechanism should be put in place */
	snprintf(buf, sizeof(buf), "%sip6tables %s OUTPUT -o %s -p icmpv6 --icmpv6-type redirect -j DROP",
		 vrfstr, on ? "-A" : "-D", ifp->name);
	return zebra_nhrp_call_only(buf, ifp->vrf->vrf_id, retstr, strlen(retstr));
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
		if (ctx->zebra_nhrp_retry_event)
			event_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
					 ctx, 1, &ctx->zebra_nhrp_retry_event);
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

static void zebra_nhrp_6wind_notify_differ(struct event *event)
{
	struct zebra_nhrp_ctx *ctx = EVENT_ARG(event);
	int ret = 0;
	afi_t i;
	bool relaunch = false;

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
				relaunch = true;
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
			relaunch = true;
		}
	}

 end_function:
	if (relaunch)
		event_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ctx, 1, &ctx->zebra_nhrp_retry_event);
	else
		ctx->zebra_nhrp_retry_event = NULL;
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
		event_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ptr, 1, &ptr->zebra_nhrp_retry_event);
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

static void zebra_nhrp_6wind_log_recv(struct event *t)
{
	int fd = EVENT_FD(t);
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

	zebra_nhrp_log_event = NULL;
	event_add_read(zrouter.master, zebra_nhrp_6wind_log_recv,
			NULL, fd,
			&zebra_nhrp_log_event);

	len = read(fd, buf, ZEBRA_GRE_NHRP_6WIND_RCV_BUF);
	if (len <= 0) {
		zlog_err("%s(): len negative. retry", __func__);
		return;
	}
	ctxt = (struct zebra_nhrp_header *)buf;
	packet_length = ntohs(ctxt->packet_length);
	strip_size = ntohs(ctxt->strip_size);
	if (len != sizeof(struct zebra_nhrp_header) + packet_length - strip_size) {
		zlog_err("%s(): %u bytes received on nhrp 6wind port, expected %u",
			 __func__, len,
			 (unsigned int)(sizeof(struct zebra_nhrp_header) +
					packet_length - strip_size));
		return;
	}
	iface_idx = (ifindex_t)ntohl(ctxt->iface_idx);
	vrf_id = (vrf_id_t)(ctxt->vrfid);
	protocol_type = ntohs(ctxt->protocol_type);
	data = (uint8_t *)(ctxt + 1);
	ifp = if_lookup_by_index(iface_idx, vrf_id);
	if (!ifp) {
		zlog_err("%s(): unknown interface idx %u vrf_id %u",
			 __func__, iface_idx, vrf_id);
		return;
	}
	zsend_nflog_notify(ZEBRA_NFLOG_TRAFFIC_INDICATION, ifp,
			   protocol_type, data,
			   packet_length - strip_size);
	return;
}

static int zebra_nhrp_6wind_configure_listen_port(uint16_t port)
{
	struct sockaddr_in srvaddr;
	int ret = 0, flags, fd, orig;
	int rcvbuf;
	socklen_t rcvbufsz;

	if (zebra_nhrp_6wind_fd >= 0) {
		EVENT_OFF(zebra_nhrp_log_event);
		close(zebra_nhrp_6wind_fd);
		zebra_nhrp_6wind_fd = -1;
	}
	if (!port)
		return 0;

	frr_with_privs(&zserv_privs) {
		/* try to open fd fo fast-path */
		fd = open("/var/run/fast-path/namespaces/net", O_RDONLY | O_CLOEXEC);
		orig = ns_lookup(NS_DEFAULT)->fd;
	}
	if (fd < 0 || orig < 0) {
		zlog_err("%s(): netns fast-path (%d) or self vrf (%d) could not be read",
			   __func__, fd, orig);
		if (fd > 0)
			close(fd);
		return -1;
	}
	frr_with_privs(&zserv_privs) {
		ret = setns(fd, CLONE_NEWNET);
	}
	if (ret >= 0) {
		frr_with_privs(&zserv_privs) {
			zebra_nhrp_6wind_fd = socket(AF_INET, SOCK_DGRAM,
						     IPPROTO_UDP);
		}
	} else {
		zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
			 __func__, fd, strerror(errno));
		close(fd);
		return -1;
	}
	frr_with_privs(&zserv_privs) {
		ret = setns(orig, CLONE_NEWNET);
	}
	if (ret < 0) {
		zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
			   __func__, orig, strerror(errno));
		close(fd);
		return -1;
	}
	if (zebra_nhrp_6wind_fd < 0) {
		close(fd);
		return -1;
	}
	/* set the socket to non-blocking */
	frr_with_privs(&zserv_privs) {
		flags = fcntl(zebra_nhrp_6wind_fd, F_GETFL);
		flags |= O_NONBLOCK;
		ret = fcntl(zebra_nhrp_6wind_fd, F_SETFL, flags);
	}
	if (ret < 0) {
		zlog_err("%s(): fcntl(O_NONBLOCK) failed: %s", __func__, strerror(errno));
		close(zebra_nhrp_6wind_fd);
		close(fd);
		return -1;
	}
	frr_with_privs(&zserv_privs) {
		flags = fcntl(zebra_nhrp_6wind_fd, F_GETFD);
		flags |= FD_CLOEXEC;
		ret = fcntl(zebra_nhrp_6wind_fd, F_SETFD, flags);
	}
	if (ret < 0) {
		zlog_err("%s(): fcntl(F_SETFD CLOEXEC) failed: %s",
			 __func__, strerror(errno));
		close(zebra_nhrp_6wind_fd);
		close(fd);
		return -1;
	}
	memset(&srvaddr, 0, sizeof(srvaddr));
	srvaddr.sin_family = AF_INET;
	srvaddr.sin_port = htons(port);
	srvaddr.sin_addr.s_addr = inet_addr(ZEBRA_GRE_NHRP_6WIND_ADDRESS);

	frr_with_privs(&zserv_privs) {
		ret = setns(fd, CLONE_NEWNET);
		if (ret >= 0) {
			ret = bind(zebra_nhrp_6wind_fd, &srvaddr, sizeof(srvaddr));
			if (ret < 0) {
				zlog_err("%s(): bind(%u, 127.0.0.1) failed : %s",
					 __func__, zebra_nhrp_6wind_fd, strerror(errno));
			}
		}
		ret = setns(orig, CLONE_NEWNET);
	}
	if (ret < 0) {
		zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
			 __func__, orig, strerror(errno));
		close(zebra_nhrp_6wind_fd);
		close(fd);
		return -1;
	}
	rcvbuf = 0;
	rcvbufsz = sizeof(rcvbuf);
	ret = getsockopt(zebra_nhrp_6wind_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbufsz);
	if (ret < 0) {
		zlog_err("%s(): getsockopt(RCVBUF) failed: %s", __func__,
			 strerror(errno));
		close(zebra_nhrp_6wind_fd);
		close(fd);
		return -1;
	}
	if (rcvbuf < ZEBRA_GRE_NHRP_6WIND_RCV_BUF) {
		rcvbuf = ZEBRA_GRE_NHRP_6WIND_RCV_BUF;
		ret = setsockopt(zebra_nhrp_6wind_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, rcvbufsz);
		if (ret < 0) {
			zlog_err("%s(): getsockopt(RCVBUF) failed: %s", __func__,
				 strerror(errno));
			close(zebra_nhrp_6wind_fd);
			close(fd);
			return -1;
		}
		ret = getsockopt(zebra_nhrp_6wind_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &rcvbufsz);
		if (ret < 0) {
			zlog_err("%s(): getsockopt(RCVBUF) failed: %s", __func__,
				 strerror(errno));
			close(zebra_nhrp_6wind_fd);
			close(fd);
			return -1;
		}
	}
	event_add_read(zrouter.master, zebra_nhrp_6wind_log_recv,
			NULL,
			zebra_nhrp_6wind_fd,
			&zebra_nhrp_log_event);
	close(fd);
	return ret;
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

void zebra_nhrp_6wind_connection(bool on, uint16_t port)
{
	char buf[100];
	int ret = 0;

	if (!on)
		ret = zebra_nhrp_6wind_configure_listen_port(0);
	else
		ret = zebra_nhrp_6wind_configure_listen_port(port);
	if (ret < 0)
		return;

	/* fp-cli nhrp-port <port> <vrfid> */
	snprintf(buf, sizeof(buf), "/usr/bin/fp-cli nhrp-port %d 2>&1",
		 on ? port : 0);

	zebra_nhrp_call_only(buf, VRF_DEFAULT, NULL, 0);
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
	vrf = vrf_lookup_by_id(ifp->vrf->vrf_id);
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
			zebra_nhrp_call_only(buf, ifp->vrf->vrf_id, buf_vrf, sizeof(buf_vrf));
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
	ret = zebra_nhrp_call_only(buf, ifp->vrf->vrf_id, retstr, sizeof(retstr));
	if (ret && strlen(retstr))
		return -1;
	return 0;
}

void zebra_nhrp_interface_configure(struct interface *ifp, bool nhrp_6wind,
				    afi_t afi, bool enabled)
{
	struct zebra_nhrp_ctx *ctx;
	int ret = -1;

	ctx = zebra_nhrp_lookup(ifp);
	if (!ctx)
		return;

	ctx->nhrp_6wind_notify[afi] = enabled;

	/* will be triggered by if_new_hook() */
	if (ifp->ifindex == IFINDEX_INTERNAL && enabled) {
		ctx->nhrp_6wind_notify_differ[afi] = ctx->nhrp_6wind_notify[afi];
		return;
	}

	/* retry mechanism */
	ret = zebra_nhrp_configure(nhrp_6wind, afi == AFI_IP, enabled, ifp,
		     ctx->nflog_group);

	if (ret && ctx->nhrp_6wind_notify[afi]) {
		ctx->nhrp_6wind_notify_differ[afi] = ctx->nhrp_6wind_notify[afi];
		event_add_timer(zrouter.master, zebra_nhrp_6wind_notify_differ,
				 ctx, 1, &ctx->zebra_nhrp_retry_event);
	}
}

void zebra_nhrp_6wind_init()
{
	zebra_nhrp_list_init();
	zebra_nhrp_6wind_fd = -1;
	zebra_nhrp_6wind_hook_init();
}
