// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2016 by Open Source Routing.
 */

#include <zebra.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#ifdef OPEN_BSD

#include <netmpls/mpls.h>
#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"
#include "zebra/debug.h"
#include "zebra/zebra_errors.h"
#include "zebra/zebra_router.h"

#include "privs.h"
#include "prefix.h"
#include "interface.h"
#include "log.h"
#include "lib_errors.h"

extern struct zebra_privs_t zserv_privs;

struct {
	uint32_t rtseq;
	int fd;
	int ioctl_fd;
} kr_state;

static int kernel_send_rtmsg_v4(int action, mpls_label_t in_label,
				const struct zebra_nhlfe *nhlfe)
{
	struct iovec iov[5];
	struct rt_msghdr hdr;
	struct sockaddr_mpls sa_label_in, sa_label_out;
	struct sockaddr_in nexthop;
	int iovcnt = 0;
	int ret;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: 0x%x, label=%u", __func__, action, in_label);

	/* initialize header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.rtm_version = RTM_VERSION;

	hdr.rtm_type = action;
	hdr.rtm_flags = RTF_UP;
	hdr.rtm_fmask = RTF_MPLS;
	hdr.rtm_seq = kr_state.rtseq++; /* overflow doesn't matter */
	hdr.rtm_msglen = sizeof(hdr);
	hdr.rtm_hdrlen = sizeof(struct rt_msghdr);
	hdr.rtm_priority = 0;
	/* adjust iovec */
	iov[iovcnt].iov_base = &hdr;
	iov[iovcnt++].iov_len = sizeof(hdr);

	/* in label */
	memset(&sa_label_in, 0, sizeof(sa_label_in));
	sa_label_in.smpls_len = sizeof(sa_label_in);
	sa_label_in.smpls_family = AF_MPLS;
	sa_label_in.smpls_label = htonl(in_label << MPLS_LABEL_OFFSET);
	/* adjust header */
	SET_FLAG(hdr.rtm_flags, (RTF_MPLS | RTF_MPATH));
	SET_FLAG(hdr.rtm_addrs, RTA_DST);
	hdr.rtm_msglen += sizeof(sa_label_in);
	/* adjust iovec */
	iov[iovcnt].iov_base = &sa_label_in;
	iov[iovcnt++].iov_len = sizeof(sa_label_in);

	/* nexthop */
	memset(&nexthop, 0, sizeof(nexthop));
	nexthop.sin_len = sizeof(nexthop);
	nexthop.sin_family = AF_INET;
	nexthop.sin_addr = nhlfe->nexthop->gate.ipv4;
	/* adjust header */
	SET_FLAG(hdr.rtm_flags, RTF_GATEWAY);
	SET_FLAG(hdr.rtm_addrs, RTA_GATEWAY);
	hdr.rtm_msglen += sizeof(nexthop);
	/* adjust iovec */
	iov[iovcnt].iov_base = &nexthop;
	iov[iovcnt++].iov_len = sizeof(nexthop);

	/* If action is RTM_DELETE we have to get rid of MPLS infos */
	if (action != RTM_DELETE) {
		memset(&sa_label_out, 0, sizeof(sa_label_out));
		sa_label_out.smpls_len = sizeof(sa_label_out);
		sa_label_out.smpls_family = AF_MPLS;
		sa_label_out.smpls_label =
			htonl(nhlfe->nexthop->nh_label->label[0]
			      << MPLS_LABEL_OFFSET);
		/* adjust header */
		SET_FLAG(hdr.rtm_addrs, RTA_SRC);
		SET_FLAG(hdr.rtm_flags, RTF_MPLS);
		hdr.rtm_msglen += sizeof(sa_label_out);
		/* adjust iovec */
		iov[iovcnt].iov_base = &sa_label_out;
		iov[iovcnt++].iov_len = sizeof(sa_label_out);

		if (nhlfe->nexthop->nh_label->label[0] == MPLS_LABEL_IMPLNULL)
			hdr.rtm_mpls = MPLS_OP_POP;
		else
			hdr.rtm_mpls = MPLS_OP_SWAP;
	}

	frr_with_privs(&zserv_privs) {
		ret = writev(kr_state.fd, iov, iovcnt);
	}

	if (ret == -1)
		flog_err_sys(EC_LIB_SOCKET, "%s: %s", __func__,
			     safe_strerror(errno));

	return ret;
}

#if !defined(ROUNDUP)
#define ROUNDUP(a)                                                             \
	(((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))
#endif

static int kernel_send_rtmsg_v6(int action, mpls_label_t in_label,
				const struct zebra_nhlfe *nhlfe)
{
	struct iovec iov[5];
	struct rt_msghdr hdr;
	struct sockaddr_mpls sa_label_in, sa_label_out;
	struct pad {
		struct sockaddr_in6 addr;
		char pad[sizeof(long)]; /* thank you IPv6 */
	} nexthop;
	int iovcnt = 0;
	int ret;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("%s: 0x%x, label=%u", __func__, action, in_label);

	/* initialize header */
	memset(&hdr, 0, sizeof(hdr));
	hdr.rtm_version = RTM_VERSION;

	hdr.rtm_type = action;
	hdr.rtm_flags = RTF_UP;
	hdr.rtm_fmask = RTF_MPLS;
	hdr.rtm_seq = kr_state.rtseq++; /* overflow doesn't matter */
	hdr.rtm_msglen = sizeof(hdr);
	hdr.rtm_hdrlen = sizeof(struct rt_msghdr);
	hdr.rtm_priority = 0;
	/* adjust iovec */
	iov[iovcnt].iov_base = &hdr;
	iov[iovcnt++].iov_len = sizeof(hdr);

	/* in label */
	memset(&sa_label_in, 0, sizeof(sa_label_in));
	sa_label_in.smpls_len = sizeof(sa_label_in);
	sa_label_in.smpls_family = AF_MPLS;
	sa_label_in.smpls_label = htonl(in_label << MPLS_LABEL_OFFSET);
	/* adjust header */
	SET_FLAG(hdr.rtm_flags, (RTF_MPLS | RTF_MPATH));
	SET_FLAG(hdr.rtm_addrs, RTA_DST);
	hdr.rtm_msglen += sizeof(sa_label_in);
	/* adjust iovec */
	iov[iovcnt].iov_base = &sa_label_in;
	iov[iovcnt++].iov_len = sizeof(sa_label_in);

	/* nexthop */
	memset(&nexthop, 0, sizeof(nexthop));
	nexthop.addr.sin6_len = sizeof(struct sockaddr_in6);
	nexthop.addr.sin6_family = AF_INET6;
	nexthop.addr.sin6_addr = nhlfe->nexthop->gate.ipv6;
	if (IN6_IS_ADDR_LINKLOCAL(&nexthop.addr.sin6_addr)) {
		uint16_t tmp16;
		struct sockaddr_in6 *sin6 = &nexthop.addr;

		nexthop.addr.sin6_scope_id = nhlfe->nexthop->ifindex;

		memcpy(&tmp16, &sin6->sin6_addr.s6_addr[2], sizeof(tmp16));
		tmp16 = htons(sin6->sin6_scope_id);
		memcpy(&sin6->sin6_addr.s6_addr[2], &tmp16, sizeof(tmp16));
		sin6->sin6_scope_id = 0;
	}

	/* adjust header */
	SET_FLAG(hdr.rtm_flags, RTF_GATEWAY);
	SET_FLAG(hdr.rtm_addrs, RTA_GATEWAY);
	hdr.rtm_msglen += ROUNDUP(sizeof(struct sockaddr_in6));
	/* adjust iovec */
	iov[iovcnt].iov_base = &nexthop;
	iov[iovcnt++].iov_len = ROUNDUP(sizeof(struct sockaddr_in6));

	/* If action is RTM_DELETE we have to get rid of MPLS infos */
	if (action != RTM_DELETE) {
		memset(&sa_label_out, 0, sizeof(sa_label_out));
		sa_label_out.smpls_len = sizeof(sa_label_out);
		sa_label_out.smpls_family = AF_MPLS;
		sa_label_out.smpls_label =
			htonl(nhlfe->nexthop->nh_label->label[0]
			      << MPLS_LABEL_OFFSET);
		/* adjust header */
		SET_FLAG(hdr.rtm_addrs, RTA_SRC);
		SET_FLAG(hdr.rtm_flags, RTF_MPLS);
		hdr.rtm_msglen += sizeof(sa_label_out);
		/* adjust iovec */
		iov[iovcnt].iov_base = &sa_label_out;
		iov[iovcnt++].iov_len = sizeof(sa_label_out);

		if (nhlfe->nexthop->nh_label->label[0] == MPLS_LABEL_IMPLNULL)
			hdr.rtm_mpls = MPLS_OP_POP;
		else
			hdr.rtm_mpls = MPLS_OP_SWAP;
	}

	frr_with_privs(&zserv_privs) {
		ret = writev(kr_state.fd, iov, iovcnt);
	}

	if (ret == -1)
		flog_err_sys(EC_LIB_SOCKET, "%s: %s", __func__,
			     safe_strerror(errno));

	return ret;
}

static int kernel_lsp_cmd(struct zebra_dplane_ctx *ctx)
{
	const struct nhlfe_list_head *head;
	const struct zebra_nhlfe *nhlfe;
	const struct nexthop *nexthop = NULL;
	unsigned int nexthop_num = 0;
	int action;
	enum dplane_op_e op;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_LSP_DELETE)
		action = RTM_DELETE;
	else if (op == DPLANE_OP_LSP_INSTALL)
		action = RTM_ADD;
	else if (op == DPLANE_OP_LSP_UPDATE)
		action = RTM_CHANGE;
	else
		return -1;

	head = dplane_ctx_get_nhlfe_list(ctx);
	frr_each(nhlfe_list_const, head, nhlfe) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		if (nexthop_num >= zrouter.multipath_num)
			break;

		if (((action == RTM_ADD || action == RTM_CHANGE)
		     && (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
			 && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)))
		    || (action == RTM_DELETE
			&& (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)))) {
			if (nhlfe->nexthop->nh_label->num_labels > 1) {
				flog_warn(EC_ZEBRA_MAX_LABELS_PUSH,
					  "%s: can't push %u labels at once (maximum is 1)",
					  __func__,
					  nhlfe->nexthop->nh_label->num_labels);
				continue;
			}

			nexthop_num++;

			switch (NHLFE_FAMILY(nhlfe)) {
			case AF_INET:
				kernel_send_rtmsg_v4(
					action,
					dplane_ctx_get_in_label(ctx),
					nhlfe);
				break;
			case AF_INET6:
				kernel_send_rtmsg_v6(
					action,
					dplane_ctx_get_in_label(ctx),
					nhlfe);
				break;
			default:
				break;
			}
		}
	}

	return 0;
}

enum zebra_dplane_result kernel_lsp_update(struct zebra_dplane_ctx *ctx)
{
	int ret;

	ret = kernel_lsp_cmd(ctx);

	return (ret == 0 ?
		ZEBRA_DPLANE_REQUEST_SUCCESS : ZEBRA_DPLANE_REQUEST_FAILURE);
}

static enum zebra_dplane_result kmpw_install(struct zebra_dplane_ctx *ctx)
{
	struct ifreq ifr;
	struct ifmpwreq imr;
	struct sockaddr_storage ss;
	struct sockaddr_in *sa_in = (struct sockaddr_in *)&ss;
	struct sockaddr_in6 *sa_in6 = (struct sockaddr_in6 *)&ss;
	const union g_addr *gaddr;

	memset(&imr, 0, sizeof(imr));
	switch (dplane_ctx_get_pw_type(ctx)) {
	case PW_TYPE_ETHERNET:
		imr.imr_type = IMR_TYPE_ETHERNET;
		break;
	case PW_TYPE_ETHERNET_TAGGED:
		imr.imr_type = IMR_TYPE_ETHERNET_TAGGED;
		break;
	default:
		zlog_debug("%s: unhandled pseudowire type (%#X)", __func__,
			   dplane_ctx_get_pw_type(ctx));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	if (CHECK_FLAG(dplane_ctx_get_pw_flags(ctx), F_PSEUDOWIRE_CWORD))
		SET_FLAG(imr.imr_flags, IMR_FLAG_CONTROLWORD);

	/* pseudowire nexthop */
	memset(&ss, 0, sizeof(ss));
	gaddr = dplane_ctx_get_pw_dest(ctx);
	switch (dplane_ctx_get_pw_af(ctx)) {
	case AF_INET:
		sa_in->sin_family = AF_INET;
		sa_in->sin_len = sizeof(struct sockaddr_in);
		sa_in->sin_addr = gaddr->ipv4;
		break;
	case AF_INET6:
		sa_in6->sin6_family = AF_INET6;
		sa_in6->sin6_len = sizeof(struct sockaddr_in6);
		sa_in6->sin6_addr = gaddr->ipv6;
		break;
	default:
		zlog_debug("%s: unhandled pseudowire address-family (%u)",
			   __func__, dplane_ctx_get_pw_af(ctx));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}
	memcpy(&imr.imr_nexthop, (struct sockaddr *)&ss,
	       sizeof(imr.imr_nexthop));

	/* pseudowire local/remote labels */
	imr.imr_lshim.shim_label = dplane_ctx_get_pw_local_label(ctx);
	imr.imr_rshim.shim_label = dplane_ctx_get_pw_remote_label(ctx);

	/* ioctl */
	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, dplane_ctx_get_ifname(ctx),
		sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&imr;
	if (ioctl(kr_state.ioctl_fd, SIOCSETMPWCFG, &ifr) == -1) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "ioctl SIOCSETMPWCFG: %s",
			     safe_strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

static enum zebra_dplane_result kmpw_uninstall(struct zebra_dplane_ctx *ctx)
{
	struct ifreq ifr;
	struct ifmpwreq imr;

	memset(&ifr, 0, sizeof(ifr));
	memset(&imr, 0, sizeof(imr));
	strlcpy(ifr.ifr_name, dplane_ctx_get_ifname(ctx),
		sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&imr;
	if (ioctl(kr_state.ioctl_fd, SIOCSETMPWCFG, &ifr) == -1) {
		flog_err_sys(EC_LIB_SYSTEM_CALL, "ioctl SIOCSETMPWCFG: %s",
			     safe_strerror(errno));
		return ZEBRA_DPLANE_REQUEST_FAILURE;
	}

	return ZEBRA_DPLANE_REQUEST_SUCCESS;
}

/*
 * Pseudowire update api for openbsd.
 */
enum zebra_dplane_result kernel_pw_update(struct zebra_dplane_ctx *ctx)
{
	enum zebra_dplane_result result = ZEBRA_DPLANE_REQUEST_FAILURE;
	enum dplane_op_e op;

	op = dplane_ctx_get_op(ctx);

	if (op == DPLANE_OP_PW_INSTALL)
		result = kmpw_install(ctx);
	else if (op == DPLANE_OP_PW_UNINSTALL)
		result = kmpw_uninstall(ctx);

	return result;
}

#define MAX_RTSOCK_BUF	128 * 1024
int mpls_kernel_init(void)
{
	int rcvbuf, default_rcvbuf;
	socklen_t optlen;

	if ((kr_state.fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1) {
		flog_err_sys(EC_LIB_SOCKET, "%s: socket", __func__);
		return -1;
	}

	if ((kr_state.ioctl_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0))
	    == -1) {
		flog_err_sys(EC_LIB_SOCKET, "%s: ioctl socket", __func__);
		return -1;
	}

	/* grow receive buffer, don't wanna miss messages */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kr_state.fd, SOL_SOCKET, SO_RCVBUF, &default_rcvbuf,
		       &optlen)
	    == -1)
		flog_err_sys(EC_LIB_SOCKET,
			     "kr_init getsockopt SOL_SOCKET SO_RCVBUF");
	else
		for (rcvbuf = MAX_RTSOCK_BUF;
		     rcvbuf > default_rcvbuf
		     && setsockopt(kr_state.fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
				   sizeof(rcvbuf))
				== -1
		     && errno == ENOBUFS;
		     rcvbuf /= 2)
			; /* nothing */

	kr_state.rtseq = 1;

	/* Strict pseudowire reachability checking required for obsd */
	mpls_pw_reach_strict = true;

	return 0;
}

#endif /* OPEN_BSD */
