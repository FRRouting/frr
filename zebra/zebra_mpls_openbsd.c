/*
 * Copyright (C) 2016 by Open Source Routing.
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
#include <netmpls/mpls.h>
#include "zebra/rt.h"
#include "zebra/zebra_mpls.h"
#include "zebra/debug.h"

#include "privs.h"
#include "prefix.h"
#include "interface.h"
#include "log.h"

extern struct zebra_privs_t zserv_privs;

struct {
	u_int32_t rtseq;
	int fd;
} kr_state;

static int kernel_send_rtmsg_v4(int action, mpls_label_t in_label,
				zebra_nhlfe_t *nhlfe)
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
	hdr.rtm_flags |= RTF_MPLS | RTF_MPATH;
	hdr.rtm_addrs |= RTA_DST;
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
	hdr.rtm_flags |= RTF_GATEWAY;
	hdr.rtm_addrs |= RTA_GATEWAY;
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
		hdr.rtm_addrs |= RTA_SRC;
		hdr.rtm_flags |= RTF_MPLS;
		hdr.rtm_msglen += sizeof(sa_label_out);
		/* adjust iovec */
		iov[iovcnt].iov_base = &sa_label_out;
		iov[iovcnt++].iov_len = sizeof(sa_label_out);

		if (nhlfe->nexthop->nh_label->label[0] == MPLS_LABEL_IMPLNULL)
			hdr.rtm_mpls = MPLS_OP_POP;
		else
			hdr.rtm_mpls = MPLS_OP_SWAP;
	}

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	ret = writev(kr_state.fd, iov, iovcnt);
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	if (ret == -1)
		zlog_err("%s: %s", __func__, safe_strerror(errno));

	return ret;
}

#if !defined(ROUNDUP)
#define ROUNDUP(a)                                                             \
	(((a) & (sizeof(long) - 1)) ? (1 + ((a) | (sizeof(long) - 1))) : (a))
#endif

static int kernel_send_rtmsg_v6(int action, mpls_label_t in_label,
				zebra_nhlfe_t *nhlfe)
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
	hdr.rtm_flags |= RTF_MPLS | RTF_MPATH;
	hdr.rtm_addrs |= RTA_DST;
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
	hdr.rtm_flags |= RTF_GATEWAY;
	hdr.rtm_addrs |= RTA_GATEWAY;
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
		hdr.rtm_addrs |= RTA_SRC;
		hdr.rtm_flags |= RTF_MPLS;
		hdr.rtm_msglen += sizeof(sa_label_out);
		/* adjust iovec */
		iov[iovcnt].iov_base = &sa_label_out;
		iov[iovcnt++].iov_len = sizeof(sa_label_out);

		if (nhlfe->nexthop->nh_label->label[0] == MPLS_LABEL_IMPLNULL)
			hdr.rtm_mpls = MPLS_OP_POP;
		else
			hdr.rtm_mpls = MPLS_OP_SWAP;
	}

	if (zserv_privs.change(ZPRIVS_RAISE))
		zlog_err("Can't raise privileges");
	ret = writev(kr_state.fd, iov, iovcnt);
	if (zserv_privs.change(ZPRIVS_LOWER))
		zlog_err("Can't lower privileges");

	if (ret == -1)
		zlog_err("%s: %s", __func__, safe_strerror(errno));

	return ret;
}

static int kernel_lsp_cmd(int action, zebra_lsp_t *lsp)
{
	zebra_nhlfe_t *nhlfe;
	struct nexthop *nexthop = NULL;
	unsigned int nexthop_num = 0;

	for (nhlfe = lsp->nhlfe_list; nhlfe; nhlfe = nhlfe->next) {
		nexthop = nhlfe->nexthop;
		if (!nexthop)
			continue;

		if (nexthop_num >= multipath_num)
			break;

		if (((action == RTM_ADD || action == RTM_CHANGE)
		     && (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_SELECTED)
			 && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_ACTIVE)))
		    || (action == RTM_DELETE
			&& (CHECK_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED)
			    && CHECK_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB)))) {
			nexthop_num++;

			switch (NHLFE_FAMILY(nhlfe)) {
			case AF_INET:
				kernel_send_rtmsg_v4(action, lsp->ile.in_label,
						     nhlfe);
				break;
			case AF_INET6:
				kernel_send_rtmsg_v6(action, lsp->ile.in_label,
						     nhlfe);
				break;
			default:
				break;
			}
			if (action == RTM_ADD || action == RTM_CHANGE) {
				SET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
				SET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			} else {
				UNSET_FLAG(nhlfe->flags, NHLFE_FLAG_INSTALLED);
				UNSET_FLAG(nexthop->flags, NEXTHOP_FLAG_FIB);
			}
		}
	}

	return (0);
}

int kernel_add_lsp(zebra_lsp_t *lsp)
{
	int ret;

	if (!lsp || !lsp->best_nhlfe) // unexpected
		return -1;

	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
	ret = kernel_lsp_cmd(RTM_ADD, lsp);
	if (!ret)
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

	return ret;
}

int kernel_upd_lsp(zebra_lsp_t *lsp)
{
	int ret;

	if (!lsp || !lsp->best_nhlfe) // unexpected
		return -1;

	UNSET_FLAG(lsp->flags, LSP_FLAG_CHANGED);
	UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);
	ret = kernel_lsp_cmd(RTM_CHANGE, lsp);
	if (!ret)
		SET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

	return ret;
}

int kernel_del_lsp(zebra_lsp_t *lsp)
{
	int ret;

	if (!lsp) // unexpected
		return -1;

	if (!CHECK_FLAG(lsp->flags, LSP_FLAG_INSTALLED))
		return -1;

	ret = kernel_lsp_cmd(RTM_DELETE, lsp);
	if (!ret)
		UNSET_FLAG(lsp->flags, LSP_FLAG_INSTALLED);

	return ret;
}

#define MAX_RTSOCK_BUF	128 * 1024
int mpls_kernel_init(void)
{
	int rcvbuf, default_rcvbuf;
	socklen_t optlen;

	if ((kr_state.fd = socket(AF_ROUTE, SOCK_RAW, 0)) == -1) {
		zlog_warn("%s: socket", __func__);
		return -1;
	}

	/* grow receive buffer, don't wanna miss messages */
	optlen = sizeof(default_rcvbuf);
	if (getsockopt(kr_state.fd, SOL_SOCKET, SO_RCVBUF, &default_rcvbuf,
		       &optlen)
	    == -1)
		zlog_warn("kr_init getsockopt SOL_SOCKET SO_RCVBUF");
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

	return 0;
}
