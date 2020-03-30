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

#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
/* New network namespace (lo, device, names sockets, etc) */
#endif

#include <privs.h>
#include <log.h>
#include <ns.h>
#include "lib_errors.h"
#include "if.h"

#include <zebra/zebra_router.h>
#include <zebra/zebra_nhrp.h>
#include <zebra/zebra_ns.h>
#include "zebra/debug.h"
#include <zebra/zebra_dplane.h>
#include <zebra/kernel_netlink.h>
#include <zebra/if_netlink.h>

#define ZEBRA_FASTPATH_NETNS  "/var/run/fast-path/namespaces/net"

#define ZEBRA_GRE_NHRP_6WIND_ADDRESS "127.0.0.1"

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

static int zebra_nhrp_fastpath_status;

/* must be launched if fast path is configured
 * returned fd_fp value must be closed after usage
 */
int zebra_nhrp_6wind_access(int *fd_fp, int *fd_orig)
{
	int fd, orig;

	/* let the monitor thread enable the fast-path */
	frr_with_privs(&zserv_privs) {
		/* try to open fd fo fast-path */
		fd = open(ZEBRA_FASTPATH_NETNS, O_RDONLY | O_CLOEXEC);
		orig = ns_lookup(NS_DEFAULT)->fd;
	}
	if (orig < 0) {
		zlog_err("%s(): netns self vrf (%d) could not be read",
			   __func__, orig);
		if (fd > 0)
			close(fd);
		return -1;
	}
	*fd_orig = orig;
	/* not an error, as fast path can be on current netns */
	if (fd < 0) {
		zlog_err("%s(): netns fast-path (%d) not present.",
			   __func__, orig);
		*fd_fp = -1;
		return 0;
	}
	*fd_fp = fd;
	return 0;
}

static int zebra_nhrp_netlink_socket(struct nlsock *nl, unsigned long groups,
				     int fd, int orig_fd, int protocol) {
	int ret;
	struct sockaddr_nl snl;
	int sock;
	int namelen;

	frr_with_privs(&zserv_privs) {
		ret = setns(fd, CLONE_NEWNET);
	}
	if (ret < 0) {
		zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
			 __func__, fd, strerror(errno));
		close(fd);
		return -1;
	}
	frr_with_privs(&zserv_privs) {
		sock = socket(AF_NETLINK, SOCK_RAW, protocol);
	}
	if (sock < 0) {
		zlog_err("Can't open %s socket: %s", nl->name,
			 safe_strerror(errno));
		frr_with_privs(&zserv_privs) {
			ret = setns(orig_fd, CLONE_NEWNET);
		}
		return -1;
	}

	memset(&snl, 0, sizeof snl);
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = groups;
	frr_with_privs(&zserv_privs) {
		/* Bind the socket to the netlink structure for anything. */
		ret = bind(sock, (struct sockaddr *)&snl, sizeof snl);
	}

	frr_with_privs(&zserv_privs) {
		setns(orig_fd, CLONE_NEWNET);
	}
	if (ret < 0) {
		zlog_err("Can't bind %s socket to group 0x%x: %s", nl->name,
			 snl.nl_groups, safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* multiple netlink sockets will have different nl_pid */
	namelen = sizeof snl;
	ret = getsockname(sock, (struct sockaddr *)&snl, (socklen_t *)&namelen);
	if (ret < 0 || namelen != sizeof snl) {
		flog_err_sys(EC_LIB_SOCKET, "Can't get %s socket name: %s",
			     nl->name, safe_strerror(errno));
		close(sock);
		return -1;
	}

	nl->snl = snl;
	nl->sock = sock;
	return 0;
}

int zebra_nhrp_6wind_configure_listen_port(uint16_t port)
{
	struct sockaddr_in srvaddr;
	int ret = 0, flags, fd = -1, orig;
	int rcvbuf;
	socklen_t rcvbufsz;

	if (zebra_nhrp_6wind_fd >= 0) {
		THREAD_OFF(zebra_nhrp_log_thread);
		close(zebra_nhrp_6wind_fd);
		zebra_nhrp_6wind_fd = -1;
	}
	if (!port)
		return 0;
	/* fast-path not configured. no need to go further */
	if (!zebra_nhrp_fastpath_configured)
		return -1;
	/* let the monitor thread enable the fast-path */
	if (zebra_nhrp_6wind_access(&fd, &orig) < 0)
		return -1;
	if (fd >= 0) {
		frr_with_privs(&zserv_privs) {
			ret = setns(fd, CLONE_NEWNET);
		}
		if (ret < 0) {
			zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
				 __func__, fd, strerror(errno));
			close(fd);
			return -1;
		}
	}
	frr_with_privs(&zserv_privs) {
		zebra_nhrp_6wind_fd = socket(AF_INET, SOCK_DGRAM,
					     IPPROTO_UDP);
	}
	if (fd >= 0) {
		frr_with_privs(&zserv_privs) {
			ret = setns(orig, CLONE_NEWNET);
		}
		if (ret < 0) {
			zlog_err("%s(): setns(%u, CLONE_NEWNET) failed: %s",
				   __func__, orig, strerror(errno));
			close(fd);
			return -1;
		}
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
	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug("NHRP: 6wind port %u configured and ready", port);
	thread_add_read(zrouter.master, zebra_nhrp_6wind_log_recv,
			NULL,
			zebra_nhrp_6wind_fd,
			&zebra_nhrp_log_thread);
	close(fd);
	return ret;
}

static int zebra_nhrp_netlink_interface(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	/* XXX ns_id is the netlink file descriptor */
	struct ifinfomsg *ifi;
	int len;
	char *name = NULL;
	struct rtattr *tb[IFLA_MAX + 1];
	struct interface ifp;

	ifi = NLMSG_DATA(h);
	len = h->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
	if (len < 0) {
		zlog_err("%s: Message received from netlink is of a broken size: %d %zu",
			 __PRETTY_FUNCTION__,
			 h->nlmsg_len,
			 (size_t)NLMSG_LENGTH(sizeof(struct ifinfomsg)));
		return -1;
	}
	/* Looking up interface name. */
	memset(tb, 0, sizeof tb);
	netlink_parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);

	/* check for wireless messages to ignore */
	if ((tb[IFLA_WIRELESS] != NULL) && (ifi->ifi_change == 0)) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_err("%s: ignoring IFLA_WIRELESS message",
				 __func__);
		return 0;
	}
	if (tb[IFLA_IFNAME] == NULL)
		return -1;

	name = (char *)RTA_DATA(tb[IFLA_IFNAME]);
	memset(&ifp, 0, sizeof(ifp));
	ifp.flags = ifi->ifi_flags & 0x0000fffff;
	if (strmatch(name, "fpn0")) {
		if (if_is_running(&ifp))
			zebra_nhrp_fastpath_status = 1;
	}
	return 0;
}

int zebra_nhrp_netlink_fastpath_parse(int fd, int orig_fd, int *status)
{
	struct zebra_ns zns;
	struct nlsock netlink_cmd;
	struct zebra_dplane_info dp_info;
	int ret;

	*status = 0;

	zebra_nhrp_fastpath_status = 0;

	/* trick - so that it can be used with netlink_parse_info() */
	memset(&dp_info, 0, sizeof(dp_info));
	memset(&netlink_cmd, 0, sizeof(netlink_cmd));
	memset(&zns, 0, sizeof(zns));
	/* used by netlink_parse_info() and zebra_dplane_info_from_zns() */
	zns.ns_id = fd;
	zebra_dplane_info_from_zns(&dp_info, &zns, true /*is_cmd*/);

	/* monitor fpn0 presence with netlink */
	snprintf(netlink_cmd.name, sizeof("(fast-path)"), "(fast-path)");
	netlink_cmd.sock = -1;
	if (zebra_nhrp_netlink_socket(&netlink_cmd, 0, fd, orig_fd, NETLINK_ROUTE) < 0) {
		zlog_err("%s(): Failure to create %s socket", __func__, netlink_cmd.name);
		return -1;
	}

	/* Get interface information. */
	ret = netlink_request_intf_addr(&netlink_cmd, AF_PACKET, RTM_GETLINK, 0);
	if (ret < 0) {
		zlog_err("Failure to request GETLINK for %s socket", netlink_cmd.name);
		close(netlink_cmd.sock);
		return -1;
	}
	ret = netlink_parse_info(zebra_nhrp_netlink_interface,
				 &netlink_cmd, &dp_info, 0, 1);
	if (ret < 0) {
		close(netlink_cmd.sock);
		return -1;
	}
	/* all interfaces have been walked. status is in
	 * status is in zebra_nhrp_fastpath_status)
	 */
	*status = zebra_nhrp_fastpath_status;

	/* todo : close socket netlink */
	close(netlink_cmd.sock);
	return 0;
}
