/* zebra NETNS ID handling routines
 * those routines are implemented locally to avoid having external dependencies.
 * Copyright (C) 2018 6WIND
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "ns.h"
#include "vrf.h"
#include "log.h"

#if defined(HAVE_NETLINK)

#include <linux/net_namespace.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "rib.h"
#include "zebra_ns.h"
#include "kernel_netlink.h"
#endif /* defined(HAVE_NETLINK) */

#include "zebra_netns_id.h"

/* default NS ID value used when VRF backend is not NETNS */
#define NS_DEFAULT_INTERNAL 0

/* in case NEWNSID not available, the NSID will be locally obtained
 */
#define NS_BASE_NSID 0

#if defined(HAVE_NETLINK)

#define NETLINK_SOCKET_BUFFER_SIZE 512
#define NETLINK_ALIGNTO             4
#define NETLINK_ALIGN(len)                                                     \
	(((len) + NETLINK_ALIGNTO - 1) & ~(NETLINK_ALIGNTO - 1))
#define NETLINK_NLATTR_LEN(_a, _b)   (unsigned int)((char *)_a - (char *)_b)

#endif /* defined(HAVE_NETLINK) */

static ns_id_t zebra_ns_id_get_fallback(const char *netnspath)
{
	static int zebra_ns_id_local;

	return zebra_ns_id_local++;
}

#if defined(HAVE_NETLINK)

static struct nlmsghdr *initiate_nlh(char *buf, unsigned int *seq, int type)
{
	struct nlmsghdr *nlh;

	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_len = NETLINK_ALIGN(sizeof(struct nlmsghdr));

	nlh->nlmsg_type = type;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	if (type == RTM_NEWNSID)
		nlh->nlmsg_flags |= NLM_F_ACK;
	nlh->nlmsg_seq = *seq = time(NULL);
	return nlh;
}

static int send_receive(int sock, struct nlmsghdr *nlh, unsigned int seq,
			char *buf)
{
	int ret;
	static const struct sockaddr_nl snl = {.nl_family = AF_NETLINK};

	ret = sendto(sock, (const void *)nlh, (size_t)nlh->nlmsg_len, 0,
		     (struct sockaddr *)&snl, (socklen_t)sizeof(snl));
	if (ret < 0) {
		zlog_err("netlink( %u) sendmsg() error: %s", sock,
			 safe_strerror(errno));
		return -1;
	}

	/* reception */
	struct sockaddr_nl addr;
	struct iovec iov = {
		.iov_base = buf, .iov_len = NETLINK_SOCKET_BUFFER_SIZE,
	};
	struct msghdr msg = {
		.msg_name = &addr,
		.msg_namelen = sizeof(struct sockaddr_nl),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0) {
		zlog_err("netlink recvmsg: error %d (errno %u)", ret, errno);
		return -1;
	}
	if (msg.msg_flags & MSG_TRUNC) {
		zlog_err("netlink recvmsg : error message truncated");
		return -1;
	}
	/* nlh already points to buf */
	if (nlh->nlmsg_seq != seq) {
		zlog_err(
			"netlink recvmsg: bad sequence number %x (expected %x)",
			seq, nlh->nlmsg_seq);
		return -1;
	}
	return ret;
}

/* extract on a valid nlmsg the nsid
 * valid nlmsghdr - not a nlmsgerr
 */
static ns_id_t extract_nsid(struct nlmsghdr *nlh, char *buf)
{
	ns_id_t ns_id = NS_UNKNOWN;
	int offset = NETLINK_ALIGN(sizeof(struct nlmsghdr))
		     + NETLINK_ALIGN(sizeof(struct rtgenmsg));
	int curr_length = offset;
	void *tail = (void *)((char *)nlh + NETLINK_ALIGN(nlh->nlmsg_len));
	struct nlattr *attr;

	for (attr = (struct nlattr *)((char *)buf + offset);
	     NETLINK_NLATTR_LEN(tail, attr) >= sizeof(struct nlattr)
	     && attr->nla_len >= sizeof(struct nlattr)
	     && attr->nla_len <= NETLINK_NLATTR_LEN(tail, attr);
	     attr += NETLINK_ALIGN(attr->nla_len)) {
		curr_length += attr->nla_len;
		if ((attr->nla_type & NLA_TYPE_MASK) == NETNSA_NSID) {
			uint32_t *ptr = (uint32_t *)(attr);

			ns_id = ptr[1];
			break;
		}
	}
	return ns_id;
}

ns_id_t zebra_ns_id_get(const char *netnspath)
{
	int ns_id = -1;
	struct sockaddr_nl snl;
	int fd, sock, ret;
	unsigned int seq;
	ns_id_t return_nsid = NS_UNKNOWN;

	/* netns path check */
	if (!netnspath)
		return NS_UNKNOWN;
	fd = open(netnspath, O_RDONLY);
	if (fd == -1)
		return NS_UNKNOWN;

	/* netlink socket */
	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		zlog_err("netlink( %u) socket() error: %s", sock,
			 safe_strerror(errno));
		close(fd);
		return NS_UNKNOWN;
	}
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = RTNLGRP_NSID;
	snl.nl_pid = 0; /* AUTO PID */
	ret = bind(sock, (struct sockaddr *)&snl, sizeof(snl));
	if (ret < 0) {
		zlog_err("netlink( %u) socket() bind error: %s", sock,
			 safe_strerror(errno));
		close(sock);
		close(fd);
		return NS_UNKNOWN;
	}

	/* message to send to netlink,and response : NEWNSID */
	char buf[NETLINK_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh;
	struct rtgenmsg *rt;
	int len;

	memset(buf, 0, NETLINK_SOCKET_BUFFER_SIZE);
	nlh = initiate_nlh(buf, &seq, RTM_NEWNSID);
	rt = (struct rtgenmsg *)(buf + nlh->nlmsg_len);
	nlh->nlmsg_len += NETLINK_ALIGN(sizeof(struct rtgenmsg));
	rt->rtgen_family = AF_UNSPEC;

	addattr32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_FD, fd);
	addattr32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_NSID, ns_id);

	ret = send_receive(sock, nlh, seq, buf);
	if (ret < 0) {
		close(sock);
		close(fd);
		return NS_UNKNOWN;
	}
	nlh = (struct nlmsghdr *)buf;

	/* message to analyse : NEWNSID response */
	len = ret;
	ret = 0;
	do {
		if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
			return_nsid = extract_nsid(nlh, buf);
			if (return_nsid != NS_UNKNOWN)
				break;
		} else {
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr
						 *)((char *)nlh
						    + NETLINK_ALIGN(sizeof(
							      struct
							      nlmsghdr)));

				ret = -1;
				if (err->error < 0)
					errno = -err->error;
				else
					errno = err->error;
				if (errno == 0) {
					/* request NEWNSID was successfull
					 * return EEXIST error to get GETNSID
					 */
					errno = EEXIST;
				}
			} else {
				/* other errors ignored
				 * attempt to get nsid
				 */
				ret = -1;
				errno = EEXIST;
				break;
			}
		}
		len = len - NETLINK_ALIGN(nlh->nlmsg_len);
		nlh = (struct nlmsghdr *)((char *)nlh
					  + NETLINK_ALIGN(nlh->nlmsg_len));
	} while (len != 0 && return_nsid != NS_UNKNOWN && ret == 0);

	if (ret <= 0) {
		if (errno != EEXIST && ret != 0) {
			zlog_err(
				"netlink( %u) recvfrom() error 2 when reading: %s",
				fd, safe_strerror(errno));
			close(sock);
			close(fd);
			if (errno == ENOTSUP) {
				zlog_warn("NEWNSID locally generated");
				return zebra_ns_id_get_fallback(netnspath);
			}
			return NS_UNKNOWN;
		}
		/* message to send to netlink : GETNSID */
		memset(buf, 0, NETLINK_SOCKET_BUFFER_SIZE);
		nlh = initiate_nlh(buf, &seq, RTM_GETNSID);
		rt = (struct rtgenmsg *)(buf + nlh->nlmsg_len);
		nlh->nlmsg_len += NETLINK_ALIGN(sizeof(struct rtgenmsg));
		rt->rtgen_family = AF_UNSPEC;

		addattr32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_FD, fd);
		addattr32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_NSID, ns_id);

		ret = send_receive(sock, nlh, seq, buf);
		if (ret < 0) {
			close(sock);
			close(fd);
			return NS_UNKNOWN;
		}
		nlh = (struct nlmsghdr *)buf;
		len = ret;
		ret = 0;
		do {
			if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
				return_nsid = extract_nsid(nlh, buf);
				if (return_nsid != NS_UNKNOWN)
					break;
			} else if (nlh->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err =
					(struct nlmsgerr
						 *)((char *)nlh
						    + NETLINK_ALIGN(sizeof(
							      struct
							      nlmsghdr)));
				if (err->error < 0)
					errno = -err->error;
				else
					errno = err->error;
				break;
			}
			len = len - NETLINK_ALIGN(nlh->nlmsg_len);
			nlh = (struct nlmsghdr *)((char *)nlh
						  + NETLINK_ALIGN(
							    nlh->nlmsg_len));
		} while (len != 0 && ret == 0);
	}

	close(fd);
	close(sock);
	return return_nsid;
}

#else
ns_id_t zebra_ns_id_get(const char *netnspath)
{
	return zebra_ns_id_get_fallback(netnspath);
}
#endif /* ! defined(HAVE_NETLINK) */

#ifdef HAVE_NETNS
static void zebra_ns_create_netns_directory(void)
{
	/* check that /var/run/netns is created */
	/* S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH */
	if (mkdir(NS_RUN_DIR, 0755)) {
		if (errno != EEXIST) {
			zlog_warn("NS check: failed to access %s", NS_RUN_DIR);
			return;
		}
	}
}
#endif

ns_id_t zebra_ns_id_get_default(void)
{
#ifdef HAVE_NETNS
	int fd;
#endif /* !HAVE_NETNS */

#ifdef HAVE_NETNS
	if (vrf_is_backend_netns())
		zebra_ns_create_netns_directory();
	fd = open(NS_DEFAULT_NAME, O_RDONLY);

	if (fd == -1)
		return NS_DEFAULT_INTERNAL;
	if (!vrf_is_backend_netns()) {
		close(fd);
		return NS_DEFAULT_INTERNAL;
	}
	close(fd);
	return zebra_ns_id_get((char *)NS_DEFAULT_NAME);
#else  /* HAVE_NETNS */
	return NS_DEFAULT_INTERNAL;
#endif /* !HAVE_NETNS */
}
