// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra NETNS ID handling routines
 * those routines are implemented locally to avoid having external dependencies.
 * Copyright (C) 2018 6WIND
 */

#include <zebra.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef GNU_LINUX
#include <linux/if_link.h>
#endif

#include "ns.h"
#include "vrf.h"
#include "log.h"
#include "lib_errors.h"
#include "network.h"

#include "zebra/rib.h"
#include "zebra/zebra_dplane.h"
#if defined(HAVE_NETLINK)

#include <linux/net_namespace.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "zebra_ns.h"
#include "kernel_netlink.h"
#endif /* defined(HAVE_NETLINK) */

#include "zebra/zebra_netns_id.h"
#include "zebra/zebra_errors.h"

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
	nlh->nlmsg_seq = *seq = frr_sequence32_next();
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
		flog_err_sys(EC_LIB_SOCKET, "netlink( %u) sendmsg() error: %s",
			     sock, safe_strerror(errno));
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
		flog_err_sys(EC_LIB_SOCKET,
			     "netlink recvmsg: error %d (errno %u)", ret,
			     errno);
		return -1;
	}
	if (msg.msg_flags & MSG_TRUNC) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "netlink recvmsg : error message truncated");
		return -1;
	}
	/* nlh already points to buf */
	if (nlh->nlmsg_seq != seq) {
		flog_err(
			EC_ZEBRA_NETLINK_BAD_SEQUENCE,
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
	void *tail = (void *)((char *)nlh + NETLINK_ALIGN(nlh->nlmsg_len));
	struct nlattr *attr;

	for (attr = (struct nlattr *)(buf + offset);
	     NETLINK_NLATTR_LEN(tail, attr) >= sizeof(struct nlattr)
	     && attr->nla_len >= sizeof(struct nlattr)
	     && attr->nla_len <= NETLINK_NLATTR_LEN(tail, attr);
	     attr += NETLINK_ALIGN(attr->nla_len)) {
		if ((attr->nla_type & NLA_TYPE_MASK) == NETNSA_NSID) {
			uint32_t *ptr = (uint32_t *)(attr);

			ns_id = ptr[1];
			break;
		}
	}
	return ns_id;
}

/* fd_param = -1 is ignored.
 * netnspath set to null is ignored.
 * one of the 2 params is mandatory. netnspath is looked in priority
 */
ns_id_t zebra_ns_id_get(const char *netnspath, int fd_param)
{
	int ns_id = -1;
	struct sockaddr_nl snl;
	int fd = -1, sock, ret;
	unsigned int seq;
	ns_id_t return_nsid = NS_UNKNOWN;

	/* netns path check */
	if (!netnspath && fd_param == -1)
		return NS_UNKNOWN;
	if (netnspath)  {
		fd = open(netnspath, O_RDONLY);
		if (fd == -1)
			return NS_UNKNOWN;
	} else if (fd_param != -1)
		fd = fd_param;
	/* netlink socket */
	sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "netlink( %u) socket() error: %s",
			     sock, safe_strerror(errno));
		if (netnspath)
			close(fd);
		return NS_UNKNOWN;
	}
	memset(&snl, 0, sizeof(snl));
	snl.nl_family = AF_NETLINK;
	snl.nl_groups = RTNLGRP_NSID;
	snl.nl_pid = 0; /* AUTO PID */
	ret = bind(sock, (struct sockaddr *)&snl, sizeof(snl));
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "netlink( %u) socket() bind error: %s", sock,
			     safe_strerror(errno));
		close(sock);
		if (netnspath)
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

	nl_attr_put32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_FD, fd);
	nl_attr_put32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_NSID, ns_id);

	ret = send_receive(sock, nlh, seq, buf);
	if (ret < 0) {
		close(sock);
		if (netnspath)
			close(fd);
		return NS_UNKNOWN;
	}
	nlh = (struct nlmsghdr *)buf;

	/* message to analyse : NEWNSID response */
	ret = 0;
	if (nlh->nlmsg_type >= NLMSG_MIN_TYPE) {
		return_nsid = extract_nsid(nlh, buf);
	} else {
		if (nlh->nlmsg_type == NLMSG_ERROR) {
			struct nlmsgerr *err =
				(struct nlmsgerr
					 *)((char *)nlh
					    + NETLINK_ALIGN(
						      sizeof(struct nlmsghdr)));

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
		}
	}

	if (errno != EEXIST && ret != 0) {
		flog_err(EC_LIB_SOCKET,
			 "netlink( %u) recvfrom() error 2 when reading: %s", fd,
			 safe_strerror(errno));
		close(sock);
		if (netnspath)
			close(fd);
		if (errno == ENOTSUP) {
			zlog_debug("NEWNSID locally generated");
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

	nl_attr_put32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_FD, fd);
	nl_attr_put32(nlh, NETLINK_SOCKET_BUFFER_SIZE, NETNSA_NSID, ns_id);

	ret = send_receive(sock, nlh, seq, buf);
	if (ret < 0) {
		close(sock);
		if (netnspath)
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
				(struct nlmsgerr *)((char *)nlh +
						    NETLINK_ALIGN(sizeof(
							    struct nlmsghdr)));
			if (err->error < 0)
				errno = -err->error;
			else
				errno = err->error;
			break;
		}
		len = len - NETLINK_ALIGN(nlh->nlmsg_len);
		nlh = (struct nlmsghdr *)((char *)nlh +
					  NETLINK_ALIGN(nlh->nlmsg_len));
	} while (len != 0 && ret == 0);

	if (netnspath)
		close(fd);
	close(sock);
	return return_nsid;
}

#else
ns_id_t zebra_ns_id_get(const char *netnspath, int fd __attribute__ ((unused)))
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
			flog_warn(EC_ZEBRA_NAMESPACE_DIR_INACCESSIBLE,
				  "NS check: failed to access %s", NS_RUN_DIR);
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
		return NS_DEFAULT;
	if (!vrf_is_backend_netns()) {
		close(fd);
		return NS_DEFAULT;
	}
	close(fd);
	return zebra_ns_id_get((char *)NS_DEFAULT_NAME, -1);
#else  /* HAVE_NETNS */
	return NS_DEFAULT;
#endif /* !HAVE_NETNS */
}
