// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP daemon Linux specific glue
 * Copyright (c) 2014-2015 Timo Teräs
 */

#include "zebra.h"

#include <fcntl.h>
#include <errno.h>
#include <linux/if_packet.h>

#include "nhrp_protocol.h"
#include "os.h"

#ifndef HAVE_STRLCPY
size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize);
#endif

static int nhrp_socket_fd = -1;

int os_socket(void)
{
	if (nhrp_socket_fd < 0)
		nhrp_socket_fd =
			socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_NHRP));
	return nhrp_socket_fd;
}

int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen, uint16_t protocol)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = (void *)buf, .iov_len = len,
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int status, fd;

	if (addrlen > sizeof(lladdr.sll_addr))
		return -1;

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = htons(protocol);
	lladdr.sll_ifindex = ifindex;
	lladdr.sll_halen = addrlen;
	memcpy(lladdr.sll_addr, addr, addrlen);

	fd = os_socket();
	if (fd < 0)
		return -1;

	status = sendmsg(fd, &msg, 0);
	if (status < 0)
		return -errno;

	return status;
}

int os_recvmsg(uint8_t *buf, size_t *len, int *ifindex, uint8_t *addr,
	       size_t *addrlen)
{
	struct sockaddr_ll lladdr;
	struct iovec iov = {
		.iov_base = buf, .iov_len = *len,
	};
	struct msghdr msg = {
		.msg_name = &lladdr,
		.msg_namelen = sizeof(lladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	int r;

	r = recvmsg(nhrp_socket_fd, &msg, MSG_DONTWAIT);
	if (r < 0)
		return r;

	*len = r;
	*ifindex = lladdr.sll_ifindex;

	if (*addrlen <= (size_t)lladdr.sll_addr) {
		if (memcmp(lladdr.sll_addr, "\x00\x00\x00\x00", 4) != 0) {
			memcpy(addr, lladdr.sll_addr, lladdr.sll_halen);
			*addrlen = lladdr.sll_halen;
		} else {
			*addrlen = 0;
		}
	}

	return 0;
}

static int linux_icmp_redirect_off(const char *iface)
{
	char fname[PATH_MAX];
	int fd, ret = -1;

	snprintf(fname, sizeof(fname),
		 "/proc/sys/net/ipv4/conf/%s/send_redirects", iface);
	fd = open(fname, O_WRONLY);
	if (fd < 0)
		return -1;
	if (write(fd, "0\n", 2) == 2)
		ret = 0;
	close(fd);

	return ret;
}

int os_configure_dmvpn(unsigned int ifindex, const char *ifname, int af)
{
	int ret = 0;

	switch (af) {
	case AF_INET:
		ret |= linux_icmp_redirect_off("all");
		ret |= linux_icmp_redirect_off(ifname);
		break;
	}

	return ret;
}
