/* NHRP daemon Linux specific glue
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/ip.h>
#include <linux/if_arp.h>
#include <linux/if_tunnel.h>

#include "nhrp_protocol.h"
#include "os.h"
#include "netlink.h"

static int nhrp_socket_fd = -1;

int os_socket(void)
{
	if (nhrp_socket_fd < 0)
		nhrp_socket_fd =
			socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_NHRP));
	return nhrp_socket_fd;
}

int os_sendmsg(const uint8_t *buf, size_t len, int ifindex, const uint8_t *addr,
	       size_t addrlen)
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
	int status;

	if (addrlen > sizeof(lladdr.sll_addr))
		return -1;

	memset(&lladdr, 0, sizeof(lladdr));
	lladdr.sll_family = AF_PACKET;
	lladdr.sll_protocol = htons(ETH_P_NHRP);
	lladdr.sll_ifindex = ifindex;
	lladdr.sll_halen = addrlen;
	memcpy(lladdr.sll_addr, addr, addrlen);

	status = sendmsg(nhrp_socket_fd, &msg, 0);
	if (status < 0)
		return -1;

	return 0;
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

static int linux_configure_arp(const char *iface, int on)
{
	struct ifreq ifr;

	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	if (ioctl(nhrp_socket_fd, SIOCGIFFLAGS, &ifr))
		return -1;

	if (on)
		ifr.ifr_flags &= ~IFF_NOARP;
	else
		ifr.ifr_flags |= IFF_NOARP;

	if (ioctl(nhrp_socket_fd, SIOCSIFFLAGS, &ifr))
		return -1;

	return 0;
}

static int linux_icmp_redirect_off(const char *iface)
{
	char fname[256];
	int fd, ret = -1;

	sprintf(fname, "/proc/sys/net/ipv4/conf/%s/send_redirects", iface);
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
	ret |= linux_configure_arp(ifname, 1);
	ret |= netlink_configure_arp(ifindex, af);

	return ret;
}
