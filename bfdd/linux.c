/*
 * Linux specific code
 *
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#ifdef BFD_LINUX

/* XXX: fix compilation error on Ubuntu 16.04 or older. */
#ifndef _UAPI_IPV6_H
#define _UAPI_IPV6_H
#endif /* _UAPI_IPV6_H */

#include <linux/filter.h>
#include <linux/if_packet.h>

#include <netinet/if_ether.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include "bfd.h"

/* Berkeley Packet filter code to filter out BFD Echo packets.
 * tcpdump -dd "(udp dst port 3785)"
 */
static struct sock_filter bfd_echo_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 4, 0x000086dd},
	{0x30, 0, 0, 0x00000014}, {0x15, 0, 11, 0x00000011},
	{0x28, 0, 0, 0x00000038}, {0x15, 8, 9, 0x00000ec9},
	{0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
	{0x15, 0, 6, 0x00000011}, {0x28, 0, 0, 0x00000014},
	{0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x00000010}, {0x15, 0, 1, 0x00000ec9},
	{0x6, 0, 0, 0x0000ffff},  {0x6, 0, 0, 0x00000000},
};

/* Berkeley Packet filter code to filter out BFD vxlan packets.
 * tcpdump -dd "(udp dst port 4789)"
 */
static struct sock_filter bfd_vxlan_filter[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 4, 0x000086dd},
	{0x30, 0, 0, 0x00000014}, {0x15, 0, 11, 0x00000011},
	{0x28, 0, 0, 0x00000038}, {0x15, 8, 9, 0x000012b5},
	{0x15, 0, 8, 0x00000800}, {0x30, 0, 0, 0x00000017},
	{0x15, 0, 6, 0x00000011}, {0x28, 0, 0, 0x00000014},
	{0x45, 4, 0, 0x00001fff}, {0xb1, 0, 0, 0x0000000e},
	{0x48, 0, 0, 0x00000010}, {0x15, 0, 1, 0x000012b5},
	{0x6, 0, 0, 0x0000ffff},  {0x6, 0, 0, 0x00000000},
};


/*
 * Definitions.
 */
int ptm_bfd_fetch_ifindex(const char *ifname)
{
	struct ifreq ifr;

	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
	    > sizeof(ifr.ifr_name)) {
		CRITLOG("Interface name %s truncated", ifr.ifr_name);
	}

	if (ioctl(bglobal.bg_shop, SIOCGIFINDEX, &ifr) == -1) {
		CRITLOG("Getting ifindex for %s failed: %s", ifname,
			strerror(errno));
		return -1;
	}

	return ifr.ifr_ifindex;
}

void ptm_bfd_fetch_local_mac(const char *ifname, uint8_t *mac)
{
	struct ifreq ifr;

	if (strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name))
	    > sizeof(ifr.ifr_name)) {
		CRITLOG("Interface name %s truncated", ifr.ifr_name);
	}

	if (ioctl(bglobal.bg_shop, SIOCGIFHWADDR, &ifr) == -1) {
		CRITLOG("Getting mac address for %s failed: %s", ifname,
			strerror(errno));
		return;
	}

	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETHERNET_ADDRESS_LENGTH);
}


/* Was _fetch_portname_from_ifindex() */
void fetch_portname_from_ifindex(int ifindex, char *ifname, size_t ifnamelen)
{
	struct ifreq ifr;

	ifname[0] = 0;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifindex = ifindex;

	if (ioctl(bglobal.bg_shop, SIOCGIFNAME, &ifr) == -1) {
		CRITLOG("Getting ifname for ifindex %d failed: %s", ifindex,
			strerror(errno));
		return;
	}

	strlcpy(ifname, ifr.ifr_name, ifnamelen);
}

int ptm_bfd_echo_sock_init(void)
{
	int s;
	struct sock_fprog bpf = {.len = sizeof(bfd_echo_filter)
					/ sizeof(bfd_echo_filter[0]),
				 .filter = bfd_echo_filter};

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (s == -1) {
		ERRLOG("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))
	    == -1) {
		ERRLOG("%s: setsockopt(SO_ATTACH_FILTER): %s", __func__,
		       strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

int ptm_bfd_vxlan_sock_init(void)
{
	int s;
	struct sock_fprog bpf = {.len = sizeof(bfd_vxlan_filter)
					/ sizeof(bfd_vxlan_filter[0]),
				 .filter = bfd_vxlan_filter};

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (s == -1) {
		ERRLOG("%s: socket: %s", __func__, strerror(errno));
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf))
	    == -1) {
		ERRLOG("%s: setsockopt(SO_ATTACH_FILTER): %s", __func__,
		       strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

int bp_bind_dev(int sd __attribute__((__unused__)),
		const char *dev __attribute__((__unused__)))
{
	/*
	 * TODO: implement this differently. It is not possible to
	 * SO_BINDTODEVICE after the daemon has dropped its privileges.
	 */
#if 0
	size_t devlen = strlen(dev) + 1;

	if (setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, dev, devlen) == -1) {
		log_warning("%s: setsockopt(SO_BINDTODEVICE, \"%s\"): %s",
			    __func__, dev, strerror(errno));
		return -1;
	}
#endif

	return 0;
}

uint16_t udp4_checksum(struct iphdr *iph, uint8_t *buf, int len)
{
	char *ptr;
	struct udp_psuedo_header pudp_hdr;
	uint16_t csum;

	pudp_hdr.saddr = iph->saddr;
	pudp_hdr.daddr = iph->daddr;
	pudp_hdr.reserved = 0;
	pudp_hdr.protocol = iph->protocol;
	pudp_hdr.len = htons(len);

	ptr = XMALLOC(MTYPE_BFDD_TMP, UDP_PSUEDO_HDR_LEN + len);
	memcpy(ptr, &pudp_hdr, UDP_PSUEDO_HDR_LEN);
	memcpy(ptr + UDP_PSUEDO_HDR_LEN, buf, len);

	csum = checksum((uint16_t *)ptr, UDP_PSUEDO_HDR_LEN + len);
	XFREE(MTYPE_BFDD_TMP, ptr);
	return csum;
}

#endif /* BFD_LINUX */
