/*
 * *BSD specific code
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

#ifdef BFD_BSD

#include <net/if.h>
#include <net/if_types.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <ifaddrs.h>

#include "bfd.h"

/*
 * Prototypes
 */
static const char *sockaddr_to_string(const void *sv, char *buf, size_t buflen);

/*
 * Definitions.
 */
static const char *sockaddr_to_string(const void *sv, char *buf, size_t buflen)
{
	const struct sockaddr *sa = sv;
	const struct sockaddr_in *sin = sv;
	const struct sockaddr_in6 *sin6 = sv;
	int unknown = 1;

	switch (sa->sa_family) {
	case AF_INET:
		if (inet_ntop(AF_INET, &sin->sin_addr, buf, buflen) != NULL)
			unknown = 0;
		break;

	case AF_INET6:
		if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf, buflen) != NULL)
			unknown = 0;
		break;
	}
	if (unknown == 0)
		return buf;

	snprintf(buf, buflen, "unknown (af=%d)", sa->sa_family);
	return buf;
}

int ptm_bfd_fetch_ifindex(const char *ifname)
{
	return if_nametoindex(ifname);
}

void ptm_bfd_fetch_local_mac(const char *ifname, uint8_t *mac)
{
	struct ifaddrs *ifap, *ifa;
	struct if_data *ifi;
	struct sockaddr_dl *sdl;
	size_t maclen;

	/* Always clean the target, zeroed macs mean failure. */
	memset(mac, 0, ETHERNET_ADDRESS_LENGTH);

	if (getifaddrs(&ifap) != 0)
		return;

	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/* Find interface with that name. */
		if (strcmp(ifa->ifa_name, ifname) != 0)
			continue;
		/* Skip non link addresses. We want the MAC address. */
		if (ifa->ifa_addr->sa_family != AF_LINK)
			continue;

		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		ifi = (struct if_data *)ifa->ifa_data;
		/* Skip non ethernet related data. */
		if (ifi->ifi_type != IFT_ETHER)
			continue;

		if (sdl->sdl_alen != ETHERNET_ADDRESS_LENGTH)
			log_warning("%s:%d mac address length %d (expected %d)",
				    __func__, __LINE__, sdl->sdl_alen,
				    ETHERNET_ADDRESS_LENGTH);

		maclen = (sdl->sdl_alen > ETHERNET_ADDRESS_LENGTH)
				 ? ETHERNET_ADDRESS_LENGTH
				 : sdl->sdl_alen;
		memcpy(mac, LLADDR(sdl), maclen);
		break;
	}

	freeifaddrs(ifap);
}


/* Was _fetch_portname_from_ifindex() */
void fetch_portname_from_ifindex(int ifindex, char *ifname, size_t ifnamelen)
{
	char ifname_tmp[IF_NAMESIZE];

	/* Set ifname to empty to signalize failures. */
	memset(ifname, 0, ifnamelen);

	if (if_indextoname(ifindex, ifname_tmp) == NULL)
		return;

	if (strlcpy(ifname, ifname_tmp, ifnamelen) > ifnamelen)
		log_warning("%s:%d interface name truncated", __func__,
			    __LINE__);
}

int ptm_bfd_echo_sock_init(void)
{
	int s, ttl, yes = 1;
	struct sockaddr_in sin;

	s = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
	if (s == -1) {
		log_error("echo-socket: creation failed: %s", strerror(errno));
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	/* OmniOS doesn't have this field, but uses this code. */
	sin.sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	sin.sin_family = AF_INET;
	sin.sin_port = htons(3785);
	if (bind(s, (struct sockaddr *)&sin, sizeof(sin)) == -1) {
		log_error("echo-socket: bind failure: %s", strerror(errno));
		close(s);
		return -1;
	}

	if (setsockopt(s, IPPROTO_IP, IP_RECVTTL, &yes, sizeof(yes)) == -1) {
		log_error("echo-socket: setsockopt(IP_RECVTTL): %s",
			  strerror(errno));
		close(s);
		return -1;
	}

	ttl = BFD_TTL_VAL;
	if (setsockopt(s, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		log_error("echo-socket: setsockopt(IP_TTL): %s",
			  strerror(errno));
		close(s);
		return -1;
	}

	return s;
}

ssize_t bsd_echo_sock_read(int sd, uint8_t *buf, ssize_t *buflen,
			   struct sockaddr_storage *ss, socklen_t *sslen,
			   uint8_t *ttl, uint32_t *id)
{
	struct cmsghdr *cmsg;
	struct bfd_echo_pkt *bep;
	ssize_t readlen;
	struct iovec iov;
	struct msghdr msg;
	uint8_t msgctl[255];
	char errbuf[255];

	/* Prepare socket read. */
	memset(ss, 0, sizeof(*ss));
	memset(&msg, 0, sizeof(msg));
	iov.iov_base = buf;
	iov.iov_len = *buflen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = msgctl;
	msg.msg_controllen = sizeof(msgctl);
	msg.msg_name = ss;
	msg.msg_namelen = *sslen;

	/* Read the socket and treat errors. */
	readlen = recvmsg(sd, &msg, 0);
	if (readlen == 0) {
		log_error("%s: recvmsg: socket closed", __func__);
		return -1;
	}
	if (readlen == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
			return -1;

		log_error("%s: recvmsg: (%d) %s", __func__, errno,
			  strerror(errno));
		return -1;
	}
	/* Short packet, better not risk reading it. */
	if (readlen < (ssize_t)sizeof(*bep)) {
		log_warning("%s: short packet (%ld of %d) from %s", __func__,
			    readlen, sizeof(*bep),
			    sockaddr_to_string(ss, errbuf, sizeof(errbuf)));
		return -1;
	}
	*buflen = readlen;

	/* Read TTL information. */
	*ttl = 0;
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IP)
			continue;
		if (cmsg->cmsg_type != IP_RECVTTL)
			continue;

		*ttl = *(uint8_t *)CMSG_DATA(cmsg);
		break;
	}
	if (*ttl == 0) {
		log_debug("%s: failed to read TTL", __func__);
		return -1;
	}

	/* Read my discriminator from BFD Echo packet. */
	bep = (struct bfd_echo_pkt *)buf;
	*id = bep->my_discr;
	if (*id == 0) {
		log_debug("%s: invalid packet discriminator from: %s", __func__,
			  sockaddr_to_string(ss, errbuf, sizeof(errbuf)));
		return -1;
	}

	/* Set the returned sockaddr new length. */
	*sslen = msg.msg_namelen;

	return 0;
}

int bp_bind_dev(int sd, const char *dev)
{
	/*
	 * *BSDs don't support `SO_BINDTODEVICE`, instead you must
	 * manually specify the main address of the interface or use
	 * BPF on the socket descriptor.
	 */
	return 0;
}

uint16_t udp4_checksum(struct ip *ip, uint8_t *buf, int len)
{
	char *ptr;
	struct udp_psuedo_header pudp_hdr;
	uint16_t csum;

	pudp_hdr.saddr = ip->ip_src.s_addr;
	pudp_hdr.daddr = ip->ip_dst.s_addr;
	pudp_hdr.reserved = 0;
	pudp_hdr.protocol = ip->ip_p;
	pudp_hdr.len = htons(len);

	ptr = XMALLOC(MTYPE_BFDD_TMP, UDP_PSUEDO_HDR_LEN + len);
	memcpy(ptr, &pudp_hdr, UDP_PSUEDO_HDR_LEN);
	memcpy(ptr + UDP_PSUEDO_HDR_LEN, buf, len);

	csum = checksum((uint16_t *)ptr, UDP_PSUEDO_HDR_LEN + len);
	XFREE(MTYPE_BFDD_TMP, ptr);
	return csum;
}

#endif /* BFD_BSD */
