// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra EVPN ARP/ND packet handler
 *
 * Copyright (C) 2020 Cumulus Networks, Inc.
 * Anuradha Karuppiah
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/if_packet.h>
#include <linux/filter.h>
#else
struct ethhdr;
#endif
#include "fcntl.h"
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "command.h"
#include "if.h"
#include "debug.h"
#include "log.h"
#include "lib_errors.h"
#include "memory.h"
#include "prefix.h"
#include "stream.h"
#include "vlan.h"
#include "zebra/zebra_vxlan.h"
#include "zebra/zebra_vxlan_private.h"
#include "zebra_evpn.h"
#include "zebra_evpn_mac.h"
#include "zebra_evpn_mh.h"
#include "zebra_evpn_arp_nd.h"
#include "zebra_privs.h"

struct zebra_evpn_arp_nd_info zevpn_arp_nd_info;

#ifdef GNU_LINUX
#define DO_NOT_CRASH_COMPILER 0
/*****************************************************************************
 * ARP-ND handling
 * A snooper socket is created for each bridge access port to listen
 * in on ARP replies and NAs. These packets are redirected to an ES-peer
 * via the VxLAN overlay if the destination associated with the DMAC
 * is oper-down
 ****************************************************************************/
static void zebra_evpn_arp_nd_pkt_dump(struct zebra_if *zif, uint16_t vlan,
				       uint8_t *data, int len)
{
#if DO_NOT_CRASH_COMPILER
	struct ethhdr *ethh = (struct ethhdr *)data;
#endif

	if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT) {
#if DO_NOT_CRASH_COMPILER
		zlog_debug("evpn arp_nd pkt on %s vlan %d [dm=%pEA sm=%pEA et=0x%x]",
			   zif->ifp->name, vlan ? vlan : zif->pvid,
			   &ethh->h_dest, &ethh->h_source, ntohs(ethh->h_proto));
		/* XXX - dump ARP/NA info */
#else
		zlog_debug(
			"evpn arp_nd pkt zlog_debug was causing crash, avoiding");
#endif
	}
}
#endif

void zebra_evpn_arp_nd_print_summary(struct vty *vty, bool uj)
{
	json_object *json = NULL;

	if (uj) {
		json = json_object_new_object();
		json_object_boolean_true_add(json, "arpRedirect");
		json_object_int_add(json, "arpReplyPkts",
				    zevpn_arp_nd_info.stat.arp);
		json_object_int_add(json, "naPkts", zevpn_arp_nd_info.stat.na);
		json_object_int_add(json, "redirectPkts",
				    zevpn_arp_nd_info.stat.redirect);
		json_object_int_add(json, "notReadyPkts",
				    zevpn_arp_nd_info.stat.not_ready);
		json_object_int_add(json, "vniMissingPkts",
				    zevpn_arp_nd_info.stat.vni_missing);
		json_object_int_add(json, "macMissingPkts",
				    zevpn_arp_nd_info.stat.mac_missing);
		json_object_int_add(json, "esNonLocalPkts",
				    zevpn_arp_nd_info.stat.es_non_local);
		json_object_int_add(json, "esUpPkts",
				    zevpn_arp_nd_info.stat.es_up);
	} else {
		vty_out(vty, "EVPN ARP-reply/NA redirect: %s\n",
			(zevpn_arp_nd_info.flags & ZEBRA_EVPN_ARP_ND_FAILOVER)
				? "enabled"
				: "disabled");
		vty_out(vty, "Stats:\n");
		vty_out(vty, "  IPv4 ARP replies: %u\n",
			zevpn_arp_nd_info.stat.arp);
		vty_out(vty, "  IPv6 neighbor advertisements: %u\n",
			zevpn_arp_nd_info.stat.na);
		vty_out(vty, "  Redirected packets: %u\n",
			zevpn_arp_nd_info.stat.redirect);
		vty_out(vty, "  Skipped packets:\n");
		vty_out(vty, "    Not ready: %u\n",
			zevpn_arp_nd_info.stat.not_ready);
		vty_out(vty, "    VNI missing: %u\n",
			zevpn_arp_nd_info.stat.vni_missing);
		vty_out(vty, "    MAC missing: %u\n",
			zevpn_arp_nd_info.stat.mac_missing);
		vty_out(vty, "    Dest is not local ES: %u\n",
			zevpn_arp_nd_info.stat.es_non_local);
		vty_out(vty, "    Dest ES oper-up: %u\n",
			zevpn_arp_nd_info.stat.es_up);
	}

	if (uj)
		vty_json(vty, json);
}

void zebra_evpn_arp_nd_if_print(struct vty *vty, struct zebra_if *zif)
{
	if (zif->arp_nd_info.pkt_fd > 0)
		vty_out(vty, "  ARP-ND redirect enabled: ARP-replies %u NA %u\n",
			zif->arp_nd_info.arp_pkts, zif->arp_nd_info.na_pkts);
}

#ifdef GNU_LINUX
/* Send to the ES peer VTEP-IP */
static void zebra_evpn_arp_nd_udp_send(struct ipaddr vtep_ip, uint8_t *data, int len)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	/* XXX - the VxLAN UDP port is user configurable so we
	 * need to get that info via if_netlink instead of using the
	 * standard port
	 */
	sin.sin_port = htons(ZEBRA_EVPN_VXLAN_UDP_PORT);
	sin.sin_addr = vtep_ip.ipaddr_v4;

	sendto(zevpn_arp_nd_info.udp_fd, data, len, 0, (struct sockaddr *)&sin,
	       sizeof(sin));
}
#endif

#ifdef GNU_LINUX
/***************************** from net/vxlan.h ****************************/
/* VXLAN protocol (RFC 7348) header:
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |R|R|R|R|I|R|R|R|               Reserved                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                VXLAN Network Identifier (VNI) |   Reserved    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * I = VXLAN Network Identifier (VNI) present.
 */
struct vxlanhdr {
	uint32_t vx_flags;
	uint32_t vx_vni;
} __attribute__((packed));

#define VXLAN_HF_VNI (1 << 27)
/***************************** from net/vxlan.h ****************************/

/* vxlan encapsulate the data */
static void zebra_evpn_arp_nd_vxlan_encap(struct zebra_evpn *zevpn, struct ipaddr vtep_ip,
					  uint8_t *data, int len)
{
	struct vxlanhdr *vxh;
	uint8_t vxlan_data[ZEBRA_EVPN_ARP_ND_MAX_PKT_LEN +
			   sizeof(struct vxlanhdr *)];

	++zevpn_arp_nd_info.stat.redirect;
	/* pre-pend a vxlan header */
	vxh = (struct vxlanhdr *)vxlan_data;
	vxh->vx_flags = htonl(VXLAN_HF_VNI);
	vxh->vx_vni = htonl(zevpn->vni << 8);
	memcpy(vxlan_data + sizeof(struct vxlanhdr), data, len);

	if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
		zlog_debug("evpn arp_nd of len %lu redirect to vni %d %pIA with vxh(0x%x 0x%x)",
			   (unsigned long)(len + sizeof(struct vxlanhdr)),
			   zevpn->vni, &vtep_ip, vxh->vx_flags, vxh->vx_vni);

	zebra_evpn_arp_nd_udp_send(vtep_ip, vxlan_data,
				   len + sizeof(struct vxlanhdr));
}
/* Locate an ES peer to redirect the packet to */
static struct ipaddr zebra_evpn_arp_nd_get_vtep(struct zebra_evpn_es *es, struct ethhdr *ethh)
{
	struct zebra_evpn_es_vtep *es_vtep = NULL;
	struct ipaddr nh = { 0 };

	/* XXX - use a modulo hash to loadbalance the traffic instead
	 * of redirecting to the first active nexthop
	 */
	if (listhead(es->es_vtep_list))
		es_vtep = listgetdata(listhead(es->es_vtep_list));

	if (es_vtep)
		nh = es_vtep->vtep_ip;

	return nh;
}
#endif

#ifndef GNU_LINUX
/* Redirect ARP/NA packet via the vxlan overlay */
static int zebra_evpn_arp_nd_proc(struct zebra_if *zif, uint16_t vlan,
				  uint8_t *data, int len)
{
	return -1;
}
#else
/* Redirect ARP/NA packet via the vxlan overlay */
static int zebra_evpn_arp_nd_proc(struct zebra_if *zif, uint16_t vlan,
				  uint8_t *data, int len)
{
	struct ethhdr *ethh = (struct ethhdr *)data;
	struct zebra_evpn_access_bd *acc_bd;
	struct zebra_mac *zmac;
	struct zebra_evpn_es *es;
	struct ipaddr nh;

	zebra_evpn_arp_nd_pkt_dump(zif, vlan, data, len);

	if (ntohs(ethh->h_proto) == ETH_P_ARP) {
		++zif->arp_nd_info.arp_pkts;
		++zevpn_arp_nd_info.stat.arp;
	} else {
		++zif->arp_nd_info.na_pkts;
		++zevpn_arp_nd_info.stat.na;
	}


	if (zevpn_arp_nd_info.udp_fd < 0) {
		++zevpn_arp_nd_info.stat.not_ready;
		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
			zlog_debug("evpn arp_nd on %s vlan %d; not ready to redirect",
				   zif->ifp->name, vlan);
		return 0;
	}

	acc_bd = zebra_evpn_acc_vl_find(vlan ? vlan : zif->pvid, zif->ifp);
	if (!acc_bd || !acc_bd->zevpn) {
		++zevpn_arp_nd_info.stat.vni_missing;
		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
			zlog_debug("evpn arp_nd on %s vlan %d; vni mapping missing",
				   zif->ifp->name, vlan);
		return 0;
	}

	zmac = zebra_evpn_mac_lookup(acc_bd->zevpn,
				     (struct ethaddr *)ethh->h_dest);
	if (!zmac) {
		++zevpn_arp_nd_info.stat.mac_missing;
		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
			zlog_debug("evpn arp_nd on %s vni %d; mac missing",
				   zif->ifp->name, acc_bd->zevpn->vni);
		return 0;
	}

	/* If the dest is not an oper-down ES there is nothing to be done */
	es = zmac->es;
	if (!es || !(es->flags & ZEBRA_EVPNES_LOCAL)) {
		++zevpn_arp_nd_info.stat.es_non_local;
		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
			zlog_debug("evpn arp_nd on %s vni %d; mac dest is not a local ES",
				   zif->ifp->name, acc_bd->zevpn->vni);
		return 0;
	}

	if (es->flags & ZEBRA_EVPNES_OPER_UP) {
		++zevpn_arp_nd_info.stat.es_up;
		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
			zlog_debug("evpn arp_nd on %s vni %d; mac dest ES is oper-up",
				   zif->ifp->name, acc_bd->zevpn->vni);
		return 0;
	}

	/*
	 * dest ES is oper-down; see if there is an active peer we can
	 * redirect the traffic to
	 */
	nh = zebra_evpn_arp_nd_get_vtep(es, ethh);
	if (!ipaddr_is_zero(&nh)) {
		++zevpn_arp_nd_info.stat.nh_missing;
		zlog_debug("evpn arp_nd on %s vni %d; no ES peers",
			   zif->ifp->name, acc_bd->zevpn->vni);
		return 0;
	}


	zebra_evpn_arp_nd_vxlan_encap(acc_bd->zevpn, nh, data, len);

	return 0;
}
#endif

#ifndef GNU_LINUX
/* Read ctrl and data for a single packet on the ARP-ND socket */
static int zebra_evpn_arp_nd_recvmsg(int fd, uint8_t *buf, size_t len,
				     uint16_t *vlan_p, int *packetlen_p)
{
	return -1;
}
#else
/* Read ctrl and data for a single packet on the ARP-ND socket */
static int zebra_evpn_arp_nd_recvmsg(int fd, uint8_t *buf, size_t len,
				     uint16_t *vlan_p, int *packetlen_p)
{
	struct msghdr msgh;
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct sockaddr_ll from;
	int packetlen;
	char cbuf[sizeof(struct cmsghdr) + sizeof(struct tpacket_auxdata)];

	/* setup data buf */
	iov.iov_base = buf;
	iov.iov_len = len;

	/* setup ctrl info */
	memset(&msgh, 0, sizeof(struct msghdr));
	msgh.msg_name = &from;
	msgh.msg_namelen = sizeof(from);
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = cbuf;
	msgh.msg_controllen = sizeof(cbuf);
	msgh.msg_flags = 0;

	/* recv */
	packetlen = recvmsg(fd, &msgh, 0);
	*packetlen_p = packetlen;
	if (packetlen < ZEBRA_EVPN_ARP_ND_MIN_PKT_LEN)
		return -1;

	/* invalid control data */
	if (msgh.msg_controllen < sizeof(cbuf))
		return -1;

	/* The BPF should only result in incoming packets; if an outgoing
	 * packet is handed to us ignore it
	 */
	if (from.sll_pkttype == PACKET_OUTGOING)
		return -1;

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if ((cmsg->cmsg_level == SOL_PACKET) &&
		    (cmsg->cmsg_type == PACKET_AUXDATA)) {
			struct tpacket_auxdata *aux =
				(struct tpacket_auxdata *)CMSG_DATA(cmsg);

			if (aux->tp_vlan_tci != 0 ||
			    aux->tp_status & TP_STATUS_VLAN_VALID)
				*vlan_p = aux->tp_vlan_tci & 0xffff;

			return 0;
		}
	}

	return -1;
}
#endif

/* Re-add thread for reading packets of the per-br-port ARP-ND socket */
static void zebra_evpn_arp_nd_read(struct event *thread);
static void zebra_evpn_arp_nd_pkt_read_enable(struct zebra_if *zif)
{
	event_add_read(zrouter.master, zebra_evpn_arp_nd_read, zif,
		       zif->arp_nd_info.pkt_fd, &zif->arp_nd_info.t_pkt_read);
}

/* Read N packets of the ARP socket and process */
static void zebra_evpn_arp_nd_read(struct event *t)
{
	int count;
	uint16_t vlan = 0;
	struct zebra_if *zif;
	int fd;
	int len = 0;
	uint8_t buf[ZEBRA_EVPN_ARP_ND_MAX_PKT_LEN];

	zif = EVENT_ARG(t);
	fd = EVENT_FD(t);

	for (count = 0; count < ZEBRA_EVPN_ARP_ND_PKT_MAX; ++count) {
		if (zebra_evpn_arp_nd_recvmsg(fd, buf, sizeof(buf), &vlan,
					      &len) < 0) {
			if (errno == EINTR)
				continue;

			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_PKT)
				zlog_debug("evpn arp_nd read failed:len %d %s",
					   len, safe_strerror(errno));
			break;
		}

		if (zebra_evpn_arp_nd_proc(zif, vlan, buf, len) < 0)
			break;
	}

	/*
	 * prepare for next installment of packets
	 */
	zebra_evpn_arp_nd_pkt_read_enable(zif);
}

#ifndef GNU_LINUX
/* Setup socket per-access bridge port */
static int zebra_evpn_arp_nd_sock_create(struct zebra_if *zif)
{
	return -1;
}
#else

/* BPF filter for snooping on ARP replies and IPv6 Neighbor advertisements -
 * tcpdump -dd '((arp and arp[6:2] == 2)
 *			or (icmp6 and ip6[40] == 136)) and inbound'
 */
static struct sock_filter arp_nd_reply_filter[] = {
	{ 0x28, 0, 0, 0x0000000c },  { 0x15, 0, 2, 0x00000806 },
	{ 0x28, 0, 0, 0x00000014 },  { 0x15, 8, 11, 0x00000002 },
	{ 0x15, 0, 10, 0x000086dd }, { 0x30, 0, 0, 0x00000014 },
	{ 0x15, 3, 0, 0x0000003a },  { 0x15, 0, 7, 0x0000002c },
	{ 0x30, 0, 0, 0x00000036 },  { 0x15, 0, 5, 0x0000003a },
	{ 0x30, 0, 0, 0x00000036 },  { 0x15, 0, 3, 0x00000088 },
	{ 0x28, 0, 0, 0xfffff004 },  { 0x15, 1, 0, 0x00000004 },
	{ 0x6, 0, 0, 0x00040000 },   { 0x6, 0, 0, 0x00000000 },
};

/* Setup socket per-access bridge port */
static int zebra_evpn_arp_nd_sock_create(struct zebra_if *zif)
{
	int fd;
	int reuse = 1;
	int rcvbuf = ZEBRA_EVPN_ARP_ND_SOC_RCVBUF;
	long flags;
	struct sock_fprog prog = {
		.len = sizeof(arp_nd_reply_filter) /
		       sizeof(arp_nd_reply_filter[0]),
		.filter = arp_nd_reply_filter,
	};

	frr_with_privs (&zserv_privs) {
		fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	}

	if (fd < 0) {
		flog_err(EC_LIB_SOCKET, "evpn arp_nd sock create: errno %s",
			 safe_strerror(errno));
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse,
		       sizeof(reuse))) {
		flog_err(EC_LIB_SOCKET,
			 "evpn arp_nd sock SO_REUSEADDR set: fd %d errno %s",
			 fd, safe_strerror(errno));
		close(fd);
		return -1;
	}

	frr_with_privs (&zserv_privs) {
		if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &rcvbuf,
			       sizeof(rcvbuf)))
			zlog_warn("evpn arp_nd sock Failure to set rcvbuf to %d errno %s",
				  rcvbuf, safe_strerror(errno));
	}

	/* enable aux data for getting the vlan if (kernel strips the
	 * vlan tag for raw sockets)
	 */
	if (setsockopt(fd, SOL_PACKET, PACKET_AUXDATA, (void *)&reuse,
		       sizeof(reuse))) {
		flog_err(EC_LIB_SOCKET,
			 "evpn arp_nd sock PACKET_AUXDATA set: fd %d errno %s",
			 fd, safe_strerror(errno));
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog)) <
	    0) {
		flog_err(EC_LIB_SOCKET,
			 "evpn arp_nd sock PACKET_AUXDATA set: fd %d errno %s",
			 fd, safe_strerror(errno));
		close(fd);
		return -1;
	}

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		flog_err(EC_LIB_SOCKET,
			 "evpn arp_nd sock fcntl get: fd %d errno %s", fd,
			 safe_strerror(errno));
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
		flog_err(EC_LIB_SOCKET,
			 "evpn arp_nd sock fcntl set: fd %d errno %s", fd,
			 safe_strerror(errno));
		close(fd);
		return -1;
	}


	frr_with_privs (&zserv_privs) {
		struct sockaddr_ll sin;

		memset(&sin, 0, sizeof(sin));
		sin.sll_family = PF_PACKET;
		sin.sll_protocol = htons(ETH_P_ALL);
		sin.sll_ifindex = zif->ifp->ifindex;
		if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
			flog_err(EC_LIB_SOCKET,
				 "evpn arp_nd sock fd %d bind to %s errno %s",
				 fd, zif->ifp->name, safe_strerror(errno));
			close(fd);
			return -1;
		}
	}

	return fd;
}
#endif

/* ARP-replies and NA packets are snooped on non-vxlan bridge members.
 * Create a raw socket and read thread to do that per-member.
 */
void zebra_evpn_arp_nd_if_update(struct zebra_if *zif, bool enable)
{
	bool old_snoop;

	if (!(zevpn_arp_nd_info.flags & ZEBRA_EVPN_ARP_ND_FAILOVER))
		return;

	if (!zif || (zif->zif_type == ZEBRA_IF_VXLAN))
		return;

	old_snoop = !!(zif->flags & ZIF_FLAG_ARP_ND_SNOOP);
	if (old_snoop == enable)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_EVT)
		zlog_debug("%s arp_nd snooping on %s %d",
			   enable ? "enable" : "disable", zif->ifp->name,
			   zif->ifp->ifindex);

	if (enable) {
		zif->flags |= ZIF_FLAG_ARP_ND_SNOOP;
		/* create a snooper socket for the bridge-port */
		zif->arp_nd_info.pkt_fd = zebra_evpn_arp_nd_sock_create(zif);
		/* create a thread to read and process the packets */
		zebra_evpn_arp_nd_pkt_read_enable(zif);
	} else {
		zif->flags &= ~ZIF_FLAG_ARP_ND_SNOOP;
		event_cancel(&zif->arp_nd_info.t_pkt_read);
		if (zif->arp_nd_info.pkt_fd > 0) {
			close(zif->arp_nd_info.pkt_fd);
			zif->arp_nd_info.pkt_fd = -1;
		}
	}
}

/* A global/single UDP socket is created and bound to the VTEP SIP.
 * This socket is used for transmitting redirect ARP/NA packets post
 * VxLAN encapsulation
 */
void zebra_evpn_arp_nd_udp_sock_create(void)
{
	if (!ipaddr_is_zero(&zmh_info->es_originator_ip)) {
		struct sockaddr_in sin;

		if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_EVT)
			zlog_debug("Create UDP sock for arp_nd redirect from %pIA",
				   &zmh_info->es_originator_ip);
		if (zevpn_arp_nd_info.udp_fd <= 0)
			zevpn_arp_nd_info.udp_fd = socket(AF_INET, SOCK_DGRAM,
							  IPPROTO_UDP);

		if (zevpn_arp_nd_info.udp_fd <= 0) {
			flog_err(EC_LIB_SOCKET,
				 "evpn arp_nd UDP sock fd %d bind to %pIA errno %s",
				 zevpn_arp_nd_info.udp_fd,
				 &zmh_info->es_originator_ip,
				 safe_strerror(errno));
			return;
		}

		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = zmh_info->es_originator_ip.ipaddr_v4;
		if (bind(zevpn_arp_nd_info.udp_fd, (struct sockaddr *)&sin,
			 sizeof(sin)) < 0) {
			flog_err(EC_LIB_SOCKET,
				 "evpn arp_nd UDP sock fd %d bind to %pIA errno %s",
				 zevpn_arp_nd_info.udp_fd,
				 &zmh_info->es_originator_ip,
				 safe_strerror(errno));
			close(zevpn_arp_nd_info.udp_fd);
			zevpn_arp_nd_info.udp_fd = -1;
		}
	} else {
		if (zevpn_arp_nd_info.udp_fd > 0) {
			zlog_debug("Close arp_nd redirect UDP socket");
			close(zevpn_arp_nd_info.udp_fd);
			zevpn_arp_nd_info.udp_fd = -1;
		}
	}
}

/* Enable ARP/NA snooping on all existing brigde members */
static void zebra_evpn_arp_nd_if_update_all(bool enable)
{
	struct vrf *vrf;
	struct interface *ifp;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ifp->ifindex == IFINDEX_INTERNAL || !ifp->info)
				continue;
			if (!IS_ZEBRA_IF_BRIDGE_SLAVE(ifp))
				continue;
			zebra_evpn_arp_nd_if_update(ifp->info, enable);
		}
	}
}

/* ARP redirect for fast failover is enabled on the first local ES add */
void zebra_evpn_arp_nd_failover_enable(void)
{
	/* If fast failover is not enabled there is nothing to do */
	if (zmh_info->flags & ZEBRA_EVPN_MH_REDIRECT_OFF)
		return;

	if (zevpn_arp_nd_info.flags & ZEBRA_EVPN_ARP_ND_FAILOVER)
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_EVT)
		zlog_debug("Enable arp_nd failover");

	zevpn_arp_nd_info.flags |= ZEBRA_EVPN_ARP_ND_FAILOVER;

	/*
	 * create a UDP socket for sending the vxlan encapsulated
	 * packets
	 */
	zebra_evpn_arp_nd_udp_sock_create();

	/*
	 * walkthrough existing br-ports and enable
	 * snooping on them
	 */
	zebra_evpn_arp_nd_if_update_all(true);
}

void zebra_evpn_arp_nd_failover_disable(void)
{
	/* If fast failover is not enabled there is nothing to do */
	if (!(zevpn_arp_nd_info.flags & ZEBRA_EVPN_ARP_ND_FAILOVER))
		return;

	if (IS_ZEBRA_DEBUG_EVPN_MH_ARP_ND_EVT)
		zlog_debug("Disable arp_nd failover");

	/*
	 * walkthrough existing br-ports and disable
	 * snooping on them
	 */
	zebra_evpn_arp_nd_if_update_all(false);

	/* close the UDP tx socket */
	close(zevpn_arp_nd_info.udp_fd);
	zevpn_arp_nd_info.udp_fd = -1;

	zevpn_arp_nd_info.flags &= ~ZEBRA_EVPN_ARP_ND_FAILOVER;
}
