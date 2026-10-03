// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include <zebra.h>

#include "lib/checksum.h"
#include "lib/lib_errors.h"
#include "lib/libfrr.h"
#include "lib/network.h"
#include "lib/sockopt.h"
#include "lib/typesafe.h"

#include "pimd/pimd.h"
#include "pimd/pim_iface.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_southbound_common.h"
#include "pimd/pim_time.h"
#include "pimd/pim6_mld_packet.h"
#include "pimd/pim6_mld_protocol.h"
#include "pimd/pim6_mld.h"

struct pimsb_ctx {
	/** MLD socket */
	int mld_fd;
	/** MLD socket read event */
	struct event *mld_read_ev;

	/** PIM socket */
	int pim_fd;
	/** PIM socket read event */
	struct event *pim_read_ev;

	/** PIM unicast socket */
	int pim_unicast_fd;
	/** PIM unicast read event */
	struct event *pim_unicast_read_ev;

	/** PIM southbound connection data */
	struct network_address address;

	/** Packet receive buffer */
	uint8_t *packet;
	/** Packet receive buffer size */
	size_t packet_size;
};

/** Largest IPv6 payload (no jumbograms): raw sockets don't return the header. */
#define PIMSB_MAXIMUM_PAYLOAD_SIZE UINT16_MAX

/** Control messages of the received packets (packet and flow information). */
union pimsb_recv_cmsgbuf {
	struct cmsghdr align;
	uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(uint32_t))];
};

static struct pimsb_ctx ctx = {
	.mld_fd = -1,
	.pim_fd = -1,
	.pim_unicast_fd = -1,
};

DEFINE_MTYPE_STATIC(PIMD, PIM6_LOOPBACK_PACKET, "PIMv6 southbound loopback packet");

PREDECL_DLIST(pimsb_loopback_list);

/** MLD packet we sent, queued to be received by our own MLD instance. */
struct pimsb_loopback_packet {
	/** Pending packets list entry. */
	struct pimsb_loopback_list_item entry;
	/** Delivery event. */
	struct event *ev;

	/*
	 * The interface is looked up again when the event runs: MLD may be
	 * disabled (and `struct gm_if` freed) before that.
	 */
	ifindex_t ifindex;
	vrf_id_t vrf_id;
	struct sockaddr_in6 src;
	pim_addr dst;

	size_t data_len;
	uint8_t data[];
};

DECLARE_DLIST(pimsb_loopback_list, struct pimsb_loopback_packet, entry);

/** Packets waiting for `pimsb_recv_loopback`, freed on shutdown. */
static struct pimsb_loopback_list_head pimsb_loopback_packets = INIT_DLIST(pimsb_loopback_packets);

static void pimsb_recv_loopback(struct event *event)
{
	struct pimsb_loopback_packet *packet = EVENT_ARG(event);
	struct pim_interface *pim_interface;
	struct interface *interface;

	pimsb_loopback_list_del(&pimsb_loopback_packets, packet);

	interface = if_lookup_by_index(packet->ifindex, packet->vrf_id);
	pim_interface = interface ? interface->info : NULL;
	if (pim_interface && pim_interface->mld)
		gm_rx_process(pim_interface->mld, &packet->src, &packet->dst, packet->data,
			      packet->data_len);

	XFREE(MTYPE_PIM6_LOOPBACK_PACKET, packet);
}

static void pimsb_send_loopback(struct gm_if *gm_if, const pim_addr *source,
				const pim_addr *destination, const void *data, size_t data_len)
{
	struct pimsb_loopback_packet *packet;

	packet = XCALLOC(MTYPE_PIM6_LOOPBACK_PACKET, sizeof(*packet) + data_len);
	packet->ifindex = gm_if->ifp->ifindex;
	packet->vrf_id = gm_if->ifp->vrf->vrf_id;
	packet->src = (struct sockaddr_in6){
		.sin6_family = AF_INET6,
		.sin6_addr = *source,
	};
	packet->dst = *destination;

	packet->data_len = data_len;
	memcpy(packet->data, data, data_len);

	pimsb_loopback_list_add_tail(&pimsb_loopback_packets, packet);
	event_add_timer(router->master, pimsb_recv_loopback, packet, 0, &packet->ev);
}

static ssize_t pimsb_send_interface(const struct interface *interface, const pim_addr *source,
				    const pim_addr *destination, uint8_t protocol, uint8_t ttl,
				    const void *data, size_t data_length);

static void pimsb_mld_send(const struct interface *interface, bool join, const pim_addr *source,
			   const pim_addr *group)
{
	struct pim_interface *pim_interface = interface->info;
	struct mld_packet_list *packet_list;
	struct mld_packet *packet;
	pim_addr packet_source;
	pim_addr packet_destination;

	packet_list = mld_generate_packet_list(interface, join, source, group);

	/* MLD static join was called, but no groups configured. */
	if (packet_list == NULL)
		return;

	SLIST_FOREACH (packet, packet_list, entry) {
		/* Copied out: the pseudo header is packed. */
		packet_source = packet->ip6->src;
		packet_destination = packet->ip6->dst;

		/* Our own MLD instance must learn about the static joins too. */
		pimsb_send_loopback(pim_interface->mld, &packet_source, &packet_destination,
				    packet->icmp6, packet->size);

		/* The data plane doesn't handle loopbacks. */
		if (!if_is_loopback(interface))
			pimsb_send_interface(interface, &packet_source, &packet_destination,
					     IPPROTO_ICMPV6, 1, packet->icmp6, packet->size);
	}

	mld_free_packet_list(packet_list);
}

/**
 * Skips the hop-by-hop options block in front of a MLD packet and tells
 * whether it carries the MLD Router Alert.
 *
 * The data plane always supplies that block: with a Router Alert it has
 * ICMPv6 as next header and the option, otherwise it is all zeros. A packet
 * that doesn't fit the block is returned with zero length (malformed).
 */
static bool pimsb_mld_parse_hopopts(uint8_t *hopopt, const size_t hopopt_len, uint8_t **data,
				    size_t *data_len)
{
	size_t hopopt_end;

	*data = hopopt;
	*data_len = 0;
	if (hopopt_len <= 8)
		return false;

	hopopt_end = (size_t)(hopopt[1] + 1) * 8;
	if (hopopt_len <= hopopt_end)
		return false;

	*data = hopopt + hopopt_end;
	*data_len = hopopt_len - hopopt_end;
	return hopopt[0] == IPPROTO_ICMPV6 &&
	       ip6_check_hopopts_ra(hopopt, hopopt_end, IP6_ALERT_MLD);
}

/**
 * The data plane delivers MLD to the loopback address, so the original
 * destination is lost: restore the one the packet must have been sent to
 * (RFC 3810 Section 5.1.15 and 5.2.14). `gm_rx_process` checks it for
 * queries and MLDv1 reports.
 *
 * Unlike the kernel path this can't tell a query or report sent to the
 * wrong destination (e.g. unicast): the data plane has to filter them.
 */
static pim_addr pimsb_mld_destination(const uint8_t *data, size_t data_len)
{
	const struct icmp6_plain_hdr *icmp6 = (const struct icmp6_plain_hdr *)data;
	struct mld_v1_pkt mld;

	switch (icmp6->icmp6_type) {
	case ICMP6_MLD_QUERY:
	case ICMP6_MLD_V1_REPORT:
		/* Truncated: the MLD handlers drop it as malformed. */
		if (data_len < sizeof(*icmp6) + sizeof(mld))
			return in6addr_loopback;

		memcpy(&mld, icmp6 + 1, sizeof(mld));
		if (icmp6->icmp6_type == ICMP6_MLD_QUERY && pim_addr_is_any(mld.grp))
			return qpim_all_systems_addr;

		return mld.grp;

	case ICMP6_MLD_V1_DONE:
		return qpim_all_routers_addr;

	case ICMP6_MLD_V2_REPORT:
		return qpim_all_gmp_routers_addr;

	default:
		return in6addr_loopback;
	}
}

/**
 * Tells whether the packet came from the data plane, which delivers packets
 * to the loopback address. That can't come from another host: drop
 * everything else (e.g. injected packets using the encapsulation protocol
 * number) and our own packets to the data plane (multicast).
 */
static bool pimsb_from_data_plane(const struct in6_pktinfo *ipi6)
{
	if (IN6_IS_ADDR_MULTICAST(&ipi6->ipi6_addr))
		return false;

	if (!IN6_IS_ADDR_LOOPBACK(&ipi6->ipi6_addr)) {
		if (PIM_DEBUG_GM_PACKETS || PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: dropping packet to %pI6 (not from the data plane)",
				   __func__, &ipi6->ipi6_addr);
		return false;
	}

	return true;
}

static void pimsb_mld_read(struct event *event __attribute__((unused)))
{
	struct pim_interface *pim_interface;
	struct interface *interface;
	struct vrf *vrf;
	struct cmsghdr *cmsg;
	uint8_t *pktbuf;
	bool has_router_alert;
	size_t pktbuf_len;
	ssize_t brecv;
	uint32_t flow_label;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	pim_addr destination;
	union pimsb_recv_cmsgbuf cmsgbuf;

	event_add_read(router->master, pimsb_mld_read, NULL, ctx.mld_fd, &ctx.mld_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	/* Raw sockets have no EOF. */
	brecv = recvmsg(ctx.mld_fd, &msg, 0);
	if (brecv <= 0) {
		if (brecv == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: recvmsg: %s", __func__, safe_strerror(errno));
		return;
	}

	/* The data plane carries the real interface index in the flow label. */
	if (!getsockopt_ipv6_flowlabel(&msg, &flow_label)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: no flow label, unable to identify interface", __func__);
		return;
	}

	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	/*
	 * Drop what isn't from the data plane before accounting anything in
	 * the interface statistics.
	 */
	if (!pimsb_from_data_plane(&ipi6))
		return;

	interface = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		interface = if_lookup_by_index(flow_label, vrf->vrf_id);
		if (interface)
			break;
	}
	if (interface == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %u", __func__, flow_label);
		return;
	}

	pim_interface = interface->info;
	if (pim_interface == NULL || pim_interface->mld == NULL) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: interface %s has MLD disabled", __func__, interface->name);
		return;
	}

	has_router_alert = pimsb_mld_parse_hopopts((uint8_t *)ctx.packet, (size_t)brecv, &pktbuf,
						   &pktbuf_len);

	if (pktbuf_len < sizeof(struct icmp6_plain_hdr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: %s: packet too small (%zu expected %zu)", __func__,
				   interface->name, pktbuf_len, sizeof(struct icmp6_plain_hdr));
		pim_interface->mld->stats.rx_drop_malformed++;
		return;
	}

	if (IN6_IS_ADDR_UNSPECIFIED(&src.sin6_addr)) {
		/*
		 * reports from :: happen in normal operation for DAD, so
		 * don't spam log messages about this
		 */
		return;
	}

	if (!IN6_IS_ADDR_LINKLOCAL(&src.sin6_addr)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: %s: invalid source %pI6", __func__, interface->name,
				   &src.sin6_addr);
		pim_interface->mld->stats.rx_drop_srcaddr++;
		return;
	}

	if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: [%pI6]->[%pI6] (%s vif %d if %d) router alert %s", __func__,
			   &src.sin6_addr, &ipi6.ipi6_addr, interface->name, interface->vif_index,
			   interface->ifindex, has_router_alert ? "yes" : "no");

	if (pim_interface->gmp_require_ra && !has_router_alert) {
		zlog_err("[MLD %s:%s %pI6] packet without IPv6 Router Alert MLD option",
			 interface->vrf->name, interface->name, &src.sin6_addr);
		pim_interface->mld->stats.rx_drop_ra++;
		return;
	}

	/*
	 * Checksum is skipped on purpose, and the hop limit is lost in the
	 * encapsulation: the data plane is responsible for validating both
	 * before the packet gets here.
	 */

	destination = pimsb_mld_destination(pktbuf, pktbuf_len);
	gm_rx_process(pim_interface->mld, &src, &destination, pktbuf, pktbuf_len);
}

/**
 * Tells whether `source` is one of our addresses.
 *
 * Link-local addresses are only unique on their link (the same one may be
 * used on several interfaces, e.g. `fe80::1` everywhere), so only the
 * receiving interface addresses are checked for them.
 */
static bool pimsb_source_is_local(struct interface *interface, const struct in6_addr *source)
{
	struct connected *ifc;

	if (!IN6_IS_ADDR_LINKLOCAL(source))
		return if_address_is_local(source, AF_INET6, interface->vrf->vrf_id);

	frr_each (if_connected, interface->connected, ifc) {
		if (ifc->address->family == AF_INET6 &&
		    IN6_ARE_ADDR_EQUAL(&ifc->address->u.prefix6, source))
			return true;
	}

	return false;
}

static void pimsb_pim_packet_read(struct event *event __attribute__((unused)))
{
	struct pim_interface *pim_interface;
	struct interface *interface;
	struct cmsghdr *cmsg;
	struct vrf *vrf;
	ssize_t brecv;
	pim_sgaddr sg;
	uint32_t flow_label;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	union pimsb_recv_cmsgbuf cmsgbuf;

	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	/* Raw sockets have no EOF. */
	brecv = recvmsg(ctx.pim_fd, &msg, 0);
	if (brecv <= 0) {
		if (brecv == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: recvmsg: %s", __func__, safe_strerror(errno));
		return;
	}

	/* The data plane carries the real interface index in the flow label. */
	if (!getsockopt_ipv6_flowlabel(&msg, &flow_label)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: no flow label, unable to identify interface", __func__);
		return;
	}

	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	interface = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		interface = if_lookup_by_index(flow_label, vrf->vrf_id);
		if (interface)
			break;
	}
	if (interface == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: could not find interface %u", __func__, flow_label);
		return;
	}

	pim_interface = interface->info;
	if (pim_interface == NULL || !pim_interface->pim_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: interface %s has PIM disabled", __func__, interface->name);
		return;
	}

	if (!pimsb_from_data_plane(&ipi6))
		return;

	if (pimsb_source_is_local(interface, &src.sin6_addr)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	/*
	 * The data plane only relays link-local multicast PIM here and
	 * delivers it to the loopback: restore the original destination. It
	 * also validates the packet and rewrites the checksum for its
	 * encapsulation, so don't verify it again.
	 */
	sg.src = src.sin6_addr;
	sg.grp = qpim_all_pim_routers_addr;
	pim_pim_packet_nocksum(interface, ctx.packet, (size_t)brecv, sg, true);
}

static void pimsb_pim_unicast_read(struct event *event __attribute__((unused)))
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	struct cmsghdr *cmsg;
	struct vrf *vrf;
	ssize_t brecv;
	pim_sgaddr sg;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in6 src;
	struct in6_pktinfo ipi6;
	union {
		struct cmsghdr align;
		uint8_t buf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
	} cmsgbuf;

	event_add_read(router->master, pimsb_pim_unicast_read, NULL, ctx.pim_unicast_fd,
		       &ctx.pim_unicast_read_ev);

	iov.iov_base = ctx.packet;
	iov.iov_len = ctx.packet_size;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_name = &src;
	msg.msg_namelen = sizeof(src);
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	/* Raw sockets have no EOF. */
	brecv = recvmsg(ctx.pim_unicast_fd, &msg, 0);
	if (brecv <= 0) {
		if (brecv == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: recvmsg: %s", __func__, safe_strerror(errno));
		return;
	}

	memset(&ipi6, 0, sizeof(ipi6));
	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != IPPROTO_IPV6)
			continue;

		switch (cmsg->cmsg_type) {
		case IPV6_PKTINFO:
			memcpy(&ipi6, CMSG_DATA(cmsg), sizeof(ipi6));
			break;
		}
	}

	/*
	 * Use the receiving interface, like the kernel path per interface
	 * sockets do: the destination may be an address of an interface
	 * without PIM (e.g. the RP address on the loopback).
	 */
	ifp = NULL;
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index((ifindex_t)ipi6.ipi6_ifindex, vrf->vrf_id);
		if (ifp)
			break;
	}
	if (ifp == NULL) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: could not find interface %u for address %pI6", __func__,
				   ipi6.ipi6_ifindex, &ipi6.ipi6_addr);
		return;
	}

	pim_ifp = ifp->info;
	if (pim_ifp == NULL || !pim_ifp->pim_enable) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: interface %s has PIM disabled", __func__, ifp->name);
		return;
	}

	/* Ignore multicast packets: the data plane never sends them here. */
	if (IN6_IS_ADDR_MULTICAST(&ipi6.ipi6_addr))
		return;

	/*
	 * This socket stands in for the per interface PIM sockets, so all of
	 * it is link traffic (e.g. register, register-stop). Unicast
	 * Candidate-RP advertisements also reach the BSR unicast socket (a
	 * plain IPv6 PIM socket like this one), which processes them: like the
	 * kernel path per interface sockets, don't process them twice.
	 */
	sg.src = src.sin6_addr;
	sg.grp = ipi6.ipi6_addr;
	pim_pim_packet(ifp, ctx.packet, (size_t)brecv, sg, true);
}

static void pimsb_mld_join_cb(struct event *event)
{
	struct gm_if *gm_if = EVENT_ARG(event);

	pimsb_mld_send(gm_if->ifp, true, NULL, NULL);
}

static void pimsb_mld_join(const struct interface *interface)
{
	struct pim_interface *pim_interface = interface->info;

	/*
	 * Static groups are joined through our MLD instance: without MLD on
	 * the interface they are not announced (unlike the kernel which
	 * reports them on any interface).
	 */
	if (pim_interface->mld == NULL) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: no MLD on interface %s, static groups not announced",
				   __func__, interface->name);
		return;
	}

	/*
	 * Called for every configured join, query and expiry: send the
	 * (complete) reports once those settle.
	 */
	event_cancel(&pim_interface->mld->join_event);
	event_add_timer(router->master, pimsb_mld_join_cb, pim_interface->mld, 0,
			&pim_interface->mld->join_event);
}

static void pimsb_mld_leave(const struct interface *interface, const pim_addr *source,
			    const pim_addr *group)
{
	struct pim_interface *pim_interface = interface->info;

	/*
	 * Static groups are joined through our MLD instance: without MLD on
	 * the interface they are not announced (unlike the kernel which
	 * reports them on any interface).
	 */
	if (pim_interface->mld == NULL) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: no MLD on interface %s, static groups not announced",
				   __func__, interface->name);
		return;
	}

	pimsb_mld_send(interface, false, source, group);
}

/**
 * Packets go out through the data plane virtual interface (`vif_index`) when
 * there is one, but keep the real interface link-local source: Linux rejects
 * a link-local source the output interface doesn't have unless non local
 * sources are allowed.
 */
static void pimsb_socket_freebind(int fd)
{
#ifdef IPV6_FREEBIND
	int on = 1;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_FREEBIND, &on, sizeof(on)) == -1)
		flog_err(EC_LIB_SOCKET, "Can't set IPV6_FREEBIND option for fd %d: %s", fd,
			 safe_strerror(errno));
#endif /* IPV6_FREEBIND */
}

/**
 * Packets without an interface (unicast) must carry flow label zero, which
 * the data plane reads as "no interface": don't let Linux generate one.
 */
static void pimsb_socket_no_autoflowlabel(int fd)
{
#ifdef IPV6_AUTOFLOWLABEL
	int off = 0;

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_AUTOFLOWLABEL, &off, sizeof(off)) == -1)
		flog_err(EC_LIB_SOCKET, "Can't unset IPV6_AUTOFLOWLABEL option for fd %d: %s", fd,
			 safe_strerror(errno));
#endif /* IPV6_AUTOFLOWLABEL */
}

static void pimsb_init_pim(void)
{
	int fd;

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, PIM_IP_ENCAP_PIM);
		if (fd == -1) {
			flog_err(EC_LIB_SOCKET, "Can't create PIM socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		if (setsockopt_ipv6_tclass(fd, IPTOS_PREC_INTERNETCONTROL)) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_TCLASS option for fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}

		if (setsockopt_ipv6_pktinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			exit(1);
		}

		if (setsockopt_ipv6_flowinfo(fd, 1) == -1) {
			close(fd);
			exit(1);
		}

		if (setsockopt_ipv6_flowinfo_send(fd, 1) == -1) {
			close(fd);
			exit(1);
		}

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);
	pimsb_socket_freebind(fd);
	pimsb_socket_no_autoflowlabel(fd);

	ctx.pim_fd = fd;
	pim_southbound.pim_fd = fd;
	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, IPPROTO_PIM);
		if (fd == -1) {
			flog_err(EC_LIB_SOCKET, "Can't create PIM unicast socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		if (setsockopt_ipv6_pktinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			exit(1);
		}

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_recvbuf(fd, 8 * 1024 * 1024);
	ctx.pim_unicast_fd = fd;
	event_add_read(router->master, pimsb_pim_unicast_read, NULL, ctx.pim_unicast_fd,
		       &ctx.pim_unicast_read_ev);
}

static void pimsb_init_mld(void)
{
	int fd;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET6, SOCK_RAW, PIM_IPV6_ENCAP_MLD);
		if (fd == -1) {
			flog_err(EC_LIB_SOCKET, "Can't create MLD socket: %s",
				 safe_strerror(errno));
			exit(1);
		}

		if (setsockopt_ipv6_flowinfo(fd, 1) == -1) {
			close(fd);
			exit(1);
		}

		if (setsockopt_ipv6_flowinfo_send(fd, 1) == -1) {
			close(fd);
			exit(1);
		}

		if (setsockopt_ipv6_pktinfo(fd, 1) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IPV6_RECVPKTINFO option for fd %d: %s",
				 fd, safe_strerror(errno));
			close(fd);
			exit(1);
		}

		if (set_nonblocking(fd) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set non blocking fd %d: %s", fd,
				 safe_strerror(errno));
			close(fd);
			exit(1);
		}
	}

	setsockopt_so_sendbuf(fd, 1024 * 1024);
	setsockopt_so_recvbuf(fd, 1024 * 1024);
	pimsb_socket_freebind(fd);
	pimsb_socket_no_autoflowlabel(fd);

	ctx.mld_fd = fd;
	event_add_read(router->master, pimsb_mld_read, NULL, ctx.mld_fd, &ctx.mld_read_ev);
}

/*
 * PIM southbound callbacks
 */
void pimsb_mroute_socket_enable(struct pim_instance *pim)
{
	/* There is no kernel multicast routing socket: the data plane routes. */
	pim->mroute_socket = -1;
	pim->mroute_socket_creation = pim_time_monotonic_sec();
}

void pimsb_mroute_socket_disable(struct pim_instance *pim)
{
	pim->mroute_socket = -1;
}

void pimsb_interface_join(struct interface *interface)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_mld_join(interface);
}

void pimsb_interface_leave(struct interface *interface, const pim_addr *source,
			   const pim_addr *group)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_mld_leave(interface, source, group);
}

/**
 * Sends PIM or MLD (`IPPROTO_ICMPV6`) through the data plane. Without an
 * interface the packet is sent as unicast (PIM only: MLD is link scoped).
 */
static ssize_t pimsb_send_interface(const struct interface *interface, const pim_addr *source,
				    const pim_addr *destination, uint8_t protocol, uint8_t ttl,
				    const void *data, size_t data_length)
{
	struct cmsghdr *cmsg;
	ssize_t bytes;
	size_t controllen;
	uint32_t ifindex;
	uint8_t *dp;
	int hop_limit = ttl;
	int fd;
	struct msghdr msg;
	struct iovec iov;
	struct in6_pktinfo ipi6;
	struct sockaddr_in6 dest;
	/* Hop limit, hop-by-hop options, packet information and flow information. */
	union {
		struct cmsghdr align;
		uint8_t buf[CMSG_SPACE(sizeof(int)) + CMSG_SPACE(8) +
			    CMSG_SPACE(sizeof(struct in6_pktinfo)) + CMSG_SPACE(sizeof(uint32_t))];
	} cmsgbuf = {};

	switch (protocol) {
	case PIM_IP_PROTO_PIM:
		fd = ctx.pim_fd;
		break;
	case IPPROTO_ICMPV6:
		if (interface == NULL) {
			errno = EINVAL;
			return -1;
		}
		fd = ctx.mld_fd;
		break;
	default:
		if (PIM_DEBUG_PIM_PACKETS || PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: unsupported protocol %u", __func__, protocol);

		errno = EPROTONOSUPPORT;
		return -1;
	}

	/* The flow label can't carry (nor the data plane know) other indexes. */
	if (interface &&
	    (interface->ifindex <= 0 || interface->ifindex >= pim_southbound.interface_max)) {
		if (PIM_DEBUG_PIM_PACKETS || PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: interface %s index %d is out of the southbound range",
				   __func__, interface->name, interface->ifindex);
		errno = ERANGE;
		return -1;
	}

	memset(&dest, 0, sizeof(dest));
	dest.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	dest.sin6_len = sizeof(struct sockaddr_in6);
#endif /*SIN6_LEN*/
	dest.sin6_addr = *destination;
	if (interface != NULL) {
		if (interface->vif_index)
			dest.sin6_scope_id = interface->vif_index;
		else
			dest.sin6_scope_id = interface->ifindex;
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &dest;
	msg.msg_namelen = sizeof(dest);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	iov.iov_base = (void *)(uintptr_t)data;
	iov.iov_len = data_length;

	/* `CMSG_NXTHDR` needs the whole buffer: the real size is set below. */
	msg.msg_control = cmsgbuf.buf;
	msg.msg_controllen = sizeof(cmsgbuf.buf);

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_HOPLIMIT;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &hop_limit, sizeof(hop_limit));
	controllen = CMSG_SPACE(sizeof(int));

	if (protocol == IPPROTO_ICMPV6) {
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_HOPOPTS;
		cmsg->cmsg_len = CMSG_LEN(8);
		dp = CMSG_DATA(cmsg);
		*dp++ = 0;		     /* next header */
		*dp++ = 0;		     /* length (8-byte blocks, minus 1) */
		*dp++ = IP6OPT_ROUTER_ALERT; /* router alert */
		*dp++ = 2;		     /* length */
		*dp++ = 0;		     /* value (2 bytes) */
		*dp++ = 0;		     /* value (2 bytes) (0 = MLD) */
		*dp++ = 0;		     /* pad0 */
		*dp++ = 0;		     /* pad0 */
		controllen += CMSG_SPACE(8);
	}

	/*
	 * Always pin the source: the PIM checksum pseudo-header was computed
	 * with it, so the kernel must not pick another one (e.g. for unicast
	 * without an interface, where `ipi6_ifindex` stays zero).
	 */
	if (interface != NULL || !pim_addr_is_any(*source)) {
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_PKTINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
		memset(&ipi6, 0, sizeof(ipi6));
		ipi6.ipi6_addr = *source;
		ipi6.ipi6_ifindex = dest.sin6_scope_id;
		memcpy(CMSG_DATA(cmsg), &ipi6, sizeof(ipi6));
		controllen += CMSG_SPACE(sizeof(struct in6_pktinfo));
	}

	if (interface != NULL) {
		/* Configure flow with real interface id. */
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = IPPROTO_IPV6;
		cmsg->cmsg_type = IPV6_FLOWINFO;
		cmsg->cmsg_len = CMSG_LEN(sizeof(uint32_t));
		ifindex = htonl((uint32_t)interface->ifindex);
		memcpy(CMSG_DATA(cmsg), &ifindex, sizeof(uint32_t));
		controllen += CMSG_SPACE(sizeof(uint32_t));
	}

	msg.msg_controllen = controllen;

	/* Linux requires `CAP_NET_RAW` to send `IPV6_HOPOPTS`. */
	if (protocol == IPPROTO_ICMPV6) {
		frr_with_privs (&pimd_privs) {
			bytes = sendmsg(fd, &msg, 0);
		}
	} else {
		bytes = sendmsg(fd, &msg, 0);
	}

	/* PIM and MLD query senders log the failure (static reports are periodic). */
	if (bytes == -1 && (PIM_DEBUG_PIM_PACKETS || PIM_DEBUG_GM_PACKETS))
		zlog_debug("%s: sendmsg: (%d) %s", __func__, errno, safe_strerror(errno));

	return bytes;
}

ssize_t pimsb_send(const struct interface *interface, const pim_addr *source,
		   const pim_addr *destination, uint8_t protocol, uint8_t ttl, const void *data,
		   size_t data_length)
{
	const struct pim_interface *pim_interface;
	pim_addr source_address;
	ssize_t bytes;

	assert((interface && interface->info) || source);

	/* The callers' checksums use the link-local address too. */
	if (source == NULL) {
		pim_interface = interface->info;
		source_address = pim_interface->ll_lowest;
		source = &source_address;
	}

	bytes = pimsb_send_interface(interface, source, destination, protocol, ttl, data,
				     data_length);

	/*
	 * The kernel loops our multicast MLD packets (queries) back to the MLD
	 * socket and the MLD code depends on it: the general and group
	 * specific expiries only start when it receives its own queries.
	 */
	if (bytes >= 0 && protocol == IPPROTO_ICMPV6 && IN6_IS_ADDR_MULTICAST(destination)) {
		pim_interface = interface->info;
		if (pim_interface && pim_interface->mld)
			pimsb_send_loopback(pim_interface->mld, source, destination, data,
					    data_length);
	}

	return bytes;
}

/*
 * PIM southbound module functions
 */
DEFINE_MTYPE_STATIC(PIMD, PIM6_PACKET_BUFFER, "PIMv6 packet buffer");

static int pim6_southbound_stop(void)
{
	struct pimsb_loopback_packet *packet;

	pimsb_socket_stop();

	/* Leaves generated while shutting down never get delivered. */
	while ((packet = pimsb_loopback_list_pop(&pimsb_loopback_packets))) {
		event_cancel(&packet->ev);
		XFREE(MTYPE_PIM6_LOOPBACK_PACKET, packet);
	}

	event_cancel(&ctx.mld_read_ev);
	event_cancel(&ctx.pim_read_ev);
	event_cancel(&ctx.pim_unicast_read_ev);

	if (ctx.mld_fd != -1) {
		close(ctx.mld_fd);
		ctx.mld_fd = -1;
	}
	if (ctx.pim_fd != -1) {
		close(ctx.pim_fd);
		ctx.pim_fd = -1;
		pim_southbound.pim_fd = -1;
	}
	if (ctx.pim_unicast_fd != -1) {
		close(ctx.pim_unicast_fd);
		ctx.pim_unicast_fd = -1;
	}

	XFREE(MTYPE_PIM6_PACKET_BUFFER, ctx.packet);

	return 0;
}

static int pim6_southbound_start(struct event_loop *event_loop __attribute__((unused)))
{
	/* Allocate big buffer to read incoming packets (maximum IPv6 payload). */
	ctx.packet_size = PIMSB_MAXIMUM_PAYLOAD_SIZE;
	ctx.packet = XCALLOC(MTYPE_PIM6_PACKET_BUFFER, ctx.packet_size);

	/* Initialize MLD packets handler */
	pimsb_init_mld();

	/* Initialize PIM packets handler */
	pimsb_init_pim();

	/* Initialize PIM data plane listening socket */
	pimsb_socket_init(&ctx.address.address, (socklen_t)ctx.address.address_size,
			  !ctx.address.listen);

	/* Register callback to stop southbound on shutdown */
	hook_register(frr_fini, pim6_southbound_stop);

	return 0;
}

static int pim6_southbound_init(void)
{
	/*
	 * Each daemon has its own build of this module (`PIM_IPV` changes the
	 * data structures): refuse being loaded by name into another one.
	 */
	if (strcmp(frr_protoname, "PIM6") != 0) {
		zlog_err("PIM southbound initialization: module is for pim6d, not %s",
			 frr_protoname);
		return -1;
	}

	if (!network_address_parse(THIS_MODULE->load_args, &ctx.address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", ctx.address.error);
		return -1;
	}

	pimsb_configure();

	hook_register(frr_late_init, pim6_southbound_start);

	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "pim6d_southbound",
	.version = "0.0.1",
	.description = "Data plane plugin for PIMv6.",
	.init = pim6_southbound_init,
);
/* clang-format on */
