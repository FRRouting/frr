// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include <zebra.h>

#include "lib/lib_errors.h"
#include "lib/libfrr.h"
#include "lib/network.h"
#include "lib/sockopt.h"
#include "lib/zlog.h"

#include "pimd/pim_iface.h"
#include "pimd/pim_igmp_packet.h"
#include "pimd/pim_instance.h"
#include "pimd/pim_msg.h"
#include "pimd/pim_mroute.h"
#include "pimd/pim_pim.h"
#include "pimd/pim_sock.h"
#include "pimd/pim_southbound_common.h"
#include "pimd/pim_time.h"
#include "pimd/pimd.h"

/*
 * PIM southbound
 */
struct pimsb_ctx {
	/** IGMP socket */
	int igmp_fd;
	/** IGMP socket read event */
	struct event *igmp_read_ev;

	/** PIM socket */
	int pim_fd;
	/** PIM socket read event */
	struct event *pim_read_ev;

	/** PIM southbound connection data */
	struct network_address address;

	/** Packet receive buffer */
	uint8_t *packet;
	/** Packet receiver buffer size */
	size_t packet_size;
};

static struct pimsb_ctx ctx = {
	.igmp_fd = -1,
	.pim_fd = -1,
};

/**
 * Tells whether `data` (IPv4 + IGMP) is an mtrace query/request or response:
 * those don't go through the data plane, the operating system delivers them
 * (see `pimsb_igmp_os_read`).
 */
static bool pimsb_igmp_is_mtrace(const uint8_t *data, size_t data_len)
{
	size_t header_length;

	if (data_len < sizeof(struct ipv4_header))
		return false;

	header_length = ipv4_header_length((const struct ipv4_header *)data);
	if (header_length < sizeof(struct ipv4_header) || header_length >= data_len)
		return false;

	return data[header_length] == PIM_IGMP_MTRACE_RESPONSE ||
	       data[header_length] == PIM_IGMP_MTRACE_QUERY_REQUEST;
}

static void pimsb_igmp_read(struct event *event __attribute__((unused)))
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	struct pim_interface *pim_interface;
	struct interface *interface = NULL;
	const struct ipv4_header *ipv4;
	const uint8_t *packet;
	struct vrf *vrf;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;

	event_add_read(router->master, pimsb_igmp_read, NULL, ctx.igmp_fd, &ctx.igmp_read_ev);

	/* Attempt to read a whole packet (raw sockets have no EOF). */
	bytes_read = read(ctx.igmp_fd, ctx.packet, ctx.packet_size);
	if (bytes_read <= 0) {
		if (bytes_read == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: read: %s", __func__, safe_strerror(errno));
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(ctx.packet, bytes_read, &encap_result);
	if (erv != IEPA_OK) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: invalid encapsulated packet (error %d)", __func__, erv);
		return;
	}

	/* Skip packets to data plane. */
	if (encap_result.destination.s_addr == htonl(IPV4_ENCAP_DST))
		return;

	/*
	 * The data plane delivers packets to the loopback, which can't come
	 * from another host: drop everything else (e.g. injected packets
	 * using the encapsulation protocol number).
	 */
	if (!IPV4_NET127(ntohl(encap_result.destination.s_addr))) {
		if (PIM_DEBUG_GM_PACKETS || PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: dropping packet to %pI4 (not from the data plane)",
				   __func__, &encap_result.destination);
		return;
	}

	/*
	 * Find interface to figure out which VRF it belongs (the index
	 * namespace is global: with the network namespace VRF backend the
	 * first match is used).
	 */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		interface = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (interface)
			break;
	}
	if (!interface) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: could not find interface %d", __func__,
				   encap_result.ifindex);
		return;
	}

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&ctx.packet[encap_result.encap_length],
				  bytes_read - encap_result.encap_length, encap_result.ifindex,
				  &packet, &packet_length);
	if (rv != IPA_NOT_FRAGMENTED && rv != IPA_OK) {
		/* Assembly failed (or waits for more fragments), just quit. */
		if (PIM_DEBUG_GM_PACKETS && rv != IPA_OK_INCOMPLETE)
			zlog_debug("%s: packet assembly failed: %s", __func__,
				   ip_packet_assemble_result_str(rv));
		return;
	}

	/* `pim_mroute_msg` takes protocol zero for a kernel upcall: only IGMP. */
	ipv4 = (const struct ipv4_header *)packet;
	if (ipv4->protocol != PIM_IP_PROTO_IGMP) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: dropping protocol %u packet on %s", __func__,
				   ipv4->protocol, interface->name);
		return;
	}

	/* mtrace is received from the operating system (only once). */
	if (pimsb_igmp_is_mtrace(packet, packet_length)) {
		if (PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: dropping mtrace packet on %s (not from the data plane)",
				   __func__, interface->name);
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_interface = interface->info;
	if (pim_interface)
		pim_mroute_msg(pim_interface->pim, (char *)packet, packet_length,
			       encap_result.ifindex);
	else if (PIM_DEBUG_GM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s", __func__,
			   interface->ifindex, interface->name);
}

static void pimsb_init_igmp(void)
{
	int fd;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		fd = socket(AF_INET, SOCK_RAW, PIM_IP_ENCAP_IGMP);
		if (fd == -1) {
			flog_err(EC_LIB_SOCKET, "socket creation failed: %s", safe_strerror(errno));
			exit(1);
		}

		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IP_HDRINCL option for fd %d: %s", fd,
				 safe_strerror(errno));
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

	ctx.igmp_fd = fd;
	event_add_read(router->master, pimsb_igmp_read, NULL, ctx.igmp_fd, &ctx.igmp_read_ev);
}

static void pimsb_pim_packet_read(struct event *event __attribute__((unused)))
{
	enum ip_encap_packet_assemble_result erv;
	enum ip_packet_assemble_result rv;
	struct pim_interface *pim_interface;
	struct interface *interface = NULL;
	const struct ipv4_header *ipv4;
	const uint8_t *packet;
	struct vrf *vrf;
	size_t packet_length;
	ssize_t bytes_read;
	struct ipv4_encap_result encap_result;
	const struct pim_msg_header *header;
	bool link_traffic;
	pim_sgaddr addr = {};

	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);

	/* Attempt to read a whole packet (raw sockets have no EOF). */
	bytes_read = read(ctx.pim_fd, ctx.packet, ctx.packet_size);
	if (bytes_read <= 0) {
		if (bytes_read == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: read: %s", __func__, safe_strerror(errno));
		return;
	}

	/* Parse the encapsulation. */
	erv = ipv4_encap_parse(ctx.packet, bytes_read, &encap_result);
	if (erv != IEPA_OK) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: invalid encapsulated packet (error %d)", __func__, erv);
		return;
	}

	/* Skip packets to data plane. */
	if (encap_result.destination.s_addr == htonl(IPV4_ENCAP_DST))
		return;

	/*
	 * The data plane delivers packets to the loopback, which can't come
	 * from another host: drop everything else (e.g. injected packets
	 * using the encapsulation protocol number).
	 */
	if (!IPV4_NET127(ntohl(encap_result.destination.s_addr))) {
		if (PIM_DEBUG_GM_PACKETS || PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: dropping packet to %pI4 (not from the data plane)",
				   __func__, &encap_result.destination);
		return;
	}

	/* Reassemble the packet (if fragmented) and pass it along. */
	rv = ipv4_packet_assemble(&ctx.packet[encap_result.encap_length],
				  bytes_read - encap_result.encap_length, encap_result.ifindex,
				  &packet, &packet_length);
	if (rv != IPA_NOT_FRAGMENTED && rv != IPA_OK) {
		/* Assembly failed (or waits for more fragments), just quit. */
		if (PIM_DEBUG_PIM_PACKETS && rv != IPA_OK_INCOMPLETE)
			zlog_debug("%s: packet assembly failed: %s", __func__,
				   ip_packet_assemble_result_str(rv));
		return;
	}

	/*
	 * Find interface to figure out which VRF it belongs (the index
	 * namespace is global: with the network namespace VRF backend the
	 * first match is used).
	 */
	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		interface = if_lookup_by_index(encap_result.ifindex, vrf->vrf_id);
		if (interface)
			break;
	}
	if (!interface) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet on unknown interface %d", __func__,
				   encap_result.ifindex);
		return;
	}

	/* Packet assembled, get VRF information and call PIM code. */
	pim_interface = interface->info;

	if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: incoming pim packet on %s(%d)", __func__, interface->name,
			   encap_result.ifindex);

	ipv4 = (const struct ipv4_header *)packet;
	if (ipv4->protocol != PIM_IP_PROTO_PIM) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: dropping protocol %u packet on %s", __func__,
				   ipv4->protocol, interface->name);
		return;
	}

	if (if_address_is_local(&ipv4->source, AF_INET, interface->vrf->vrf_id)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("%s: incoming packet from myself", __func__);
		return;
	}

	addr.src = ipv4->source;
	addr.grp = ipv4->destination;

	/*
	 * This socket stands in for the per interface PIM sockets, so unicast
	 * link traffic (e.g. register, register-stop) must not be treated as
	 * coming from the BSR unicast socket. Only unicast Candidate-RP
	 * advertisements belong there.
	 */
	link_traffic = true;
	if (!IN_CLASSD(ntohl(ipv4->destination.s_addr)) &&
	    packet_length >= ipv4_header_length(ipv4) + PIM_HDR_LEN) {
		header = (const struct pim_msg_header *)(packet + ipv4_header_length(ipv4));
		if (header->type == PIM_MSG_TYPE_CANDIDATE)
			link_traffic = false;
	}

	/*
	 * Like the kernel per interface PIM sockets, only PIM interfaces get
	 * link traffic (the BSR unicast socket takes Candidate-RP
	 * advertisements from any interface).
	 */
	if ((pim_interface && pim_interface->pim_enable) || !link_traffic)
		pim_pim_packet(interface, (uint8_t *)(uintptr_t)packet, packet_length, addr,
			       link_traffic);
	else if (PIM_DEBUG_PIM_PACKETS)
		zlog_debug("%s: received packet on disabled interface (%d) %s", __func__,
			   interface->ifindex, interface->name);
}

static void pimsb_init_pim(void)
{
	int fd;
	int on = 1;

	frr_with_privs (&pimd_privs) {
		fd = socket(PIM_AF, SOCK_RAW, PIM_IP_ENCAP_PIM);
		if (fd == -1) {
			flog_err(EC_LIB_SOCKET, "socket creation failed: %s", safe_strerror(errno));
			exit(1);
		}

		/* Include IP header. */
		if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) == -1) {
			flog_err(EC_LIB_SOCKET, "Can't set IP_HDRINCL option for fd %d: %s", fd,
				 safe_strerror(errno));
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

	ctx.pim_fd = fd;
	pim_southbound.pim_fd = fd;

	event_add_read(router->master, pimsb_pim_packet_read, NULL, ctx.pim_fd, &ctx.pim_read_ev);
}

/**
 * IGMP join callback: when timer expires it injects an IGMP join packet
 * into the IGMP input path to simulate a local membership to source/group.
 *
 * This callback is called on `pimsb_igmp_join` or when a IGMP general query
 * is sent.
 */
static void pimsb_igmp_join_cb(struct event *e)
{
	struct gm_sock *igmp_socket = EVENT_ARG(e);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	params = pim_interface_generate_igmp_static_params(igmp_socket->interface, true, NULL,
							   NULL);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (!packets)
		return;

	SLIST_FOREACH (packet, packets, entry) {
		const struct ipv4_header *ip = (const struct ipv4_header *)packet->data;

		/* The data plane doesn't handle loopbacks. */
		if (!if_is_loopback(igmp_socket->interface))
			pimsb_send(igmp_socket->interface, &ip->source, &ip->destination,
				   ip->protocol, ip->ttl, packet->data + ipv4_header_length(ip),
				   packet->size - ipv4_header_length(ip));

		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->size);
	}

	igmp_packet_list_free(packets);
}

static void pimsb_igmp_join(const struct pim_interface *pim_interface)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(pim_interface->gm_socket_list,
								  pim_interface->primary_address);

	/*
	 * Static groups are joined through our IGMP instance: without IGMP on
	 * the interface (PIM only interfaces have an mtrace only socket, which
	 * never sends or hears queries) they are not announced (unlike the
	 * kernel which reports them on any interface).
	 */
	if (!igmp_socket || igmp_socket->mtrace_only) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: no IGMP on interface %pI4, static groups not announced",
				   __func__, &pim_interface->primary_address);
		return;
	}

	event_cancel(&igmp_socket->join_event);
	event_add_timer(router->master, pimsb_igmp_join_cb, igmp_socket, 0,
			&igmp_socket->join_event);
}

DEFINE_MTYPE_STATIC(PIMD, PIM_LOOPBACK_PACKET, "PIM southbound loopback packet");

PREDECL_DLIST(pimsb_loopback_list);

/** IGMP packet we sent, queued to be received by our own IGMP instance. */
struct pimsb_loopback_packet {
	/** Pending packets list entry. */
	struct pimsb_loopback_list_item entry;
	/** Delivery event. */
	struct event *ev;

	/*
	 * The socket is looked up again when the event runs: it may be gone
	 * before that (e.g. `pim_if_delete` leaves the static joins right
	 * before deleting the IGMP sockets).
	 */
	ifindex_t ifindex;
	vrf_id_t vrf_id;
	struct in_addr ifaddr;

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
	struct gm_sock *igmp_socket = NULL;

	pimsb_loopback_list_del(&pimsb_loopback_packets, packet);

	interface = if_lookup_by_index(packet->ifindex, packet->vrf_id);
	pim_interface = interface ? interface->info : NULL;
	if (pim_interface)
		igmp_socket = pim_igmp_sock_lookup_ifaddr(pim_interface->gm_socket_list,
							  packet->ifaddr);
	if (igmp_socket && !igmp_socket->mtrace_only)
		pim_igmp_packet(igmp_socket, (char *)packet->data, packet->data_len);

	XFREE(MTYPE_PIM_LOOPBACK_PACKET, packet);
}

/**
 * Hands `data` (IPv4 + IGMP) to our own IGMP instance from an event: the
 * callers may run inside the IGMP code (e.g. the IGMP proxy leaves its joins
 * while processing a membership change), which is not reentrant.
 */
static void pimsb_send_loopback(const struct gm_sock *igmp_socket, const void *data,
				size_t data_len)
{
	struct pimsb_loopback_packet *packet;

	packet = XCALLOC(MTYPE_PIM_LOOPBACK_PACKET, sizeof(*packet) + data_len);
	packet->ifindex = igmp_socket->interface->ifindex;
	packet->vrf_id = igmp_socket->interface->vrf->vrf_id;
	packet->ifaddr = igmp_socket->ifaddr;

	packet->data_len = data_len;
	memcpy(packet->data, data, data_len);

	pimsb_loopback_list_add_tail(&pimsb_loopback_packets, packet);
	event_add_timer(router->master, pimsb_recv_loopback, packet, 0, &packet->ev);
}

static void pimsb_igmp_leave(const struct pim_interface *pim_interface,
			     const struct in_addr *source, const struct in_addr *group)
{
	struct gm_sock *igmp_socket = pim_igmp_sock_lookup_ifaddr(pim_interface->gm_socket_list,
								  pim_interface->primary_address);
	const struct igmp_packet *packet;
	struct igmp_packet_list *packets;
	struct igmp_packet_params *params;

	/*
	 * Static groups are joined through our IGMP instance: without IGMP on
	 * the interface (PIM only interfaces have an mtrace only socket, which
	 * never sends or hears queries) they are not announced (unlike the
	 * kernel which reports them on any interface).
	 */
	if (!igmp_socket || igmp_socket->mtrace_only) {
		if (PIM_DEBUG_GM_TRACE)
			zlog_debug("%s: no IGMP on interface %pI4, static groups not announced",
				   __func__, &pim_interface->primary_address);
		return;
	}

	params = pim_interface_generate_igmp_static_params(igmp_socket->interface, false, source,
							   group);
	packets = igmp_generate_packets(params);
	igmp_join_params_free(params);

	/* IGMP static join was called, but no groups configured. */
	if (!packets)
		return;

	/*
	 * Like the join: tell the data plane and our own IGMP instance (later:
	 * see `pimsb_send_loopback`).
	 */
	SLIST_FOREACH (packet, packets, entry) {
		const struct ipv4_header *ip = (const struct ipv4_header *)packet->data;

		if (!if_is_loopback(igmp_socket->interface))
			pimsb_send(igmp_socket->interface, &ip->source, &ip->destination,
				   ip->protocol, ip->ttl, packet->data + ipv4_header_length(ip),
				   packet->size - ipv4_header_length(ip));

		pimsb_send_loopback(igmp_socket, packet->data, packet->size);
	}

	igmp_packet_list_free(packets);
}

/*
 * PIM southbound callbacks
 */

/**
 * Reads the IGMP of the interfaces the data plane doesn't own (loopbacks):
 * like the kernel mroute socket, unlike the per interface IGMP sockets (bound
 * to the interface address), it receives the reports.
 *
 * It also reads the mtrace packets of the interfaces the data plane owns:
 * mtrace keeps using the operating system, like its per interface IGMP
 * sockets (`mtrace_only` included) do without the southbound.
 */
static void pimsb_igmp_os_read(struct event *event)
{
	struct pim_instance *pim = EVENT_ARG(event);
	struct interface *interface;
	ifindex_t ifindex = 0;
	ssize_t bytes_read;

	event_add_read(router->master, pimsb_igmp_os_read, pim, pim->mroute_socket, &pim->event);

	/* The buffer is allocated by `pim_southbound_start`. */
	if (ctx.packet == NULL)
		return;

	bytes_read = pim_socket_recvfromto(pim->mroute_socket, ctx.packet, ctx.packet_size, NULL,
					   NULL, NULL, NULL, &ifindex);
	if (bytes_read <= 0) {
		if (bytes_read == -1 && !ERRNO_IO_RETRY(errno))
			zlog_warn("%s: read: %s", __func__, safe_strerror(errno));
		return;
	}

	/*
	 * The default VRF socket also receives the VRF devices packets, which
	 * their own VRF socket handles.
	 */
	interface = if_lookup_by_index(ifindex, pim->vrf->vrf_id);
	if (interface == NULL || interface->vrf != pim->vrf)
		return;

	/*
	 * The data plane hands us the IGMP of the interfaces it owns: the
	 * operating system would only deliver copies of it. mtrace doesn't go
	 * through the data plane.
	 */
	if (pim_sb_owns_interface(interface) &&
	    !pimsb_igmp_is_mtrace(ctx.packet, (size_t)bytes_read))
		return;

	pim_mroute_msg(pim, (const char *)ctx.packet, (size_t)bytes_read, ifindex);
}

void pimsb_mroute_socket_enable(struct pim_instance *pim)
{
	int fd;

	/* A re-enabled VRF (device deleted and added again) gets a new one. */
	pimsb_mroute_socket_disable(pim);

	/*
	 * There is no kernel multicast routing: this socket only receives the
	 * IGMP of the interfaces the data plane doesn't own, and the mtrace
	 * packets of every interface.
	 */
	pim->mroute_socket = -1;
	pim->mroute_socket_creation = pim_time_monotonic_sec();

	frr_with_privs (&pimd_privs) {
		fd = vrf_socket(AF_INET, SOCK_RAW, IPPROTO_IGMP, pim->vrf->vrf_id, NULL);
	}
	if (fd == -1) {
		flog_err(EC_LIB_SOCKET, "%s: VRF %s IGMP socket: %s", __func__, pim->vrf->name,
			 safe_strerror(errno));
		return;
	}

	if (setsockopt_ifindex(AF_INET, fd, 1) == -1 || set_nonblocking(fd) == -1) {
		flog_err(EC_LIB_SOCKET, "%s: VRF %s IGMP socket options: %s", __func__,
			 pim->vrf->name, safe_strerror(errno));
		close(fd);
		return;
	}

	pim->mroute_socket = fd;
	event_add_read(router->master, pimsb_igmp_os_read, pim, pim->mroute_socket, &pim->event);
}

void pimsb_mroute_socket_disable(struct pim_instance *pim)
{
	/*
	 * Only an open socket has the read event. VRFs that were never
	 * enabled (e.g. configured without their device) have none: the
	 * instance starts zeroed, so `mroute_socket` is 0 and not ours.
	 */
	if (pim->event == NULL)
		return;

	event_cancel(&pim->event);
	close(pim->mroute_socket);
	pim->mroute_socket = -1;
}

void pimsb_interface_join(struct interface *interface)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_igmp_join(interface->info);
}

void pimsb_interface_leave(struct interface *interface, const pim_addr *source,
			   const pim_addr *group)
{
	/* Multicast not enabled */
	if (!interface->info)
		return;

	pimsb_igmp_leave(interface->info, source, group);
}

ssize_t pimsb_send(const struct interface *interface, const pim_addr *source,
		   const pim_addr *destination, uint8_t protocol, uint8_t ttl, const void *data,
		   size_t data_length)
{
	const struct pim_interface *pim_interface = interface ? interface->info : NULL;
	struct in_addr source_address;
	struct ipv4_output_params params;

	assert((interface && pim_interface) || source);

	/* The encapsulation can't carry (nor the data plane know) other indexes. */
	if (interface &&
	    (interface->ifindex <= 0 || interface->ifindex >= pim_southbound.interface_max)) {
		if (PIM_DEBUG_PIM_PACKETS || PIM_DEBUG_GM_PACKETS)
			zlog_debug("%s: interface %s index %d is out of the southbound range",
				   __func__, interface->name, interface->ifindex);
		errno = ERANGE;
		return -1;
	}

	if (source)
		source_address = *source;
	else
		source_address = pim_interface->primary_address;

	params = (struct ipv4_output_params){
		.destination = *destination,
		.source = source_address,
		.protocol = protocol,
		.tos = IPTOS_PREC_INTERNETCONTROL,
		.socket = (protocol == PIM_IP_PROTO_PIM) ? ctx.pim_fd : ctx.igmp_fd,
		.router_alert = (protocol == PIM_IP_PROTO_IGMP),
		.ttl = ttl,
		/* `mtu` is 16 bits wide (e.g. the loopback has 65536). */
		.mtu = interface ? MIN(interface->mtu, IPV4_MAXIMUM_PACKET_SIZE) : 1500,
		.encap.ifindex = interface ? interface->ifindex : 0,
		.encap.source = source_address,
	};

	return ipv4_output(&params, data, data_length);
}

/*
 * PIM southbound module functions
 */
DEFINE_MTYPE_STATIC(PIMD, PIM_PACKET_BUFFER, "PIM packet buffer");

static int pim_southbound_stop(void)
{
	struct pimsb_loopback_packet *packet;

	pimsb_socket_stop();

	/* Leaves generated while shutting down never get delivered. */
	while ((packet = pimsb_loopback_list_pop(&pimsb_loopback_packets))) {
		event_cancel(&packet->ev);
		XFREE(MTYPE_PIM_LOOPBACK_PACKET, packet);
	}

	event_cancel(&ctx.igmp_read_ev);
	event_cancel(&ctx.pim_read_ev);

	if (ctx.igmp_fd != -1) {
		close(ctx.igmp_fd);
		ctx.igmp_fd = -1;
	}
	if (ctx.pim_fd != -1) {
		close(ctx.pim_fd);
		ctx.pim_fd = -1;
		pim_southbound.pim_fd = -1;
	}

	XFREE(MTYPE_PIM_PACKET_BUFFER, ctx.packet);

	ip_fragmentation_handler_stop();

	return 0;
}

static int pim_southbound_start(struct event_loop *event_loop)
{
	/* Initialize IP handler */
	ip_fragmentation_handler_init(event_loop);

	/* Allocate big buffer to read incoming packets */
	ctx.packet_size = IPV4_MAXIMUM_PACKET_SIZE;
	ctx.packet = XCALLOC(MTYPE_PIM_PACKET_BUFFER, ctx.packet_size);

	/* Initialize IGMP packets handler */
	pimsb_init_igmp();

	/* Initialize PIM packets handler */
	pimsb_init_pim();

	/* Initialize PIM data plane listening socket */
	pimsb_socket_init(&ctx.address.address, (socklen_t)ctx.address.address_size,
			  !ctx.address.listen);

	/* Register callback to stop southbound on shutdown */
	hook_register(frr_fini, pim_southbound_stop);

	return 0;
}

static int pim_southbound_init(void)
{
	/*
	 * Each daemon has its own build of this module (`PIM_IPV` changes the
	 * data structures): refuse being loaded by name into another one.
	 */
	if (strcmp(frr_protoname, "PIM") != 0) {
		zlog_err("PIM southbound initialization: module is for pimd, not %s",
			 frr_protoname);
		return -1;
	}

	if (!network_address_parse(THIS_MODULE->load_args, &ctx.address, PIMSB_DEFAULT_PORT)) {
		zlog_err("PIM southbound initialization: %s", ctx.address.error);
		return -1;
	}

	pimsb_configure();

	hook_register(frr_late_init, pim_southbound_start);

	return 0;
}

/* clang-format off */
FRR_MODULE_SETUP(
	.name = "pimd_southbound",
	.version = "0.0.1",
	.description = "Data plane plugin for PIM.",
	.init = pim_southbound_init,
);
/* clang-format on */
