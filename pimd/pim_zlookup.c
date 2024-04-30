// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "frrevent.h"
#include "prefix.h"
#include "vty.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_iface.h"
#include "pim_neighbor.h"
#include "pim_pim.h"
#include "pim_str.h"
#include "pim_oil.h"
#include "pim_zlookup.h"
#include "pim_addr.h"

static struct zclient *zlookup = NULL;
struct event *zlookup_read;

static void zclient_lookup_sched(struct zclient *zlookup, int delay);
static void zclient_lookup_read_pipe(struct event *thread);

/* Connect to zebra for nexthop lookup. */
static void zclient_lookup_connect(struct event *t)
{
	struct zclient *zlookup;

	zlookup = EVENT_ARG(t);

	if (zlookup->sock >= 0) {
		return;
	}

	if (zclient_socket_connect(zlookup) < 0) {
		++zlookup->fail;
		zlog_warn("%s: failure connecting zclient socket: failures=%d",
			  __func__, zlookup->fail);
	} else {
		zlookup->fail = 0; /* reset counter on connection */
	}

	if (zclient_send_hello(zlookup) == ZCLIENT_SEND_FAILURE) {
		if (close(zlookup->sock)) {
			zlog_warn("%s: closing fd=%d: errno=%d %s", __func__,
				  zlookup->sock, errno, safe_strerror(errno));
		}
		zlookup->sock = -1;
	}

	if (zlookup->sock < 0) {
		/* Since last connect failed, retry within 10 secs */
		zclient_lookup_sched(zlookup, 10);
		return;
	}

	event_add_timer(router->master, zclient_lookup_read_pipe, zlookup, 60,
			&zlookup_read);
}

/* Schedule connection with delay. */
static void zclient_lookup_sched(struct zclient *zlookup, int delay)
{
	event_add_timer(router->master, zclient_lookup_connect, zlookup, delay,
			&zlookup->t_connect);

	zlog_notice("%s: zclient lookup connection scheduled for %d seconds",
		    __func__, delay);
}

/* Schedule connection for now. */
static void zclient_lookup_sched_now(struct zclient *zlookup)
{
	event_add_event(router->master, zclient_lookup_connect, zlookup, 0,
			&zlookup->t_connect);

	zlog_notice("%s: zclient lookup immediate connection scheduled",
		    __func__);
}

/* Schedule reconnection, if needed. */
static void zclient_lookup_reconnect(struct zclient *zlookup)
{
	if (zlookup->t_connect) {
		return;
	}

	zclient_lookup_sched_now(zlookup);
}

static void zclient_lookup_failed(struct zclient *zlookup)
{
	if (zlookup->sock >= 0) {
		if (close(zlookup->sock)) {
			zlog_warn("%s: closing fd=%d: errno=%d %s", __func__,
				  zlookup->sock, errno, safe_strerror(errno));
		}
		zlookup->sock = -1;
	}

	zclient_lookup_reconnect(zlookup);
}

void zclient_lookup_free(void)
{
	EVENT_OFF(zlookup_read);
	zclient_stop(zlookup);
	zclient_free(zlookup);
	zlookup = NULL;
}

void zclient_lookup_new(void)
{
	zlookup = zclient_new(router->master, &zclient_options_sync, NULL, 0);
	if (!zlookup) {
		flog_err(EC_LIB_ZAPI_SOCKET, "%s: zclient_new() failure",
			 __func__);
		return;
	}

	zlookup->sock = -1;
	zlookup->t_connect = NULL;
	zlookup->privs = &pimd_privs;

	zclient_lookup_sched_now(zlookup);

	zlog_notice("%s: zclient lookup socket initialized", __func__);
}

static int zclient_read_nexthop(struct pim_instance *pim,
				struct zclient *zlookup,
				struct pim_zlookup_nexthop nexthop_tab[],
				const int tab_size, pim_addr addr)
{
	int num_ifindex = 0;
	struct stream *s;
	uint16_t length;
	uint8_t marker;
	uint8_t version;
	vrf_id_t vrf_id;
	uint16_t command = 0;
	struct ipaddr raddr;
	uint8_t distance;
	uint32_t metric;
	int nexthop_num;
	int i, err;

	if (PIM_DEBUG_PIM_NHT_DETAIL)
		zlog_debug("%s: addr=%pPAs(%s)", __func__, &addr,
			   pim->vrf->name);

	s = zlookup->ibuf;

	while (command != ZEBRA_NEXTHOP_LOOKUP_MRIB) {
		stream_reset(s);
		err = zclient_read_header(s, zlookup->sock, &length, &marker,
					  &version, &vrf_id, &command);
		if (err < 0) {
			flog_err(EC_LIB_ZAPI_MISSMATCH,
				 "%s: zclient_read_header() failed", __func__);
			zclient_lookup_failed(zlookup);
			return -1;
		}

		if (command == ZEBRA_ERROR) {
			enum zebra_error_types error;

			zapi_error_decode(s, &error);
			/* Do nothing with it for now */
			return -1;
		}
	}

	stream_get_ipaddr(s, &raddr);

	if (raddr.ipa_type != PIM_IPADDR ||
	    pim_addr_cmp(raddr.ipaddr_pim, addr)) {
		zlog_warn("%s: address mismatch: addr=%pPA(%s) raddr=%pIA",
			  __func__, &addr, pim->vrf->name, &raddr);
		/* warning only */
	}

	distance = stream_getc(s);
	metric = stream_getl(s);
	nexthop_num = stream_getc(s);

	if (nexthop_num < 1 || nexthop_num > router->multipath) {
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: socket %d bad nexthop_num=%d", __func__,
				   zlookup->sock, nexthop_num);
		return -6;
	}

	for (i = 0; i < nexthop_num; ++i) {
		vrf_id_t nexthop_vrf_id;
		enum nexthop_types_t nexthop_type;
		struct in_addr nh_ip4;
		struct in6_addr nh_ip6;
		ifindex_t nh_ifi;

		nexthop_vrf_id = stream_getl(s);
		nexthop_type = stream_getc(s);
		if (num_ifindex >= tab_size) {
			zlog_warn(
				"%s: found too many nexthop ifindexes (%d > %d) for address %pPAs(%s)",
				__func__, (num_ifindex + 1), tab_size, &addr,
				pim->vrf->name);
			return num_ifindex;
		}
		nexthop_tab[num_ifindex].protocol_distance = distance;
		nexthop_tab[num_ifindex].route_metric = metric;
		nexthop_tab[num_ifindex].vrf_id = nexthop_vrf_id;
		switch (nexthop_type) {
		case NEXTHOP_TYPE_IFINDEX:
			nexthop_tab[num_ifindex].ifindex = stream_getl(s);
			/*
			 * Connected route (i.e. no nexthop), use
			 * address passed in as PIM nexthop.  This will
			 * allow us to work in cases where we are
			 * trying to find a route for this box.
			 */
			nexthop_tab[num_ifindex].nexthop_addr = addr;
			++num_ifindex;
			break;
		case NEXTHOP_TYPE_IPV4_IFINDEX:
		case NEXTHOP_TYPE_IPV4:
			nh_ip4.s_addr = stream_get_ipv4(s);
			nh_ifi = stream_getl(s);
#if PIM_IPV == 4
			nexthop_tab[num_ifindex].nexthop_addr = nh_ip4;
			nexthop_tab[num_ifindex].ifindex = nh_ifi;
			++num_ifindex;
#else
			zlog_warn(
				"cannot use IPv4 nexthop %pI4(%d) for IPv6 %pPA",
				&nh_ip4, nh_ifi, &addr);
#endif
			break;
		case NEXTHOP_TYPE_IPV6:
		case NEXTHOP_TYPE_IPV6_IFINDEX:
			stream_get(&nh_ip6, s, sizeof(nh_ip6));
			nh_ifi = stream_getl(s);

#if PIM_IPV == 6
			nexthop_tab[num_ifindex].nexthop_addr = nh_ip6;
			nexthop_tab[num_ifindex].ifindex = nh_ifi;
			++num_ifindex;
#else
			/* RFC 5549 v4-over-v6 nexthop handling */

			/*
			 * If we are sending v6 secondary assume we receive v6
			 * secondary
			 */
			struct interface *ifp = if_lookup_by_index(
				nh_ifi,
				nexthop_vrf_id);

			if (!ifp)
				break;

			struct pim_neighbor *nbr;

			if (pim->send_v6_secondary) {
				struct prefix p;

				p.family = AF_INET6;
				p.prefixlen = IPV6_MAX_BITLEN;
				p.u.prefix6 = nh_ip6;

				nbr = pim_neighbor_find_by_secondary(ifp, &p);
			} else
				nbr = pim_neighbor_find_if(ifp);

			if (!nbr)
				break;

			nexthop_tab[num_ifindex].nexthop_addr =
				nbr->source_addr;
			nexthop_tab[num_ifindex].ifindex = nh_ifi;
			++num_ifindex;
#endif
			break;
		case NEXTHOP_TYPE_BLACKHOLE:
			/* do nothing */
			zlog_warn(
				"%s: found non-ifindex nexthop type=%d for address %pPAs(%s)",
				__func__, nexthop_type, &addr, pim->vrf->name);
			break;
		}
	}

	return num_ifindex;
}

static int zclient_lookup_nexthop_once(struct pim_instance *pim,
				       struct pim_zlookup_nexthop nexthop_tab[],
				       const int tab_size, pim_addr addr)
{
	struct stream *s;
	int ret;
	struct ipaddr ipaddr;

	if (PIM_DEBUG_PIM_NHT_DETAIL)
		zlog_debug("%s: addr=%pPAs(%s)", __func__, &addr,
			   pim->vrf->name);

	/* Check socket. */
	if (zlookup->sock < 0) {
		flog_err(EC_LIB_ZAPI_SOCKET,
			 "%s: zclient lookup socket is not connected",
			 __func__);
		zclient_lookup_failed(zlookup);
		return -1;
	}

	if (pim->vrf->vrf_id == VRF_UNKNOWN) {
		zlog_notice(
			"%s: VRF: %s does not fully exist yet, delaying lookup",
			__func__, pim->vrf->name);
		return -1;
	}

	ipaddr.ipa_type = PIM_IPADDR;
	ipaddr.ipaddr_pim = addr;

	s = zlookup->obuf;
	stream_reset(s);
	zclient_create_header(s, ZEBRA_NEXTHOP_LOOKUP_MRIB, pim->vrf->vrf_id);
	stream_put_ipaddr(s, &ipaddr);
	stream_putw_at(s, 0, stream_get_endp(s));

	ret = writen(zlookup->sock, s->data, stream_get_endp(s));
	if (ret < 0) {
		flog_err(
			EC_LIB_SOCKET,
			"%s: writen() failure: %d writing to zclient lookup socket",
			__func__, errno);
		zclient_lookup_failed(zlookup);
		return -2;
	}
	if (ret == 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: connection closed on zclient lookup socket",
			     __func__);
		zclient_lookup_failed(zlookup);
		return -3;
	}

	return zclient_read_nexthop(pim, zlookup, nexthop_tab, tab_size, addr);
}

void zclient_lookup_read_pipe(struct event *thread)
{
	struct zclient *zlookup = EVENT_ARG(thread);
	struct pim_instance *pim = pim_get_pim_instance(VRF_DEFAULT);
	struct pim_zlookup_nexthop nexthop_tab[10];
	pim_addr l = PIMADDR_ANY;

	if (!pim) {
		if (PIM_DEBUG_PIM_NHT_DETAIL)
			zlog_debug("%s: Unable to find pim instance", __func__);
		return;
	}

	zclient_lookup_nexthop_once(pim, nexthop_tab, 10, l);
	event_add_timer(router->master, zclient_lookup_read_pipe, zlookup, 60,
			&zlookup_read);
}

int zclient_lookup_nexthop(struct pim_instance *pim,
			   struct pim_zlookup_nexthop nexthop_tab[],
			   const int tab_size, pim_addr addr,
			   int max_lookup)
{
	int lookup;
	uint32_t route_metric = 0xFFFFFFFF;
	uint8_t protocol_distance = 0xFF;

	pim->nexthop_lookups++;

	for (lookup = 0; lookup < max_lookup; ++lookup) {
		int num_ifindex;
		int first_ifindex;
		pim_addr nexthop_addr;

		num_ifindex = zclient_lookup_nexthop_once(pim, nexthop_tab,
							  tab_size, addr);
		if (num_ifindex < 1) {
			if (PIM_DEBUG_PIM_NHT_DETAIL)
				zlog_debug(
					"%s: lookup=%d/%d: could not find nexthop ifindex for address %pPA(%s)",
					__func__, lookup, max_lookup, &addr,
					pim->vrf->name);
			return -1;
		}

		if (lookup < 1) {
			/* this is the non-recursive lookup - save original
			 * metric/distance */
			route_metric = nexthop_tab[0].route_metric;
			protocol_distance = nexthop_tab[0].protocol_distance;
		}

		/*
		 * FIXME: Non-recursive nexthop ensured only for first ifindex.
		 * However, recursive route lookup should really be fixed in
		 * zebra daemon.
		 * See also TODO T24.
		 *
		 * So Zebra for NEXTHOP_TYPE_IPV4 returns the ifindex now since
		 * it was being stored.  This Doesn't solve all cases of
		 * recursive lookup but for the most common types it does.
		 */
		first_ifindex = nexthop_tab[0].ifindex;
		nexthop_addr = nexthop_tab[0].nexthop_addr;
		if (first_ifindex > 0) {
			/* found: first ifindex is non-recursive nexthop */

			if (lookup > 0) {
				/* Report non-recursive success after first
				 * lookup */
				if (PIM_DEBUG_PIM_NHT)
					zlog_debug(
						"%s: lookup=%d/%d: found non-recursive ifindex=%d for address %pPA(%s) dist=%d met=%d",
						__func__, lookup, max_lookup,
						first_ifindex, &addr,
						pim->vrf->name,
						nexthop_tab[0]
							.protocol_distance,
						nexthop_tab[0].route_metric);

				/* use last address as nexthop address */
				nexthop_tab[0].nexthop_addr = addr;

				/* report original route metric/distance */
				nexthop_tab[0].route_metric = route_metric;
				nexthop_tab[0].protocol_distance =
					protocol_distance;
			}

			return num_ifindex;
		}

		if (PIM_DEBUG_PIM_NHT)
			zlog_debug(
				"%s: lookup=%d/%d: zebra returned recursive nexthop %pPAs for address %pPA(%s) dist=%d met=%d",
				__func__, lookup, max_lookup, &nexthop_addr,
				&addr, pim->vrf->name,
				nexthop_tab[0].protocol_distance,
				nexthop_tab[0].route_metric);

		addr = nexthop_addr; /* use nexthop
					addr for recursive lookup */

	} /* for (max_lookup) */

	if (PIM_DEBUG_PIM_NHT)
		zlog_warn(
			"%s: lookup=%d/%d: failure searching recursive nexthop ifindex for address %pPA(%s)",
			__func__, lookup, max_lookup, &addr, pim->vrf->name);

	return -2;
}

void pim_zlookup_show_ip_multicast(struct vty *vty)
{
	vty_out(vty, "Zclient lookup socket: ");
	if (zlookup) {
		vty_out(vty, "%d failures=%d\n", zlookup->sock, zlookup->fail);
	} else {
		vty_out(vty, "<null zclient>\n");
	}
}

int pim_zlookup_sg_statistics(struct channel_oil *c_oil)
{
	struct stream *s = zlookup->obuf;
	uint16_t command = 0;
	unsigned long long lastused;
	pim_sgaddr sg;
	int count = 0;
	int ret;
	pim_sgaddr more = {};
	struct interface *ifp =
		pim_if_find_by_vif_index(c_oil->pim, *oil_incoming_vif(c_oil));

	if (PIM_DEBUG_ZEBRA) {
		more.src = *oil_origin(c_oil);
		more.grp = *oil_mcastgrp(c_oil);
		zlog_debug("Sending Request for New Channel Oil Information%pSG VIIF %d(%s:%s)",
			   &more, *oil_incoming_vif(c_oil),
			   ifp ? ifp->name : "Unknown", c_oil->pim->vrf->name);
	}

	if (!ifp)
		return -1;

	stream_reset(s);
	zclient_create_header(s, ZEBRA_IPMR_ROUTE_STATS,
			      c_oil->pim->vrf->vrf_id);
	stream_putl(s, PIM_AF);
	stream_write(s, oil_origin(c_oil), sizeof(pim_addr));
	stream_write(s, oil_mcastgrp(c_oil), sizeof(pim_addr));
	stream_putl(s, ifp->ifindex);
	stream_putw_at(s, 0, stream_get_endp(s));

	count = stream_get_endp(s);
	ret = writen(zlookup->sock, s->data, count);
	if (ret <= 0) {
		flog_err(
			EC_LIB_SOCKET,
			"%s: writen() failure: %d writing to zclient lookup socket",
			__func__, errno);
		return -1;
	}

	s = zlookup->ibuf;

	while (command != ZEBRA_IPMR_ROUTE_STATS) {
		int err;
		uint16_t length = 0;
		vrf_id_t vrf_id;
		uint8_t marker;
		uint8_t version;

		stream_reset(s);
		err = zclient_read_header(s, zlookup->sock, &length, &marker,
					  &version, &vrf_id, &command);
		if (err < 0) {
			flog_err(EC_LIB_ZAPI_MISSMATCH,
				 "%s: zclient_read_header() failed", __func__);
			zclient_lookup_failed(zlookup);
			return -1;
		}
	}

	stream_get(&sg.src, s, sizeof(pim_addr));
	stream_get(&sg.grp, s, sizeof(pim_addr));

	more.src = *oil_origin(c_oil);
	more.grp = *oil_mcastgrp(c_oil);
	if (pim_sgaddr_cmp(sg, more)) {
		if (PIM_DEBUG_ZEBRA)
			flog_err(
				EC_LIB_ZAPI_MISSMATCH,
				"%s: Received wrong %pSG(%s) information requested",
				__func__, &more, c_oil->pim->vrf->name);
		zclient_lookup_failed(zlookup);
		return -3;
	}

	stream_get(&lastused, s, sizeof(lastused));
	/* signed success value from netlink_talk; currently unused */
	(void)stream_getl(s);

	c_oil->cc.lastused = lastused;

	return 0;
}
