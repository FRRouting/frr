// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM southbound implementation.
 *
 * Copyright (C) 2021-2026 Network Device Education Foundation, Inc. ("NetDEF")
 *                         Rafael Zalamena
 */

#include <zebra.h>

#include <sys/file.h>

#include "lib/sockopt.h"
#include "lib/lib_errors.h"
#include "lib/libfrr.h"
#include "lib/network.h"
#include "lib/zlog.h"

#include "pim_iface.h"
#include "pim_instance.h"
#include "pim_join.h"
#include "pim_neighbor.h"
#include "pim_register.h"
#include "pim_rp.h"
#include "pim_southbound_common.h"
#include "pim_ssm.h"
#include "pim_static.h"
#include "pim_time.h"
#include "pim_util.h"
#include "pim_zebra.h"

/*
 * PIM southbound.
 */
enum multicast_event_type {
	MRT_EVENT_DATA_START = 0,
	MRT_EVENT_DATA_STOP = 1,
	MRT_EVENT_WRONG_IF = 2,
	MRT_EVENT_JOIN_SPT = 3,
	MRT_EVENT_DATA_PACKET = 4,
};

/** PIM southbound message version. */
#define MRE_VERSION_V1 0x01

struct mroute_event_header {
	/** Protocol message version. */
	uint8_t version;
	/** Multicast route event. \see enum multicast_event_type. */
	uint8_t type;
	/** Message length. */
	uint16_t length;
};

struct mroute_event {
	/** Event header. */
	struct mroute_event_header header;
	/** Event flags (reserved: zero, ignored). */
	uint32_t flags;
	/** Input interface index. */
	int32_t iif_idx;
	/** Source address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} source;
	/** Group address. */
	union {
		struct in_addr v4;
		struct in6_addr v6;
	} group;
};

static pim_addr pim_addr_any = PIMADDR_ANY;

/*
 * FPM handling.
 */
/** Tell data plane that SPT switch over is allowed. */
#define MRT_FLAG_JOIN_SPT_ALLOWED 0x0001
/** Ask data plane to tell us when the data flow stops. */
#define MRT_FLAG_RESTART_DL_TIMER 0x0002
/** Flag IPv6 addresses for the data plane. */
#define MRT_FLAG_ADDR_TYPE_V6 0x0008
/** Blackhole multicast packets. */
#define MRT_FLAG_DUMMY 0x0020
/** Used with dummy to remove blackhole after a time. */
#define MRT_FLAG_DL_TIMER 0x0040

/** `ZEBRA_MROUTE_EVENT` size without the output interfaces (see `pimsb_mroute_do`). */
#define PIMSB_MROUTE_FIXED_SIZE                                                                   \
	(ZEBRA_HEADER_SIZE + 2 /* action */ + 2 /* family */ + 2 * sizeof(pim_addr) /* S,G */ +   \
	 4 /* iif */ + 4 /* notifif */ + 2 /* flags */ + 2 /* oif amount */ +                     \
	 4 /* SPT threshold */ + 2 * sizeof(pim_addr) /* local, remote */)

/**
 * Most output interfaces a route can have: zebra drops clients sending larger
 * messages (4072 for IPv6, 4084 for IPv4).
 */
#define PIMSB_MROUTE_MAX_OIFS ((ZEBRA_MAX_PACKET_SIZ - PIMSB_MROUTE_FIXED_SIZE) / sizeof(uint32_t))

/**
 * Finds the interface towards the source of `oil` (the SPT path).
 *
 * PIM already resolved it for the upstream (and keeps it current through
 * NHT), so only routes without one (e.g. static mroutes) need the
 * synchronous zebra lookup.
 */
static struct interface *pimsb_source_interface(const struct channel_oil *oil)
{
	const struct pim_upstream *upstream = oil->up;
	struct pim_nexthop pn = {};

	if (upstream && !pim_addr_cmp(upstream->upstream_addr, oil->source))
		return upstream->rpf.source_nexthop.interface;

	if (pim_nht_lookup(oil->pim, &pn, oil->source, oil->group, false))
		return pn.interface;

	return NULL;
}

/**
 * Compute the data plane input and notification interfaces of `oil`.
 *
 * The results are data plane interface indexes (or `PIM_REG_IF_IDX` / 0), not
 * PIM VIFs, so they are only returned: `oil->iif` must keep the VIF PIM chose.
 */
static void pimsb_route_interfaces(const struct rp_info *rp, const struct channel_oil *oil,
				   bool i_am_rp, ifindex_t *iif, ifindex_t *notifif)
{
	struct pim_upstream *upstream = oil->up;
	struct interface *interface;
	struct interface *source_interface;
	int32_t rp_if = 0;
	bool has_rp_if = false;
	bool star_source = false;

	/* Figure out what part of the topology we are. */
	star_source = pim_addr_is_any(oil->source);

	/* Figure out RP information. */
	if (rp && rp->rp.source_nexthop.interface) {
		has_rp_if = true;
		rp_if = rp->rp.source_nexthop.interface->ifindex;
	}

	*iif = oil->iif.index;
	*notifif = 0;

	/*
	 * Set input interface:
	 * 1. Use special index when `pimreg`.
	 * 2. `pim_southbound.interface_max` means no interface.
	 * 3. If PIM decided to use its own RP interface (the RPT) and we are
	 *    RP, then use `pimreg` (also see item (1)). A source behind the
	 *    RP address interface keeps it.
	 * 4. Otherwise use what PIM decided (an interface that is gone means
	 *    no interface, or `pimreg` for the RP).
	 */
	if (*iif == PIM_OIF_PIM_REGISTER_VIF)
		*iif = PIM_REG_IF_IDX;
	else if (*iif == pim_southbound.interface_max)
		*iif = 0;
	else {
		interface = pim_if_find_by_vif_index(oil->pim, *iif);
		if (interface)
			*iif = interface->ifindex;
		else
			*iif = (i_am_rp && upstream) ? PIM_REG_IF_IDX : 0;
	}

	/*
	 * Static mroutes (no upstream) forward from their configured input
	 * interface: no register or SPT handling.
	 */
	if (!upstream)
		return;

	/*
	 * Handle simple case first (non-RP)
	 */
	if (!i_am_rp) {
		/*
		 * Notification interface must be used when we want to know
		 * that we are receiving multicast data on the specified
		 * interface.
		 *
		 * SG(*,G) does not need to watch for multicast data.
		 */
		if (!star_source && has_rp_if && (*iif == 0 || rp_if == *iif)) {
			/* Figure out the SPT path. */
			source_interface = pimsb_source_interface(oil);
			if (source_interface && *iif != source_interface->ifindex)
				*notifif = source_interface->ifindex;
			else
				*notifif = 0;

		} else
			*notifif = 0;

		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: SG(%pPA, %pPA) IAmNotRP RPIF:%d iif:%d notifif:%d",
				   __func__, &oil->source, &oil->group, rp_if, *iif, *notifif);
		return;
	}

	/*
	 * Handle the RP case
	 */
	if (star_source)
		*iif = PIM_REG_IF_IDX;
	else if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(upstream->flags) && has_rp_if && rp_if == *iif)
		*iif = PIM_REG_IF_IDX;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: SG(%pPA, %pPA) IAmRP iif:%d RPIF:%d", __func__, &oil->source,
			   &oil->group, *iif, rp_if);

	/*
	 * If no traffic has been seen yet, then set notification
	 * interface instead of input interface.
	 */
	if (!CHECK_FLAG(upstream->flags, PIM_UPSTREAM_FLAG_MASK_DATA_START) &&
	    *iif != PIM_REG_IF_IDX) {
		*notifif = *iif;
		*iif = 0;
		return;
	}

	/*
	 * Figure out the SPT path.
	 *
	 * SG(*,G) has no source to look up: on IPv6 the lookup of `::` may
	 * succeed through the (empty) cache without an interface.
	 */
	source_interface = star_source ? NULL : pimsb_source_interface(oil);
	*notifif = source_interface ? source_interface->ifindex : 0;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s:   notifif:%d iif:%d", __func__, *notifif, *iif);
}

static void pimsb_debug_oil(struct channel_oil *oil)
{
	struct channel_oif *oif;
	struct interface *ifp;
	char line[128];
	char buf[BUFSIZ];

	zlog_debug("OIL[installed:%d rescan:%d size:%zu refcount:%d]", oil->installed,
		   oil->oil_inherited_rescan, channel_oif_list_count(&oil->oif_list),
		   oil->oil_ref_count);
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		ifp = pim_if_find_by_vif_index(oil->pim, oif->index);
		if (!ifp)
			snprintfrr(buf, sizeof(buf), "  IF[index:%d flags:", oif->index);
		else
			snprintfrr(buf, sizeof(buf), "  IF[index:%d name:%s flags:", oif->index,
				   ifp->name);

		if (CHECK_FLAG(oif->flags, PIM_OIF_FLAG_PROTO_GM))
			strlcat(buf, " GM", sizeof(buf));
		if (CHECK_FLAG(oif->flags, PIM_OIF_FLAG_PROTO_PIM))
			strlcat(buf, " PIM", sizeof(buf));
		if (CHECK_FLAG(oif->flags, PIM_OIF_FLAG_PROTO_STAR))
			strlcat(buf, " STAR", sizeof(buf));
		if (CHECK_FLAG(oif->flags, PIM_OIF_FLAG_PROTO_VXLAN))
			strlcat(buf, " VXLAN", sizeof(buf));
		strlcat(buf, "]", sizeof(buf));
		zlog_debug("%s", buf);
	}

	snprintfrr(buf, sizeof(buf), "  MFC(%pPA,%pPA)[iif:%d,", &oil->source, &oil->group,
		   oil->iif.index);
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		ifp = pim_if_find_by_vif_index(oil->pim, oif->index);
		if (!ifp)
			snprintfrr(line, sizeof(line), "X(%d:X),", oif->index);
		else
			snprintfrr(line, sizeof(line), "%s(%d,%d),", ifp->name, oif->index,
				   ifp->ifindex);

		strlcat(buf, line, sizeof(buf));
	}
	zlog_debug("%s]", buf);
}

static void pimsb_debug_upstream(const struct pim_upstream *up)
{
	struct pim_ifchannel *ch;
	struct listnode *node;
	char buf[BUFSIZ];

	snprintfrr(buf, sizeof(buf), "UP[up:%pPA register:%pPA sg:%s join:%d reg:%d spt:%d flags:",
		   &up->upstream_addr, &up->upstream_register, up->sg_str, up->join_state,
		   up->reg_state, up->sptbit);

#define PRINT_FLAG(flags, flag, str)                                                              \
	do {                                                                                      \
		if (CHECK_FLAG((flags), (flag)))                                                  \
			strlcat(buf, str ",", sizeof(buf));                                       \
	} while (0)
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED, "DR_JOIN_DESIRED");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_DR_JOIN_DESIRED_UPDATED,
		   "DR_JOIN_DESIRED_UPDATED");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_FHR, "FHR");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_IGMP, "SRC_IGMP");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_PIM, "SRC_PIM");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_STREAM, "SRC_STREAM");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_MSDP, "SRC_MSDP");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SEND_SG_RPT_PRUNE, "SEND_SG_RPT_PRUNE");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_LHR, "SRC_LHR");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_STATIC_IIF, "STATIC_IIF");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_ALLOW_IIF_IN_OIL, "ALLOW_IIF_IN_OIL");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_NO_PIMREG_DATA, "NO_PIMREG_DATA");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_FORCE_PIMREG, "FORCE_PIMREG");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_ORIG, "SRC_VXLAN_ORIG");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_VXLAN_TERM, "SRC_VXLAN_TERM");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_VXLAN, "MLAG_VXLAN");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_NON_DF, "MLAG_NON_DF");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_PEER, "MLAG_PEER");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, "SRC_NOCACHE");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_USE_RPT, "USE_RPT");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_MLAG_INTERFACE, "MLAG_INTERFACE");
	PRINT_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_DATA_START, "DATA_START");
	zlog_debug("%s]", buf);
	zlog_debug("  RPF[if:%s nh:%pPA rpf_addr:%pPA]",
		   up->rpf.source_nexthop.interface != NULL ? up->rpf.source_nexthop.interface->name
							    : "unknown",
		   &up->rpf.source_nexthop.mrib_nexthop_addr, &up->rpf.rpf_addr);

	for (ALL_LIST_ELEMENTS_RO(up->ifchannels, node, ch)) {
		buf[0] = 0;
		PRINT_FLAG(ch->flags, PIM_IF_FLAG_MASK_COULD_ASSERT, "COULD_ASSERT");
		PRINT_FLAG(ch->flags, PIM_IF_FLAG_MASK_ASSERT_TRACKING_DESIRED,
			   "ASSERT_TRACKING_DESIRED");
		PRINT_FLAG(ch->flags, PIM_IF_FLAG_MASK_PROTO_PIM, "PROTO_PIM");
		PRINT_FLAG(ch->flags, PIM_IF_FLAG_MASK_PROTO_IGMP, "PROTO_IGMP");
		zlog_debug("  SOURCE[sg:%s if:%s join:%d assert:%d winner:%pPA flags:%s]",
			   ch->sg_str, ch->interface ? ch->interface->name : "unknown",
			   ch->ifjoin_state, ch->ifassert_state, &ch->ifassert_winner, buf);
	}
#undef PRINT_FLAG

	if (PIM_UPSTREAM_FLAG_TEST_USE_RPT(up->flags)) {
		if (up->parent)
			pimsb_debug_upstream(up->parent);
		else
			zlog_debug("%s:  no upstream parent, but USE_RPT set", __func__);
	}
}

static void pimsb_debug_route_flags(uint16_t flags)
{
	char buf[128] = {};

	if (CHECK_FLAG(flags, MRT_FLAG_JOIN_SPT_ALLOWED))
		strlcat(buf, "JOIN_SPT_ALLOWED ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_RESTART_DL_TIMER))
		strlcat(buf, "RESTART_DL_TIMER ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_ADDR_TYPE_V6))
		strlcat(buf, "ADDR_TYPE_V6 ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_DUMMY))
		strlcat(buf, "DUMMY ", sizeof(buf));
	if (CHECK_FLAG(flags, MRT_FLAG_DL_TIMER))
		strlcat(buf, "DL_TIMER ", sizeof(buf));

	zlog_debug("route_flags: %s", buf);
}

/**
 * Tells whether the data plane must forward to `oif`: the same filtering
 * `channel_oil_to_mfcc` does for the kernel (no muted or assert losing
 * interfaces, and no input interface unless allowed).
 */
static bool pimsb_oif_forwards(struct channel_oil *oil, const struct channel_oif *oif)
{
	if (oif->index == oil->iif.index && !pim_mroute_allow_iif_in_oil(oil, oif->index))
		return false;

	return !channel_oif_no_forward(oif);
}

/** \returns `false` if the route could not be sent. */
static bool pimsb_mroute_do(struct channel_oil *oil, bool install)
{
	struct pim_upstream *upstream = oil->up;
	struct channel_oif *oif;
	struct interface *ifp;
	struct rp_info *rp;
	struct stream *s;
	ifindex_t iif;
	ifindex_t notifif;
	size_t oif_count;
	bool i_am_rp = false;
	bool i_am_fhr = false;
	bool i_am_lhr = false;
	bool i_am_mhr = false;
	bool registers = false;
	bool is_static = false;
	bool star_source = false;
	bool traffic_owned = false;
	uint16_t route_flags = 0;
	pim_addr source_encap = PIMADDR_ANY;
	struct prefix p = {};
	char intf[128];
	char oifs[BUFSIZ];

	if (PIM_DEBUG_MROUTE) {
		pimsb_debug_oil(oil);
		if (upstream)
			pimsb_debug_upstream(upstream);
	}

	/* Static mroutes (no upstream) and IGMP joined routes are static. */
	if (upstream == NULL || CHECK_FLAG(upstream->flags, PIM_UPSTREAM_FLAG_MASK_SRC_IGMP))
		is_static = true;

	/* Figure out what part of the topology we are. */
	star_source = pim_addr_is_any(oil->source);
	/* Like the kernel path, SSM ignores the RP. */
	i_am_rp = !pim_is_grp_ssm(oil->pim, oil->group) && pim_rp_i_am_rp(oil->pim, oil->group);
	if (upstream) {
		i_am_lhr = PIM_UPSTREAM_FLAG_TEST_SRC_LHR(upstream->flags);
		i_am_fhr = PIM_UPSTREAM_FLAG_TEST_FHR(upstream->flags);
		/* State that only exists while the traffic flows. */
		traffic_owned = pim_upstream_data_started(upstream) ||
				PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(upstream->flags) ||
				PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(upstream->flags);
	}

	i_am_mhr = !i_am_lhr && !i_am_rp && !i_am_fhr;

	/* Figure out RP information. */
	pim_addr_to_prefix(&p, oil->group);
	rp = pim_rp_find_match_group(oil->pim, &p);
	registers = pim_rp_sb_registers(rp, oil);

	/* Data plane input and notification interfaces. */
	pimsb_route_interfaces(rp, oil, i_am_rp, &iif, &notifif);

	/* Output interfaces the data plane forwards to. */
	oif_count = 0;
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		if (pimsb_oif_forwards(oil, oif))
			oif_count++;
	}

	if (oif_count > PIMSB_MROUTE_MAX_OIFS) {
		flog_err(EC_LIB_ZAPI_ENCODE,
			 "%s: SG(%pPAs, %pPAs) has %zu output interfaces (maximum %zu)%s",
			 __func__, &oil->source, &oil->group, oif_count, PIMSB_MROUTE_MAX_OIFS,
			 install ? ", not installed" : "");
		/* Like a failed kernel install: the previous route stays. */
		if (install)
			return false;

		/* Deletes don't need the output interfaces: don't leave it behind. */
		oif_count = 0;
	}

	/*
	 * Generate flags based on detected information.
	 *
	 * Ask to be told when the traffic stops for the FHR/LHR/RP routes and
	 * for the ones the traffic created (static ones too, e.g. an IGMP
	 * joined FHR route): DATA_STOP releases their references (see
	 * `pimsb_upstream_data_stop`).
	 */
	if (!star_source && (traffic_owned || (!is_static && !i_am_mhr)))
		route_flags |= MRT_FLAG_RESTART_DL_TIMER;

	/*
	 * SPT only matters for LHR (the router which receives the IGMP join),
	 * however since we don't know about LHR status in star route until
	 * it is too late we'll check for not FHR and not RP.
	 *
	 * Intermediary routers do not create star route so it shouldn't be
	 * a problem.
	 *
	 * The `spt-switchover` configuration is applied (like for the kernel)
	 * by adding `pimreg` to the LHR SG(*,G) OIL when switching is allowed.
	 * Its flags are only set after the route is installed, so don't look
	 * at them: nothing else adds `pimreg` to a non RP SG(*,G).
	 */
	if (!i_am_fhr && !i_am_rp && star_source &&
	    channel_oil_oif_find(oil, PIM_OIF_PIM_REGISTER_VIF))
		route_flags |= MRT_FLAG_JOIN_SPT_ALLOWED;
	if (!is_static && oif_count == 0)
		route_flags |= MRT_FLAG_DUMMY | MRT_FLAG_DL_TIMER;

	/*
	 * Handle special case: RP and FHR.
	 *
	 * If there is a upstream to send traffic but it has not yet joined
	 * the stream then don't attempt to send any traffic. Keep asking for
	 * DATA_STOP: no registers refresh the keepalive timer of our own
	 * sources, so only DATA_STOP releases their references (see
	 * `pimsb_upstream_data_stop`).
	 */
	if (i_am_rp && i_am_fhr) {
		route_flags &= ~MRT_FLAG_DUMMY;
		route_flags |= MRT_FLAG_DL_TIMER;
	}

	/*
	 * Disable data plane notification to remove dummy route if no
	 * input interface is configured.
	 */
	if (iif == 0)
		route_flags &= ~MRT_FLAG_DL_TIMER;

#if PIM_IPV == 6
	/* Flag all multicast routes coming from us to be IPv6. */
	route_flags |= MRT_FLAG_ADDR_TYPE_V6;
#endif /* PIM_IPV == 6 */

	if (PIM_DEBUG_MROUTE)
		pimsb_debug_route_flags(route_flags);

	/*
	 * Multicast route internal communication format:
	 *  - 2 bytes: Action (0: install, 1: delete).
	 *  - 2 bytes: address family.
	 *  - X bytes: IP(v4|v6) source address.
	 *  - X bytes: IP(v4|v6) group address.
	 *  - 4 bytes: input interface.
	 *  - 4 bytes: notification interface.
	 *  - 2 bytes: flags (MRT_FLAG_*).
	 *  - 2 bytes: output interface amount.
	 *  - 4 * X bytes: output interface array.
	 *  - 4 bytes: SPT threshould.
	 *  - X bytes: IP(v4|v6) local address.
	 *  - X bytes: IP(v4|v6) remote address.
	 */
	s = pim_zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, ZEBRA_MROUTE_EVENT, oil->pim->vrf->vrf_id);
	stream_putw(s, install ? 0 : 1);
	stream_putw(s, PIM_AF);
	stream_put(s, &oil->source, sizeof(pim_addr));
	stream_put(s, &oil->group, sizeof(pim_addr));

	/* Input interface. */
	stream_putl(s, iif);
	/* Notification interface. */
	stream_putl(s, notifif);

	/* Multicast route flags. */
	stream_putw(s, route_flags);

	/* Output interface amount. */
	stream_putw(s, oif_count);

	/* Output interfaces. */
	frr_each (channel_oif_list, &oil->oif_list, oif) {
		if (oif_count == 0)
			break;
		if (!pimsb_oif_forwards(oil, oif))
			continue;

		/* The data plane knows `pimreg` by its special index. */
		if (oif->index == PIM_OIF_PIM_REGISTER_VIF)
			stream_putl(s, PIM_REG_IF_IDX);
		else
			stream_putl(s, oif->index);
	}

	/* SPT threshold (unused: `spt-switchover` is applied with `pimreg`). */
	stream_putl(s, 0);

	/* Interface address in the way to the RP. */
	if (registers) {
		source_encap = pim_rp_sb_register_source(rp);
#if PIM_IPV == 6
		if (pim_addr_is_any(source_encap) && PIM_DEBUG_MROUTE)
			zlog_debug("%s: SG(%pPAs, %pPAs) interface %s towards the RP has no global address to register from",
				   __func__, &oil->source, &oil->group,
				   rp->rp.source_nexthop.interface->name);
#endif /* PIM_IPV == 6 */
	}
	stream_put(s, &source_encap, sizeof(pim_addr));

	/* Remote RP address. */
	stream_put(s, registers ? &rp->rp.rpf_addr : &pim_addr_any, sizeof(pim_addr));

	/* `pim_rp_sb_register_update` compares them to the current ones. */
	if (upstream) {
		upstream->sb_register_to = registers ? rp->rp.rpf_addr : pim_addr_any;
		upstream->sb_register_from = source_encap;
	}

	stream_putw_at(s, 0, (uint16_t)stream_get_endp(s));

	/*
	 * `installed` (below) tracks what the data plane must have, not what
	 * zebra acknowledged: we replay the installed ones once connected
	 * again (`pim_zebra_connected`). Zebra keeps no multicast route state,
	 * so deletes sent while it is unreachable are lost.
	 */
	if (zclient_send_message(pim_zclient) == ZCLIENT_SEND_FAILURE && PIM_DEBUG_MROUTE)
		zlog_debug("%s: zebra unreachable, SG(%pPAs, %pPAs) %s waits for reconnection",
			   __func__, &oil->source, &oil->group, install ? "install" : "delete");

	if (PIM_DEBUG_MROUTE) {
		oifs[0] = 0;
		frr_each (channel_oif_list, &oil->oif_list, oif) {
			if (oif_count == 0)
				break;
			if (!pimsb_oif_forwards(oil, oif))
				continue;

			if (oif->index == PIM_OIF_PIM_REGISTER_VIF) {
				snprintfrr(intf, sizeof(intf), PIMREG "(%d),", PIM_REG_IF_IDX);
				strlcat(oifs, intf, sizeof(oifs));
				continue;
			}

			ifp = if_lookup_by_index(oif->index, oil->pim->vrf->vrf_id);
			snprintfrr(intf, sizeof(intf), "%s(%d),", ifp ? ifp->name : "?",
				   oif->index);
			strlcat(oifs, intf, sizeof(oifs));
		}
		if (oifs[0])
			oifs[strlen(oifs) - 1] = 0;

		zlog_debug("%s: %s SG(%pPAs, %pPAs) iif:%d notifif:%d flags:0x%04x OIFS_AMOUNT:%zu OIF:[%s] encap:(local:%pPAs, rp:%pPAs) rp:%s fhr:%s lhr:%s",
			   __func__, install ? "INSTALL" : "DELETE", &oil->source, &oil->group,
			   iif, notifif, route_flags, oif_count, oifs,
			   registers ? &source_encap : &pim_addr_any,
			   registers ? &rp->rp.rpf_addr : &pim_addr_any, i_am_rp ? "yes" : "no",
			   i_am_fhr ? "yes" : "no", i_am_lhr ? "yes" : "no");
	}

	/* Update route installation status.  */
	if (install) {
		if (!oil->installed)
			oil->mroute_creation = pim_time_monotonic_sec();

		oil->installed = 1;
	} else
		oil->installed = 0;

	return true;
}

static int pimsb_mroute_add(struct channel_oil *c_oil, const char *name)
{
	c_oil->pim->mroute_add_last = pim_time_monotonic_sec();
	c_oil->pim->mroute_add_events++;

	if (!pimsb_mroute_do(c_oil, true))
		return -1;

	if (PIM_DEBUG_MROUTE) {
		char buf[BUFSIZ];

		zlog_debug("%s(%s), vrf %s Added Route: %s", __func__, name, c_oil->pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buf, sizeof(buf)));
	}

	return 0;
}

static int pimsb_mroute_del(struct channel_oil *c_oil, const char *name)
{
	c_oil->pim->mroute_del_last = pim_time_monotonic_sec();
	c_oil->pim->mroute_del_events++;

	if (!c_oil->installed) {
		if (PIM_DEBUG_MROUTE) {
			char buffer[BUFSIZ];

			zlog_debug("%s %s: vifi %d for route is %s not installed, do not need to send del req. ",
				   __FILE__, __func__, c_oil->iif.index,
				   pim_channel_oil_dump(c_oil, buffer, sizeof(buffer)));
		}
		return -2;
	}

	pimsb_mroute_do(c_oil, false);

	if (PIM_DEBUG_MROUTE) {
		char buffer[BUFSIZ];

		zlog_debug("%s(%s), vrf %s Deleted Route: %s", __func__, name,
			   c_oil->pim->vrf->name,
			   pim_channel_oil_dump(c_oil, buffer, sizeof(buffer)));
	}

	return 0;
}

/*
 * Southbound callbacks
 */

/**
 * VRF each interface index was last multicast enabled in (`VRF_UNKNOWN` if
 * never): the data plane may still report the flows of an interface that is
 * gone, which only this tells apart when VRFs use overlapping addresses.
 */
static vrf_id_t pimsb_interface_vrf[PIMSB_MAX_MULTICAST_IFS];

static int pimsb_interface_enable(struct interface *ifp, pim_addr ifaddr, unsigned char flags)
{
	struct pim_interface *pim_ifp = ifp->info;

	/*
	 * In southbound we do 1:1 mapping interface index and
	 * multicast interface index. Indexes from `interface_max` on mean "no
	 * interface" and the data plane encapsulation doesn't carry more than
	 * that (16 bits for IPv4, 20 bits flow label for IPv6).
	 */
	if (ifp->ifindex < 0 || ifp->ifindex >= pim_southbound.interface_max) {
		flog_err(EC_LIB_INTERFACE,
			 "%s: interface %s index %d is out of the southbound range (0-%d)",
			 __func__, ifp->name, ifp->ifindex, pim_southbound.interface_max - 1);
		/*
		 * Don't keep the index PIM picked: it is another interface's in
		 * the data plane. PIM expects a non negative one (output
		 * interfaces assert it), so use "no interface": routes refuse
		 * it as output interface and don't install with it as input.
		 */
		pim_ifp->mroute_vif_index = pim_southbound.interface_max;
		return -1;
	}

	pim_ifp->mroute_vif_index = ifp->ifindex;
	pimsb_interface_vrf[ifp->ifindex] = ifp->vrf->vrf_id;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Add Vif %d (%s[%s])", __func__, pim_ifp->mroute_vif_index,
			   ifp->name, pim_ifp->pim->vrf->name);

	return 0;
}

static void pimsb_interface_disable(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: Del Vif %d (%s[%s])", __func__, pim_ifp->mroute_vif_index,
			   ifp->name, pim_ifp->pim->vrf->name);
}

void pimsb_configure(void)
{
	size_t index;

	for (index = 0; index < array_size(pimsb_interface_vrf); index++)
		pimsb_interface_vrf[index] = VRF_UNKNOWN;

	pim_southbound = (struct pim_sb_cbs){
		.interface_max = PIMSB_MAX_MULTICAST_IFS,
		.fpm_sync = true,
		.own_sockets = true,
		.pim_fd = -1,
		.no_register_on_rp = true,
		.mroute_enable = pimsb_mroute_socket_enable,
		.mroute_disable = pimsb_mroute_socket_disable,
		.mroute_install = pimsb_mroute_add,
		.mroute_uninstall = pimsb_mroute_del,
		.interface_enable = pimsb_interface_enable,
		.interface_disable = pimsb_interface_disable,
		.interface_join = pimsb_interface_join,
		.interface_leave = pimsb_interface_leave,
		.send = pimsb_send,
	};
}

/*
 * Southbound connection handling
 */

/** Data plane message buffer size (the maximum message length). */
#define PIMSB_MSGBUF_SIZE 8192

/** PIM southbound data plane connection (both modes). */
struct pimsb_client {
	/** Peer socket. */
	int sock;
	/** Input events. */
	struct event *in_ev;
	/** Output events. */
	struct event *out_ev;
	/** Connection start event. */
	struct event *connstart_ev;

	/** Peer message buffer. */
	char msgbuf[PIMSB_MSGBUF_SIZE];
	/** Bytes available. */
	size_t msgbuf_available;

	/** Whether the data plane connection got established. */
	bool connected;
};

/** PIM southbound server information for server mode. */
struct pimsb_server {
	/** Listening socket for server mode. */
	int listening_socket;
	/** Listening event. */
	struct event *listening_ev;
	/** Unix socket path lock file (or -1). */
	int lock_fd;
	/** Reuse PIM client context for server. */
	struct pimsb_client client;
};

/** PIM southbound context information. */
struct pimsb_ctx {
	/*
	 * PIM southbound can operate in two ways:
	 *  - Client mode (connects to a server)
	 *  - Server mode (accepts only one connection a time)
	 */
	union {
		struct pimsb_client client;
		struct pimsb_server server;
	};
	/** Client/server indicator. */
	bool is_server;
	/** Listening/connect address. */
	struct sockaddr_storage ss;
	/** Address length. */
	socklen_t sslen;
};

static struct pimsb_ctx pimsb_ctx;

static void pimsb_client_start_connection_cb(struct event *event);

static void pimsb_client_stop(struct pimsb_client *client)
{
	if (client->sock != -1) {
		close(client->sock);
		client->sock = -1;
	}

	client->msgbuf_available = 0;
	client->connected = false;
	event_cancel(&client->in_ev);
	event_cancel(&client->out_ev);
	event_cancel(&client->connstart_ev);
}

static void pimsb_upstream_data_stop(struct pim_upstream *up);

/**
 * Upstreams holding references the keepalive timer expiry releases, which
 * DATA_STOP stands in for (the data plane has no per route counters).
 *
 * Not every such reference comes with DATA_START: WRONG_IF may take a
 * SRC_NOCACHE one and JOIN_SPT (or a (S,G) join below a SG(*,G)) a SRC_LHR
 * one. SRC_STREAM is left out: the data plane events always set DATA_START
 * with it, while registers received by the RP also set it.
 */
#define PIMSB_TRAFFIC_FLAGS                                                                       \
	(PIM_UPSTREAM_FLAG_MASK_DATA_START | PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE |                 \
	 PIM_UPSTREAM_FLAG_MASK_SRC_LHR)

/**
 * The data plane connection is gone and with it the knowledge of which
 * flows are active: release the references their traffic took. Flows still
 * active get reported again once the data plane is back.
 */
static void pimsb_data_plane_lost(void)
{
	struct pim_upstream *up;
	struct pim_instance *pim;
	struct vrf *vrf;
	pim_sgaddr *sgs;
	size_t count, index;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		pim = vrf->info;
		if (pim == NULL)
			continue;

		count = rb_pim_upstream_count(&pim->upstream_head);
		if (count == 0)
			continue;

		/*
		 * Releasing references may delete other upstreams than the
		 * current one (e.g. a SG(*,G) deletes its SRC_LHR children),
		 * so don't walk the tree while releasing them.
		 */
		sgs = XCALLOC(MTYPE_TMP, count * sizeof(*sgs));
		count = 0;
		frr_each (rb_pim_upstream, &pim->upstream_head, up) {
			if (CHECK_FLAG(up->flags, PIMSB_TRAFFIC_FLAGS))
				sgs[count++] = up->sg;
		}

		for (index = 0; index < count; index++) {
			up = pim_upstream_find(pim, &sgs[index]);
			if (up && CHECK_FLAG(up->flags, PIMSB_TRAFFIC_FLAGS))
				pimsb_upstream_data_stop(up);
		}

		XFREE(MTYPE_TMP, sgs);
	}
}

/** Data plane silence (in seconds) before the first keepalive probe. */
#define PIMSB_KEEPALIVE_IDLE 10
/** Seconds between keepalive probes. */
#define PIMSB_KEEPALIVE_INTERVAL 5
/** Unanswered keepalive probes before the connection is closed. */
#define PIMSB_KEEPALIVE_PROBES 3

/**
 * Enables connection keepalive to detect data planes that went away silently:
 * we never write to this connection, so without it a dead data plane would
 * only be noticed once the system defaults expire (hours).
 */
static void pimsb_client_keepalive(int sock)
{
	if (pimsb_ctx.ss.ss_family == AF_UNIX)
		return;

	/* Errors are logged by the function. */
	setsockopt_tcp_keepalive(sock, PIMSB_KEEPALIVE_IDLE, PIMSB_KEEPALIVE_INTERVAL,
				 PIMSB_KEEPALIVE_PROBES);
}

static void pimsb_client_restart(struct pimsb_client *client)
{
	bool was_connected = client->connected;

	pimsb_client_stop(client);

	/* Failed connection attempts (e.g. data plane not up yet) had no flows. */
	if (was_connected) {
		zlog_info("PIM southbound: data plane connection lost");
		pimsb_data_plane_lost();
	}

	/* If server then wait for the next accepted connection. */
	if (pimsb_ctx.is_server)
		return;

	/* If client then try to connect again. */
	event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
			&client->connstart_ev);
}

/** LHR got SPT data: set the SPT bit and prune the source off the RPT. */
static void pimsb_lhr_spt_data(struct pim_interface *pim_ifp, struct pim_upstream *up,
			       struct interface *ifp)
{
	struct pim_neighbor *nbr;

	pim_upstream_set_sptbit(up, ifp);
	pim_upstream_update_use_rpt(up, true);
	pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

	/*
	 * Generate the prune message immediately for SG(*,G)
	 * so we only receive traffic from SG(S,G).
	 */
	if (up->parent && up->parent->rpf.source_nexthop.interface) {
		nbr = pim_neighbor_find(up->parent->rpf.source_nexthop.interface,
					up->parent->rpf.rpf_addr, true);
		if (nbr) {
			struct pim_rpf rpf = {};

			rpf.source_nexthop.interface = nbr->interface;
			rpf.rpf_addr = nbr->source_addr;
			pim_joinprune_send(&rpf, nbr->upstream_jp_agg);
		}
	}
}

/**
 * Decodes the event (S,G): events report traffic, so the source must be a
 * unicast address and the group a multicast one routers forward (IPv6
 * routers don't forward link-local sources either, RFC 4291 Section 2.5.6).
 *
 * The data plane controls these values, so failures are only logged with
 * debugs enabled (a misbehaving data plane must not flood the logs).
 *
 * \returns `true` if the (S,G) is valid.
 */
static bool pimsb_event_sg(const struct mroute_event *me, const char *event, pim_sgaddr *sg)
{
	bool link_local;

	*sg = (pim_sgaddr){
#if PIM_IPV == 4
		.src = me->source.v4,
		.grp = me->group.v4,
#else
		.src = me->source.v6,
		.grp = me->group.v6,
#endif
	};

#if PIM_IPV == 4
	link_local = pim_is_group_224_0_0_0_24(sg->grp);
#else
	link_local = IN6_IS_ADDR_MC_NODELOCAL(&sg->grp) || IN6_IS_ADDR_MC_LINKLOCAL(&sg->grp) ||
		     IN6_IS_ADDR_LINKLOCAL(&sg->src);
#endif /* PIM_IPV == 4 */

	if (pim_addr_is_any(sg->src) || pim_addr_is_multicast(sg->src) ||
	    !pim_addr_is_multicast(sg->grp) || link_local) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: %s invalid %pSG", __func__, event, sg);
		return false;
	}

	return true;
}

/**
 * Finds the interface the event refers to.
 *
 * The interface index namespace is global (the event carries no VRF), so
 * with the network namespace VRF backend the first match is used.
 *
 * \returns the interface (multicast enabled or not) or `NULL`.
 */
static struct interface *pimsb_event_interface_lookup(const struct mroute_event *me)
{
	const ifindex_t ifindex = (ifindex_t)ntohl((uint32_t)me->iif_idx);
	struct interface *ifp;
	struct vrf *vrf;

	RB_FOREACH (vrf, vrf_id_head, &vrfs_by_id) {
		ifp = if_lookup_by_index(ifindex, vrf->vrf_id);
		if (ifp)
			return ifp;
	}

	return NULL;
}

/**
 * Finds the multicast enabled interface the event refers to (see
 * `pimsb_event_interface_lookup`).
 *
 * \returns the multicast enabled interface or `NULL`.
 */
static struct interface *pimsb_event_interface(const struct mroute_event *me, const char *event,
					       const pim_sgaddr *sg)
{
	const ifindex_t ifindex = (ifindex_t)ntohl((uint32_t)me->iif_idx);
	struct pim_interface *pim_ifp;
	struct interface *ifp;

	ifp = pimsb_event_interface_lookup(me);
	if (!ifp) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: %s %pSG interface %d not found", __func__, event, sg,
				   ifindex);
		return NULL;
	}

	/* Interfaces out of the southbound range get `interface_max`. */
	pim_ifp = ifp->info;
	if (!pim_ifp || pim_ifp->mroute_vif_index < 0 ||
	    pim_ifp->mroute_vif_index >= pim_southbound.interface_max) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: %s %pSG interface %s(%d) disabled", __func__, event, sg,
				   ifp->name, ifp->ifindex);
		return NULL;
	}

	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: %s %pSG interface %s(%d)", __func__, event, sg, ifp->name,
			   ifp->ifindex);

	return ifp;
}

/** Finds the SG(*,G) of the event (S,G). */
static struct pim_upstream *pimsb_star_g_find(struct pim_instance *pim, const pim_sgaddr *sg)
{
	pim_sgaddr star_g = {
		.src = PIMADDR_ANY,
		.grp = sg->grp,
	};

	return pim_upstream_find(pim, &star_g);
}

/**
 * The same checks `pim_mroute_msg_nocache` does before acting on new
 * traffic.
 *
 * \returns `true` if the traffic should be handled.
 */
static bool pimsb_data_start_allowed(struct interface *ifp, pim_sgaddr *sg)
{
	struct pim_interface *pim_ifp = ifp->info;
	struct pim_rpf *rpg;

	if (!pim_ifp->pim_enable) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: PIM not enabled on %s, ignoring %pSG", __func__, ifp->name,
				   sg);
		return false;
	}

	/* "ip mroute OIF GROUP [SOURCE]" overrides PIM handling. */
	if (pim_static_nocache_resolve(pim_ifp->pim, ifp, sg) != 1)
		return false;

	/* SSM is join driven. */
	if (pim_is_grp_ssm(pim_ifp->pim, sg->grp))
		return true;

	/* Not an SSM group and configured for SSM only. */
	if (pim_ifp->pim_mode == PIM_MODE_SSM)
		return false;

#if PIM_IPV == 6
	pim_addr embedded_rp;

	if (pim_ifp->pim->embedded_rp.enable && pim_embedded_rp_extract(&sg->grp, &embedded_rp) &&
	    !pim_embedded_rp_filter_match(pim_ifp->pim, &sg->grp))
		pim_embedded_rp_new(pim_ifp->pim, &sg->grp, &embedded_rp);
#endif /* PIM_IPV == 6 */

	/* ASM needs a path to the RP (the southbound doesn't do dense mode flooding). */
	rpg = HAVE_SPARSE_MODE(pim_ifp->pim_mode) ? RP(pim_ifp->pim, sg->grp) : NULL;
	if (rpg == NULL || pim_rpf_addr_is_inaddr_any(rpg)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: no RP for %pSG on %s%s", __func__, sg, ifp->name,
				   HAVE_DENSE_MODE(pim_ifp->pim_mode)
					   ? " (dense mode is not supported by the southbound)"
					   : "");
		return false;
	}

	return true;
}

static void pimsb_client_data_start(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp;
	pim_sgaddr sg_p;

	if (!pimsb_event_sg(me, "DATA_START", &sg_p))
		return;

	ifp = pimsb_event_interface(me, "DATA_START", &sg_p);
	if (!ifp)
		return;

	pim_ifp = ifp->info;
	if (!pimsb_data_start_allowed(ifp, &sg_p))
		return;

	/* Handle simplest case first. */
	if (pim_if_connected_to_source(ifp, sg_p.src)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: source connected (%s, %pPA)", __func__, ifp->name,
				   &sg_p.src);

		if (!(PIM_I_am_DR(pim_ifp))) {
			if (PIM_DEBUG_MROUTE_DETAIL)
				zlog_debug("%s: '%s' is not the DR for %pSG", __func__, ifp->name,
					   &sg_p);

			/*
			 * Hold a SRC_NOCACHE reference (the upstream scan adds a
			 * SRC_STREAM one while the traffic flows, like the kernel
			 * path): DATA_STOP (or the keepalive timer expiry)
			 * releases them.
			 */
			up = pim_upstream_find(pim_ifp->pim, &sg_p);
			if (!up || !PIM_UPSTREAM_FLAG_TEST_SRC_NOCACHE(up->flags))
				up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp,
						      PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE, __func__,
						      NULL);
			pim_upstream_data_start(up);
			pim_upstream_mroute_add(up->channel_oil, __func__);
			return;
		}

		/*
		 * Hold a single SRC_STREAM reference (FHR shares it), released
		 * by DATA_STOP.
		 */
		up = pim_upstream_find(pim_ifp->pim, &sg_p);
		if (!up)
			up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_FHR,
					      __func__, NULL);
		else if (!PIM_UPSTREAM_FLAG_TEST_SRC_STREAM(up->flags))
			pim_upstream_ref(up, PIM_UPSTREAM_FLAG_MASK_FHR, __func__);

		PIM_UPSTREAM_FLAG_SET_FHR(up->flags);
		PIM_UPSTREAM_FLAG_SET_SRC_STREAM(up->flags);
		pim_upstream_data_start(up);
		pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

		up->channel_oil->cc.pktcnt++;
		if (up->rpf.source_nexthop.interface != NULL &&
		    up->channel_oil->iif.index >= pim_southbound.interface_max)
			pim_upstream_mroute_iif_update(up->channel_oil, __func__);

		/*
		 * Repeated DATA_STARTs must not undo a register-stop (the
		 * register state is reset when the traffic stops).
		 */
		if (up->reg_state == PIM_REG_NOINFO &&
		    !pim_is_group_filtered(pim_ifp, &sg_p.grp, &sg_p.src))
			pim_register_join(up);
		pim_upstream_inherited_olist_decide(pim_ifp->pim, up);
		pim_upstream_update_join_desired(pim_ifp->pim, up);
		pim_upstream_mroute_add(up->channel_oil, __func__);
		return;
	}

	/* Figure out what case this is by looking at upstream. */
	up = pim_upstream_find(pim_ifp->pim, &sg_p);
	if (PIM_DEBUG_MROUTE)
		zlog_debug("%s: unconnected source (%s, %pPA) %s", __func__, ifp->name, &sg_p.src,
			   up ? "upstream" : "no upstream");

	if (up && CHECK_FLAG(up->flags, PIM_UPSTREAM_FLAG_MASK_SRC_LHR)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%pSG: extra DATA_START after SPT switch", &up->sg);

		/*
		 * JOIN_SPT already made us SRC_LHR, so this is the data plane
		 * telling us traffic arrived on the SPT: finish the switch.
		 */
		if (up->sptbit != PIM_UPSTREAM_SPTBIT_TRUE && up->rpf.source_nexthop.interface)
			pimsb_lhr_spt_data(pim_ifp, up, ifp);
		return;
	}

	/* SSM is join driven: only note the traffic on existing state. */
	if (pim_is_grp_ssm(pim_ifp->pim, sg_p.grp)) {
		if (up) {
			pim_upstream_data_start(up);
			pim_upstream_mroute_add(up->channel_oil, __func__);
		}
		return;
	}

	/*
	 * Unlike the kernel (whose (*,G) entry forwards the source's RPT
	 * traffic by itself), a data plane may only report the traffic and
	 * wait for a (S,G) entry to forward it: create one inheriting the
	 * (*,G) OIL. The traffic owns it, so hold a SRC_STREAM reference
	 * which DATA_STOP releases.
	 *
	 * Without a (*,G) there is nothing to inherit: don't turn every
	 * reported flow into state.
	 */
	if (!up) {
		if (!pimsb_star_g_find(pim_ifp->pim, &sg_p)) {
			if (PIM_DEBUG_MROUTE)
				zlog_debug("%s: no SG(*,G) for %pSG, ignoring", __func__, &sg_p);
			return;
		}

		up = pim_upstream_add(pim_ifp->pim, &sg_p, ifp, PIM_UPSTREAM_FLAG_MASK_SRC_STREAM,
				      __func__, NULL);
		if (!up)
			return;
	}

	pim_upstream_data_start(up);
	/* The mroute is pushed below, after the OIL is inherited. */
	pim_upstream_update_use_rpt(up, false);

	/*
	 * Inherit the (*,G) OIL now instead of waiting for the next upstream
	 * scan: until then the data plane drops the source's RPT traffic and
	 * the (*,G) join prunes it with an empty inherited_olist(S,G,rpt).
	 */
	pim_upstream_inherited_olist_decide(pim_ifp->pim, up);

	/*
	 * Only start the keepalive timer where the kernel path would: a
	 * running timer makes JoinDesired(S,G) true with a non-empty
	 * inherited_olist(S,G), so starting it for (S,G,rpt) forwarding would
	 * pull the SPT on any router of the RPT (ignoring `spt-switchover`).
	 */
	if (pim_upstream_kat_start_ok(up))
		pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);

	pim_upstream_mroute_add(up->channel_oil, __func__);
}

/**
 * Traffic stopped (or the data plane that reported it is gone): release the
 * references the traffic took.
 */
static void pimsb_upstream_data_stop(struct pim_upstream *up)
{
	/* Only the data plane tells whether the flow is active. */
	pim_upstream_data_stop(up);

	/*
	 * The RP keepalive timer also tracks the registers, which restart it
	 * (RFC 7761 Section 4.4.2): let it expire by itself like with the
	 * kernel, otherwise the stream state (and the MSDP SA) the registers
	 * hold would go away while the source is still active. Without
	 * DATA_START nothing else restarts it, so the references the traffic
	 * took are released then.
	 */
	if (I_am_RP(up->pim, up->sg.grp) && !PIM_UPSTREAM_FLAG_TEST_FHR(up->flags) &&
	    !CHECK_FLAG(up->flags,
			PIM_UPSTREAM_FLAG_MASK_SRC_NOCACHE | PIM_UPSTREAM_FLAG_MASK_SRC_LHR) &&
	    pim_upstream_is_kat_running(up)) {
		if (up->channel_oil->installed)
			pim_upstream_mroute_add(up->channel_oil, __func__);
		return;
	}

	/*
	 * The data plane has no per route counters, so its DATA_STOP is the
	 * keepalive timer expiry: drop only the references the traffic took
	 * (SRC_STREAM, SRC_NOCACHE, SRC_LHR). Joins, MSDP and the other owners
	 * keep theirs, and the entry is only deleted once nothing else holds it.
	 */
	event_cancel(&up->t_ka_timer);
	up = pim_upstream_keep_alive_timer_proc(up);

	/* Still in use: reprogram it so the data plane reports new traffic. */
	if (up && up->channel_oil->installed)
		pim_upstream_mroute_add(up->channel_oil, __func__);
}

static void pimsb_client_data_stop(const struct mroute_event *me)
{
	const ifindex_t ifindex = (ifindex_t)ntohl((uint32_t)me->iif_idx);
	struct pim_upstream *up;
	struct pim_instance *pim;
	struct interface *ifp;
	vrf_id_t vrf_id;
	pim_sgaddr sg;

	if (!pimsb_event_sg(me, "DATA_STOP", &sg))
		return;

	/*
	 * The input interface may no longer be multicast enabled (or be
	 * gone), but the references the traffic took still need releasing:
	 * otherwise the flow looks active until the data plane disconnects.
	 * The traffic only takes references on multicast enabled interfaces,
	 * so look in the VRF the interface was last enabled in.
	 */
	ifp = pimsb_event_interface(me, "DATA_STOP", &sg);
	if (ifp)
		vrf_id = ifp->vrf->vrf_id;
	else if (ifindex >= 0 && ifindex < PIMSB_MAX_MULTICAST_IFS)
		vrf_id = pimsb_interface_vrf[ifindex];
	else
		vrf_id = VRF_UNKNOWN;

	pim = vrf_id == VRF_UNKNOWN ? NULL : pim_get_pim_instance(vrf_id);
	if (pim == NULL) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   no PIM instance for %pSG interface %d", __func__, &sg,
				   ifindex);
		return;
	}

	up = pim_upstream_find(pim, &sg);
	if (!up) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   upstream %pSG not found in VRF %s", __func__, &sg,
				   pim->vrf->name);
		return;
	}

	/*
	 * Only release what the reported traffic took: e.g. the RP keeps the
	 * references registers took (and duplicated DATA_STOPs find nothing to
	 * release).
	 */
	if (!CHECK_FLAG(up->flags, PIMSB_TRAFFIC_FLAGS)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s:   upstream %pSG has no reported traffic", __func__, &sg);
		return;
	}

	pimsb_upstream_data_stop(up);
}

static void pimsb_client_wrong_if(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;
	kernmsg im = {};
	pim_sgaddr sg;

	if (!pimsb_event_sg(me, "WRONG_IF", &sg))
		return;

	ifp = pimsb_event_interface(me, "WRONG_IF", &sg);
	if (!ifp)
		return;

	/* Only used for debug messages (and truncated there). */
#if PIM_IPV == 4
	im.im_msgtype = IGMPMSG_WRONGVIF;
	im.im_src = sg.src;
	im.im_dst = sg.grp;
	im.im_vif = (unsigned char)ifp->ifindex;
#else
	im.im6_msgtype = MRT6MSG_WRONGMIF;
	im.im6_src = sg.src;
	im.im6_dst = sg.grp;
	im.im6_mif = (mifi_t)ifp->ifindex;
#endif

	pim_ifp = ifp->info;
	pim_mroute_msg_wrongvif(pim_ifp->pim->mroute_socket, ifp, &im);
}

static void pimsb_client_spt_join(const struct mroute_event *me)
{
	struct pim_interface *pim_ifp;
	struct pim_upstream *up;
	struct interface *ifp;
	pim_sgaddr sg_p;

	if (!pimsb_event_sg(me, "JOIN_SPT", &sg_p))
		return;

	ifp = pimsb_event_interface(me, "JOIN_SPT", &sg_p);
	if (!ifp)
		return;

	pim_ifp = ifp->info;
	if (!pim_ifp->pim_enable) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: PIM not enabled on %s, ignoring %pSG", __func__, ifp->name,
				   &sg_p);
		return;
	}

	/* Only LHRs switch to the SPT, and those have the SG(*,G). */
	if (!pimsb_star_g_find(pim_ifp->pim, &sg_p)) {
		if (PIM_DEBUG_MROUTE)
			zlog_debug("%s: no SG(*,G) for %pSG, ignoring", __func__, &sg_p);
		return;
	}

	up = pim_upstream_find(pim_ifp->pim, &sg_p);
	if (up && PIM_UPSTREAM_FLAG_TEST_SRC_LHR(up->flags)) {
		/* Already switching: that flag holds the reference. */
	} else {
		/*
		 * Once the data plane switches this flow over to the SPT it
		 * is handled entirely in hardware, so a follow-up DATA_START
		 * may never show up.  Mark this as SRC_LHR right away instead
		 * of waiting on that event, otherwise nothing ever keeps this
		 * upstream's keepalive timer running and the SPT silently
		 * reverts back to the RPT once it expires.
		 */
		up = pim_upstream_add(pim_ifp->pim, &sg_p, NULL, PIM_UPSTREAM_FLAG_MASK_SRC_LHR,
				      __func__, NULL);
		if (!up)
			return;
	}

	pim_upstream_keep_alive_timer_start(up, pim_ifp->pim->keep_alive_time);
	pim_upstream_inherited_olist(pim_ifp->pim, up);
}

/** Parses message buffer and returns whether it can be called again. */
static bool pimsb_client_msg_parse(struct pimsb_client *client)
{
	const struct mroute_event_header *meheader;
	size_t msglen;

	/* Check for minimum amount of data. */
	if (client->msgbuf_available < sizeof(*meheader)) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: header incomplete (%zu of %zu bytes)", __func__,
				   client->msgbuf_available, sizeof(*meheader));
		return false;
	}

	/* Basic header length check. */
	meheader = (const struct mroute_event_header *)client->msgbuf;
	msglen = ntohs(meheader->length);
	if (msglen < sizeof(*meheader)) {
		zlog_err("%s: invalid length %zu", __func__, msglen);
		/*
		 * We've got an invalid message length so all other messages
		 * in this stream will be unaligned or wrong.
		 */
		pimsb_client_restart(client);
		return false;
	}

	/*
	 * A message larger than the buffer can never be completed: the buffer
	 * would fill up and `read()` return 0, which looks like a closed
	 * connection. Reset instead, since the stream can't be resynchronized.
	 */
	if (msglen > sizeof(client->msgbuf)) {
		zlog_err("%s: message length %zu exceeds buffer size %zu", __func__, msglen,
			 sizeof(client->msgbuf));
		pimsb_client_restart(client);
		return false;
	}

	/* Check if we've downloaded the whole message. */
	if (msglen > client->msgbuf_available) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: message incomplete (%zu of %zu bytes)", __func__, msglen,
				   client->msgbuf_available);
		return false;
	}

	/* Basic version check. */
	if (meheader->version != MRE_VERSION_V1) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: invalid version %d (skipping message)", __func__,
				   meheader->version);
		goto prepare_next_message;
	}

	/* Events are fixed size: don't read past a short one. */
	switch (meheader->type) {
	case MRT_EVENT_DATA_START:
	case MRT_EVENT_DATA_STOP:
	case MRT_EVENT_WRONG_IF:
	case MRT_EVENT_JOIN_SPT:
		if (msglen < sizeof(struct mroute_event)) {
			if (PIM_DEBUG_MROUTE_DETAIL)
				zlog_debug("%s: type %d too short (%zu of %zu bytes, skipping message)",
					   __func__, meheader->type, msglen,
					   sizeof(struct mroute_event));
			goto prepare_next_message;
		}
		break;
	default:
		break;
	}

	switch (meheader->type) {
	case MRT_EVENT_DATA_START:
		pimsb_client_data_start((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_STOP:
		pimsb_client_data_stop((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_WRONG_IF:
		pimsb_client_wrong_if((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_JOIN_SPT:
		pimsb_client_spt_join((const struct mroute_event *)meheader);
		break;
	case MRT_EVENT_DATA_PACKET:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: DATA_PACKET: not implemented", __func__);
		break;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: unhandled type %d", __func__, meheader->type);
		break;
	}

prepare_next_message:
	/* Move data to the beginning of the buffer and account it. */
	if ((client->msgbuf_available - msglen) > 0)
		memmove(client->msgbuf, client->msgbuf + msglen, client->msgbuf_available - msglen);

	client->msgbuf_available -= msglen;
	return client->msgbuf_available > 0;
}

static void pimsb_client_read_cb(struct event *event)
{
	struct pimsb_client *client = EVENT_ARG(event);
	ssize_t bytes_read;

	bytes_read = read(client->sock, client->msgbuf + client->msgbuf_available,
			  sizeof(client->msgbuf) - client->msgbuf_available);
	if (bytes_read == -1) {
		if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
			goto schedule_and_return;

		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: %s", __func__, safe_strerror(errno));

		/* Fatal connection error, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}
	if (bytes_read == 0) {
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: read: connection closed", __func__);

		/* Connection closed, don't schedule anymore. */
		pimsb_client_restart(client);
		return;
	}

	client->msgbuf_available += bytes_read;

	/* Handle data. */
	while (pimsb_client_msg_parse(client))
		;

	/* If client closed then don't attempt to reschedule. */
	if (client->sock == -1)
		return;

schedule_and_return:
	event_add_read(router->master, pimsb_client_read_cb, client, client->sock, &client->in_ev);
}

static void pimsb_client_connect_cb(struct event *event)
{
	struct pimsb_client *client = EVENT_ARG(event);
	int rv = 0;
	socklen_t rvlen = sizeof(rv);

	/* Make sure `errno` is reset, then test `getsockopt` success. */
	errno = 0;
	if (getsockopt(client->sock, SOL_SOCKET, SO_ERROR, &rv, &rvlen) == -1)
		rv = errno;

	/* Connection successful. */
	if (rv == 0) {
		zlog_info("PIM southbound: connected to the data plane");
		client->connected = true;
		if (!client->in_ev)
			event_add_read(router->master, pimsb_client_read_cb, client, client->sock,
				       &client->in_ev);
		return;
	}

	switch (rv) {
	case EINTR:
	case EAGAIN:
	case EALREADY:
	case EINPROGRESS:
		/* non error, wait more. */
		if (!client->out_ev)
			event_add_write(router->master, pimsb_client_connect_cb, client,
					client->sock, &client->out_ev);
		return;

	default:
		if (PIM_DEBUG_MROUTE_DETAIL)
			zlog_debug("%s: connection failed: %s", __func__, safe_strerror(rv));

		pimsb_client_restart(client);
		return;
	}
}

static void pimsb_client_start_connection_cb(struct event *event)
{
	struct pimsb_client *client = EVENT_ARG(event);
	int rv;

	client->sock = socket(pimsb_ctx.ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
			      0);
	if (client->sock == -1) {
		zlog_err("%s: socket: %s", __func__, safe_strerror(errno));
		event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
				&client->connstart_ev);
		return;
	}

	/* Set 'no delay' (disables nagle algorithm) for IPv4/IPv6. */
	rv = 1;
	if (pimsb_ctx.ss.ss_family != AF_UNIX &&
	    setsockopt(client->sock, IPPROTO_TCP, TCP_NODELAY, &rv, sizeof(rv)) == -1)
		zlog_warn("%s: setsockopt(TCP_NODELAY): %s", __func__, safe_strerror(errno));
	pimsb_client_keepalive(client->sock);

	rv = connect(client->sock, (struct sockaddr *)&pimsb_ctx.ss, pimsb_ctx.sslen);
	/* Connection successful, just schedule read. */
	if (rv == 0) {
		zlog_info("PIM southbound: connected to the data plane");
		client->connected = true;
		event_add_read(router->master, pimsb_client_read_cb, client, client->sock,
			       &client->in_ev);
		return;
	}

	/*
	 * Connect failed, handle it according to the failure (`EAGAIN` means
	 * no connection is in progress: the unix socket backlog is full).
	 */
	if (errno == EALREADY || errno == EINPROGRESS) {
		event_add_write(router->master, pimsb_client_connect_cb, client, client->sock,
				&client->out_ev);
		return;
	}

	close(client->sock);
	client->sock = -1;

	/* Try again later, maybe the server will be available. */
	event_add_timer(router->master, pimsb_client_start_connection_cb, client, 3,
			&client->connstart_ev);
}

static void pimsb_server_wait_cb(struct event *event);

static void pimsb_server_wait_retry_cb(struct event *event)
{
	event_add_read(router->master, pimsb_server_wait_cb, NULL,
		       pimsb_ctx.server.listening_socket, &pimsb_ctx.server.listening_ev);
}

static void pimsb_server_wait_cb(struct event *event)
{
	int sock = EVENT_FD(event);
	int fd;

	/* Accept new connection. */
	fd = accept(sock, NULL, NULL);
	if (fd == -1) {
		/* The pending connection may be gone before we got to it. */
		if (ERRNO_IO_RETRY(errno) || errno == ECONNABORTED)
			goto schedule_and_return;

		/*
		 * E.g. out of descriptors: the connection stays pending (the
		 * socket readable), so back off instead of spinning.
		 */
		zlog_err("%s: accept: %s", __func__, safe_strerror(errno));
		event_add_timer(router->master, pimsb_server_wait_retry_cb, NULL, 1,
				&pimsb_ctx.server.listening_ev);
		return;
	}
	if (set_cloexec(fd) == -1 || set_nonblocking(fd) == -1) {
		zlog_err("%s: socket options: %s", __func__, safe_strerror(errno));
		close(fd);
		goto schedule_and_return;
	}

	/*
	 * Only one data plane at a time: a new connection replaces the old
	 * one (e.g. the data plane restarted without closing it).
	 */
	if (pimsb_ctx.server.client.sock != -1) {
		zlog_info("%s: new data plane connection, dropping the previous one", __func__);
		pimsb_client_restart(&pimsb_ctx.server.client);
	}

	pimsb_client_keepalive(fd);
	zlog_info("PIM southbound: data plane connected");

	/* Schedule new client read events. */
	pimsb_ctx.server.client.sock = fd;
	pimsb_ctx.server.client.connected = true;
	event_add_read(router->master, pimsb_client_read_cb, &pimsb_ctx.server.client, fd,
		       &pimsb_ctx.server.client.in_ev);

schedule_and_return:
	/* Re-schedule accept connection. */
	event_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
		       &pimsb_ctx.server.listening_ev);
}

/**
 * Locks the unix socket path `sun` (a `.lock` file next to it) so other
 * instances don't take it over. Connecting to the socket to see whether it is
 * in use would make the instance listening on it drop its data plane for the
 * probe.
 *
 * \returns the lock file descriptor or -1 if it couldn't be locked.
 */
static int pimsb_unix_socket_lock(const struct sockaddr_un *sun)
{
	char path[sizeof(sun->sun_path) + sizeof(".lock")];
	int fd;

	snprintfrr(path, sizeof(path), "%.*s.lock",
		   (int)strnlen(sun->sun_path, sizeof(sun->sun_path)), sun->sun_path);
	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0600);
	if (fd == -1) {
		zlog_err("%s: open %s: %s", __func__, path, safe_strerror(errno));
		return -1;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) == -1) {
		zlog_err("%s: %s is in use by another process", __func__, sun->sun_path);
		close(fd);
		return -1;
	}

	return fd;
}

void pimsb_socket_init(const struct sockaddr_storage *ss, socklen_t sslen, bool client)
{
	int sock;

	pimsb_ctx.ss = *ss;
	pimsb_ctx.sslen = sslen;

	if (client) {
		/* Start client socket. */
		zlog_info("initializing PIM southbound (client mode)");
		pimsb_ctx.client.sock = -1;
		event_add_timer(router->master, pimsb_client_start_connection_cb,
				&pimsb_ctx.client, 0, &pimsb_ctx.client.connstart_ev);
		return;
	}

	zlog_info("initializing PIM southbound (server mode)");

	/* Start server socket. */
	sock = socket(ss->ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (sock == -1) {
		zlog_err("%s: socket: %s", __func__, safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (set_nonblocking(sock) == -1) {
		zlog_err("%s: set_nonblocking: %s", __func__, safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (sockopt_reuseaddr(sock) == -1) {
		zlog_err("%s: reuseaddr: %s", __func__, safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	/*
	 * Remove stale socket file left by a previous run, but don't take
	 * over the socket of a running instance (abstract sockets have no
	 * file: their bind fails instead).
	 */
	pimsb_ctx.server.lock_fd = -1;
	if (ss->ss_family == AF_UNIX && ((const struct sockaddr_un *)ss)->sun_path[0] != 0) {
		const struct sockaddr_un *sun = (const struct sockaddr_un *)ss;

		pimsb_ctx.server.lock_fd = pimsb_unix_socket_lock(sun);
		if (pimsb_ctx.server.lock_fd == -1)
			exit(EXIT_FAILURE);

		if (unlink(sun->sun_path) == -1 && errno != ENOENT)
			zlog_warn("%s: unlink %s: %s", __func__, sun->sun_path,
				  safe_strerror(errno));
	}

	if (bind(sock, (struct sockaddr *)ss, sslen) == -1) {
		zlog_err("%s: bind: %s", __func__, safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	if (listen(sock, 1) == -1) {
		zlog_err("%s: listen: %s", __func__, safe_strerror(errno));
		exit(EXIT_FAILURE);
	}

	/* Reset server's client data socket value. */
	pimsb_ctx.server.listening_socket = sock;
	pimsb_ctx.server.client.sock = -1;

	/* Schedule listening events. */
	event_add_read(router->master, pimsb_server_wait_cb, NULL, sock,
		       &pimsb_ctx.server.listening_ev);

	pimsb_ctx.is_server = true;
}

void pimsb_socket_stop(void)
{
	if (pimsb_ctx.is_server) {
		event_cancel(&pimsb_ctx.server.listening_ev);
		if (pimsb_ctx.server.listening_socket != -1) {
			close(pimsb_ctx.server.listening_socket);

			if (pimsb_ctx.ss.ss_family == AF_UNIX) {
				const struct sockaddr_un *sun =
					(const struct sockaddr_un *)&pimsb_ctx.ss;

				if (sun->sun_path[0] != 0)
					unlink(sun->sun_path);
			}
		}
		pimsb_ctx.server.listening_socket = -1;

		/*
		 * The lock file stays: removing it would let an instance that
		 * already opened it and a new one both get a lock.
		 */
		if (pimsb_ctx.server.lock_fd != -1) {
			close(pimsb_ctx.server.lock_fd);
			pimsb_ctx.server.lock_fd = -1;
		}
		pimsb_client_stop(&pimsb_ctx.server.client);
	} else
		pimsb_client_stop(&pimsb_ctx.client);
}
