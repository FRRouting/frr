// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra connect code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include "frrevent.h"
#include "command.h"
#include "network.h"
#include "prefix.h"
#include "routemap.h"
#include "table.h"
#include "srcdest_table.h"
#include "stream.h"
#include "memory.h"
#include "zclient.h"
#include "filter.h"
#include "plist.h"
#include "log.h"
#include "nexthop.h"
#include "nexthop_group.h"
#include "hash.h"
#include "jhash.h"

#include "static_vrf.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_nht.h"
#include "static_vty.h"
#include "static_debug.h"
#include "zclient.h"
#include "static_srv6.h"
#include "lib_errors.h"

DEFINE_MTYPE_STATIC(STATIC, STATIC_NHT_DATA, "Static Nexthop tracking data");
PREDECL_HASH(static_nht_hash);

struct static_nht_data {
	struct static_nht_hash_item itm;

	struct prefix nh;
	safi_t safi;

	vrf_id_t nh_vrf_id;

	uint32_t refcount;
	uint16_t nh_num;
	bool registered;
};

static int static_nht_data_cmp(const struct static_nht_data *nhtd1,
			       const struct static_nht_data *nhtd2)
{
	if (nhtd1->nh_vrf_id != nhtd2->nh_vrf_id)
		return numcmp(nhtd1->nh_vrf_id, nhtd2->nh_vrf_id);
	if (nhtd1->safi != nhtd2->safi)
		return numcmp(nhtd1->safi, nhtd2->safi);

	return prefix_cmp(&nhtd1->nh, &nhtd2->nh);
}

static unsigned int static_nht_data_hash(const struct static_nht_data *nhtd)
{
	unsigned int key = 0;

	key = prefix_hash_key(&nhtd->nh);
	return jhash_2words(nhtd->nh_vrf_id, nhtd->safi, key);
}

DECLARE_HASH(static_nht_hash, struct static_nht_data, itm, static_nht_data_cmp,
	     static_nht_data_hash);

static struct static_nht_hash_head static_nht_hash[1];

/* Zebra structure to hold current status. */
struct zclient *static_zclient;
uint32_t zebra_ecmp_count = MULTIPATH_NUM;

/* Interface addition message from zebra. */
static int static_ifp_create(struct interface *ifp)
{
	static_ifindex_update(ifp, true);

	return 0;
}

static int static_ifp_destroy(struct interface *ifp)
{
	static_ifindex_update(ifp, false);
	return 0;
}

static int interface_address_add(ZAPI_CALLBACK_ARGS)
{
	zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	return 0;
}

static int interface_address_delete(ZAPI_CALLBACK_ARGS)
{
	struct connected *c;

	c = zebra_interface_address_read(cmd, zclient->ibuf, vrf_id);

	if (!c)
		return 0;

	connected_free(&c);
	return 0;
}

static int static_ifp_up(struct interface *ifp)
{
	static_ifindex_update(ifp, true);

	static_ifp_srv6_sids_update(ifp, true);

	return 0;
}

static int static_ifp_down(struct interface *ifp)
{
	static_ifindex_update(ifp, false);

	static_ifp_srv6_sids_update(ifp, false);

	return 0;
}

static int route_notify_owner(ZAPI_CALLBACK_ARGS)
{
	struct prefix p, src_p, *src_pp;
	enum zapi_route_notify_owner note;
	uint32_t table_id;
	safi_t safi;

	if (!zapi_route_notify_decode_srcdest(zclient->ibuf, &p, &src_p, &table_id, &note, NULL,
					      &safi))
		return -1;

	src_pp = src_p.prefixlen ? &src_p : NULL;

	switch (note) {
	case ZAPI_ROUTE_FAIL_INSTALL:
		static_nht_mark_state(&p, src_pp, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn("%s: Route %pFX failed to install for table: %u",
			  __func__, &p, table_id);
		break;
	case ZAPI_ROUTE_BETTER_ADMIN_WON:
		static_nht_mark_state(&p, src_pp, safi, vrf_id, STATIC_NOT_INSTALLED);
		zlog_warn(
			"%s: Route %pFX over-ridden by better route for table: %u",
			__func__, &p, table_id);
		break;
	case ZAPI_ROUTE_INSTALLED:
		static_nht_mark_state(&p, src_pp, safi, vrf_id, STATIC_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVED:
		static_nht_mark_state(&p, src_pp, safi, vrf_id, STATIC_NOT_INSTALLED);
		break;
	case ZAPI_ROUTE_REMOVE_FAIL:
		static_nht_mark_state(&p, src_pp, safi, vrf_id, STATIC_INSTALLED);
		zlog_warn("%s: Route %pFX failure to remove for table: %u",
			  __func__, &p, table_id);
		break;
	}

	return 0;
}

static void zebra_connected(struct zclient *zclient)
{
	struct vrf *vrf;

	zebra_route_notify_send(ZEBRA_ROUTE_NOTIFY_REQUEST, zclient, true);
	zclient_send_reg_requests(zclient, VRF_DEFAULT);

	vrf = vrf_lookup_by_id(VRF_DEFAULT);
	assert(vrf);
	static_fixup_vrf_ids(vrf);

	/*
	 * It's possible that staticd connected after config was read
	 * in.
	 */
	static_install_nexthops_on_startup();

	static_zebra_request_srv6_sids();
}

/* API to check whether the configured nexthop address is
 * one of its local connected address or not.
 */
static bool
static_nexthop_is_local(vrf_id_t vrfid, struct prefix *addr, int family)
{
	if (family == AF_INET) {
		if (if_address_is_local(&addr->u.prefix4, AF_INET, vrfid))
			return true;
	} else if (family == AF_INET6) {
		if (if_address_is_local(&addr->u.prefix6, AF_INET6, vrfid))
			return true;
	}
	return false;
}

static void static_zebra_nexthop_update(struct vrf *vrf, struct prefix *matched,
					struct zapi_route *nhr)
{
	struct static_nht_data *nhtd, lookup;

	if (static_zclient->bfd_integration)
		bfd_nht_update(matched, nhr);

	if (nhr->type == ZEBRA_ROUTE_CONNECT) {
		if (static_nexthop_is_local(vrf->vrf_id, matched,
					    nhr->prefix.family))
			nhr->nexthop_num = 0;
	}

	memset(&lookup, 0, sizeof(lookup));
	lookup.nh = *matched;
	lookup.nh_vrf_id = vrf->vrf_id;
	lookup.safi = nhr->safi;

	nhtd = static_nht_hash_find(static_nht_hash, &lookup);

	if (nhtd) {
		nhtd->nh_num = nhr->nexthop_num;

		/* The tracked nexthop might be used by IPv4 and IPv6 routes */
		static_nht_reset_start(matched, AFI_IP, nhr->safi, nhtd->nh_vrf_id);
		static_nht_update(NULL, NULL, matched, nhr->nexthop_num, AFI_IP, nhr->safi,
				  nhtd->nh_vrf_id);
		static_nht_reset_start(matched, AFI_IP6, nhr->safi, nhtd->nh_vrf_id);
		static_nht_update(NULL, NULL, matched, nhr->nexthop_num, AFI_IP6, nhr->safi,
				  nhtd->nh_vrf_id);
	} else
		zlog_err("No nhtd?");
}

static void static_zebra_capabilities(struct zclient_capabilities *cap)
{
	mpls_enabled = cap->mpls_enabled;
	zebra_ecmp_count = cap->ecmp;
}

static struct static_nht_data *
static_nht_hash_getref(const struct static_nht_data *ref)
{
	struct static_nht_data *nhtd;

	nhtd = static_nht_hash_find(static_nht_hash, ref);
	if (!nhtd) {
		nhtd = XCALLOC(MTYPE_STATIC_NHT_DATA, sizeof(*nhtd));

		prefix_copy(&nhtd->nh, &ref->nh);
		nhtd->nh_vrf_id = ref->nh_vrf_id;
		nhtd->safi = ref->safi;

		static_nht_hash_add(static_nht_hash, nhtd);
	}

	nhtd->refcount++;
	return nhtd;
}

static bool static_nht_hash_decref(struct static_nht_data **nhtd_p)
{
	struct static_nht_data *nhtd = *nhtd_p;

	*nhtd_p = NULL;

	if (--nhtd->refcount > 0)
		return true;

	static_nht_hash_del(static_nht_hash, nhtd);
	XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
	return false;
}

static void static_nht_hash_clear(void)
{
	struct static_nht_data *nhtd;

	while ((nhtd = static_nht_hash_pop(static_nht_hash)))
		XFREE(MTYPE_STATIC_NHT_DATA, nhtd);
}

static bool static_zebra_nht_get_prefix(const struct static_nexthop *nh,
					struct prefix *p)
{
	switch (nh->type) {
	case STATIC_IFNAME:
	case STATIC_BLACKHOLE:
		p->family = AF_UNSPEC;
		return false;

	case STATIC_IPV4_GATEWAY:
	case STATIC_IPV4_GATEWAY_IFNAME:
		p->family = AF_INET;
		p->prefixlen = IPV4_MAX_BITLEN;
		p->u.prefix4 = nh->addr.ipv4;
		return true;

	case STATIC_IPV6_GATEWAY:
	case STATIC_IPV6_GATEWAY_IFNAME:
		p->family = AF_INET6;
		p->prefixlen = IPV6_MAX_BITLEN;
		p->u.prefix6 = nh->addr.ipv6;
		return true;
	}

	assertf(0, "BUG: someone forgot to add nexthop type %u", nh->type);
	return false;
}

void static_zebra_nht_register(struct static_nexthop *nh, bool reg)
{
	struct static_path *pn = nh->pn;
	struct route_node *rn = pn->rn;
	const struct prefix *p, *src_p;
	struct static_route_info *si = static_route_info_from_rnode(rn);
	struct static_nht_data *nhtd, lookup = {};
	uint32_t cmd;

	srcdest_rnode_prefixes(rn, &p, &src_p);

	if (!static_zebra_nht_get_prefix(nh, &lookup.nh))
		return;

	if (nh->nh_vrf_id == VRF_UNKNOWN)
		return;

	lookup.nh_vrf_id = nh->nh_vrf_id;
	lookup.safi = si->safi;

	if (nh->nh_registered) {
		/* nh->nh_registered means we own a reference on the nhtd */
		nhtd = static_nht_hash_find(static_nht_hash, &lookup);

		assertf(nhtd, "BUG: NH %pFX registered but not in hashtable",
			&lookup.nh);
	} else if (reg) {
		nhtd = static_nht_hash_getref(&lookup);

		if (nhtd->refcount > 1)
			DEBUGD(&static_dbg_route,
			       "Reusing registered nexthop(%pFX) for %pRN %d",
			       &lookup.nh, rn, nhtd->nh_num);
	} else {
		/* !reg && !nh->nh_registered */
		zlog_warn("trying to unregister nexthop %pFX twice",
			  &lookup.nh);
		return;
	}

	nh->nh_registered = reg;

	if (reg) {
		if (nhtd->nh_num) {
			/* refresh with existing data */
			afi_t afi = prefix_afi(&rn->p);

			if (nh->state == STATIC_NOT_INSTALLED ||
			    nh->state == STATIC_SENT_TO_ZEBRA)
				nh->state = STATIC_START;
			static_nht_update(p, src_p, &nhtd->nh, nhtd->nh_num, afi, si->safi,
					  nh->nh_vrf_id);
			return;
		}

		if (nhtd->registered)
			/* have no data, but did send register */
			return;

		cmd = ZEBRA_NEXTHOP_REGISTER;
		DEBUGD(&static_dbg_route, "Registering nexthop(%pFX) for %pRN",
		       &lookup.nh, rn);
	} else {
		bool was_zebra_registered;

		was_zebra_registered = nhtd->registered;
		if (static_nht_hash_decref(&nhtd))
			/* still got references alive */
			return;

		/* NB: nhtd is now NULL. */
		if (!was_zebra_registered)
			return;

		cmd = ZEBRA_NEXTHOP_UNREGISTER;
		DEBUGD(&static_dbg_route,
		       "Unregistering nexthop(%pFX) for %pRN", &lookup.nh, rn);
	}

	if (zclient_send_rnh(static_zclient, cmd, &lookup.nh, si->safi, false, false,
			     nh->nh_vrf_id) == ZCLIENT_SEND_FAILURE)
		zlog_warn("%s: Failure to send nexthop %pFX for %pRN to zebra",
			  __func__, &lookup.nh, rn);
	else if (reg)
		nhtd->registered = true;
}

extern void static_zebra_route_add(struct static_path *pn, bool install)
{
	struct route_node *rn = pn->rn;
	struct static_route_info *si = rn->info;
	struct static_nexthop *nh;
	const struct prefix *p, *src_pp;
	struct zapi_nexthop *api_nh;
	struct zapi_route api;
	uint32_t nh_num = 0;

	if (!si->svrf->vrf || si->svrf->vrf->vrf_id == VRF_UNKNOWN)
		return;

	p = src_pp = NULL;
	srcdest_rnode_prefixes(rn, &p, &src_pp);

	zapi_route_init(&api);
	api.vrf_id = si->svrf->vrf->vrf_id;
	api.type = ZEBRA_ROUTE_STATIC;
	api.safi = si->safi;
	memcpy(&api.prefix, p, sizeof(api.prefix));

	if (src_pp) {
		SET_FLAG(api.message, ZAPI_MESSAGE_SRCPFX);
		memcpy(&api.src_prefix, src_pp, sizeof(api.src_prefix));
	}
	SET_FLAG(api.flags, ZEBRA_FLAG_RR_USE_DISTANCE);
	SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	if (pn->distance) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = pn->distance;
	}
	if (pn->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = pn->tag;
	}
	if (pn->table_id != 0) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TABLEID);
		api.tableid = pn->table_id;
	}
	frr_each(static_nexthop_list, &pn->nexthop_list, nh) {
		/* Don't overrun the nexthop array */
		if (nh_num == zebra_ecmp_count)
			break;

		api_nh = &api.nexthops[nh_num];
		if (nh->nh_vrf_id == VRF_UNKNOWN)
			continue;
		/* Skip next hop which peer is down. */
		if (nh->path_down)
			continue;

		zapi_nexthop_init(api_nh);
		api_nh->vrf_id = nh->nh_vrf_id;
		if (nh->onlink)
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_ONLINK);
		if (nh->color != 0) {
			SET_FLAG(api.message, ZAPI_MESSAGE_SRTE);
			api_nh->srte_color = nh->color;
		}

		nh->state = STATIC_SENT_TO_ZEBRA;

		switch (nh->type) {
		case STATIC_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IFINDEX;
			break;
		case STATIC_IPV4_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV4;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV4_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->ifindex = nh->ifindex;
			api_nh->type = NEXTHOP_TYPE_IPV4_IFINDEX;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY:
			if (!nh->nh_valid)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6;
			api_nh->gate = nh->addr;
			break;
		case STATIC_IPV6_GATEWAY_IFNAME:
			if (nh->ifindex == IFINDEX_INTERNAL)
				continue;
			api_nh->type = NEXTHOP_TYPE_IPV6_IFINDEX;
			api_nh->ifindex = nh->ifindex;
			api_nh->gate = nh->addr;
			break;
		case STATIC_BLACKHOLE:
			api_nh->type = NEXTHOP_TYPE_BLACKHOLE;
			switch (nh->bh_type) {
			case STATIC_BLACKHOLE_DROP:
			case STATIC_BLACKHOLE_NULL:
				api_nh->bh_type = BLACKHOLE_NULL;
				break;
			case STATIC_BLACKHOLE_REJECT:
				api_nh->bh_type = BLACKHOLE_REJECT;
			}
			break;
		}

		if (nh->snh_label.num_labels) {
			int i;

			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_LABEL);
			api_nh->label_num = nh->snh_label.num_labels;
			for (i = 0; i < api_nh->label_num; i++)
				api_nh->labels[i] = nh->snh_label.label[i];
		}
		if (nh->snh_seg.num_segs) {
			int i;

			api_nh->seg6local_action =
				ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
			SET_FLAG(api_nh->flags, ZAPI_NEXTHOP_FLAG_SEG6);
			SET_FLAG(api.flags, ZEBRA_FLAG_ALLOW_RECURSION);
			api.safi = SAFI_UNICAST;

			api_nh->seg_num = nh->snh_seg.num_segs;
			for (i = 0; i < api_nh->seg_num; i++)
				memcpy(&api_nh->seg6_segs[i],
				       &nh->snh_seg.seg[i],
				       sizeof(struct in6_addr));

			api_nh->srv6_encap_behavior = nh->snh_seg.encap_behavior;
		}
		nh_num++;
	}

	api.nexthop_num = nh_num;

	/*
	 * If we have been given an install but nothing is valid
	 * go ahead and delete the route for double plus fun
	 */
	if (!nh_num && install)
		install = false;

	zclient_route_send(install ?
			   ZEBRA_ROUTE_ADD : ZEBRA_ROUTE_DELETE,
			   static_zclient, &api);
}

/**
 * Install SRv6 SID in the forwarding plane through Zebra.
 *
 * @param sid		SRv6 SID
 */
void static_zebra_srv6_sid_install(struct static_srv6_sid *sid)
{
	enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct seg6local_context ctx = {};
	struct interface *ifp = NULL;
	struct vrf *vrf;
	struct prefix_ipv6 sid_locator = {};
	const struct in6_addr *nexthop;

	if (!sid)
		return;

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		return;

	if (!sid->locator) {
		zlog_err("Failed to install SID %pFX: missing locator information", &sid->addr);
		return;
	}

	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_X;

		/* Get effective nexthop (resolved or configured) */
		nexthop = static_srv6_sid_get_nexthop(sid);
		if (!nexthop) {
			DEBUGD(&static_dbg_srv6,
			       "%s: Cannot install SID %pFX - nexthop not available", __func__,
			       &sid->addr);
			return;
		}
		ctx.nh6 = *nexthop;

		/* Lookup interface */
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get interface %s",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		break;
	}

	ctx.block_len = sid->locator->block_bits_length;
	sid_locator = sid->addr;
	sid_locator.prefixlen = sid->locator->block_bits_length + sid->locator->node_bits_length;
	apply_mask(&sid_locator);

	if (prefix_same(&sid_locator, &sid->locator->prefix))
		ctx.node_len = sid->locator->node_bits_length;

	ctx.function_len = sid->addr.prefixlen - (ctx.block_len + ctx.node_len);

	ctx.flv.lcblock_len = sid->locator->block_bits_length;
	ctx.flv.lcnode_func_len = ctx.node_len + ctx.function_len;

	/* Attach the SID to the SRv6 interface */
	if (!ifp) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SRv6 SID %pFX: %s interface not found",
				  &sid->addr, DEFAULT_SRV6_IFNAME);
			return;
		}
	}

	/* Send the SID to zebra */
	zclient_send_localsid(static_zclient, ZEBRA_ROUTE_ADD, &sid->addr.prefix,
			      sid->addr.prefixlen, ifp->ifindex, action, &ctx);

	SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

void static_zebra_srv6_sid_uninstall(struct static_srv6_sid *sid)
{
	enum seg6local_action_t action = ZEBRA_SEG6_LOCAL_ACTION_UNSPEC;
	struct interface *ifp = NULL;
	struct seg6local_context ctx = {};
	struct vrf *vrf;
	struct prefix_ipv6 sid_block = {};
	struct prefix_ipv6 locator_block = {};
	struct prefix_ipv6 sid_locator = {};
	const struct in6_addr *nexthop;

	if (!sid)
		return;

	if (!CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA))
		return;

	if (!sid->locator) {
		zlog_err("Failed to uninstall SID %pFX: missing locator information", &sid->addr);
		return;
	}

	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_PSP);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		action = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
		if (!vrf_is_enabled(vrf)) {
			zlog_warn("Failed to install SID %pFX: VRF %s is inactive", &sid->addr,
				  sid->attributes.vrf_name);
			return;
		}
		ctx.table = vrf->data.l.table_id;
		ifp = if_get_vrf_loopback(vrf->vrf_id);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get loopback for vrf %s",
				  &sid->addr, sid->attributes.vrf_name);
			return;
		}
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		action = ZEBRA_SEG6_LOCAL_ACTION_END_X;

		/* Use same nexthop that was used during installation */
		nexthop = static_srv6_sid_get_nexthop(sid);
		assert(nexthop != NULL);
		ctx.nh6 = *nexthop;

		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to install SID %pFX: failed to get interface %s",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;
		SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		break;
	}

	/* The SID is attached to the SRv6 interface */
	if (!ifp) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("%s interface not found: nothing to uninstall",
				  DEFAULT_SRV6_IFNAME);
			return;
		}
	}

	sid_block = sid->addr;
	sid_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&sid_block);

	locator_block = sid->locator->prefix;
	locator_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&locator_block);

	if (prefix_same(&sid_block, &locator_block))
		ctx.block_len = sid->locator->block_bits_length;
	else {
		zlog_warn("SID block %pFX does not match locator block %pFX", &sid_block,
			  &locator_block);
		return;
	}

	sid_locator = sid->addr;
	sid_locator.prefixlen = sid->locator->block_bits_length + sid->locator->node_bits_length;
	apply_mask(&sid_locator);

	if (prefix_same(&sid_locator, &sid->locator->prefix))
		ctx.node_len = sid->locator->node_bits_length;

	ctx.function_len = sid->addr.prefixlen - (ctx.block_len + ctx.node_len);

	ctx.flv.lcblock_len = sid->locator->block_bits_length;
	ctx.flv.lcnode_func_len = ctx.node_len + ctx.function_len;

	zclient_send_localsid(static_zclient, ZEBRA_ROUTE_DELETE, &sid->addr.prefix,
			      sid->addr.prefixlen, ifp->ifindex, action, &ctx);

	if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_NEEDS_NH_RESOLUTION))
		static_srv6_sid_clear_resolution(sid);

	UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
}

/* Validate if the sid block and locator block are the same */
static bool static_zebra_sid_locator_block_check(struct static_srv6_sid *sid)
{
	struct prefix_ipv6 sid_block = {};
	struct prefix_ipv6 locator_block = {};

	sid_block = sid->addr;
	sid_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&sid_block);

	locator_block = sid->locator->prefix;
	locator_block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&locator_block);

	if (!prefix_same(&sid_block, &locator_block)) {
		zlog_warn("SID block %pFX does not match locator block %pFX", &sid_block,
			  &locator_block);

		return false;
	}

	return true;
}

static bool is_srv6_sid_localonly(const struct static_srv6_sid *sid)
{
	struct prefix_ipv6 block = {};
	struct prefix_ipv6 locator = {};

	block = sid->locator->prefix;
	block.prefixlen = sid->locator->block_bits_length;
	apply_mask(&block);

	locator = sid->locator->prefix;

	if (prefix_match(&block, &sid->addr) && !prefix_match(&locator, &sid->addr))
		return true;

	return false;
}

extern void static_zebra_request_srv6_sid(struct static_srv6_sid *sid)
{
	struct srv6_sid_ctx ctx = {};
	int ret = 0;
	struct vrf *vrf;
	struct interface *ifp;

	if (!sid)
		return;

	if (!sid->locator) {
		static_zebra_srv6_manager_get_locator(sid->locator_name);
		return;
	}

	if (!static_zebra_sid_locator_block_check(sid))
		return;

	/* convert `srv6_endpoint_behavior_codepoint` to `seg6local_action_t` */
	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END:
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to request SRv6 SID %pFX: interface %s does not exist",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED_NEXT_CSID:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		return;
	}

	/* Request SRv6 SID from SID Manager */
	ret = srv6_manager_get_sid(static_zclient, &ctx, &sid->addr.prefix, sid->locator->name,
				   NULL, is_srv6_sid_localonly(sid));
	if (ret < 0)
		zlog_warn("%s: error getting SRv6 SID!", __func__);
}

extern void static_zebra_release_srv6_sid(struct static_srv6_sid *sid)
{
	struct srv6_sid_ctx ctx = {};
	struct vrf *vrf;
	int ret = 0;
	struct interface *ifp;

	if (!sid || !CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID))
		return;

	/* convert `srv6_endpoint_behavior_codepoint` to `seg6local_action_t` */
	switch (sid->behavior) {
	case SRV6_ENDPOINT_BEHAVIOR_END:
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46:
	case SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		/* process SRv6 SID attributes */
		/* generate table ID from the VRF name, if configured */
		if (sid->attributes.vrf_name[0] != '\0') {
			vrf = vrf_lookup_by_name(sid->attributes.vrf_name);
			if (!vrf_is_enabled(vrf))
				return;
			ctx.vrf_id = vrf->vrf_id;
		}

		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID:
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_X;
		ctx.nh6 = sid->attributes.nh6;
		ifp = if_lookup_by_name(sid->attributes.ifname, VRF_DEFAULT);
		if (!ifp) {
			zlog_warn("Failed to request SRv6 SID %pFX: interface %s does not exist",
				  &sid->addr, sid->attributes.ifname);
			return;
		}
		ctx.ifindex = ifp->ifindex;
		break;
	case SRV6_ENDPOINT_BEHAVIOR_END_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP:
	case SRV6_ENDPOINT_BEHAVIOR_END_X_NEXT_CSID_PSP_USD:
	case SRV6_ENDPOINT_BEHAVIOR_OPAQUE:
	case SRV6_ENDPOINT_BEHAVIOR_RESERVED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_NEXT_CSID:
	case SRV6_ENDPOINT_BEHAVIOR_END_B6_ENCAPS_RED_NEXT_CSID:
		zlog_warn("unsupported behavior: %u", sid->behavior);
		return;
	}

	/* remove the SRv6 SID from the zebra RIB */
	ret = srv6_manager_release_sid(static_zclient, &ctx, sid->locator->name,
				       is_srv6_sid_localonly(sid));
	if (ret == ZCLIENT_SEND_FAILURE)
		flog_err(EC_LIB_ZAPI_SOCKET, "zclient_send_get_srv6_sid() delete failed: %s",
			 safe_strerror(errno));
}

/**
 * Ask the SRv6 Manager (zebra) about a specific locator
 *
 * @param name Locator name
 * @return 0 on success, -1 otherwise
 */
int static_zebra_srv6_manager_get_locator(const char *name)
{
	if (!name)
		return -1;

	/*
	 * Send the Get Locator request to the SRv6 Manager and return the
	 * result
	 */
	return srv6_manager_get_locator(static_zclient, name);
}

static void request_srv6_sids(struct static_srv6_locator *locator)
{
	struct static_srv6_sid *sid;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (sid->locator == locator)
			static_zebra_request_srv6_sid(sid);
	}
}

/**
 * Internal function to process an SRv6 locator
 *
 * @param locator The locator to be processed
 */
static int static_zebra_process_srv6_locator_internal(struct srv6_locator *locator)
{
	struct static_srv6_locator *loc;
	struct listnode *node;
	struct static_srv6_sid *sid;

	if (!locator)
		return -1;

	DEBUGD(&static_dbg_srv6,
	       "%s: Received SRv6 locator %s %pFX, loc-block-len=%u, loc-node-len=%u func-len=%u, arg-len=%u",
	       __func__, locator->name, &locator->prefix, locator->block_bits_length,
	       locator->node_bits_length, locator->function_bits_length,
	       locator->argument_bits_length);

	/* If we are already aware about the locator, nothing to do */
	loc = static_srv6_locator_lookup(locator->name);
	if (loc)
		return 0;

	loc = static_srv6_locator_alloc(locator->name);

	DEBUGD(&static_dbg_srv6, "%s: SRv6 locator (locator %s, prefix %pFX) set", __func__,
	       locator->name, &locator->prefix);

	/* Store the locator prefix */
	loc->prefix = locator->prefix;
	loc->block_bits_length = locator->block_bits_length;
	loc->node_bits_length = locator->node_bits_length;
	loc->function_bits_length = locator->function_bits_length;
	loc->argument_bits_length = locator->argument_bits_length;
	loc->flags = locator->flags;

	listnode_add(srv6_locators, loc);

	for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
		if (strncmp(sid->locator_name, loc->name, sizeof(loc->name)) == 0)
			sid->locator = loc;
	}

	/* Request SIDs from the locator */
	request_srv6_sids(loc);

	return 0;
}

/**
 * Callback to process an SRv6 locator received from SRv6 Manager (zebra).
 *
 * @result 0 on success, -1 otherwise
 */
static int static_zebra_process_srv6_locator_add(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};

	if (!srv6_locators)
		return -1;

	/* Decode the SRv6 locator */
	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	return static_zebra_process_srv6_locator_internal(&loc);
}

/**
 * Callback to process a notification from SRv6 Manager (zebra) of an SRv6
 * locator deleted.
 *
 * @result 0 on success, -1 otherwise
 */
static int static_zebra_process_srv6_locator_delete(ZAPI_CALLBACK_ARGS)
{
	struct srv6_locator loc = {};
	struct listnode *node2, *nnode2;
	struct static_srv6_sid *sid;
	struct static_srv6_locator *locator;

	if (!srv6_locators)
		return -1;

	/* Decode the received zebra message */
	if (zapi_srv6_locator_decode(zclient->ibuf, &loc) < 0)
		return -1;

	DEBUGD(&static_dbg_srv6,
	       "%s: SRv6 locator deleted in zebra: name %s, prefix %pFX, block_len %u, node_len %u, func_len %u, arg_len %u",
	       __func__, loc.name, &loc.prefix, loc.block_bits_length, loc.node_bits_length,
	       loc.function_bits_length, loc.argument_bits_length);

	locator = static_srv6_locator_lookup(loc.name);
	if (!locator)
		return 0;

	DEBUGD(&static_dbg_srv6, "%s: Deleting srv6 sids from locator %s", __func__, locator->name);

	/* Delete SRv6 SIDs */
	for (ALL_LIST_ELEMENTS(srv6_sids, node2, nnode2, sid)) {
		if (sid->locator != locator)
			continue;


		DEBUGD(&static_dbg_srv6, "%s: Deleting SRv6 SID (locator %s, sid %pFX)", __func__,
		       locator->name, &sid->addr);

		/*
		 * Uninstall the SRv6 SID from the forwarding plane
		 * through Zebra
		 */
		if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
			static_zebra_srv6_sid_uninstall(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
		}
	}

	listnode_delete(srv6_locators, locator);
	static_srv6_locator_free(locator);

	return 0;
}

static int static_zebra_srv6_sid_notify(ZAPI_CALLBACK_ARGS)
{
	struct srv6_sid_ctx ctx;
	struct in6_addr sid_addr;
	enum zapi_srv6_sid_notify note;
	uint32_t sid_func;
	struct listnode *node;
	char buf[256];
	struct static_srv6_sid *sid = NULL;
	char *loc_name;
	bool found = false;

	if (!srv6_locators)
		return -1;

	/* Decode the received notification message */
	if (!zapi_srv6_sid_notify_decode(zclient->ibuf, &ctx, &sid_addr, &sid_func, NULL, &note,
					 &loc_name)) {
		zlog_err("%s : error in msg decode", __func__);
		return -1;
	}

	DEBUGD(&static_dbg_srv6,
	       "%s: received SRv6 SID notify: ctx %s sid_value %pI6 sid_func %u note %s", __func__,
	       srv6_sid_ctx2str(buf, sizeof(buf), &ctx), &sid_addr, sid_func,
	       zapi_srv6_sid_notify2str(note));

	/* Handle notification */
	switch (note) {
	case ZAPI_SRV6_SID_ALLOCATED:

		DEBUGD(&static_dbg_srv6, "%s: SRv6 SID %pI6 %s ALLOCATED", __func__, &sid_addr,
		       srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
			if (IPV6_ADDR_SAME(&sid->addr.prefix, &sid_addr)) {
				found = true;
				break;
			}
		}

		if (!found || !sid) {
			zlog_err("SRv6 SID %pI6 %s: not found", &sid_addr,
				 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));
			return 0;
		}

		if (!IPV6_ADDR_SAME(&ctx.nh6, &in6addr_any))
			sid->attributes.nh6 = ctx.nh6;

		SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

		/*
		 * Install the new SRv6 End SID in the forwarding plane through
		 * Zebra
		 */
		static_zebra_srv6_sid_install(sid);

		SET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);

		break;
	case ZAPI_SRV6_SID_RELEASED:

		DEBUGD(&static_dbg_srv6, "%s: SRv6 SID %pI6 %s: RELEASED", __func__, &sid_addr,
		       srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		for (ALL_LIST_ELEMENTS_RO(srv6_sids, node, sid)) {
			if (IPV6_ADDR_SAME(&sid->addr.prefix, &sid_addr)) {
				found = true;
				break;
			}
		}

		if (!found || !sid) {
			zlog_err("SRv6 SID %pI6 %s: not found", &sid_addr,
				 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));
			return 0;
		}

		UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_VALID);

		if (CHECK_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA)) {
			static_zebra_srv6_sid_uninstall(sid);
			UNSET_FLAG(sid->flags, STATIC_FLAG_SRV6_SID_SENT_TO_ZEBRA);
		}

		break;
	case ZAPI_SRV6_SID_FAIL_ALLOC:
		zlog_err("SRv6 SID %pI6 %s: Failed to allocate", &sid_addr,
			 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	case ZAPI_SRV6_SID_FAIL_RELEASE:
		zlog_err("%s: SRv6 SID %pI6 %s failure to release", __func__, &sid_addr,
			 srv6_sid_ctx2str(buf, sizeof(buf), &ctx));

		/* Error will be logged by zebra module */
		break;
	}

	return 0;
}

void static_zebra_neigh_get(struct interface *ifp, afi_t afi)
{
	if (!static_zclient || static_zclient->sock < 0) {
		zlog_err("%s: Cannot send neighbor GET request - zclient not connected", __func__);
		return;
	}

	if (!ifp) {
		zlog_err("%s: Cannot send neighbor GET request - interface is NULL", __func__);
		return;
	}

	DEBUGD(&static_dbg_events,
	       "%s: Sending neighbor GET request for interface %s (index %u), afi %u", __func__,
	       ifp->name, ifp->ifindex, afi);

	zclient_neigh_get(static_zclient, ifp, afi);
}

void static_zebra_neigh_register(afi_t afi, bool reg)
{
	DEBUGD(&static_dbg_events, "%s: Sending neighbor %s request for afi %u", __func__,
	       reg ? "register" : "unregister", afi);

	zclient_register_neigh(static_zclient, VRF_DEFAULT, afi, reg);
}

static zclient_handler *const static_handlers[] = {
	[ZEBRA_INTERFACE_ADDRESS_ADD] = interface_address_add,
	[ZEBRA_INTERFACE_ADDRESS_DELETE] = interface_address_delete,
	[ZEBRA_ROUTE_NOTIFY_OWNER] = route_notify_owner,
	[ZEBRA_SRV6_LOCATOR_ADD] = static_zebra_process_srv6_locator_add,
	[ZEBRA_SRV6_LOCATOR_DELETE] = static_zebra_process_srv6_locator_delete,
	[ZEBRA_SRV6_SID_NOTIFY] = static_zebra_srv6_sid_notify,
};

void static_zebra_init(void)
{
	hook_register_prio(if_real, 0, static_ifp_create);
	hook_register_prio(if_up, 0, static_ifp_up);
	hook_register_prio(if_down, 0, static_ifp_down);
	hook_register_prio(if_unreal, 0, static_ifp_destroy);

	static_zclient = zclient_new(master, &zclient_options_default, static_handlers,
				     array_size(static_handlers));

	zclient_init(static_zclient, ZEBRA_ROUTE_STATIC, 0, &static_privs);
	static_zclient->zebra_capabilities = static_zebra_capabilities;
	static_zclient->zebra_connected = zebra_connected;
	static_zclient->nexthop_update = static_zebra_nexthop_update;

	static_nht_hash_init(static_nht_hash);
	static_bfd_initialize(static_zclient, master);
}

/* static_zebra_stop used by tests/lib/test_grpc.cpp */
void static_zebra_stop(void)
{
	static_nht_hash_clear();
	static_nht_hash_fini(static_nht_hash);

	if (!static_zclient)
		return;
	zclient_stop(static_zclient);
	zclient_free(static_zclient);
	static_zclient = NULL;
}

void static_zebra_vrf_register(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_reg_requests(static_zclient, vrf->vrf_id);
}

void static_zebra_vrf_unregister(struct vrf *vrf)
{
	if (vrf->vrf_id == VRF_DEFAULT)
		return;
	zclient_send_dereg_requests(static_zclient, vrf->vrf_id);
}
