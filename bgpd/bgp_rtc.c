// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"

DEFINE_MTYPE(BGPD, BGP_RTC_PLIST, "BGP Route-Target Constraint prefix-list");
DEFINE_MTYPE(BGPD, BGP_RTC_PLIST_ENTRY, "BGP Route-Target Constraint prefix-list entry");
DEFINE_MTYPE(BGPD, BGP_RTC_PLIST_ENTRY_ASN, "BGP Route-Target Constraint prefix-list Origin AS");

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	int psize = 0;

	/* Iterate over all received prefixes */
	for (; pnt < lim; pnt += psize) {
		struct prefix p = { 0 };

		p.prefixlen = *pnt++;
		if ((p.prefixlen > 0 && p.prefixlen < 32) || p.prefixlen > RTC_MAX_BITLEN) {
			zlog_err("SAFI_RTC parse error. Invalid prefixlen: %u", p.prefixlen);
			return BGP_NLRI_PARSE_ERROR;
		}

		p.family = AF_RTC;
		psize = PSIZE(p.prefixlen);
		if (pnt + psize > lim) {
			zlog_err("SAFI_RTC parse error.");
			return BGP_NLRI_PARSE_ERROR;
		}

		if (p.prefixlen)
			p.u.prefix_rtc.origin_as = ntohl(*(uint32_t *)pnt);

		if (p.prefixlen > 32)
			memcpy(&p.u.prefix_rtc.route_target, pnt + 4, psize - 4);

		apply_mask(&p);

		if (withdraw || peer->as == peer->bgp->as)
			/* RFC4684 says
			 * "When processing RT membership NLRIs received from internal iBGP
			 * peers, it is necessary to consider all available iBGP paths for a
			 * given RT prefix, for building the outbound route filter, and not just
			 * the best path."
			 *
			 * (Un)set prefix-list for internal peers for all received path here.
			 *
			 * Prefixes from external peers are added if needed into prefix-list
			 * after best path computation. They can be deleted on withdraw now
			 * because they cannot be selected anymore by best path computation.
			 */
			bgp_rtc_plist_entry_set(peer, &p, !withdraw);

		if (withdraw)
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		else
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
	}

	return BGP_NLRI_PARSE_OK;
}
static void bgp_rtc_add_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], prefix);
	bgp_static = bgp_dest_get_bgp_static_info(dest);

	if (bgp_static) {
		bgp_dest_unlock_node(dest);
		return;
	}

	bgp_static = bgp_static_new();
	bgp_static->label = MPLS_INVALID_LABEL;
	bgp_static->label_index = BGP_INVALID_LABEL_INDEX;

	bgp_dest_set_bgp_static_info(dest, bgp_static);

	bgp_static->valid = 1;
	bgp_static_update(bgp, prefix, bgp_static, AFI_IP, SAFI_RTC);
}

/* Adaption of bgp_static_update */
void bgp_rtc_add_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = RTC_MAX_BITLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, sizeof(prefix.u.prefix_rtc.route_target));
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;


	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);

	attr.nexthop.s_addr = INADDR_ANY;

	bgp_attr_set_med(&attr, 0);

	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;


	if (bgp_in_graceful_shutdown(bgp))
		bgp_attr_add_gshut_community(&attr);

	attr_new = bgp_attr_intern(&attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	if (pi) {
		bgp_attr_unintern(&attr_new);
		bgp_dest_unlock_node(dest);
		return;
	}
	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_new, dest);

	bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, &prefix, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, new, afi, safi);

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

/* Adaption of bgp_static_withdraw */
static void bgp_rtc_remove_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], prefix);

	if (!dest)
		return;

	bgp_static_withdraw(bgp, prefix, AFI_IP, SAFI_RTC, NULL);

	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static)
		bgp_static_free(bgp_static);

	bgp_dest_set_bgp_static_info(dest, NULL);
	bgp_dest_unlock_node(dest);
}

void bgp_rtc_remove_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = RTC_MAX_BITLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, sizeof(prefix.u.prefix_rtc.route_target));

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	/* Check selected route and self inserted route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	/* Withdraw static BGP route from routing table. */
	if (pi) {
		SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
		bgp_aggregate_decrement(bgp, &prefix, pi, afi, safi);
		bgp_unlink_nexthop(pi);
		bgp_path_info_delete(dest, pi);
		bgp_process(bgp, dest, pi, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
	bgp_dest_unlock_node(dest);
}

/* Is "ecom_val" rt value used in "ecom" list ? */
static bool bgp_rtc_is_rt_used(struct ecommunity *ecom, struct ecommunity_val *ecom_val)
{
	struct ecommunity_val *pnt;
	uint32_t i;

	for (i = 0, pnt = (struct ecommunity_val *)ecom->val; i < ecom->size;
	     pnt += ecom->unit_size, i++) {
		if (!memcmp(pnt, ecom_val, ecom->unit_size))
			return true;
	}

	return false;
}

void bgp_rtc_update_vpn_policy_ecommunity_dynamic(struct bgp *bgp, afi_t afi,
						  struct ecommunity *old_ecom,
						  struct ecommunity *new_ecom)
{
	struct ecommunity *ecom_iter;
	struct listnode *node;
	struct bgp *bgp_iter;
	afi_t afi_iter;
	bool rt_used;
	uint8_t *pnt;
	uint32_t i;

	if (!bgp_get_default())
		return;

	if (old_ecom) {
		/* Withdraw the previous values that are not present:
		 * - in the new values
		 * - in any other BGP instance
		 */
		for (i = 0, pnt = old_ecom->val; i < old_ecom->size;
		     pnt += old_ecom->unit_size, i++) {
			if (new_ecom && bgp_rtc_is_rt_used(new_ecom, (struct ecommunity_val *)pnt))
				/* The RT value is present in the new set. Do not remote it */
				continue;

			rt_used = false;

			/* Check if the value if present in any other BGP instance */
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_iter)) {
				if (bgp_iter->inst_type == BGP_INSTANCE_TYPE_VIEW)
					continue;
				for (afi_iter = AFI_IP; afi_iter <= AFI_IP6; ++afi_iter) {
					if (bgp_iter == bgp && afi_iter == afi)
						continue;
					ecom_iter = bgp_iter->vpn_policy[afi_iter]
							    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN];
					if (!ecom_iter)
						continue;

					if (bgp_rtc_is_rt_used(ecom_iter,
							       (struct ecommunity_val *)pnt)) {
						rt_used = true;
						break;
					}
				}
				if (rt_used)
					break;
			}

			if (rt_used)
				continue;

			bgp_rtc_remove_ecommunity_val_dynamic(bgp_get_default(),
							      (struct ecommunity_val *)pnt);
		}
	}

	if (new_ecom) {
		/* Add new RT values */
		for (i = 0, pnt = new_ecom->val; i < new_ecom->size; pnt += new_ecom->unit_size, i++)
			bgp_rtc_add_ecommunity_val_dynamic(bgp_get_default(),
							   (struct ecommunity_val *)pnt);
	}
}

int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add)
{
	struct prefix prefix = {};
	char prefix_str[RTC_ADDR_STRLEN];

	if (!strstr(str, ":RT:") && !strstr(str, ":rt:") && !strstr(str, ":rT:") &&
	    !strstr(str, ":Rt:"))
		snprintf(prefix_str, sizeof(prefix_str), "%u:RT:%s", bgp->as, str);
	else
		snprintf(prefix_str, sizeof(prefix_str), "%s", str);

	if (!str2prefix(prefix_str, &prefix)) {
		vty_out(vty, "Unable to decode prefix %s\n", prefix_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&prefix);

	if (add)
		bgp_rtc_add_static(bgp, &prefix);
	else
		bgp_rtc_remove_static(bgp, &prefix);

	return CMD_SUCCESS;
}

char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
			     const struct rtc_info *rtc_info)
{
	char *cbuf = buf;

	if (prefix_len >= 48 && prefix_len <= 96)
		/* Only prefixes with a length of at least 48 have the
		 * type and subtype field set that can indentify the
		 * Extended Community as a route-target.
		 */
		snprintfrr(buf, size, "%u:%s", rtc_info->origin_as,
			   ecommunity_rt_str(rtc_info->route_target));
	else if (prefix_len > 32 && prefix_len < 48)
		snprintfrr(buf, size, "%u:UNK", rtc_info->origin_as);
	else if (prefix_len == 32)
		snprintfrr(buf, size, "%u:RT:0", rtc_info->origin_as);
	else if (prefix_len == 0)
		snprintfrr(buf, size, "0:RT:0");
	else
		snprintfrr(buf, size, "UNK-RTC");

	return cbuf;
}

static as_t *bgp_rtc_plist_entry_asn_new(void)
{
	return XCALLOC(MTYPE_BGP_RTC_PLIST_ENTRY_ASN, sizeof(as_t));
}

static void bgp_rtc_plist_entry_asn_free(void *arg)
{
	as_t *origin_as = arg;

	XFREE(MTYPE_BGP_RTC_PLIST_ENTRY_ASN, origin_as);
}

static struct bgp_rtc_plist_entry *bgp_rtc_plist_entry_new(void)
{
	struct bgp_rtc_plist_entry *rtc_pentry;

	rtc_pentry = XCALLOC(MTYPE_BGP_RTC_PLIST_ENTRY, sizeof(struct bgp_rtc_plist_entry));
	rtc_pentry->origin_as = list_new();
	rtc_pentry->origin_as->del = bgp_rtc_plist_entry_asn_free;

	return rtc_pentry;
}

static void bgp_rtc_plist_entry_free(void *args)
{
	struct bgp_rtc_plist_entry *rtc_pentry = args;

	list_delete(&rtc_pentry->origin_as);

	XFREE(MTYPE_BGP_RTC_PLIST_ENTRY, rtc_pentry);
}

static struct bgp_rtc_plist *bgp_rtc_plist_new(void)
{
	struct bgp_rtc_plist *rtc_plist;

	rtc_plist = XCALLOC(MTYPE_BGP_RTC_PLIST, sizeof(struct bgp_rtc_plist));
	rtc_plist->entries = list_new();
	rtc_plist->entries->del = bgp_rtc_plist_entry_free;

	return rtc_plist;
}

void bgp_rtc_plist_free(void *arg)
{
	struct bgp_rtc_plist *rtc_plist = arg;

	list_delete(&rtc_plist->entries);

	XFREE(MTYPE_BGP_RTC_PLIST, rtc_plist);
}

/* Add a RTC prefix p into rtc_plist RTC prefix-list
 *
 * Return 0 if the entry was already present and nothing has been done.
 * Return 1 instead if the entry was added.
 */
static int bgp_rtc_plist_entry_add(struct bgp_rtc_plist *rtc_plist, struct prefix *p)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	as_t *origin_as = NULL;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(rtc_plist->entries, node, rtc_pentry)) {
		if (memcmp(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
			   sizeof(rtc_pentry->route_target)))
			continue;
		if (rtc_pentry->prefixlen == p->prefixlen)
			break;
	}

	if (!rtc_pentry) {
		rtc_pentry = bgp_rtc_plist_entry_new();
		memcpy(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
		       sizeof(rtc_pentry->route_target));
		rtc_pentry->prefixlen = p->prefixlen;

		origin_as = bgp_rtc_plist_entry_asn_new();
		*origin_as = p->u.prefix_rtc.origin_as;

		listnode_add(rtc_pentry->origin_as, origin_as);
		listnode_add(rtc_plist->entries, rtc_pentry);

		return 1;
	}

	for (ALL_LIST_ELEMENTS_RO(rtc_pentry->origin_as, node, origin_as)) {
		if (*origin_as == p->u.prefix_rtc.origin_as)
			break;
	}

	if (!origin_as) {
		origin_as = bgp_rtc_plist_entry_asn_new();
		*origin_as = p->u.prefix_rtc.origin_as;

		listnode_add(rtc_pentry->origin_as, origin_as);

		return 1;
	}

	return 0;
}

/* Delete a RTC prefix p from rtc_plist RTC prefix-list
 *
 * Return 0 if no entry was found.
 * Return 1 instead if an entry was actually removed.
 */
static int bgp_rtc_plist_entry_del(struct bgp_rtc_plist *rtc_plist, struct prefix *p)
{
	struct bgp_rtc_plist_entry *rtc_pentry = NULL;
	struct listnode *enode, *nenode, *asnode, *nasnode;
	as_t *origin_as = NULL;
	int ret = 0;

	for (ALL_LIST_ELEMENTS(rtc_plist->entries, enode, nenode, rtc_pentry)) {
		if (memcmp(rtc_pentry->route_target, &p->u.prefix_rtc.route_target,
			   sizeof(rtc_pentry->route_target)))
			continue;
		if (rtc_pentry->prefixlen != p->prefixlen)
			continue;
		for (ALL_LIST_ELEMENTS(rtc_pentry->origin_as, asnode, nasnode, origin_as)) {
			if (*origin_as != p->u.prefix_rtc.origin_as)
				continue;
			listnode_delete(rtc_pentry->origin_as, origin_as);
			bgp_rtc_plist_entry_asn_free(origin_as);
			ret = 1;
			break;
		}
		if (!list_isempty(rtc_pentry->origin_as))
			break;

		listnode_delete(rtc_plist->entries, rtc_pentry);
		bgp_rtc_plist_entry_free(rtc_pentry);
		break;
	}

	return ret;
}

static void bgp_peer_init_rtc_plist(struct peer *peer)
{
	peer->rtc_plist = bgp_rtc_plist_new();
	peer->rtc_plist->router_id.s_addr = peer->remote_id.s_addr;

	listnode_add(peer->bgp->rtc_plists, peer->rtc_plist);
}

struct bgp_rtc_plist *bgp_peer_get_rtc_plist(struct peer *peer)
{
	struct bgp_rtc_plist *rtc_plist = NULL;
	struct listnode *node;

	if (peer->rtc_plist)
		return peer->rtc_plist;

	if (!peer->remote_id.s_addr)
		return NULL;

	if (peer->afc_nego[AFI_IP][SAFI_RTC]) {
		bgp_peer_init_rtc_plist(peer);

		return peer->rtc_plist;
	}

	for (ALL_LIST_ELEMENTS_RO(peer->bgp->rtc_plists, node, rtc_plist)) {
		if (!IPV4_ADDR_CMP(&rtc_plist->router_id, &peer->remote_id))
			return rtc_plist;
	}

	return NULL;
}

int bgp_rtc_plist_entry_set(struct peer *peer, struct prefix *p, bool add)
{
	if (!peer->rtc_plist)
		bgp_peer_init_rtc_plist(peer);

	if (add)
		return bgp_rtc_plist_entry_add(peer->rtc_plist, p);

	return bgp_rtc_plist_entry_del(peer->rtc_plist, p);
}

void bgp_rtc_init(void)
{
	prefix_set_rtc_display_hook(bgp_rtc_prefix_display);
}
