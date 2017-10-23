/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2016 6WIND
 * Copyright (C) 2017 Cumulus Networks, Inc.
 *
 * This file is part of FRR.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"
#include "bitfield.h"
#include "zclient.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"

/*
 * Definitions and external declarations.
 */
extern struct zclient *zclient;

DEFINE_QOBJ_TYPE(bgpevpn)


/*
 * Static function declarations
 */
static void delete_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				    afi_t afi, safi_t safi, struct bgp_node *rn,
				    struct bgp_info **ri);
static int delete_all_vni_routes(struct bgp *bgp, struct bgpevpn *vpn);

/*
 * Private functions.
 */

/*
 * Make vni hash key.
 */
static unsigned int vni_hash_key_make(void *p)
{
	struct bgpevpn *vpn = p;
	return (jhash_1word(vpn->vni, 0));
}

/*
 * Comparison function for vni hash
 */
static int vni_hash_cmp(const void *p1, const void *p2)
{
	const struct bgpevpn *vpn1 = p1;
	const struct bgpevpn *vpn2 = p2;

	if (!vpn1 && !vpn2)
		return 1;
	if (!vpn1 || !vpn2)
		return 0;
	return (vpn1->vni == vpn2->vni);
}

/*
 * Make import route target hash key.
 */
static unsigned int import_rt_hash_key_make(void *p)
{
	struct irt_node *irt = p;
	char *pnt = irt->rt.val;
	unsigned int key = 0;
	int c = 0;

	key += pnt[c];
	key += pnt[c + 1];
	key += pnt[c + 2];
	key += pnt[c + 3];
	key += pnt[c + 4];
	key += pnt[c + 5];
	key += pnt[c + 6];
	key += pnt[c + 7];

	return (key);
}

/*
 * Comparison function for import rt hash
 */
static int import_rt_hash_cmp(const void *p1, const void *p2)
{
	const struct irt_node *irt1 = p1;
	const struct irt_node *irt2 = p2;

	if (irt1 == NULL && irt2 == NULL)
		return 1;

	if (irt1 == NULL || irt2 == NULL)
		return 0;

	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
}

/*
 * Create a new import_rt
 */
static struct irt_node *import_rt_new(struct bgp *bgp,
				      struct ecommunity_val *rt)
{
	struct irt_node *irt;

	if (!bgp)
		return NULL;

	irt = XCALLOC(MTYPE_BGP_EVPN_IMPORT_RT, sizeof(struct irt_node));
	if (!irt)
		return NULL;

	irt->rt = *rt;
	irt->vnis = list_new();

	/* Add to hash */
	if (!hash_get(bgp->import_rt_hash, irt, hash_alloc_intern)) {
		XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
		return NULL;
	}

	return irt;
}

/*
 * Free the import rt node
 */
static void import_rt_free(struct bgp *bgp, struct irt_node *irt)
{
	hash_release(bgp->import_rt_hash, irt);
	XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
}

/*
 * Function to lookup Import RT node - used to map a RT to set of
 * VNIs importing routes with that RT.
 */
static struct irt_node *lookup_import_rt(struct bgp *bgp,
					 struct ecommunity_val *rt)
{
	struct irt_node *irt;
	struct irt_node tmp;

	memset(&tmp, 0, sizeof(struct irt_node));
	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
	irt = hash_lookup(bgp->import_rt_hash, &tmp);
	return irt;
}

/*
 * Is specified VNI present on the RT's list of "importing" VNIs?
 */
static int is_vni_present_in_irt_vnis(struct list *vnis, struct bgpevpn *vpn)
{
	struct listnode *node, *nnode;
	struct bgpevpn *tmp_vpn;

	for (ALL_LIST_ELEMENTS(vnis, node, nnode, tmp_vpn)) {
		if (tmp_vpn == vpn)
			return 1;
	}

	return 0;
}

/*
 * Compare Route Targets.
 */
static int evpn_route_target_cmp(struct ecommunity *ecom1,
				 struct ecommunity *ecom2)
{
	if (ecom1 && !ecom2)
		return -1;

	if (!ecom1 && ecom2)
		return 1;

	if (!ecom1 && !ecom2)
		return 0;

	if (ecom1->str && !ecom2->str)
		return -1;

	if (!ecom1->str && ecom2->str)
		return 1;

	if (!ecom1->str && !ecom2->str)
		return 0;

	return strcmp(ecom1->str, ecom2->str);
}

/*
 * Mask off global-admin field of specified extended community (RT),
 * just retain the local-admin field.
 */
static inline void mask_ecom_global_admin(struct ecommunity_val *dst,
					  struct ecommunity_val *src)
{
	u_char type;

	type = src->val[0];
	dst->val[0] = 0;
	if (type == ECOMMUNITY_ENCODE_AS) {
		dst->val[2] = dst->val[3] = 0;
	} else if (type == ECOMMUNITY_ENCODE_AS4
		   || type == ECOMMUNITY_ENCODE_IP) {
		dst->val[2] = dst->val[3] = 0;
		dst->val[4] = dst->val[5] = 0;
	}
}

/*
 * Map one RT to specified VNI.
 */
static void map_vni_to_rt(struct bgp *bgp, struct bgpevpn *vpn,
			  struct ecommunity_val *eval)
{
	struct irt_node *irt;
	struct ecommunity_val eval_tmp;

	/* If using "automatic" RT, we only care about the local-admin
	 * sub-field.
	 * This is to facilitate using VNI as the RT for EBGP peering too.
	 */
	memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
	if (!is_import_rt_configured(vpn))
		mask_ecom_global_admin(&eval_tmp, eval);

	irt = lookup_import_rt(bgp, &eval_tmp);
	if (irt && irt->vnis)
		if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
			/* Already mapped. */
			return;

	if (!irt) {
		irt = import_rt_new(bgp, &eval_tmp);
		assert(irt);
	}

	/* Add VNI to the hash list for this RT. */
	listnode_add(irt->vnis, vpn);
}

/*
 * Unmap specified VNI from specified RT. If there are no other
 * VNIs for this RT, then the RT hash is deleted.
 */
static void unmap_vni_from_rt(struct bgp *bgp, struct bgpevpn *vpn,
			      struct irt_node *irt)
{
	/* Delete VNI from hash list for this RT. */
	listnode_delete(irt->vnis, vpn);
	if (!listnode_head(irt->vnis)) {
		list_delete_and_null(&irt->vnis);
		import_rt_free(bgp, irt);
	}
}

/*
 * Create RT extended community automatically from passed information:
 * of the form AS:VNI.
 * NOTE: We use only the lower 16 bits of the AS. This is sufficient as
 * the need is to get a RT value that will be unique across different
 * VNIs but the same across routers (in the same AS) for a particular
 * VNI.
 */
static void form_auto_rt(struct bgp *bgp, struct bgpevpn *vpn, struct list *rtl)
{
	struct ecommunity_val eval;
	struct ecommunity *ecomadd;

	encode_route_target_as((bgp->as & 0xFFFF), vpn->vni, &eval);

	ecomadd = ecommunity_new();
	ecommunity_add_val(ecomadd, &eval);
	listnode_add_sort(rtl, ecomadd);
}

/*
 * Derive RD and RT for a VNI automatically. Invoked at the time of
 * creation of a VNI.
 */
static void derive_rd_rt_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	bgp_evpn_derive_auto_rd(bgp, vpn);
	bgp_evpn_derive_auto_rt_import(bgp, vpn);
	bgp_evpn_derive_auto_rt_export(bgp, vpn);
}

/*
 * Add (update) or delete MACIP from zebra.
 */
static int bgp_zebra_send_remote_macip(struct bgp *bgp, struct bgpevpn *vpn,
				       struct prefix_evpn *p,
				       struct in_addr remote_vtep_ip, int add,
				       u_char sticky)
{
	struct stream *s;
	int ipa_len;
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[INET6_ADDRSTRLEN];
	char buf3[INET6_ADDRSTRLEN];

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, add ? ZEBRA_REMOTE_MACIP_ADD
				     : ZEBRA_REMOTE_MACIP_DEL,
			      bgp->vrf_id);
	stream_putl(s, vpn->vni);
	stream_put(s, &p->prefix.mac.octet, ETH_ALEN); /* Mac Addr */
	/* IP address length and IP address, if any. */
	if (IS_EVPN_PREFIX_IPADDR_NONE(p))
		stream_putl(s, 0);
	else {
		ipa_len = IS_EVPN_PREFIX_IPADDR_V4(p) ? IPV4_MAX_BYTELEN
						      : IPV6_MAX_BYTELEN;
		stream_putl(s, ipa_len);
		stream_put(s, &p->prefix.ip.ip.addr, ipa_len);
	}
	stream_put_in_addr(s, &remote_vtep_ip);

	/* TX MAC sticky status */
	if (add)
		stream_putc(s, sticky);

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL))
		zlog_debug("Tx %s MACIP, VNI %u %sMAC %s IP %s remote VTEP %s",
			   add ? "ADD" : "DEL", vpn->vni,
			   sticky ? "sticky " : "",
			   prefix_mac2str(&p->prefix.mac, buf1, sizeof(buf1)),
			   ipaddr2str(&p->prefix.ip, buf3, sizeof(buf3)),
			   inet_ntop(AF_INET, &remote_vtep_ip, buf2,
				     sizeof(buf2)));

	return zclient_send_message(zclient);
}

/*
 * Add (update) or delete remote VTEP from zebra.
 */
static int bgp_zebra_send_remote_vtep(struct bgp *bgp, struct bgpevpn *vpn,
				      struct prefix_evpn *p, int add)
{
	struct stream *s;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
		return 0;

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(s, add ? ZEBRA_REMOTE_VTEP_ADD
				     : ZEBRA_REMOTE_VTEP_DEL,
			      bgp->vrf_id);
	stream_putl(s, vpn->vni);
	if (IS_EVPN_PREFIX_IPADDR_V4(p))
		stream_put_in_addr(s, &p->prefix.ip.ipaddr_v4);
	else if (IS_EVPN_PREFIX_IPADDR_V6(p)) {
		zlog_err(
			"Bad remote IP when trying to %s remote VTEP for VNI %u",
			add ? "ADD" : "DEL", vpn->vni);
		return -1;
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL))
		zlog_debug("Tx %s Remote VTEP, VNI %u remote VTEP %s",
			   add ? "ADD" : "DEL", vpn->vni,
			   inet_ntoa(p->prefix.ip.ipaddr_v4));

	return zclient_send_message(zclient);
}

/*
 * Build extended communities for EVPN route. RT and ENCAP are
 * applicable to all routes.
 */
static void build_evpn_route_extcomm(struct bgpevpn *vpn, struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_sticky;
	struct ecommunity_val eval;
	struct ecommunity_val eval_sticky;
	bgp_encap_types tnl_type;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	u_int32_t seqnum;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.val = (u_int8_t *)eval.val;

	/* Add Encap */
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* Add the export RTs */
	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom))
		attr->ecommunity = ecommunity_merge(attr->ecommunity, ecom);

	if (attr->sticky) {
		seqnum = 0;
		memset(&ecom_sticky, 0, sizeof(ecom_sticky));
		encode_mac_mobility_extcomm(1, seqnum, &eval_sticky);
		ecom_sticky.size = 1;
		ecom_sticky.val = (u_int8_t *)eval_sticky.val;
		attr->ecommunity =
			ecommunity_merge(attr->ecommunity, &ecom_sticky);
	}

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
}

/*
 * Add MAC mobility extended community to attribute.
 */
static void add_mac_mobility_to_attr(u_int32_t seq_num, struct attr *attr)
{
	struct ecommunity ecom_tmp;
	struct ecommunity_val eval;
	u_int8_t *ecom_val_ptr;
	int i;
	u_int8_t *pnt;
	int type = 0;
	int sub_type = 0;

	/* Build MM */
	encode_mac_mobility_extcomm(0, seq_num, &eval);

	/* Find current MM ecommunity */
	ecom_val_ptr = NULL;

	if (attr->ecommunity) {
		for (i = 0; i < attr->ecommunity->size; i++) {
			pnt = attr->ecommunity->val + (i * 8);
			type = *pnt++;
			sub_type = *pnt++;

			if (type == ECOMMUNITY_ENCODE_EVPN
			    && sub_type
				       == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY) {
				ecom_val_ptr =
					(u_int8_t *)(attr->ecommunity->val
						     + (i * 8));
				break;
			}
		}
	}

	/* Update the existing MM ecommunity */
	if (ecom_val_ptr) {
		memcpy(ecom_val_ptr, eval.val, sizeof(char) * ECOMMUNITY_SIZE);
	}
	/* Add MM to existing */
	else {
		memset(&ecom_tmp, 0, sizeof(ecom_tmp));
		ecom_tmp.size = 1;
		ecom_tmp.val = (u_int8_t *)eval.val;

		attr->ecommunity =
			ecommunity_merge(attr->ecommunity, &ecom_tmp);
	}
}

/* Install EVPN route into zebra. */
static int evpn_zebra_install(struct bgp *bgp, struct bgpevpn *vpn,
			      struct prefix_evpn *p,
			      struct in_addr remote_vtep_ip, u_char sticky)
{
	int ret;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ret = bgp_zebra_send_remote_macip(bgp, vpn, p, remote_vtep_ip,
						  1, sticky);
	else
		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p, 1);

	return ret;
}

/* Uninstall EVPN route from zebra. */
static int evpn_zebra_uninstall(struct bgp *bgp, struct bgpevpn *vpn,
				struct prefix_evpn *p,
				struct in_addr remote_vtep_ip)
{
	int ret;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ret = bgp_zebra_send_remote_macip(bgp, vpn, p, remote_vtep_ip,
						  0, 0);
	else
		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p, 0);

	return ret;
}

/*
 * Due to MAC mobility, the prior "local" best route has been supplanted
 * by a "remote" best route. The prior route has to be deleted and withdrawn
 * from peers.
 */
static void evpn_delete_old_local_route(struct bgp *bgp, struct bgpevpn *vpn,
					struct bgp_node *rn,
					struct bgp_info *old_local)
{
	struct bgp_node *global_rn;
	struct bgp_info *ri;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
					(struct prefix *)&rn->p, &vpn->prd);
	if (global_rn) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, vpn, afi, safi, global_rn, &ri);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (ri)
			bgp_process(bgp, global_rn, afi, safi);
		bgp_unlock_node(global_rn);
	}

	/* Delete route entry in the VNI route table, caller to remove. */
	bgp_info_delete(rn, old_local);
}

/*
 * Calculate the best path for an EVPN route. Install/update best path in zebra,
 * if appropriate.
 */
static int evpn_route_select_install(struct bgp *bgp, struct bgpevpn *vpn,
				     struct bgp_node *rn)
{
	struct bgp_info *old_select, *new_select;
	struct bgp_info_pair old_and_new;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int ret = 0;

	/* Compute the best path. */
	bgp_best_selection(bgp, rn, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/* If the best path hasn't changed - see if there is still something to
	 * update
	 * to zebra RIB.
	 */
	if (old_select && old_select == new_select
	    && old_select->type == ZEBRA_ROUTE_BGP
	    && old_select->sub_type == BGP_ROUTE_NORMAL
	    && !CHECK_FLAG(rn->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_INFO_ATTR_CHANGED)
	    && !bgp->addpath_tx_used[afi][safi]) {
		if (bgp_zebra_has_route_changed(rn, old_select))
			ret = evpn_zebra_install(bgp, vpn,
						 (struct prefix_evpn *)&rn->p,
						 old_select->attr->nexthop,
						 old_select->attr->sticky);
		UNSET_FLAG(old_select->flags, BGP_INFO_MULTIPATH_CHG);
		bgp_zebra_clear_route_change_flags(rn);
		return ret;
	}

	/* If the user did a "clear" this flag will be set */
	UNSET_FLAG(rn->flags, BGP_NODE_USER_CLEAR);

	/* bestpath has changed; update relevant fields and install or uninstall
	 * into the zebra RIB.
	 */
	if (old_select || new_select)
		bgp_bump_version(rn);

	if (old_select)
		bgp_info_unset_flag(rn, old_select, BGP_INFO_SELECTED);
	if (new_select) {
		bgp_info_set_flag(rn, new_select, BGP_INFO_SELECTED);
		bgp_info_unset_flag(rn, new_select, BGP_INFO_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_INFO_MULTIPATH_CHG);
	}

	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
	    && new_select->sub_type == BGP_ROUTE_NORMAL) {
		ret = evpn_zebra_install(bgp, vpn, (struct prefix_evpn *)&rn->p,
					 new_select->attr->nexthop,
					 new_select->attr->sticky);
		/* If an old best existed and it was a "local" route, the only
		 * reason
		 * it would be supplanted is due to MAC mobility procedures. So,
		 * we
		 * need to do an implicit delete and withdraw that route from
		 * peers.
		 */
		if (old_select && old_select->peer == bgp->peer_self
		    && old_select->type == ZEBRA_ROUTE_BGP
		    && old_select->sub_type == BGP_ROUTE_STATIC)
			evpn_delete_old_local_route(bgp, vpn, rn, old_select);
	} else {
		if (old_select && old_select->type == ZEBRA_ROUTE_BGP
		    && old_select->sub_type == BGP_ROUTE_NORMAL)
			ret = evpn_zebra_uninstall(bgp, vpn,
						   (struct prefix_evpn *)&rn->p,
						   old_select->attr->nexthop);
	}

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(rn);

	/* Reap old select bgp_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_INFO_REMOVED))
		bgp_info_reap(rn, old_select);

	return ret;
}


/*
 * Return true if the local ri for this rn has sticky set
 */
static int evpn_route_is_sticky(struct bgp *bgp, struct bgp_node *rn)
{
	struct bgp_info *tmp_ri;
	struct bgp_info *local_ri;

	local_ri = NULL;
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next) {
		if (tmp_ri->peer == bgp->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			local_ri = tmp_ri;
	}

	if (!local_ri)
		return 0;

	return local_ri->attr->sticky;
}

/*
 * Create or update EVPN route entry. This could be in the VNI route table
 * or the global route table.
 */
static int update_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				   afi_t afi, safi_t safi, struct bgp_node *rn,
				   struct attr *attr, int add, int vni_table,
				   struct bgp_info **ri, u_char flags)
{
	struct bgp_info *tmp_ri;
	struct bgp_info *local_ri, *remote_ri;
	struct attr *attr_new;
	mpls_label_t label = MPLS_INVALID_LABEL;
	int route_change = 1;
	u_char sticky = 0;

	*ri = NULL;

	/* See if this is an update of an existing route, or a new add. Also,
	 * identify if already known from remote, and if so, the one with the
	 * highest sequence number; this is only when adding to the VNI routing
	 * table.
	 */
	local_ri = remote_ri = NULL;
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next) {
		if (tmp_ri->peer == bgp->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			local_ri = tmp_ri;
		if (vni_table) {
			if (tmp_ri->type == ZEBRA_ROUTE_BGP
			    && tmp_ri->sub_type == BGP_ROUTE_NORMAL
			    && CHECK_FLAG(tmp_ri->flags, BGP_INFO_VALID)) {
				if (!remote_ri)
					remote_ri = tmp_ri;
				else if (mac_mobility_seqnum(tmp_ri->attr)
					 > mac_mobility_seqnum(remote_ri->attr))
					remote_ri = tmp_ri;
			}
		}
	}

	/* If route doesn't exist already, create a new one, if told to.
	 * Otherwise act based on whether the attributes of the route have
	 * changed or not.
	 */
	if (!local_ri && !add)
		return 0;

	if (!local_ri) {
		/* When learnt locally for the first time but already known from
		 * remote, we have to initiate appropriate MAC mobility steps.
		 * This
		 * is applicable when updating the VNI routing table.
		 * We need to skip mobility steps for g/w macs (local mac on g/w
		 * SVI) advertised in EVPN.
		 * This will ensure that local routes are preferred for g/w macs
		 */
		if (remote_ri && !CHECK_FLAG(flags, ZEBRA_MAC_TYPE_GW)) {
			u_int32_t cur_seqnum;

			/* Add MM extended community to route. */
			cur_seqnum = mac_mobility_seqnum(remote_ri->attr);
			add_mac_mobility_to_attr(cur_seqnum + 1, attr);
		}

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(attr);

		/* Extract MAC mobility sequence number, if any. */
		attr_new->mm_seqnum =
			bgp_attr_mac_mobility_seqnum(attr_new, &sticky);
		attr_new->sticky = sticky;

		/* Create new route with its attribute. */
		tmp_ri = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
				   bgp->peer_self, attr_new, rn);
		SET_FLAG(tmp_ri->flags, BGP_INFO_VALID);
		bgp_info_extra_get(tmp_ri);

		/* The VNI goes into the 'label' field of the route */
		vni2label(vpn->vni, &label);

		memcpy(&tmp_ri->extra->label, &label, BGP_LABEL_BYTES);
		bgp_info_add(rn, tmp_ri);
	} else {
		tmp_ri = local_ri;
		if (attrhash_cmp(tmp_ri->attr, attr)
		    && !CHECK_FLAG(tmp_ri->flags, BGP_INFO_REMOVED))
			route_change = 0;
		else {
			/* The attribute has changed. */
			/* Add (or update) attribute to hash. */
			attr_new = bgp_attr_intern(attr);
			bgp_info_set_flag(rn, tmp_ri, BGP_INFO_ATTR_CHANGED);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_ri->flags, BGP_INFO_REMOVED))
				bgp_info_restore(rn, tmp_ri);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_ri->attr);
			tmp_ri->attr = attr_new;
			tmp_ri->uptime = bgp_clock();
		}
	}

	/* Return back the route entry. */
	*ri = tmp_ri;
	return route_change;
}

/*
 * Create or update EVPN route (of type based on prefix) for specified VNI
 * and schedule for processing.
 */
static int update_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
			     struct prefix_evpn *p, u_char flags)
{
	struct bgp_node *rn;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_info *ri;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int route_change;

	memset(&attr, 0, sizeof(struct attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	attr.nexthop = vpn->originator_ip;
	attr.mp_nexthop_global_in = vpn->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr.sticky = CHECK_FLAG(flags, ZEBRA_MAC_TYPE_STICKY) ? 1 : 0;

	/* Set up RT and ENCAP extended community. */
	build_evpn_route_extcomm(vpn, &attr);

	/* First, create (or fetch) route node within the VNI. */
	/* NOTE: There is no RD here. */
	rn = bgp_node_get(vpn->route_table, (struct prefix *)p);

	/* Create or update route entry. */
	route_change = update_evpn_route_entry(bgp, vpn, afi, safi, rn, &attr,
					       1, 1, &ri, flags);
	assert(ri);
	attr_new = ri->attr;

	/* Perform route selection; this is just to set the flags correctly
	 * as local route in the VNI always wins.
	 */
	evpn_route_select_install(bgp, vpn, rn);
	bgp_unlock_node(rn);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_change) {
		struct bgp_info *global_ri;

		rn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
				      (struct prefix *)p, &vpn->prd);
		update_evpn_route_entry(bgp, vpn, afi, safi, rn, attr_new, 1, 0,
					&global_ri, flags);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, rn, afi, safi);
		bgp_unlock_node(rn);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);

	return 0;
}

/*
 * Delete EVPN route entry. This could be in the VNI route table
 * or the global route table.
 */
static void delete_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				    afi_t afi, safi_t safi, struct bgp_node *rn,
				    struct bgp_info **ri)
{
	struct bgp_info *tmp_ri;

	*ri = NULL;

	/* Now, find matching route. */
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next)
		if (tmp_ri->peer == bgp->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			break;

	*ri = tmp_ri;

	/* Mark route for delete. */
	if (tmp_ri)
		bgp_info_delete(rn, tmp_ri);
}

/*
 * Delete EVPN route (of type based on prefix) for specified VNI and
 * schedule for processing.
 */
static int delete_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
			     struct prefix_evpn *p)
{
	struct bgp_node *rn, *global_rn;
	struct bgp_info *ri;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* First, locate the route node within the VNI. If it doesn't exist,
	 * there
	 * is nothing further to do.
	 */
	/* NOTE: There is no RD here. */
	rn = bgp_node_lookup(vpn->route_table, (struct prefix *)p);
	if (!rn)
		return 0;

	/* Next, locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
					(struct prefix *)p, &vpn->prd);
	if (global_rn) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, vpn, afi, safi, global_rn, &ri);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (ri)
			bgp_process(bgp, global_rn, afi, safi);
		bgp_unlock_node(global_rn);
	}

	/* Delete route entry in the VNI route table. This can just be removed.
	 */
	delete_evpn_route_entry(bgp, vpn, afi, safi, rn, &ri);
	if (ri)
		bgp_info_reap(rn, ri);
	bgp_unlock_node(rn);

	return 0;
}

/*
 * Update all type-2 (MACIP) local routes for this VNI - these should also
 * be scheduled for advertise to peers.
 */
static int update_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rn;
	struct bgp_info *ri;
	struct attr attr;
	struct attr attr_sticky;
	struct attr *attr_new;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	memset(&attr, 0, sizeof(struct attr));
	memset(&attr_sticky, 0, sizeof(struct attr));

	/* Build path-attribute - all type-2 routes for this VNI will share the
	 * same path attribute.
	 */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	bgp_attr_default_set(&attr_sticky, BGP_ORIGIN_IGP);
	attr.nexthop = vpn->originator_ip;
	attr.mp_nexthop_global_in = vpn->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_sticky.nexthop = vpn->originator_ip;
	attr_sticky.mp_nexthop_global_in = vpn->originator_ip;
	attr_sticky.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_sticky.sticky = 1;

	/* Set up RT, ENCAP and sticky MAC extended community. */
	build_evpn_route_extcomm(vpn, &attr);
	build_evpn_route_extcomm(vpn, &attr_sticky);

	/* Walk this VNI's route table and update local type-2 routes. For any
	 * routes updated, update corresponding entry in the global table too.
	 */
	for (rn = bgp_table_top(vpn->route_table); rn;
	     rn = bgp_route_next(rn)) {
		struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;
		struct bgp_node *rd_rn;
		struct bgp_info *global_ri;

		if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
			continue;

		if (evpn_route_is_sticky(bgp, rn))
			update_evpn_route_entry(bgp, vpn, afi, safi, rn,
						&attr_sticky, 0, 1, &ri, 0);
		else
			update_evpn_route_entry(bgp, vpn, afi, safi, rn, &attr,
						0, 1, &ri, 0);

		/* If a local route exists for this prefix, we need to update
		 * the global routing table too.
		 */
		if (!ri)
			continue;

		/* Perform route selection; this is just to set the flags
		 * correctly
		 * as local route in the VNI always wins.
		 */
		evpn_route_select_install(bgp, vpn, rn);

		attr_new = ri->attr;

		/* Update route in global routing table. */
		rd_rn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
					 (struct prefix *)evp, &vpn->prd);
		assert(rd_rn);
		update_evpn_route_entry(bgp, vpn, afi, safi, rd_rn, attr_new, 0,
					0, &global_ri, 0);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, rd_rn, afi, safi);
		bgp_unlock_node(rd_rn);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
	aspath_unintern(&attr_sticky.aspath);

	return 0;
}

/*
 * Delete all type-2 (MACIP) local routes for this VNI - only from the
 * global routing table. These are also scheduled for withdraw from peers.
 */
static int delete_global_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rdrn, *rn;
	struct bgp_table *table;
	struct bgp_info *ri;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	rdrn = bgp_node_lookup(bgp->rib[afi][safi], (struct prefix *)&vpn->prd);
	if (rdrn && rdrn->info) {
		table = (struct bgp_table *)rdrn->info;
		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
			struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
				continue;

			delete_evpn_route_entry(bgp, vpn, afi, safi, rn, &ri);
			if (ri)
				bgp_process(bgp, rn, afi, safi);
		}
	}

	/* Unlock RD node. */
	if (rdrn)
		bgp_unlock_node(rdrn);

	return 0;
}

/*
 * Delete all type-2 (MACIP) local routes for this VNI - from the global
 * table as well as the per-VNI route table.
 */
static int delete_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rn;
	struct bgp_info *ri;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* First, walk the global route table for this VNI's type-2 local
	 * routes.
	 * EVPN routes are a 2-level table, first get the RD table.
	 */
	delete_global_type2_routes(bgp, vpn);

	/* Next, walk this VNI's route table and delete local type-2 routes. */
	for (rn = bgp_table_top(vpn->route_table); rn;
	     rn = bgp_route_next(rn)) {
		struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

		if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
			continue;

		delete_evpn_route_entry(bgp, vpn, afi, safi, rn, &ri);

		/* Route entry in local table gets deleted immediately. */
		if (ri)
			bgp_info_reap(rn, ri);
	}

	return 0;
}

/*
 * Delete all routes in the per-VNI route table.
 */
static int delete_all_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct bgp_node *rn;
	struct bgp_info *ri, *nextri;

	/* Walk this VNI's route table and delete all routes. */
	for (rn = bgp_table_top(vpn->route_table); rn;
	     rn = bgp_route_next(rn)) {
		for (ri = rn->info; (ri != NULL) && (nextri = ri->next, 1);
		     ri = nextri) {
			bgp_info_delete(rn, ri);
			bgp_info_reap(rn, ri);
		}
	}

	return 0;
}

/*
 * Update (and advertise) local routes for a VNI. Invoked upon the VNI
 * export RT getting modified or change to tunnel IP. Note that these
 * situations need the route in the per-VNI table as well as the global
 * table to be updated (as attributes change).
 */
static int update_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;
	struct prefix_evpn p;

	/* Update and advertise the type-3 route (only one) followed by the
	 * locally learnt type-2 routes (MACIP) - for this VNI.
	 */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	ret = update_evpn_route(bgp, vpn, &p, 0);
	if (ret)
		return ret;

	return update_all_type2_routes(bgp, vpn);
}

/*
 * Delete (and withdraw) local routes for specified VNI from the global
 * table and per-VNI table. After this, remove all other routes from
 * the per-VNI table. Invoked upon the VNI being deleted or EVPN
 * (advertise-all-vni) being disabled.
 */
static int delete_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;
	struct prefix_evpn p;

	/* Delete and withdraw locally learnt type-2 routes (MACIP)
	 * followed by type-3 routes (only one) - for this VNI.
	 */
	ret = delete_all_type2_routes(bgp, vpn);
	if (ret)
		return ret;

	build_evpn_type3_prefix(&p, vpn->originator_ip);
	ret = delete_evpn_route(bgp, vpn, &p);
	if (ret)
		return ret;

	/* Delete all routes from the per-VNI table. */
	return delete_all_vni_routes(bgp, vpn);
}

/*
 * There is a tunnel endpoint IP address change for this VNI,
 * need to re-advertise routes with the new nexthop.
 */
static int handle_tunnel_ip_change(struct bgp *bgp, struct bgpevpn *vpn,
				   struct in_addr originator_ip)
{
	struct prefix_evpn p;

	/* If VNI is not live, we only need to update the originator ip */
	if (!is_vni_live(vpn)) {
		vpn->originator_ip = originator_ip;
		return 0;
	}

	/* Update the tunnel-ip hash */
	bgp_tip_del(bgp, &vpn->originator_ip);
	bgp_tip_add(bgp, &originator_ip);

	/* filter routes as martian nexthop db has changed */
	bgp_filter_evpn_routes_upon_martian_nh_change(bgp);

	/* Need to withdraw type-3 route as the originator IP is part
	 * of the key.
	 */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	delete_evpn_route(bgp, vpn, &p);

	/* Update the tunnel IP and re-advertise all routes for this VNI. */
	vpn->originator_ip = originator_ip;
	return update_routes_for_vni(bgp, vpn);
}

/*
 * Install route entry into the VNI routing table and invoke route selection.
 */
static int install_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				    struct prefix_evpn *p,
				    struct bgp_info *parent_ri)
{
	struct bgp_node *rn;
	struct bgp_info *ri;
	struct attr *attr_new;
	int ret;

	/* Create (or fetch) route within the VNI. */
	/* NOTE: There is no RD here. */
	rn = bgp_node_get(vpn->route_table, (struct prefix *)p);

	/* Check if route entry is already present. */
	for (ri = rn->info; ri; ri = ri->next)
		if (ri->extra
		    && (struct bgp_info *)ri->extra->parent == parent_ri)
			break;

	if (!ri) {
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_ri->attr);

		/* Create new route with its attribute. */
		ri = info_make(parent_ri->type, parent_ri->sub_type, 0,
			       parent_ri->peer, attr_new, rn);
		SET_FLAG(ri->flags, BGP_INFO_VALID);
		bgp_info_extra_get(ri);
		ri->extra->parent = parent_ri;
		if (parent_ri->extra)
			memcpy(&ri->extra->label, &parent_ri->extra->label,
			       BGP_LABEL_BYTES);
		bgp_info_add(rn, ri);
	} else {
		if (attrhash_cmp(ri->attr, parent_ri->attr)
		    && !CHECK_FLAG(ri->flags, BGP_INFO_REMOVED)) {
			bgp_unlock_node(rn);
			return 0;
		}
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_ri->attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(ri->flags, BGP_INFO_REMOVED))
			bgp_info_restore(rn, ri);

		/* Mark if nexthop has changed. */
		if (!IPV4_ADDR_SAME(&ri->attr->nexthop, &attr_new->nexthop))
			SET_FLAG(ri->flags, BGP_INFO_IGP_CHANGED);

		/* Unintern existing, set to new. */
		bgp_attr_unintern(&ri->attr);
		ri->attr = attr_new;
		ri->uptime = bgp_clock();
	}

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, vpn, rn);

	return ret;
}

/*
 * Uninstall route entry from the VNI routing table and send message
 * to zebra, if appropriate.
 */
static int uninstall_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				      struct prefix_evpn *p,
				      struct bgp_info *parent_ri)
{
	struct bgp_node *rn;
	struct bgp_info *ri;
	int ret;

	/* Locate route within the VNI. */
	/* NOTE: There is no RD here. */
	rn = bgp_node_lookup(vpn->route_table, (struct prefix *)p);
	if (!rn)
		return 0;

	/* Find matching route entry. */
	for (ri = rn->info; ri; ri = ri->next)
		if (ri->extra
		    && (struct bgp_info *)ri->extra->parent == parent_ri)
			break;

	if (!ri)
		return 0;

	/* Mark entry for deletion */
	bgp_info_delete(rn, ri);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, vpn, rn);

	/* Unlock route node. */
	bgp_unlock_node(rn);

	return ret;
}

/*
 * Given a route entry and a VNI, see if this route entry should be
 * imported into the VNI i.e., RTs match.
 */
static int is_route_matching_for_vni(struct bgp *bgp, struct bgpevpn *vpn,
				     struct bgp_info *ri)
{
	struct attr *attr = ri->attr;
	struct ecommunity *ecom;
	int i;

	assert(attr);
	/* Route should have valid RT to be even considered. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return 0;

	/* For each extended community RT, see if it matches this VNI. If any RT
	 * matches, we're done.
	 */
	for (i = 0; i < ecom->size; i++) {
		u_char *pnt;
		u_char type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct irt_node *irt;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* See if this RT matches specified VNIs import RTs */
		irt = lookup_import_rt(bgp, eval);
		if (irt && irt->vnis)
			if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
				return 1;

		/* Also check for non-exact match. In this, we mask out the AS
		 * and
		 * only check on the local-admin sub-field. This is to
		 * facilitate using
		 * VNI as the RT for EBGP peering too.
		 */
		irt = NULL;
		if (type == ECOMMUNITY_ENCODE_AS
		    || type == ECOMMUNITY_ENCODE_AS4
		    || type == ECOMMUNITY_ENCODE_IP) {
			memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
			mask_ecom_global_admin(&eval_tmp, eval);
			irt = lookup_import_rt(bgp, &eval_tmp);
		}
		if (irt && irt->vnis)
			if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
				return 1;
	}

	return 0;
}

/*
 * Install or uninstall routes of specified type that are appropriate for this
 * particular VNI.
 */
static int install_uninstall_routes_for_vni(struct bgp *bgp,
					    struct bgpevpn *vpn,
					    bgp_evpn_route_type rtype,
					    int install)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rd_rn, *rn;
	struct bgp_table *table;
	struct bgp_info *ri;
	int ret;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this VPN. Note that we cannot just look at the routes
	 * for
	 * the VNI's RD - remote routes applicable for this VNI could have any
	 * RD.
	 */
	/* EVPN routes are a 2-level table. */
	for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn;
	     rd_rn = bgp_route_next(rd_rn)) {
		table = (struct bgp_table *)(rd_rn->info);
		if (!table)
			continue;

		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
			struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

			if (evp->prefix.route_type != rtype)
				continue;

			for (ri = rn->info; ri; ri = ri->next) {
				/* Consider "valid" remote routes applicable for
				 * this VNI. */
				if (!(CHECK_FLAG(ri->flags, BGP_INFO_VALID)
				      && ri->type == ZEBRA_ROUTE_BGP
				      && ri->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (is_route_matching_for_vni(bgp, vpn, ri)) {
					if (install)
						ret = install_evpn_route_entry(
							bgp, vpn, evp, ri);
					else
						ret = uninstall_evpn_route_entry(
							bgp, vpn, evp, ri);

					if (ret) {
						zlog_err(
							"%u: Failed to %s EVPN %s route in VNI %u",
							bgp->vrf_id,
							install ? "install"
								: "uninstall",
							rtype == BGP_EVPN_MAC_IP_ROUTE
								? "MACIP"
								: "IMET",
							vpn->vni);
						return ret;
					}
				}
			}
		}
	}

	return 0;
}

/*
 * Install any existing remote routes applicable for this VNI into its
 * routing table. This is invoked when a VNI becomes "live" or its Import
 * RT is changed.
 */
static int install_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;

	/* Install type-3 routes followed by type-2 routes - the ones applicable
	 * for this VNI.
	 */
	ret = install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_IMET_ROUTE,
					       1);
	if (ret)
		return ret;

	return install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_MAC_IP_ROUTE,
						1);
}

/*
 * Uninstall any existing remote routes for this VNI. One scenario in which
 * this is invoked is upon an import RT change.
 */
static int uninstall_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;

	/* Uninstall type-2 routes followed by type-3 routes - the ones
	 * applicable
	 * for this VNI.
	 */
	ret = install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_MAC_IP_ROUTE,
					       0);
	if (ret)
		return ret;

	return install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_IMET_ROUTE,
						0);
}

/*
 * Install or uninstall route in matching VNIs (list).
 */
static int install_uninstall_route_in_vnis(struct bgp *bgp, afi_t afi,
					   safi_t safi, struct prefix_evpn *evp,
					   struct bgp_info *ri,
					   struct list *vnis, int install)
{
	struct bgpevpn *vpn;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(vnis, node, nnode, vpn)) {
		int ret;

		if (!is_vni_live(vpn))
			continue;

		if (install)
			ret = install_evpn_route_entry(bgp, vpn, evp, ri);
		else
			ret = uninstall_evpn_route_entry(bgp, vpn, evp, ri);

		if (ret) {
			zlog_err("%u: Failed to %s EVPN %s route in VNI %u",
				 bgp->vrf_id, install ? "install" : "uninstall",
				 evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
					 ? "MACIP"
					 : "IMET",
				 vpn->vni);
			return ret;
		}
	}

	return 0;
}

/*
 * Install or uninstall route for appropriate VNIs.
 */
static int install_uninstall_evpn_route(struct bgp *bgp, afi_t afi, safi_t safi,
					struct prefix *p, struct bgp_info *ri,
					int import)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	struct attr *attr = ri->attr;
	struct ecommunity *ecom;
	int i;

	assert(attr);

	/* Only type-2 and type-3 routes go into a L2 VNI. */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IMET_ROUTE))
		return 0;

	/* If we don't have Route Target, nothing much to do. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return -1;

	/* For each extended community RT, see which VNIs match and import
	 * the route into matching VNIs.
	 */
	for (i = 0; i < ecom->size; i++) {
		u_char *pnt;
		u_char type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct irt_node *irt;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* Are we interested in this RT? */
		irt = lookup_import_rt(bgp, eval);
		if (irt && irt->vnis)
			install_uninstall_route_in_vnis(bgp, afi, safi, evp, ri,
							irt->vnis, import);

		/* Also check for non-exact match. In this, we mask out the AS
		 * and
		 * only check on the local-admin sub-field. This is to
		 * facilitate using
		 * VNI as the RT for EBGP peering too.
		 */
		irt = NULL;
		if (type == ECOMMUNITY_ENCODE_AS
		    || type == ECOMMUNITY_ENCODE_AS4
		    || type == ECOMMUNITY_ENCODE_IP) {
			memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
			mask_ecom_global_admin(&eval_tmp, eval);
			irt = lookup_import_rt(bgp, &eval_tmp);
		}
		if (irt && irt->vnis)
			install_uninstall_route_in_vnis(bgp, afi, safi, evp, ri,
							irt->vnis, import);
	}

	return 0;
}

/*
 * Update and advertise local routes for a VNI. Invoked upon router-id
 * change. Note that the processing is done only on the global route table
 * using routes that already exist in the per-VNI table.
 */
static int update_advertise_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct prefix_evpn p;
	struct bgp_node *rn, *global_rn;
	struct bgp_info *ri, *global_ri;
	struct attr *attr;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Locate type-3 route for VNI in the per-VNI table and use its
	 * attributes to create and advertise the type-3 route for this VNI
	 * in the global table.
	 */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	rn = bgp_node_lookup(vpn->route_table, (struct prefix *)&p);
	if (!rn) /* unexpected */
		return 0;
	for (ri = rn->info; ri; ri = ri->next)
		if (ri->peer == bgp->peer_self && ri->type == ZEBRA_ROUTE_BGP
		    && ri->sub_type == BGP_ROUTE_STATIC)
			break;
	if (!ri) /* unexpected */
		return 0;
	attr = ri->attr;

	global_rn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
				     (struct prefix *)&p, &vpn->prd);
	update_evpn_route_entry(bgp, vpn, afi, safi, global_rn, attr, 1, 0, &ri,
				0);

	/* Schedule for processing and unlock node. */
	bgp_process(bgp, global_rn, afi, safi);
	bgp_unlock_node(global_rn);

	/* Now, walk this VNI's route table and use the route and its attribute
	 * to create and schedule route in global table.
	 */
	for (rn = bgp_table_top(vpn->route_table); rn;
	     rn = bgp_route_next(rn)) {
		struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

		/* Identify MAC-IP local routes. */
		if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
			continue;

		for (ri = rn->info; ri; ri = ri->next)
			if (ri->peer == bgp->peer_self
			    && ri->type == ZEBRA_ROUTE_BGP
			    && ri->sub_type == BGP_ROUTE_STATIC)
				break;
		if (!ri)
			continue;

		/* Create route in global routing table using this route entry's
		 * attribute.
		 */
		attr = ri->attr;
		global_rn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi,
					     (struct prefix *)evp, &vpn->prd);
		assert(global_rn);
		update_evpn_route_entry(bgp, vpn, afi, safi, global_rn, attr, 1,
					0, &global_ri, 0);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, global_rn, afi, safi);
		bgp_unlock_node(global_rn);
	}

	return 0;
}

/*
 * Delete (and withdraw) local routes for a VNI - only from the global
 * table. Invoked upon router-id change.
 */
static int delete_withdraw_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;
	struct prefix_evpn p;
	struct bgp_node *global_rn;
	struct bgp_info *ri;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Delete and withdraw locally learnt type-2 routes (MACIP)
	 * for this VNI - from the global table.
	 */
	ret = delete_global_type2_routes(bgp, vpn);
	if (ret)
		return ret;

	/* Remove type-3 route for this VNI from global table. */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	global_rn = bgp_afi_node_lookup(bgp->rib[afi][safi], afi, safi,
					(struct prefix *)&p, &vpn->prd);
	if (global_rn) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, vpn, afi, safi, global_rn, &ri);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (ri)
			bgp_process(bgp, global_rn, afi, safi);
		bgp_unlock_node(global_rn);
	}

	return 0;
}

/*
 * Handle router-id change. Update and advertise local routes corresponding
 * to this VNI from peers. Note that this is invoked after updating the
 * router-id. The routes in the per-VNI table are used to create routes in
 * the global table and schedule them.
 */
static void update_router_id_vni(struct hash_backet *backet, struct bgp *bgp)
{
	struct bgpevpn *vpn;

	vpn = (struct bgpevpn *)backet->data;

	if (!vpn) {
		zlog_warn("%s: VNI hash entry for VNI not found", __FUNCTION__);
		return;
	}

	/* Skip VNIs with configured RD. */
	if (is_rd_configured(vpn))
		return;

	bgp_evpn_derive_auto_rd(bgp, vpn);
	update_advertise_vni_routes(bgp, vpn);
}

/*
 * Handle router-id change. Delete and withdraw local routes corresponding
 * to this VNI from peers. Note that this is invoked prior to updating
 * the router-id and is done only on the global route table, the routes
 * are needed in the per-VNI table to re-advertise with new router id.
 */
static void withdraw_router_id_vni(struct hash_backet *backet, struct bgp *bgp)
{
	struct bgpevpn *vpn;

	vpn = (struct bgpevpn *)backet->data;

	if (!vpn) {
		zlog_warn("%s: VNI hash entry for VNI not found", __FUNCTION__);
		return;
	}

	/* Skip VNIs with configured RD. */
	if (is_rd_configured(vpn))
		return;

	delete_withdraw_vni_routes(bgp, vpn);
}

/*
 * Process received EVPN type-2 route (advertise or withdraw).
 */
static int process_type2_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, u_char *pfx, int psize,
			       u_int32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	u_char ipaddr_len;
	u_char macaddr_len;
	mpls_label_t *label_pnt;
	int ret;

	/* Type-2 route should be either 33, 37 or 49 bytes or an
	 * additional 3 bytes if there is a second label (VNI):
	 * RD (8), ESI (10), Eth Tag (4), MAC Addr Len (1),
	 * MAC Addr (6), IP len (1), IP (0, 4 or 16),
	 * MPLS Lbl1 (3), MPLS Lbl2 (0 or 3)
	 */
	if (psize != 33 && psize != 37 && psize != 49 && psize != 36
	    && psize != 40 && psize != 52) {
		zlog_err("%u:%s - Rx EVPN Type-2 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(struct prefix_evpn));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_TYPE_2_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;

	/* Skip over Ethernet Seg Identifier for now. */
	pfx += 10;

	/* Skip over Ethernet Tag for now. */
	pfx += 4;

	/* Get the MAC Addr len */
	macaddr_len = *pfx++;

	/* Get the MAC Addr */
	if (macaddr_len == (ETH_ALEN * 8)) {
		memcpy(&p.prefix.mac.octet, pfx, ETH_ALEN);
		pfx += ETH_ALEN;
	} else {
		zlog_err(
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported MAC address length %d",
			peer->bgp->vrf_id, peer->host, macaddr_len);
		return -1;
	}


	/* Get the IP. */
	ipaddr_len = *pfx++;
	if (ipaddr_len != 0 && ipaddr_len != IPV4_MAX_BITLEN
	    && ipaddr_len != IPV6_MAX_BITLEN) {
		zlog_err(
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	if (ipaddr_len) {
		ipaddr_len /= 8; /* Convert to bytes. */
		p.prefix.ip.ipa_type = (ipaddr_len == IPV4_MAX_BYTELEN)
					       ? IPADDR_V4
					       : IPADDR_V6;
		memcpy(&p.prefix.ip.ip.addr, pfx, ipaddr_len);
	}
	pfx += ipaddr_len;

	/* Get the VNI (in MPLS label field). */
	/* Note: We ignore the second VNI, if any. */
	label_pnt = (mpls_label_t *)pfx;

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, label_pnt, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, label_pnt, NULL);
	return ret;
}

/*
 * Process received EVPN type-3 route (advertise or withdraw).
 */
static int process_type3_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, u_char *pfx, int psize,
			       u_int32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	u_char ipaddr_len;
	int ret;

	/* Type-3 route should be either 17 or 29 bytes: RD (8), Eth Tag (4),
	 * IP len (1) and IP (4 or 16).
	 */
	if (psize != 17 && psize != 29) {
		zlog_err("%u:%s - Rx EVPN Type-3 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(struct prefix_evpn));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_IMET_ROUTE;

	/* Skip over Ethernet Tag for now. */
	pfx += 4;

	/* Get the IP. */
	ipaddr_len = *pfx++;
	if (ipaddr_len == IPV4_MAX_BITLEN) {
		p.prefix.ip.ipa_type = IPADDR_V4;
		memcpy(&p.prefix.ip.ip.addr, pfx, IPV4_MAX_BYTELEN);
	} else {
		zlog_err(
			"%u:%s - Rx EVPN Type-3 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, NULL, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, NULL);
	return ret;
}

/*
 * Process received EVPN type-5 route (advertise or withdraw).
 */
static int process_type5_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, u_char *pfx, int psize,
			       u_int32_t addpath_id, int withdraw)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	struct bgp_route_evpn evpn;
	u_char ippfx_len;
	u_int32_t eth_tag;
	mpls_label_t *label_pnt;
	int ret;

	/* Type-5 route should be 34 or 58 bytes:
	 * RD (8), ESI (10), Eth Tag (4), IP len (1), IP (4 or 16),
	 * GW (4 or 16) and VNI (3).
	 * Note that the IP and GW should both be IPv4 or both IPv6.
	 */
	if (psize != 34 && psize != 58) {
		zlog_err("%u:%s - Rx EVPN Type-5 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(struct prefix_evpn));
	p.family = AF_EVPN;
	p.prefix.route_type = BGP_EVPN_IP_PREFIX_ROUTE;

	/* Additional information outside of prefix - ESI and GW IP */
	memset(&evpn, 0, sizeof(evpn));

	/* Fetch ESI */
	memcpy(&evpn.eth_s_id.val, pfx, 10);
	pfx += 10;

	/* Fetch Ethernet Tag. */
	memcpy(&eth_tag, pfx, 4);
	p.prefix.eth_tag = ntohl(eth_tag);
	pfx += 4;

	/* Fetch IP prefix length. */
	ippfx_len = *pfx++;
	if (ippfx_len > IPV6_MAX_BITLEN) {
		zlog_err(
			"%u:%s - Rx EVPN Type-5 NLRI with invalid IP Prefix length %d",
			peer->bgp->vrf_id, peer->host, ippfx_len);
		return -1;
	}
	p.prefix.ip_prefix_length = ippfx_len;

	/* Determine IPv4 or IPv6 prefix */
	/* Since the address and GW are from the same family, this just becomes
	 * a simple check on the total size.
	 */
	if (psize == 34) {
		SET_IPADDR_V4(&p.prefix.ip);
		memcpy(&p.prefix.ip.ipaddr_v4, pfx, 4);
		pfx += 4;
		memcpy(&evpn.gw_ip.ipv4, pfx, 4);
		pfx += 4;
		p.prefixlen = PREFIX_LEN_ROUTE_TYPE_5_IPV4;
	} else {
		SET_IPADDR_V6(&p.prefix.ip);
		memcpy(&p.prefix.ip.ipaddr_v6, pfx, 16);
		pfx += 16;
		memcpy(&evpn.gw_ip.ipv6, pfx, 16);
		pfx += 16;
		p.prefixlen = PREFIX_LEN_ROUTE_TYPE_5_IPV6;
	}

	label_pnt = (mpls_label_t *)pfx;

	/* Process the route. */
	if (!withdraw)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, label_pnt, 0, &evpn);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, label_pnt, &evpn);

	return ret;
}

static void evpn_mpattr_encode_type5(struct stream *s, struct prefix *p,
				     struct prefix_rd *prd, mpls_label_t *label,
				     struct attr *attr)
{
	int len;
	char temp[16];
	struct evpn_addr *p_evpn_p;

	memset(&temp, 0, 16);
	if (p->family != AF_EVPN)
		return;
	p_evpn_p = &(p->u.prefix_evpn);

	if (IS_IPADDR_V4(&p_evpn_p->ip))
		len = 8; /* ipv4 */
	else
		len = 32; /* ipv6 */
	/* Prefix contains RD, ESI, EthTag, IP length, IP, GWIP and VNI */
	stream_putc(s, 8 + 10 + 4 + 1 + len + 3);
	stream_put(s, prd->val, 8);
	if (attr)
		stream_put(s, &(attr->evpn_overlay.eth_s_id), 10);
	else
		stream_put(s, &temp, 10);
	stream_putl(s, p_evpn_p->eth_tag);
	stream_putc(s, p_evpn_p->ip_prefix_length);
	if (IS_IPADDR_V4(&p_evpn_p->ip))
		stream_put_ipv4(s, p_evpn_p->ip.ipaddr_v4.s_addr);
	else
		stream_put(s, &p_evpn_p->ip.ipaddr_v6, 16);
	if (attr) {
		if (IS_IPADDR_V4(&p_evpn_p->ip))
			stream_put_ipv4(s,
					attr->evpn_overlay.gw_ip.ipv4.s_addr);
		else
			stream_put(s, &(attr->evpn_overlay.gw_ip.ipv6), 16);
	} else {
		if (IS_IPADDR_V4(&p_evpn_p->ip))
			stream_put_ipv4(s, 0);
		else
			stream_put(s, &temp, 16);
	}

	if (label)
		stream_put(s, label, 3);
	else
		stream_put3(s, 0);
}

/*
 * Cleanup specific VNI upon EVPN (advertise-all-vni) being disabled.
 */
static void cleanup_vni_on_disable(struct hash_backet *backet, struct bgp *bgp)
{
	struct bgpevpn *vpn = (struct bgpevpn *)backet->data;

	/* Remove EVPN routes and schedule for processing. */
	delete_routes_for_vni(bgp, vpn);

	/* Clear "live" flag and see if hash needs to be freed. */
	UNSET_FLAG(vpn->flags, VNI_FLAG_LIVE);
	if (!is_vni_configured(vpn))
		bgp_evpn_free(bgp, vpn);
}

/*
 * Free a VNI entry; iterator function called during cleanup.
 */
static void free_vni_entry(struct hash_backet *backet, struct bgp *bgp)
{
	struct bgpevpn *vpn;

	vpn = (struct bgpevpn *)backet->data;
	delete_all_vni_routes(bgp, vpn);
	bgp_evpn_free(bgp, vpn);
}


/*
 * Public functions.
 */

/*
 * Handle change to BGP router id. This is invoked twice by the change
 * handler, first before the router id has been changed and then after
 * the router id has been changed. The first invocation will result in
 * local routes for all VNIs being deleted and withdrawn and the next
 * will result in the routes being re-advertised.
 */
void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw)
{
	if (withdraw)
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_backet *,
				       void *))withdraw_router_id_vni,
			     bgp);
	else
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_backet *,
				       void *))update_router_id_vni,
			     bgp);
}

/*
 * Handle change to export RT - update and advertise local routes.
 */
int bgp_evpn_handle_export_rt_change(struct bgp *bgp, struct bgpevpn *vpn)
{
	return update_routes_for_vni(bgp, vpn);
}

/*
 * Handle change to RD. This is invoked twice by the change handler,
 * first before the RD has been changed and then after the RD has
 * been changed. The first invocation will result in local routes
 * of this VNI being deleted and withdrawn and the next will result
 * in the routes being re-advertised.
 */
void bgp_evpn_handle_rd_change(struct bgp *bgp, struct bgpevpn *vpn,
			       int withdraw)
{
	if (withdraw)
		delete_withdraw_vni_routes(bgp, vpn);
	else
		update_advertise_vni_routes(bgp, vpn);
}

/*
 * Install routes for this VNI. Invoked upon change to Import RT.
 */
int bgp_evpn_install_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	return install_routes_for_vni(bgp, vpn);
}

/*
 * Uninstall all routes installed for this VNI. Invoked upon change
 * to Import RT.
 */
int bgp_evpn_uninstall_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	return uninstall_routes_for_vni(bgp, vpn);
}

/*
 * Function to display "tag" in route as a VNI.
 */
char *bgp_evpn_label2str(mpls_label_t *label, char *buf, int len)
{
	vni_t vni;

	vni = label2vni(label);
	snprintf(buf, len, "%u", vni);
	return buf;
}

/*
 * Function to convert evpn route to json format.
 * NOTE: We don't use prefix2str as the output here is a bit different.
 */
void bgp_evpn_route2json(struct prefix_evpn *p, json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[PREFIX2STR_BUFFER];

	if (!json)
		return;

	if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE) {
		json_object_int_add(json, "routeType", p->prefix.route_type);
		json_object_int_add(json, "ethTag", 0);
		json_object_int_add(json, "ipLen",
				    IS_EVPN_PREFIX_IPADDR_V4(p)
					    ? IPV4_MAX_BITLEN
					    : IPV6_MAX_BITLEN);
		json_object_string_add(json, "ip",
				       inet_ntoa(p->prefix.ip.ipaddr_v4));
	} else if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (IS_EVPN_PREFIX_IPADDR_NONE(p)) {
			json_object_int_add(json, "routeType",
					    p->prefix.route_type);
			json_object_int_add(
				json, "esi",
				0); /* TODO: we don't support esi yet */
			json_object_int_add(json, "ethTag", 0);
			json_object_int_add(json, "macLen", 8 * ETH_ALEN);
			json_object_string_add(json, "mac",
					       prefix_mac2str(&p->prefix.mac,
							      buf1,
							      sizeof(buf1)));
		} else {
			u_char family;

			family = IS_EVPN_PREFIX_IPADDR_V4(p) ? AF_INET
							     : AF_INET6;

			json_object_int_add(json, "routeType",
					    p->prefix.route_type);
			json_object_int_add(
				json, "esi",
				0); /* TODO: we don't support esi yet */
			json_object_int_add(json, "ethTag", 0);
			json_object_int_add(json, "macLen", 8 * ETH_ALEN);
			json_object_string_add(json, "mac",
					       prefix_mac2str(&p->prefix.mac,
							      buf1,
							      sizeof(buf1)));
			json_object_int_add(json, "ipLen",
					    IS_EVPN_PREFIX_IPADDR_V4(p)
						    ? IPV4_MAX_BITLEN
						    : IPV6_MAX_BITLEN);
			json_object_string_add(
				json, "ip",
				inet_ntop(family, &p->prefix.ip.ip.addr, buf2,
					  PREFIX2STR_BUFFER));
		}
	} else {
		/* Currently, this is to cater to other AF_ETHERNET code. */
	}
}

/*
 * Function to convert evpn route to string.
 * NOTE: We don't use prefix2str as the output here is a bit different.
 */
char *bgp_evpn_route2str(struct prefix_evpn *p, char *buf, int len)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[PREFIX2STR_BUFFER];

	if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE) {
		snprintf(buf, len, "[%d]:[0]:[%d]:[%s]", p->prefix.route_type,
			 IS_EVPN_PREFIX_IPADDR_V4(p) ? IPV4_MAX_BITLEN
						     : IPV6_MAX_BITLEN,
			 inet_ntoa(p->prefix.ip.ipaddr_v4));
	} else if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (IS_EVPN_PREFIX_IPADDR_NONE(p))
			snprintf(buf, len, "[%d]:[0]:[0]:[%d]:[%s]",
				 p->prefix.route_type, 8 * ETH_ALEN,
				 prefix_mac2str(&p->prefix.mac, buf1,
						sizeof(buf1)));
		else {
			u_char family;

			family = IS_EVPN_PREFIX_IPADDR_V4(p) ? AF_INET
							     : AF_INET6;
			snprintf(buf, len, "[%d]:[0]:[0]:[%d]:[%s]:[%d]:[%s]",
				 p->prefix.route_type, 8 * ETH_ALEN,
				 prefix_mac2str(&p->prefix.mac, buf1,
						sizeof(buf1)),
				 family == AF_INET ? IPV4_MAX_BITLEN
						   : IPV6_MAX_BITLEN,
				 inet_ntop(family, &p->prefix.ip.ip.addr, buf2,
					   PREFIX2STR_BUFFER));
		}
	} else {
		/* For EVPN route types not supported yet. */
		snprintf(buf, len, "(unsupported route type %d)",
			 p->prefix.route_type);
	}

	return (buf);
}

/*
 * Encode EVPN prefix in Update (MP_REACH)
 */
void bgp_evpn_encode_prefix(struct stream *s, struct prefix *p,
			    struct prefix_rd *prd, mpls_label_t *label,
			    struct attr *attr, int addpath_encode,
			    u_int32_t addpath_tx_id)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	int ipa_len = 0;

	if (addpath_encode)
		stream_putl(s, addpath_tx_id);

	/* Route type */
	stream_putc(s, evp->prefix.route_type);

	switch (evp->prefix.route_type) {
	case BGP_EVPN_MAC_IP_ROUTE:
		if (IS_EVPN_PREFIX_IPADDR_V4(evp))
			ipa_len = IPV4_MAX_BYTELEN;
		else if (IS_EVPN_PREFIX_IPADDR_V6(evp))
			ipa_len = IPV6_MAX_BYTELEN;
		stream_putc(s, 33 + ipa_len);       // 1 VNI
		stream_put(s, prd->val, 8);	 /* RD */
		stream_put(s, 0, 10);		    /* ESI */
		stream_putl(s, 0);		    /* Ethernet Tag ID */
		stream_putc(s, 8 * ETH_ALEN); /* Mac Addr Len - bits */
		stream_put(s, evp->prefix.mac.octet, 6); /* Mac Addr */
		stream_putc(s, 8 * ipa_len);		 /* IP address Length */
		if (ipa_len)
			stream_put(s, &evp->prefix.ip.ip.addr,
				   ipa_len); /* IP */
		stream_put(s, label,
			   BGP_LABEL_BYTES); /* VNI is contained in 'tag' */
		break;

	case BGP_EVPN_IMET_ROUTE:
		stream_putc(s, 17); // TODO: length - assumes IPv4 address
		stream_put(s, prd->val, 8);      /* RD */
		stream_putl(s, 0);		 /* Ethernet Tag ID */
		stream_putc(s, IPV4_MAX_BITLEN); /* IP address Length - bits */
		/* Originating Router's IP Addr */
		stream_put_in_addr(s, &evp->prefix.ip.ipaddr_v4);
		break;

	case BGP_EVPN_IP_PREFIX_ROUTE:
		/* TODO: AddPath support. */
		evpn_mpattr_encode_type5(s, p, prd, label, attr);
		break;

	default:
		break;
	}
}

int bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
			struct bgp_nlri *packet, int withdraw)
{
	u_char *pnt;
	u_char *lim;
	afi_t afi;
	safi_t safi;
	u_int32_t addpath_id;
	int addpath_encoded;
	int psize = 0;
	u_char rtype;
	u_char rlen;
	struct prefix p;

	/* Check peer status. */
	if (peer->status != Established) {
		zlog_err("%u:%s - EVPN update received in state %d",
			 peer->bgp->vrf_id, peer->host, peer->status);
		return -1;
	}

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_encoded =
		(CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		 && CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ADDPATH_AF_TX_RCV));

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		/* Deal with path-id if AddPath is supported. */
		if (addpath_encoded) {
			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return -1;

			addpath_id = ntohl(*((uint32_t *)pnt));
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* All EVPN NLRI types start with type and length. */
		if (pnt + 2 > lim)
			return -1;

		rtype = *pnt++;
		psize = rlen = *pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim)
			return -1;

		switch (rtype) {
		case BGP_EVPN_MAC_IP_ROUTE:
			if (process_type2_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				zlog_err(
					"%u:%s - Error in processing EVPN type-2 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return -1;
			}
			break;

		case BGP_EVPN_IMET_ROUTE:
			if (process_type3_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				zlog_err(
					"%u:%s - Error in processing EVPN type-3 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return -1;
			}
			break;

		case BGP_EVPN_IP_PREFIX_ROUTE:
			if (process_type5_route(peer, afi, safi, attr, pnt,
						psize, addpath_id, withdraw)) {
				zlog_err(
					"%u:%s - Error in processing EVPN type-5 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return -1;
			}
			break;

		default:
			break;
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return -1;

	return 0;
}


/*
 * Map the RTs (configured or automatically derived) of a VNI to the VNI.
 * The mapping will be used during route processing.
 */
void bgp_evpn_map_vni_to_its_rts(struct bgp *bgp, struct bgpevpn *vpn)
{
	int i;
	struct ecommunity_val *eval;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			eval = (struct ecommunity_val *)(ecom->val
							 + (i
							    * ECOMMUNITY_SIZE));
			map_vni_to_rt(bgp, vpn, eval);
		}
	}
}

/*
 * Unmap the RTs (configured or automatically derived) of a VNI from the VNI.
 */
void bgp_evpn_unmap_vni_from_its_rts(struct bgp *bgp, struct bgpevpn *vpn)
{
	int i;
	struct ecommunity_val *eval;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(vpn->import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			struct irt_node *irt;
			struct ecommunity_val eval_tmp;

			eval = (struct ecommunity_val *)(ecom->val
							 + (i
							    * ECOMMUNITY_SIZE));
			/* If using "automatic" RT, we only care about the
			 * local-admin sub-field.
			 * This is to facilitate using VNI as the RT for EBGP
			 * peering too.
			 */
			memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
			if (!is_import_rt_configured(vpn))
				mask_ecom_global_admin(&eval_tmp, eval);

			irt = lookup_import_rt(bgp, &eval_tmp);
			if (irt)
				unmap_vni_from_rt(bgp, vpn, irt);
		}
	}
}

/*
 * Derive Import RT automatically for VNI and map VNI to RT.
 * The mapping will be used during route processing.
 */
void bgp_evpn_derive_auto_rt_import(struct bgp *bgp, struct bgpevpn *vpn)
{
	form_auto_rt(bgp, vpn, vpn->import_rtl);
	UNSET_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD);

	/* Map RT to VNI */
	bgp_evpn_map_vni_to_its_rts(bgp, vpn);
}

/*
 * Derive Export RT automatically for VNI.
 */
void bgp_evpn_derive_auto_rt_export(struct bgp *bgp, struct bgpevpn *vpn)
{
	form_auto_rt(bgp, vpn, vpn->export_rtl);
	UNSET_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD);
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vni.
 */
void bgp_evpn_derive_auto_rd(struct bgp *bgp, struct bgpevpn *vpn)
{
	char buf[100];

	vpn->prd.family = AF_UNSPEC;
	vpn->prd.prefixlen = 64;
	sprintf(buf, "%s:%hu", inet_ntoa(bgp->router_id), vpn->rd_id);
	(void)str2prefix_rd(buf, &vpn->prd);
	UNSET_FLAG(vpn->flags, VNI_FLAG_RD_CFGD);
}

/*
 * Lookup VNI.
 */
struct bgpevpn *bgp_evpn_lookup_vni(struct bgp *bgp, vni_t vni)
{
	struct bgpevpn *vpn;
	struct bgpevpn tmp;

	memset(&tmp, 0, sizeof(struct bgpevpn));
	tmp.vni = vni;
	vpn = hash_lookup(bgp->vnihash, &tmp);
	return vpn;
}

/*
 * Create a new vpn - invoked upon configuration or zebra notification.
 */
struct bgpevpn *bgp_evpn_new(struct bgp *bgp, vni_t vni,
			     struct in_addr originator_ip)
{
	struct bgpevpn *vpn;

	if (!bgp)
		return NULL;

	vpn = XCALLOC(MTYPE_BGP_EVPN, sizeof(struct bgpevpn));
	if (!vpn)
		return NULL;

	/* Set values - RD and RT set to defaults. */
	vpn->vni = vni;
	vpn->originator_ip = originator_ip;

	/* Initialize route-target import and export lists */
	vpn->import_rtl = list_new();
	vpn->import_rtl->cmp = (int (*)(void *, void *))evpn_route_target_cmp;
	vpn->export_rtl = list_new();
	vpn->export_rtl->cmp = (int (*)(void *, void *))evpn_route_target_cmp;
	bf_assign_index(bgp->rd_idspace, vpn->rd_id);
	derive_rd_rt_for_vni(bgp, vpn);

	/* Initialize EVPN route table. */
	vpn->route_table = bgp_table_init(AFI_L2VPN, SAFI_EVPN);

	/* Add to hash */
	if (!hash_get(bgp->vnihash, vpn, hash_alloc_intern)) {
		XFREE(MTYPE_BGP_EVPN, vpn);
		return NULL;
	}
	QOBJ_REG(vpn, bgpevpn);
	return vpn;
}

/*
 * Free a given VPN - called in multiple scenarios such as zebra
 * notification, configuration being deleted, advertise-all-vni disabled etc.
 * This just frees appropriate memory, caller should have taken other
 * needed actions.
 */
void bgp_evpn_free(struct bgp *bgp, struct bgpevpn *vpn)
{
	bgp_table_unlock(vpn->route_table);
	bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);
	list_delete_and_null(&vpn->import_rtl);
	list_delete_and_null(&vpn->export_rtl);
	bf_release_index(bgp->rd_idspace, vpn->rd_id);
	hash_release(bgp->vnihash, vpn);
	QOBJ_UNREG(vpn);
	XFREE(MTYPE_BGP_EVPN, vpn);
}

/*
 * Import route into matching VNI(s).
 */
int bgp_evpn_import_route(struct bgp *bgp, afi_t afi, safi_t safi,
			  struct prefix *p, struct bgp_info *ri)
{
	return install_uninstall_evpn_route(bgp, afi, safi, p, ri, 1);
}

/*
 * Unimport route from matching VNI(s).
 */
int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
			    struct prefix *p, struct bgp_info *ri)
{
	return install_uninstall_evpn_route(bgp, afi, safi, p, ri, 0);
}

/* filter routes which have martian next hops */
int bgp_filter_evpn_routes_upon_martian_nh_change(struct bgp *bgp)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rd_rn, *rn;
	struct bgp_table *table;
	struct bgp_info *ri;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this VPN. Note that we cannot just look at the routes
	 * for the VNI's RD -
	 * remote routes applicable for this VNI could have any RD.
	 */
	/* EVPN routes are a 2-level table. */
	for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn;
	     rd_rn = bgp_route_next(rd_rn)) {
		table = (struct bgp_table *)(rd_rn->info);
		if (!table)
			continue;

		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {

			for (ri = rn->info; ri; ri = ri->next) {

				/* Consider "valid" remote routes applicable for
				 * this VNI. */
				if (!(ri->type == ZEBRA_ROUTE_BGP
				      && ri->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (bgp_nexthop_self(bgp, ri->attr->nexthop)) {

					char attr_str[BUFSIZ];
					char pbuf[PREFIX_STRLEN];

					bgp_dump_attr(ri->attr, attr_str,
						      BUFSIZ);

					if (bgp_debug_update(ri->peer, &rn->p,
							     NULL, 1))
						zlog_debug(
							"%u: prefix %s with attr %s - DENIED due to martian or self nexthop",
							bgp->vrf_id,
							prefix2str(
								&rn->p, pbuf,
								sizeof(pbuf)),
							attr_str);

					bgp_evpn_unimport_route(bgp, afi, safi,
								&rn->p, ri);

					bgp_rib_remove(rn, ri, ri->peer, afi,
						       safi);
				}
			}
		}
	}

	return 0;
}

/*
 * Handle del of a local MACIP.
 */
int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
			     struct ipaddr *ip)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;

	if (!bgp->vnihash) {
		zlog_err("%u: VNI hash not created", bgp->vrf_id);
		return -1;
	}

	/* Lookup VNI hash - should exist. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn || !is_vni_live(vpn)) {
		zlog_warn("%u: VNI hash entry for VNI %u %s at MACIP DEL",
			  bgp->vrf_id, vni, vpn ? "not live" : "not found");
		return -1;
	}

	/* Remove EVPN type-2 route and schedule for processing. */
	build_evpn_type2_prefix(&p, mac, ip);
	delete_evpn_route(bgp, vpn, &p);

	return 0;
}

/*
 * Handle add of a local MACIP.
 */
int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
			     struct ipaddr *ip, u_char flags)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;

	if (!bgp->vnihash) {
		zlog_err("%u: VNI hash not created", bgp->vrf_id);
		return -1;
	}

	/* Lookup VNI hash - should exist. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn || !is_vni_live(vpn)) {
		zlog_warn("%u: VNI hash entry for VNI %u %s at MACIP ADD",
			  bgp->vrf_id, vni, vpn ? "not live" : "not found");
		return -1;
	}

	/* Create EVPN type-2 route and schedule for processing. */
	build_evpn_type2_prefix(&p, mac, ip);
	if (update_evpn_route(bgp, vpn, &p, flags)) {
		char buf[ETHER_ADDR_STRLEN];
		char buf2[INET6_ADDRSTRLEN];

		zlog_err(
			"%u:Failed to create Type-2 route, VNI %u %s MAC %s IP %s",
			bgp->vrf_id, vpn->vni,
			CHECK_FLAG(flags, ZEBRA_MAC_TYPE_STICKY) ? "sticky gateway"
								 : "",
			prefix_mac2str(mac, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)));
		return -1;
	}

	return 0;
}

/*
 * Handle del of a local VNI.
 */
int bgp_evpn_local_vni_del(struct bgp *bgp, vni_t vni)
{
	struct bgpevpn *vpn;

	if (!bgp->vnihash) {
		zlog_err("%u: VNI hash not created", bgp->vrf_id);
		return -1;
	}

	/* Locate VNI hash */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn) {
		zlog_warn("%u: VNI hash entry for VNI %u not found at DEL",
			  bgp->vrf_id, vni);
		return 0;
	}

	/* Remove all local EVPN routes and schedule for processing (to
	 * withdraw from peers).
	 */
	delete_routes_for_vni(bgp, vpn);

	/*
	 * tunnel is no longer active, del tunnel ip address from tip_hash
	 */
	bgp_tip_del(bgp, &vpn->originator_ip);

	/* Clear "live" flag and see if hash needs to be freed. */
	UNSET_FLAG(vpn->flags, VNI_FLAG_LIVE);
	if (!is_vni_configured(vpn))
		bgp_evpn_free(bgp, vpn);

	return 0;
}

/*
 * Handle add (or update) of a local VNI. The only VNI change we care
 * about is change to local-tunnel-ip.
 */
int bgp_evpn_local_vni_add(struct bgp *bgp, vni_t vni,
			   struct in_addr originator_ip)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;

	if (!bgp->vnihash) {
		zlog_err("%u: VNI hash not created", bgp->vrf_id);
		return -1;
	}

	/* Lookup VNI. If present and no change, exit. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (vpn) {
		if (is_vni_live(vpn)
		    && IPV4_ADDR_SAME(&vpn->originator_ip, &originator_ip))
			/* Probably some other param has changed that we don't
			 * care about. */
			return 0;

		/* Local tunnel endpoint IP address has changed */
		handle_tunnel_ip_change(bgp, vpn, originator_ip);
	}

	/* Create or update as appropriate. */
	if (!vpn) {
		vpn = bgp_evpn_new(bgp, vni, originator_ip);
		if (!vpn) {
			zlog_err(
				"%u: Failed to allocate VNI entry for VNI %u - at Add",
				bgp->vrf_id, vni);
			return -1;
		}
	}

	/* if the VNI is live already, there is nothing more to do */
	if (is_vni_live(vpn))
		return 0;

	/* Mark as "live" */
	SET_FLAG(vpn->flags, VNI_FLAG_LIVE);

	/* tunnel is now active, add tunnel-ip to db */
	bgp_tip_add(bgp, &originator_ip);

	/* filter routes as nexthop database has changed */
	bgp_filter_evpn_routes_upon_martian_nh_change(bgp);

	/* Create EVPN type-3 route and schedule for processing. */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	if (update_evpn_route(bgp, vpn, &p, 0)) {
		zlog_err("%u: Type3 route creation failure for VNI %u",
			 bgp->vrf_id, vni);
		return -1;
	}

	/* If we have learnt and retained remote routes (VTEPs, MACs) for this
	 * VNI,
	 * install them.
	 */
	install_routes_for_vni(bgp, vpn);

	/* If we are advertising gateway mac-ip
	   It needs to be conveyed again to zebra */
	bgp_zebra_advertise_gw_macip(bgp, vpn->advertise_gw_macip, vpn->vni);

	return 0;
}

/*
 * Cleanup EVPN information on disable - Need to delete and withdraw
 * EVPN routes from peers.
 */
void bgp_evpn_cleanup_on_disable(struct bgp *bgp)
{
	hash_iterate(bgp->vnihash, (void (*)(struct hash_backet *,
					     void *))cleanup_vni_on_disable,
		     bgp);
}

/*
 * Cleanup EVPN information - invoked at the time of bgpd exit or when the
 * BGP instance (default) is being freed.
 */
void bgp_evpn_cleanup(struct bgp *bgp)
{
	if (bgp->vnihash)
		hash_iterate(bgp->vnihash, (void (*)(struct hash_backet *,
						     void *))free_vni_entry,
			     bgp);
	if (bgp->import_rt_hash)
		hash_free(bgp->import_rt_hash);
	bgp->import_rt_hash = NULL;
	if (bgp->vnihash)
		hash_free(bgp->vnihash);
	bgp->vnihash = NULL;
	bf_free(bgp->rd_idspace);
}

/*
 * Initialization for EVPN
 * Create
 *  VNI hash table
 *  hash for RT to VNI
 *  unique rd id space for auto derivation of RD for VNIs
 */
void bgp_evpn_init(struct bgp *bgp)
{
	bgp->vnihash =
		hash_create(vni_hash_key_make, vni_hash_cmp, "BGP VNI Hash");
	bgp->import_rt_hash =
		hash_create(import_rt_hash_key_make, import_rt_hash_cmp,
			    "BGP Import RT Hash");
	bf_init(bgp->rd_idspace, UINT16_MAX);
	/*assign 0th index in the bitfield, so that we start with id 1*/
	bf_assign_zero_index(bgp->rd_idspace);
}
