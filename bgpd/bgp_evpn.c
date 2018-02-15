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
 * Make vrf import route target hash key.
 */
static unsigned int vrf_import_rt_hash_key_make(void *p)
{
	struct vrf_irt_node *irt = p;
	char *pnt = irt->rt.val;

	return jhash(pnt, 8, 0x5abc1234);
}

/*
 * Comparison function for vrf import rt hash
 */
static int vrf_import_rt_hash_cmp(const void *p1, const void *p2)
{
	const struct vrf_irt_node *irt1 = p1;
	const struct vrf_irt_node *irt2 = p2;

	if (irt1 == NULL && irt2 == NULL)
		return 1;

	if (irt1 == NULL || irt2 == NULL)
		return 0;

	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
}

/*
 * Create a new vrf import_rt in default instance
 */
static struct vrf_irt_node *vrf_import_rt_new(struct ecommunity_val *rt)
{
	struct bgp *bgp_def = NULL;
	struct vrf_irt_node *irt;

	bgp_def = bgp_get_default();
	if (!bgp_def) {
		zlog_err("vrf import rt new - def instance not created yet");
		return NULL;
	}

	irt = XCALLOC(MTYPE_BGP_EVPN_VRF_IMPORT_RT,
		      sizeof(struct vrf_irt_node));
	if (!irt)
		return NULL;

	irt->rt = *rt;
	irt->vrfs = list_new();

	/* Add to hash */
	if (!hash_get(bgp_def->vrf_import_rt_hash, irt, hash_alloc_intern)) {
		XFREE(MTYPE_BGP_EVPN_VRF_IMPORT_RT, irt);
		return NULL;
	}

	return irt;
}

/*
 * Free the vrf import rt node
 */
static void vrf_import_rt_free(struct vrf_irt_node *irt)
{
	struct bgp *bgp_def = NULL;

	bgp_def = bgp_get_default();
	if (!bgp_def) {
		zlog_err("vrf import rt free - def instance not created yet");
		return;
	}

	hash_release(bgp_def->vrf_import_rt_hash, irt);
	XFREE(MTYPE_BGP_EVPN_VRF_IMPORT_RT, irt);
}

/*
 * Function to lookup Import RT node - used to map a RT to set of
 * VNIs importing routes with that RT.
 */
static struct vrf_irt_node *lookup_vrf_import_rt(struct ecommunity_val *rt)
{
	struct bgp *bgp_def = NULL;
	struct vrf_irt_node *irt;
	struct vrf_irt_node tmp;

	bgp_def = bgp_get_default();
	if (!bgp_def) {
		zlog_err("vrf import rt lookup - def instance not created yet");
		return NULL;
	}

	memset(&tmp, 0, sizeof(struct vrf_irt_node));
	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
	irt = hash_lookup(bgp_def->vrf_import_rt_hash, &tmp);
	return irt;
}

/*
 * Is specified VRF present on the RT's list of "importing" VRFs?
 */
static int is_vrf_present_in_irt_vrfs(struct list *vrfs,
				      struct bgp *bgp_vrf)
{
	struct listnode *node = NULL, *nnode = NULL;
	struct bgp *tmp_bgp_vrf = NULL;

	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, tmp_bgp_vrf)) {
		if (tmp_bgp_vrf == bgp_vrf)
			return 1;
	}
	return 0;
}

/*
 * Make import route target hash key.
 */
static unsigned int import_rt_hash_key_make(void *p)
{
	struct irt_node *irt = p;
	char *pnt = irt->rt.val;

	return jhash(pnt, 8, 0xdeadbeef);
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
 * Map one RT to specified VRF.
 * bgp_vrf = BGP vrf instance
 */
static void map_vrf_to_rt(struct bgp *bgp_vrf,
			  struct ecommunity_val *eval)
{
	struct vrf_irt_node *irt = NULL;
	struct ecommunity_val eval_tmp;

	/* If using "automatic" RT,
	 * we only care about the local-admin sub-field.
	 * This is to facilitate using L3VNI(VRF-VNI)
	 * as the RT for EBGP peering too.
	 */
	memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
	if (!CHECK_FLAG(bgp_vrf->vrf_flags,
			BGP_VRF_IMPORT_RT_CFGD))
		mask_ecom_global_admin(&eval_tmp, eval);

	irt = lookup_vrf_import_rt(&eval_tmp);
	if (irt && irt->vrfs)
		if (is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
			/* Already mapped. */
			return;

	if (!irt) {
		irt = vrf_import_rt_new(&eval_tmp);
		assert(irt);
	}

	/* Add VRF to the list for this RT. */
	listnode_add(irt->vrfs, bgp_vrf);
}

/*
 * Unmap specified VRF from specified RT. If there are no other
 * VRFs for this RT, then the RT hash is deleted.
 * bgp_vrf: BGP VRF specific instance
 */
static void unmap_vrf_from_rt(struct bgp *bgp_vrf,
			      struct vrf_irt_node *irt)
{
	/* Delete VRF from list for this RT. */
	listnode_delete(irt->vrfs, bgp_vrf);
	if (!listnode_head(irt->vrfs)) {
		list_delete_and_null(&irt->vrfs);
		vrf_import_rt_free(irt);
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
static void form_auto_rt(struct bgp *bgp, vni_t vni, struct list *rtl)
{
	struct ecommunity_val eval;
	struct ecommunity *ecomadd;

	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval);

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
				       u_char flags)
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

	/* TX flags - MAC sticky status and/or gateway mac */
	if (add)
		stream_putc(s, flags);

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL))
		zlog_debug("Tx %s MACIP, VNI %u MAC %s IP %s (flags: 0x%x) remote VTEP %s",
			   add ? "ADD" : "DEL", vpn->vni,
			   prefix_mac2str(&p->prefix.mac, buf1, sizeof(buf1)),
			   ipaddr2str(&p->prefix.ip, buf3, sizeof(buf3)),
			   flags,
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
 * Build extended communities for EVPN prefix route.
 */
static void build_evpn_type5_route_extcomm(struct bgp *bgp_vrf,
					   struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_rmac;
	struct ecommunity_val eval;
	struct ecommunity_val eval_rmac;
	bgp_encap_types tnl_type;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	struct list *vrf_export_rtl = NULL;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.val = (u_int8_t *)eval.val;

	/* Add Encap */
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* Add the export RTs for L3VNI/VRF */
	vrf_export_rtl = bgp_vrf->vrf_export_rtl;
	if (vrf_export_rtl && !list_isempty(vrf_export_rtl)) {
		for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode, ecom))
			attr->ecommunity = ecommunity_merge(attr->ecommunity,
							    ecom);
	}

	/* add the router mac extended community */
	if (!is_zero_mac(&attr->rmac)) {
		memset(&ecom_rmac, 0, sizeof(ecom_rmac));
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecom_rmac.size = 1;
		ecom_rmac.val = (uint8_t *)eval_rmac.val;
		attr->ecommunity = ecommunity_merge(attr->ecommunity,
						    &ecom_rmac);
	}

	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES);
}

/*
 * Build extended communities for EVPN route. RT and ENCAP are
 * applicable to all routes.
 * TODO: currently kernel doesnt support ipv6 routes with ipv4 nexthops.
 * This means that we can't do symmetric routing for ipv6 hosts routes
 * in the same way as ipv4 host routes.
 * We wont attach l3-vni related RTs for ipv6 routes.
 * For now, We will only adevrtise ipv4 host routes
 * with L3-VNI related ext-comm.
 */
static void build_evpn_route_extcomm(struct bgpevpn *vpn, struct attr *attr,
				     afi_t afi)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_sticky;
	struct ecommunity ecom_default_gw;
	struct ecommunity ecom_rmac;
	struct ecommunity_val eval;
	struct ecommunity_val eval_sticky;
	struct ecommunity_val eval_default_gw;
	struct ecommunity_val eval_rmac;
	bgp_encap_types tnl_type;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	u_int32_t seqnum;
	struct list *vrf_export_rtl = NULL;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.val = (u_int8_t *)eval.val;

	/* Add Encap */
	attr->ecommunity = ecommunity_dup(&ecom_encap);

	/* Add the export RTs for L2VNI */
	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom))
		attr->ecommunity = ecommunity_merge(attr->ecommunity, ecom);

	/* Add the export RTs for L3VNI - currently only supported for IPV4 host
	 * routes
	 */
	if (afi == AFI_IP) {
		vrf_export_rtl = bgpevpn_get_vrf_export_rtl(vpn);
		if (vrf_export_rtl && !list_isempty(vrf_export_rtl)) {
			for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode,
					       ecom))
				attr->ecommunity =
					ecommunity_merge(attr->ecommunity,
							 ecom);
		}
	}

	if (attr->sticky) {
		seqnum = 0;
		memset(&ecom_sticky, 0, sizeof(ecom_sticky));
		encode_mac_mobility_extcomm(1, seqnum, &eval_sticky);
		ecom_sticky.size = 1;
		ecom_sticky.val = (u_int8_t *)eval_sticky.val;
		attr->ecommunity =
			ecommunity_merge(attr->ecommunity, &ecom_sticky);
	}

	if (afi == AFI_IP && !is_zero_mac(&attr->rmac)) {
		memset(&ecom_rmac, 0, sizeof(ecom_rmac));
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecom_rmac.size = 1;
		ecom_rmac.val = (uint8_t *)eval_rmac.val;
		attr->ecommunity = ecommunity_merge(attr->ecommunity,
						    &ecom_rmac);
	}

	if (attr->default_gw) {
		memset(&ecom_default_gw, 0, sizeof(ecom_default_gw));
		encode_default_gw_extcomm(&eval_default_gw);
		ecom_default_gw.size = 1;
		ecom_default_gw.val = (uint8_t *)eval_default_gw.val;
		attr->ecommunity = ecommunity_merge(attr->ecommunity,
						    &ecom_default_gw);
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
			      struct in_addr remote_vtep_ip, u_char flags)
{
	int ret;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ret = bgp_zebra_send_remote_macip(bgp, vpn, p, remote_vtep_ip,
						  1, flags);
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
	u_char			flags = 0;

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
		if (bgp_zebra_has_route_changed(rn, old_select)) {
			if (old_select->attr->sticky)
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
			if (old_select->attr->default_gw)
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
			ret = evpn_zebra_install(bgp, vpn,
						 (struct prefix_evpn *)&rn->p,
						 old_select->attr->nexthop,
						 flags);
		}
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
		flags = 0;
		if (new_select->attr->sticky)
			SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
		if (new_select->attr->default_gw)
			SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
		ret = evpn_zebra_install(bgp, vpn, (struct prefix_evpn *)&rn->p,
					 new_select->attr->nexthop,
					 flags);
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
 * Return true if the local ri for this rn is of type gateway mac
 */
static int evpn_route_is_def_gw(struct bgp *bgp, struct bgp_node *rn)
{
	struct bgp_info		*tmp_ri = NULL;
	struct bgp_info		*local_ri = NULL;

	local_ri = NULL;
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next) {
		if (tmp_ri->peer == bgp->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			local_ri = tmp_ri;
	}

	if (!local_ri)
		return 0;

	return local_ri->attr->default_gw;
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

static int update_evpn_type5_route_entry(struct bgp *bgp_def,
					 struct bgp *bgp_vrf, afi_t afi,
					 safi_t safi, struct bgp_node *rn,
					 struct attr *attr, int *route_changed)
{
	struct attr *attr_new = NULL;
	struct bgp_info *ri = NULL;
	mpls_label_t label = MPLS_INVALID_LABEL;
	struct bgp_info *local_ri = NULL;
	struct bgp_info *tmp_ri = NULL;

	*route_changed = 0;
	/* locate the local route entry if any */
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next) {
		if (tmp_ri->peer == bgp_def->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			local_ri = tmp_ri;
	}

	/* create a new route entry if one doesnt exist.
	   Otherwise see if route attr has changed
	 */
	if (!local_ri) {

		/* route has changed as this is the first entry */
		*route_changed = 1;

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(attr);

		/* create the route info from attribute */
		ri = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
			       bgp_def->peer_self, attr_new, rn);
		SET_FLAG(ri->flags, BGP_INFO_VALID);

		/* Type-5 routes advertise the L3-VNI */
		bgp_info_extra_get(ri);
		vni2label(bgp_vrf->l3vni, &label);
		memcpy(&ri->extra->label, &label, sizeof(label));
		ri->extra->num_labels = 1;

		/* add the route entry to route node*/
		bgp_info_add(rn, ri);
	} else {

		tmp_ri = local_ri;
		if (!attrhash_cmp(tmp_ri->attr, attr)) {

			/* attribute changed */
			*route_changed = 1;

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
	return 0;
}

/* update evpn type-5 route entry */
static int update_evpn_type5_route(struct bgp *bgp_vrf,
				   struct prefix_evpn *evp,
				   struct attr* src_attr)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct bgp_node *rn = NULL;
	struct bgp *bgp_def = NULL;
	int route_changed = 0;

	bgp_def = bgp_get_default();
	if (!bgp_def)
		return 0;

	/* Build path attribute for this route - use the source attr, if
	 * present, else treat as locally originated.
	 */
	if (src_attr)
		bgp_attr_dup(&attr, src_attr);
	else {
		memset(&attr, 0, sizeof(struct attr));
		bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	}
	/* Set nexthop to ourselves and fill in the Router MAC. */
	attr.nexthop = bgp_vrf->originator_ip;
	attr.mp_nexthop_global_in = bgp_vrf->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	memcpy(&attr.rmac, &bgp_vrf->rmac, sizeof(struct ethaddr));

	/* Setup RT and encap extended community */
	build_evpn_type5_route_extcomm(bgp_vrf, &attr);

	/* get the route node in global table */
	rn = bgp_afi_node_get(bgp_def->rib[afi][safi], afi, safi,
			      (struct prefix *)evp,
			      &bgp_vrf->vrf_prd);
	assert(rn);

	/* create or update the route entry within the route node */
	update_evpn_type5_route_entry(bgp_def, bgp_vrf,
				      afi, safi,
				      rn, &attr, &route_changed);

	/* schedule for processing and unlock node */
	if (route_changed) {
		bgp_process(bgp_def, rn, afi, safi);
		bgp_unlock_node(rn);
	}

	/* uninten temporary */
	if (!src_attr)
		aspath_unintern(&attr.aspath);
	return 0;
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
	mpls_label_t label[BGP_MAX_LABELS];
	u_int32_t num_labels = 1;
	int route_change = 1;
	u_char sticky = 0;
	struct prefix_evpn *evp;

	*ri = NULL;
	evp = (struct prefix_evpn *)&rn->p;
	memset(&label, 0, sizeof(label));

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
		if (remote_ri && !CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW)) {
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
		vni2label(vpn->vni, &label[0]);
		/* Type-2 routes may carry a second VNI - the L3-VNI */
		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
			vni_t l3vni;

			l3vni = bgpevpn_get_l3vni(vpn);
			if (l3vni) {
				vni2label(l3vni, &label[1]);
				num_labels++;
			}
		}

		memcpy(&tmp_ri->extra->label, label, sizeof(label));
		tmp_ri->extra->num_labels = num_labels;
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
	attr.sticky = CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY) ? 1 : 0;
	attr.default_gw = CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW) ? 1 : 0;
	attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL);
	bgpevpn_get_rmac(vpn, &attr.rmac);
	vni2label(vpn->vni, &(attr.label));

	/* Set up RT and ENCAP extended community. */
	build_evpn_route_extcomm(vpn, &attr,
				 IS_EVPN_PREFIX_IPADDR_V4(p) ?
					AFI_IP : AFI_IP6);

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

/* Delete EVPN type5 route entry from global table */
static void delete_evpn_type5_route_entry(struct bgp *bgp_def,
					  struct bgp *bgp_vrf,
					  afi_t afi, safi_t safi,
					  struct bgp_node *rn,
					  struct bgp_info **ri)
{
	struct bgp_info *tmp_ri = NULL;

	*ri = NULL;

	/* find the matching route entry */
	for (tmp_ri = rn->info; tmp_ri; tmp_ri = tmp_ri->next)
		if (tmp_ri->peer == bgp_def->peer_self
		    && tmp_ri->type == ZEBRA_ROUTE_BGP
		    && tmp_ri->sub_type == BGP_ROUTE_STATIC)
			break;

	*ri = tmp_ri;

	/* Mark route for delete. */
	if (tmp_ri)
		bgp_info_delete(rn, tmp_ri);
}

/* Delete EVPN type5 route */
static int delete_evpn_type5_route(struct bgp *bgp_vrf,
				   struct prefix_evpn *evp)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_node *rn = NULL;
	struct bgp_info *ri = NULL;
	struct bgp *bgp_def = NULL; /* default bgp instance */

	bgp_def = bgp_get_default();
	if (!bgp_def)
		return 0;

	/* locate the global route entry for this type-5 prefix */
	rn = bgp_afi_node_lookup(bgp_def->rib[afi][safi], afi, safi,
				 (struct prefix *)evp, &bgp_vrf->vrf_prd);
	if (!rn)
		return 0;

	delete_evpn_type5_route_entry(bgp_def, bgp_vrf, afi, safi, rn, &ri);
	if (ri)
		bgp_process(bgp_def, rn, afi, safi);
	bgp_unlock_node(rn);
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
	struct attr attr_def_gw;
	struct attr attr_ip6;
	struct attr attr_sticky_ip6;
	struct attr attr_def_gw_ip6;
	struct attr *attr_new;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	memset(&attr, 0, sizeof(struct attr));
	memset(&attr_sticky, 0, sizeof(struct attr));
	memset(&attr_def_gw, 0, sizeof(struct attr));
	memset(&attr_ip6, 0, sizeof(struct attr));
	memset(&attr_sticky_ip6, 0, sizeof(struct attr));
	memset(&attr_def_gw_ip6, 0, sizeof(struct attr));

	/* Build path-attribute - all type-2 routes for this VNI will share the
	 * same path attribute.
	 */
	bgp_attr_default_set(&attr, BGP_ORIGIN_IGP);
	bgp_attr_default_set(&attr_sticky, BGP_ORIGIN_IGP);
	bgp_attr_default_set(&attr_def_gw, BGP_ORIGIN_IGP);
	attr.nexthop = vpn->originator_ip;
	attr.mp_nexthop_global_in = vpn->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	bgpevpn_get_rmac(vpn, &attr.rmac);
	attr_sticky.nexthop = vpn->originator_ip;
	attr_sticky.mp_nexthop_global_in = vpn->originator_ip;
	attr_sticky.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_sticky.sticky = 1;
	bgpevpn_get_rmac(vpn, &attr_sticky.rmac);
	attr_def_gw.nexthop = vpn->originator_ip;
	attr_def_gw.mp_nexthop_global_in = vpn->originator_ip;
	attr_def_gw.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_def_gw.default_gw = 1;
	bgpevpn_get_rmac(vpn, &attr_def_gw.rmac);
	bgp_attr_default_set(&attr_ip6, BGP_ORIGIN_IGP);
	bgp_attr_default_set(&attr_sticky_ip6, BGP_ORIGIN_IGP);
	bgp_attr_default_set(&attr_def_gw_ip6, BGP_ORIGIN_IGP);
	attr_ip6.nexthop = vpn->originator_ip;
	attr_ip6.mp_nexthop_global_in = vpn->originator_ip;
	attr_ip6.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	bgpevpn_get_rmac(vpn, &attr_ip6.rmac);
	attr_sticky_ip6.nexthop = vpn->originator_ip;
	attr_sticky_ip6.mp_nexthop_global_in = vpn->originator_ip;
	attr_sticky_ip6.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_sticky_ip6.sticky = 1;
	bgpevpn_get_rmac(vpn, &attr_sticky_ip6.rmac);
	attr_def_gw_ip6.nexthop = vpn->originator_ip;
	attr_def_gw_ip6.mp_nexthop_global_in = vpn->originator_ip;
	attr_def_gw_ip6.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr_def_gw_ip6.default_gw = 1;
	bgpevpn_get_rmac(vpn, &attr_def_gw_ip6.rmac);

	/* Set up RT, ENCAP and sticky MAC extended community. */
	build_evpn_route_extcomm(vpn, &attr, AFI_IP);
	build_evpn_route_extcomm(vpn, &attr_sticky, AFI_IP);
	build_evpn_route_extcomm(vpn, &attr_def_gw, AFI_IP);
	build_evpn_route_extcomm(vpn, &attr_ip6, AFI_IP6);
	build_evpn_route_extcomm(vpn, &attr_sticky_ip6, AFI_IP6);
	build_evpn_route_extcomm(vpn, &attr_def_gw_ip6, AFI_IP);

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

		if (IS_EVPN_PREFIX_IPADDR_V4(evp)) {
			if (evpn_route_is_sticky(bgp, rn))
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr_sticky, 0, 1,
							&ri, 0);
			else if (evpn_route_is_def_gw(bgp, rn))
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr_def_gw, 0, 1,
							&ri, 0);
			else
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr, 0, 1, &ri, 0);
		} else {
			if (evpn_route_is_sticky(bgp, rn))
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr_sticky_ip6, 0, 1,
							&ri, 0);
			else if (evpn_route_is_def_gw(bgp, rn))
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr_def_gw_ip6, 0, 1,
							&ri, 0);
			else
				update_evpn_route_entry(bgp, vpn, afi, safi, rn,
							&attr_ip6, 0, 1,
							&ri, 0);
		}

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
	aspath_unintern(&attr_ip6.aspath);
	aspath_unintern(&attr_sticky.aspath);
	aspath_unintern(&attr_sticky_ip6.aspath);
	aspath_unintern(&attr_def_gw.aspath);
	aspath_unintern(&attr_def_gw_ip6.aspath);

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
 * Install route entry into the VRF routing table and invoke route selection.
 */
static int install_evpn_route_entry_in_vrf(struct bgp *bgp_vrf,
					   struct prefix_evpn *evp,
					   struct bgp_info *parent_ri)
{
	struct bgp_node *rn;
	struct bgp_info *ri;
	struct attr *attr_new;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;
	char buf[PREFIX_STRLEN];
	char buf1[PREFIX_STRLEN];

	memset(pp, 0, sizeof(struct prefix));
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ip_prefix_from_type2_prefix(evp, pp);
	else if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		ip_prefix_from_type5_prefix(evp, pp);

	if (bgp_debug_zebra(NULL)) {
		zlog_debug("installing evpn prefix %s as ip prefix %s in vrf %s",
			   prefix2str(evp, buf, sizeof(buf)),
			   prefix2str(pp, buf1, sizeof(buf)),
			   vrf_id_to_name(bgp_vrf->vrf_id));
	}

	/* Create (or fetch) route within the VRF. */
	/* NOTE: There is no RD here. */
	if (IS_EVPN_PREFIX_IPADDR_V4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		rn = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else if (IS_EVPN_PREFIX_IPADDR_V6(evp)) {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		rn = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else
		return 0;

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
		if (parent_ri->extra) {
			memcpy(&ri->extra->label, &parent_ri->extra->label,
			       sizeof(ri->extra->label));
			ri->extra->num_labels = parent_ri->extra->num_labels;
		}
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
	bgp_process(bgp_vrf, rn, afi, safi);

	return ret;
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
		if (parent_ri->extra) {
			memcpy(&ri->extra->label, &parent_ri->extra->label,
			       sizeof(ri->extra->label));
			ri->extra->num_labels = parent_ri->extra->num_labels;
		}
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
 * Uninstall route entry from the VRF routing table and send message
 * to zebra, if appropriate.
 */
static int uninstall_evpn_route_entry_in_vrf(struct bgp *bgp_vrf,
					     struct prefix_evpn *evp,
					     struct bgp_info *parent_ri)
{
	struct bgp_node *rn;
	struct bgp_info *ri;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;
	char buf[PREFIX_STRLEN];
	char buf1[PREFIX_STRLEN];

	memset(pp, 0, sizeof(struct prefix));
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ip_prefix_from_type2_prefix(evp, pp);
	else if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		ip_prefix_from_type5_prefix(evp, pp);

	if (bgp_debug_zebra(NULL)) {
		zlog_debug("uninstalling evpn prefix %s as ip prefix %s in vrf %s",
			   prefix2str(evp, buf, sizeof(buf)),
			   prefix2str(pp, buf1, sizeof(buf)),
			   vrf_id_to_name(bgp_vrf->vrf_id));
	}

	/* Locate route within the VRF. */
	/* NOTE: There is no RD here. */
	if (IS_EVPN_PREFIX_IPADDR_V4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		rn = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	} else {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		rn = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	}

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
	bgp_process(bgp_vrf, rn, afi, safi);

	/* Unlock route node. */
	bgp_unlock_node(rn);

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
 * Given a route entry and a VRF, see if this route entry should be
 * imported into the VRF i.e., RTs match.
 */
static int is_route_matching_for_vrf(struct bgp *bgp_vrf,
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
		struct vrf_irt_node *irt;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* See if this RT matches specified VNIs import RTs */
		irt = lookup_vrf_import_rt(eval);
		if (irt && irt->vrfs)
			if (is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
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
			irt = lookup_vrf_import_rt(&eval_tmp);
		}
		if (irt && irt->vrfs)
			if (is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
				return 1;
	}

	return 0;
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
 * Install or uninstall mac-ip routes are appropriate for this
 * particular VRF.
 */
static int install_uninstall_routes_for_vrf(struct bgp *bgp_vrf,
					    int install)
{
	afi_t afi;
	safi_t safi;
	struct bgp_node *rd_rn, *rn;
	struct bgp_table *table;
	struct bgp_info *ri;
	int ret;
	char buf[PREFIX_STRLEN];
	struct bgp *bgp_def = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	bgp_def = bgp_get_default();
	if (!bgp_def)
		return -1;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this VRF. Note that we need to loop through all global
	 * routes to determine which route matches the import rt on vrf
	 */
	for (rd_rn = bgp_table_top(bgp_def->rib[afi][safi]); rd_rn;
	     rd_rn = bgp_route_next(rd_rn)) {
		table = (struct bgp_table *)(rd_rn->info);
		if (!table)
			continue;

		for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
			struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

			/* if not mac-ip route skip this route */
			if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
			      evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
				continue;

			/* if not a mac+ip route skip this route */
			if (!(IS_EVPN_PREFIX_IPADDR_V4(evp) ||
			      IS_EVPN_PREFIX_IPADDR_V6(evp)))
				continue;

			for (ri = rn->info; ri; ri = ri->next) {
				/* Consider "valid" remote routes applicable for
				 * this VRF.
				 */
				if (!(CHECK_FLAG(ri->flags, BGP_INFO_VALID)
				      && ri->type == ZEBRA_ROUTE_BGP
				      && ri->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (is_route_matching_for_vrf(bgp_vrf, ri)) {
					if (install)
						ret =
						install_evpn_route_entry_in_vrf(
							bgp_vrf, evp, ri);
					else
						ret =
						uninstall_evpn_route_entry_in_vrf(
							bgp_vrf, evp, ri);

					if (ret) {
						zlog_err(
							"Failed to %s EVPN %s route in VRF %s",
							install ? "install"
								: "uninstall",
							prefix2str(evp, buf,
								   sizeof(buf)),
							vrf_id_to_name(bgp_vrf->vrf_id));
						return ret;
					}
				}
			}
		}
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

/* Install any existing remote routes applicable for this VRF into VRF RIB. This
 * is invoked upon l3vni-add or l3vni import rt change
 */
static int install_routes_for_vrf(struct bgp *bgp_vrf)
{
	install_uninstall_routes_for_vrf(bgp_vrf, 1);
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

/* uninstall routes from l3vni vrf. */
static int uninstall_routes_for_vrf(struct bgp *bgp_vrf)
{
	install_uninstall_routes_for_vrf(bgp_vrf, 0);
	return 0;
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
 * Install or uninstall route in matching VRFs (list).
 */
static int install_uninstall_route_in_vrfs(struct bgp *bgp_def, afi_t afi,
					   safi_t safi, struct prefix_evpn *evp,
					   struct bgp_info *ri,
					   struct list *vrfs, int install)
{
	char buf[PREFIX2STR_BUFFER];
	struct bgp *bgp_vrf;
	struct listnode *node, *nnode;

	/* Only type-2/type-5 routes go into a VRF */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
	      evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return 0;

	/* if it is type-2 route and not a mac+ip route skip this route */
	if ((evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    !(IS_EVPN_PREFIX_IPADDR_V4(evp) || IS_EVPN_PREFIX_IPADDR_V6(evp)))
		return 0;

	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, bgp_vrf)) {
		int ret;

		if (install)
			ret = install_evpn_route_entry_in_vrf(bgp_vrf,
							      evp, ri);
		else
			ret = uninstall_evpn_route_entry_in_vrf(bgp_vrf,
								evp, ri);

		if (ret) {
			zlog_err("%u: Failed to %s prefix %s in VRF %s",
				 bgp_def->vrf_id,
				 install ? "install" : "uninstall",
				 prefix2str(evp, buf, sizeof(buf)),
				 vrf_id_to_name(bgp_vrf->vrf_id));
			return ret;
		}
	}

	return 0;
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

	/* Only type-2 and type-3 and type-5 are supported currently */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IMET_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return 0;

	/* If we don't have Route Target, nothing much to do. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return -1;

	/* For each extended community RT, see which VNIs/VRFs match and import
	 * the route into matching VNIs/VRFs.
	 */
	for (i = 0; i < ecom->size; i++) {
		u_char *pnt;
		u_char type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct irt_node *irt; /* import rt for l2vni */
		struct vrf_irt_node *vrf_irt; /* import rt for l3vni */

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* Import route into matching l2-vnis (type-2/type-3 routes go
		 * into l2vni table)
		 */
		irt = lookup_import_rt(bgp, eval);
		if (irt && irt->vnis)
			install_uninstall_route_in_vnis(bgp, afi, safi, evp, ri,
							irt->vnis, import);

		/* Import route into matching l3-vnis (type-2/type-5 routes go
		 * into l3vni/vrf table)
		 */
		vrf_irt = lookup_vrf_import_rt(eval);
		if (vrf_irt && vrf_irt->vrfs)
			install_uninstall_route_in_vrfs(bgp, afi, safi, evp, ri,
							vrf_irt->vrfs, import);

		/* Also check for non-exact match. In this,
		 *  we mask out the AS and
		 * only check on the local-admin sub-field.
		 * This is to facilitate using
		 * VNI as the RT for EBGP peering too.
		 */
		irt = NULL;
		vrf_irt = NULL;
		if (type == ECOMMUNITY_ENCODE_AS
		    || type == ECOMMUNITY_ENCODE_AS4
		    || type == ECOMMUNITY_ENCODE_IP) {
			memcpy(&eval_tmp, eval, ECOMMUNITY_SIZE);
			mask_ecom_global_admin(&eval_tmp, eval);
			irt = lookup_import_rt(bgp, &eval_tmp);
			vrf_irt = lookup_vrf_import_rt(&eval_tmp);
		}
		if (irt && irt->vnis)
			install_uninstall_route_in_vnis(bgp, afi, safi, evp, ri,
							irt->vnis, import);
		if (vrf_irt && vrf_irt->vrfs)
			install_uninstall_route_in_vrfs(bgp, afi, safi, evp,
							ri, vrf_irt->vrfs,
							import);
	}

	return 0;
}

/* delete and withdraw all ipv4 and ipv6 routes in the vrf table as type-5
 * routes */
static void delete_withdraw_vrf_routes(struct bgp *bgp_vrf)
{
	/* delete all ipv4 routes and withdraw from peers */
	bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* delete all ipv6 routes and withdraw from peers */
	bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);
}

/* update and advertise all ipv4 and ipv6 routes in thr vrf table as type-5
 * routes */
static void update_advertise_vrf_routes(struct bgp *bgp_vrf)
{
	/* update all ipv4 routes */
	bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* update all ipv6 routes */
	bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);
}

/*
 * update and advertise local routes for a VRF as type-5 routes.
 * This is invoked upon RD change for a VRF. Note taht the processing is only
 * done in the global route table using the routes which already exist in the
 * VRF routing table
 */
static void update_router_id_vrf(struct bgp *bgp_vrf)
{
	/* skip if the RD is configured */
	if (is_vrf_rd_configured(bgp_vrf))
		return;

	/* derive the RD for the VRF based on new router-id */
	bgp_evpn_derive_auto_rd_for_vrf(bgp_vrf);

	/* update advertise ipv4|ipv6 routes as type-5 routes */
	update_advertise_vrf_routes(bgp_vrf);
}

/*
 * Delete and withdraw all type-5 routes  for the RD corresponding to VRF.
 * This is invoked upon VRF RD change. The processing is done only from global
 * table.
 */
static void withdraw_router_id_vrf(struct bgp *bgp_vrf)
{
	/* skip if the RD is configured */
	if (is_vrf_rd_configured(bgp_vrf))
		return;

	/* delete/withdraw ipv4|ipv6 routes as type-5 routes */
	delete_withdraw_vrf_routes(bgp_vrf);
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
	mpls_label_t label[BGP_MAX_LABELS]; /* holds the VNI(s) as in packet */
	u_int32_t num_labels = 0;
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

	/* Get the VNI(s). Stored as bytes here. */
	num_labels++;
	memset(label, 0, sizeof(label));
	memcpy(&label[0], pfx, BGP_LABEL_BYTES);
	pfx += BGP_LABEL_BYTES;
	psize -= (33 + ipaddr_len);
	/* Do we have a second VNI? */
	if (psize) {
		num_labels++;
		memcpy(&label[1], pfx, BGP_LABEL_BYTES);
		/*
		 * If in future, we are required to access additional fields,
		 * we MUST increment pfx by BGP_LABEL_BYTES in before reading the next field
		 */
	}

	/* Process the route. */
	if (attr)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, &label[0], num_labels, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, &label[0], num_labels, NULL);
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
				 &prd, NULL, 0, 0, NULL);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, NULL, 0, NULL);
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
	mpls_label_t label; /* holds the VNI as in the packet */
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
	p.prefixlen = EVPN_TYPE_5_ROUTE_PREFIXLEN;
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
	} else {
		SET_IPADDR_V6(&p.prefix.ip);
		memcpy(&p.prefix.ip.ipaddr_v6, pfx, 16);
		pfx += 16;
		memcpy(&evpn.gw_ip.ipv6, pfx, 16);
		pfx += 16;
	}

	/* Get the VNI (in MPLS label field). Stored as bytes here. */
	memset(&label, 0, sizeof(label));
	memcpy(&label, pfx, BGP_LABEL_BYTES);

	/*
	 * If in future, we are required to access additional fields,
	 * we MUST increment pfx by BGP_LABEL_BYTES in before reading the next field
	 */

	/* Process the route. */
	if (!withdraw)
		ret = bgp_update(peer, (struct prefix *)&p, addpath_id, attr,
				 afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				 &prd, &label, 1, 0, &evpn);
	else
		ret = bgp_withdraw(peer, (struct prefix *)&p, addpath_id, attr,
				   afi, safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, &label, 1, &evpn);

	return ret;
}

static void evpn_mpattr_encode_type5(struct stream *s, struct prefix *p,
				     struct prefix_rd *prd,
				     mpls_label_t *label, u_int32_t num_labels,
				     struct attr *attr)
{
	int len;
	char temp[16];
	struct evpn_addr *p_evpn_p;

	memset(&temp, 0, 16);
	if (p->family != AF_EVPN)
		return;
	p_evpn_p = &(p->u.prefix_evpn);

	/* len denites the total len of IP and GW-IP in the route
	   IP and GW-IP have to be both ipv4 or ipv6
	 */
	if (IS_IPADDR_V4(&p_evpn_p->ip))
		len = 8; /* IP and GWIP are both ipv4 */
	else
		len = 32; /* IP and GWIP are both ipv6 */
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

	if (num_labels)
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
 * Derive AUTO import RT for BGP VRF - L3VNI
 */
static void evpn_auto_rt_import_add_for_vrf(struct bgp *bgp_vrf)
{
	struct bgp *bgp_def = NULL;

	form_auto_rt(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_import_rtl);
	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD);

	/* Map RT to VRF */
	bgp_def = bgp_get_default();
	if (!bgp_def)
		return;
	bgp_evpn_map_vrf_to_its_rts(bgp_vrf);
}

/*
 * Delete AUTO import RT from BGP VRF - L3VNI
 */
static void evpn_auto_rt_import_delete_for_vrf(struct bgp *bgp_vrf)
{
	evpn_rt_delete_auto(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_import_rtl);
}

/*
 * Derive AUTO export RT for BGP VRF - L3VNI
 */
static void evpn_auto_rt_export_add_for_vrf(struct bgp *bgp_vrf)
{
	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD);
	form_auto_rt(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_export_rtl);
}

/*
 * Delete AUTO export RT from BGP VRF - L3VNI
 */
static void evpn_auto_rt_export_delete_for_vrf(struct bgp *bgp_vrf)
{
	evpn_rt_delete_auto(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_export_rtl);
}

static void bgp_evpn_handle_export_rt_change_for_vrf(struct bgp *bgp_vrf)
{
	struct bgp *bgp_def = NULL;
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;

	bgp_def = bgp_get_default();
	if (!bgp_def)
		return;

	/* update all type-5 routes */
	update_advertise_vrf_routes(bgp_vrf);

	/* update all type-2 routes */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn))
		update_routes_for_vni(bgp_def, vpn);
}

/*
 * Public functions.
 */

/* withdraw type-5 route corresponding to ip prefix */
void bgp_evpn_withdraw_type5_route(struct bgp *bgp_vrf, struct prefix *p,
				   afi_t afi, safi_t safi)
{
	int ret = 0;
	struct prefix_evpn evp;
	char buf[PREFIX_STRLEN];

	/* NOTE: Check needed as this is called per-route also. */
	if (!advertise_type5_routes(bgp_vrf, afi))
		return;

	build_type5_prefix_from_ip_prefix(&evp, p);
	ret = delete_evpn_type5_route(bgp_vrf, &evp);
	if (ret) {
		zlog_err(
			 "%u failed to delete type-5 route for prefix %s in vrf %s",
			 bgp_vrf->vrf_id,
			 prefix2str(p, buf, sizeof(buf)),
			 vrf_id_to_name(bgp_vrf->vrf_id));
	}
}

/* withdraw all type-5 routes for an address family */
void bgp_evpn_withdraw_type5_routes(struct bgp *bgp_vrf,
				    afi_t afi, safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_node *rn = NULL;

	/* Bail out early if we don't have to advertise type-5 routes. */
	if (!advertise_type5_routes(bgp_vrf, afi))
		return;

	table = bgp_vrf->rib[afi][safi];
	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn))
		bgp_evpn_withdraw_type5_route(bgp_vrf, &rn->p, afi, safi);

}

/*
 * Advertise IP prefix as type-5 route. The afi/safi and src_attr passed
 * to this function correspond to those of the source IP prefix (best
 * path in the case of the attr. In the case of a local prefix (when we
 * are advertising local subnets), the src_attr will be NULL.
 */
void bgp_evpn_advertise_type5_route(struct bgp *bgp_vrf, struct prefix *p,
				    struct attr *src_attr,
				    afi_t afi, safi_t safi)
{
	int ret = 0;
	struct prefix_evpn evp;
	char buf[PREFIX_STRLEN];

	/* NOTE: Check needed as this is called per-route also. */
	if (!advertise_type5_routes(bgp_vrf, afi))
		return;

	/* only advertise subnet routes as type-5 */
	if (is_host_route(p))
		return;

	build_type5_prefix_from_ip_prefix(&evp, p);
	ret = update_evpn_type5_route(bgp_vrf, &evp, src_attr);
	if (ret)
		zlog_err(
			 "%u: Failed to create type-5 route for prefix %s",
			 bgp_vrf->vrf_id,
			 prefix2str(p, buf, sizeof(buf)));
}

/* Inject all prefixes of a particular address-family (currently, IPv4 or
 * IPv6 unicast) into EVPN as type-5 routes. This is invoked when the
 * advertisement is enabled.
 */
void bgp_evpn_advertise_type5_routes(struct bgp *bgp_vrf,
				     afi_t afi, safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_node *rn = NULL;
	struct bgp_info *ri;

	/* Bail out early if we don't have to advertise type-5 routes. */
	if (!advertise_type5_routes(bgp_vrf, afi))
		return;

	table = bgp_vrf->rib[afi][safi];
	for (rn = bgp_table_top(table); rn; rn = bgp_route_next(rn)) {
		/* Need to identify the "selected" route entry to use its
		 * attribute.
		 * TODO: Support for AddPath for EVPN.
		 */
		for (ri = rn->info; ri; ri = ri->next) {
			if (CHECK_FLAG(ri->flags, BGP_INFO_SELECTED)) {
				bgp_evpn_advertise_type5_route(bgp_vrf, &rn->p,
							       ri->attr,
							       afi, safi);
				break;
			}
		}
	}
}

void evpn_rt_delete_auto(struct bgp *bgp, vni_t vni,
				struct list *rtl)
{
	struct listnode *node, *nnode, *node_to_del;
	struct ecommunity *ecom, *ecom_auto;
	struct ecommunity_val eval;

	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval);

	ecom_auto = ecommunity_new();
	ecommunity_add_val(ecom_auto, &eval);
	node_to_del = NULL;

	for (ALL_LIST_ELEMENTS(rtl, node, nnode, ecom)) {
		if (ecommunity_match(ecom, ecom_auto)) {
			ecommunity_free(&ecom);
			node_to_del = node;
		}
	}

	if (node_to_del)
		list_delete_node(rtl, node_to_del);

	ecommunity_free(&ecom_auto);
}

void bgp_evpn_configure_import_rt_for_vrf(struct bgp *bgp_vrf,
					  struct ecommunity *ecomadd)
{
	/* uninstall routes from vrf */
	uninstall_routes_for_vrf(bgp_vrf);

	/* Cleanup the RT to VRF mapping */
	bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);

	/* Remove auto generated RT */
	evpn_auto_rt_import_delete_for_vrf(bgp_vrf);

	/* Add the newly configured RT to RT list */
	listnode_add_sort(bgp_vrf->vrf_import_rtl, ecomadd);
	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD);

	/* map VRF to its RTs */
	bgp_evpn_map_vrf_to_its_rts(bgp_vrf);

	/* install routes matching the new VRF */
	install_routes_for_vrf(bgp_vrf);
}

void bgp_evpn_unconfigure_import_rt_for_vrf(struct bgp *bgp_vrf,
					    struct ecommunity *ecomdel)
{
	struct listnode *node = NULL, *nnode = NULL, *node_to_del = NULL;
	struct ecommunity *ecom = NULL;

	/* uninstall routes from vrf */
	uninstall_routes_for_vrf(bgp_vrf);

	/* Cleanup the RT to VRF mapping */
	bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);

	/* remove the RT from the RT list */
	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, ecom)) {
		if (ecommunity_match(ecom, ecomdel)) {
			ecommunity_free(&ecom);
			node_to_del = node;
			break;
		}
	}

	if (node_to_del)
		list_delete_node(bgp_vrf->vrf_import_rtl, node_to_del);

	/* fallback to auto import rt, if this was the last RT */
	if (list_isempty(bgp_vrf->vrf_import_rtl)) {
		UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD);
		evpn_auto_rt_import_add_for_vrf(bgp_vrf);
	}

	/* map VRFs to its RTs */
	bgp_evpn_map_vrf_to_its_rts(bgp_vrf);

	/* install routes matching this new RT */
	install_routes_for_vrf(bgp_vrf);
}

void bgp_evpn_configure_export_rt_for_vrf(struct bgp *bgp_vrf,
					  struct ecommunity *ecomadd)
{
	/* remove auto-generated RT */
	evpn_auto_rt_export_delete_for_vrf(bgp_vrf);

	/* Add the new RT to the RT list */
	listnode_add_sort(bgp_vrf->vrf_export_rtl, ecomadd);
	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD);

	bgp_evpn_handle_export_rt_change_for_vrf(bgp_vrf);

}

void bgp_evpn_unconfigure_export_rt_for_vrf(struct bgp *bgp_vrf,
					    struct ecommunity *ecomdel)
{
	struct listnode *node = NULL, *nnode = NULL, *node_to_del = NULL;
	struct ecommunity *ecom = NULL;

	/* Remove the RT from the RT list */
	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_export_rtl, node, nnode, ecom)) {
		if (ecommunity_match(ecom, ecomdel)) {
			ecommunity_free(&ecom);
			node_to_del = node;
			break;
		}
	}

	if (node_to_del)
		list_delete_node(bgp_vrf->vrf_export_rtl, node_to_del);

	/* fall back to auto-generated RT if this was the last RT */
	if (bgp_vrf->vrf_export_rtl && list_isempty(bgp_vrf->vrf_export_rtl)) {
		UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD);
		evpn_auto_rt_export_add_for_vrf(bgp_vrf);
	}

	bgp_evpn_handle_export_rt_change_for_vrf(bgp_vrf);
}

/*
 * Handle change to BGP router id. This is invoked twice by the change
 * handler, first before the router id has been changed and then after
 * the router id has been changed. The first invocation will result in
 * local routes for all VNIs/VRF being deleted and withdrawn and the next
 * will result in the routes being re-advertised.
 */
void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw)
{
	if (withdraw) {

		/* delete and withdraw all the type-5 routes
		   stored in the global table for this vrf
		 */
		withdraw_router_id_vrf(bgp);

		/* delete all the VNI routes (type-2/type-3) routes for all the
		 * L2-VNIs
		 */
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_backet *,
				       void *))withdraw_router_id_vni,
			     bgp);
	} else {

		/* advertise all routes in the vrf as type-5 routes with the new
		 * RD
		 */
		update_router_id_vrf(bgp);

		/* advertise all the VNI routes (type-2/type-3) routes with the
		 * new RD
		 */
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_backet *,
				       void *))update_router_id_vni,
			     bgp);
	}
}

/*
 * Handle change to export RT - update and advertise local routes.
 */
int bgp_evpn_handle_export_rt_change(struct bgp *bgp, struct bgpevpn *vpn)
{
	return update_routes_for_vni(bgp, vpn);
}

void bgp_evpn_handle_vrf_rd_change(struct bgp *bgp_vrf,
				   int withdraw)
{
	if (withdraw)
		delete_withdraw_vrf_routes(bgp_vrf);
	else
		update_advertise_vrf_routes(bgp_vrf);
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
 * TODO: Hardcoded for a maximum of 2 VNIs right now
 */
char *bgp_evpn_label2str(mpls_label_t *label, u_int32_t num_labels,
			 char *buf, int len)
{
	vni_t vni1, vni2;

	vni1 = label2vni(label);
	if (num_labels == 2) {
		vni2 = label2vni(label+1);
		snprintf(buf, len, "%u/%u", vni1, vni2);
	} else
		snprintf(buf, len, "%u", vni1);
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
	} else if (p->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		snprintf(buf, len, "[%d]:[0]:[0]:[%d]:[%s]",
			 p->prefix.route_type,
			 p->prefix.ip_prefix_length,
			 IS_EVPN_PREFIX_IPADDR_V4(p) ?
				inet_ntoa(p->prefix.ip.ipaddr_v4) :
				inet6_ntoa(p->prefix.ip.ipaddr_v6));
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
			    struct prefix_rd *prd,
			    mpls_label_t *label, u_int32_t num_labels,
			    struct attr *attr, int addpath_encode,
			    u_int32_t addpath_tx_id)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	int len, ipa_len = 0;

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
		/* RD, ESI, EthTag, MAC+len, IP len, [IP], 1 VNI */
		len = 8 + 10 + 4 + 1 + 6 + 1 + ipa_len + 3;
		if (ipa_len && num_labels > 1) /* There are 2 VNIs */
			len += 3;
		stream_putc(s, len);
		stream_put(s, prd->val, 8);	 /* RD */
		stream_put(s, 0, 10);		    /* ESI */
		stream_putl(s, 0);		    /* Ethernet Tag ID */
		stream_putc(s, 8 * ETH_ALEN); /* Mac Addr Len - bits */
		stream_put(s, evp->prefix.mac.octet, 6); /* Mac Addr */
		stream_putc(s, 8 * ipa_len);		 /* IP address Length */
		if (ipa_len) /* IP */
			stream_put(s, &evp->prefix.ip.ip.addr, ipa_len);
		/* 1st label is the L2 VNI */
		stream_put(s, label, BGP_LABEL_BYTES);
		/* Include 2nd label (L3 VNI) if advertising MAC+IP */
		if (ipa_len && num_labels > 1)
			stream_put(s, label+1, BGP_LABEL_BYTES);
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
		evpn_mpattr_encode_type5(s, p, prd, label, num_labels, attr);
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
 * Map the RTs (configured or automatically derived) of a VRF to the VRF.
 * The mapping will be used during route processing.
 * bgp_def: default bgp instance
 * bgp_vrf: specific bgp vrf instance on which RT is configured
 */
void bgp_evpn_map_vrf_to_its_rts(struct bgp *bgp_vrf)
{
	int i = 0;
	struct ecommunity_val *eval = NULL;
	struct listnode *node = NULL, *nnode = NULL;
	struct ecommunity *ecom = NULL;

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			eval = (struct ecommunity_val *)(ecom->val
							 + (i
							    * ECOMMUNITY_SIZE));
			map_vrf_to_rt(bgp_vrf, eval);
		}
	}
}

/*
 * Unmap the RTs (configured or automatically derived) of a VRF from the VRF.
 */
void bgp_evpn_unmap_vrf_from_its_rts(struct bgp *bgp_vrf)
{
	int i;
	struct ecommunity_val *eval;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, ecom)) {
		for (i = 0; i < ecom->size; i++) {
			struct vrf_irt_node *irt;
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
			if (!CHECK_FLAG(bgp_vrf->vrf_flags,
					BGP_VRF_IMPORT_RT_CFGD))
				mask_ecom_global_admin(&eval_tmp, eval);

			irt = lookup_vrf_import_rt(&eval_tmp);
			if (irt)
				unmap_vrf_from_rt(bgp_vrf, irt);
		}
	}
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
	form_auto_rt(bgp, vpn->vni, vpn->import_rtl);
	UNSET_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD);

	/* Map RT to VNI */
	bgp_evpn_map_vni_to_its_rts(bgp, vpn);
}

/*
 * Derive Export RT automatically for VNI.
 */
void bgp_evpn_derive_auto_rt_export(struct bgp *bgp, struct bgpevpn *vpn)
{
	form_auto_rt(bgp, vpn->vni, vpn->export_rtl);
	UNSET_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD);
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vni.
 */
void bgp_evpn_derive_auto_rd_for_vrf(struct bgp *bgp)
{
	char buf[100];

	bgp->vrf_prd.family = AF_UNSPEC;
	bgp->vrf_prd.prefixlen = 64;
	sprintf(buf, "%s:%hu", inet_ntoa(bgp->router_id), bgp->vrf_rd_id);
	str2prefix_rd(buf, &bgp->vrf_prd);
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
			     struct in_addr originator_ip,
			     vrf_id_t tenant_vrf_id)
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
	vpn->tenant_vrf_id = tenant_vrf_id;

	/* Initialize route-target import and export lists */
	vpn->import_rtl = list_new();
	vpn->import_rtl->cmp = (int (*)(void *, void *))evpn_route_target_cmp;
	vpn->export_rtl = list_new();
	vpn->export_rtl->cmp = (int (*)(void *, void *))evpn_route_target_cmp;
	bf_assign_index(bm->rd_idspace, vpn->rd_id);
	derive_rd_rt_for_vni(bgp, vpn);

	/* Initialize EVPN route table. */
	vpn->route_table = bgp_table_init(AFI_L2VPN, SAFI_EVPN);

	/* Add to hash */
	if (!hash_get(bgp->vnihash, vpn, hash_alloc_intern)) {
		XFREE(MTYPE_BGP_EVPN, vpn);
		return NULL;
	}

	/* add to l2vni list on corresponding vrf */
	bgpevpn_link_to_l3vni(vpn);

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
	bgpevpn_unlink_from_l3vni(vpn);
	bgp_table_unlock(vpn->route_table);
	bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);
	list_delete_and_null(&vpn->import_rtl);
	list_delete_and_null(&vpn->export_rtl);
	bf_release_index(bm->rd_idspace, vpn->rd_id);
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
			"%u:Failed to create Type-2 route, VNI %u %s MAC %s IP %s (flags: 0x%x)",
			bgp->vrf_id, vpn->vni,
			CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY) ? "sticky gateway"
								 : "",
			prefix_mac2str(mac, buf, sizeof(buf)),
			ipaddr2str(ip, buf2, sizeof(buf2)),
			flags);
		return -1;
	}

	return 0;
}

static void link_l2vni_hash_to_l3vni(struct hash_backet *backet,
				     struct bgp *bgp_vrf)
{
	struct bgpevpn *vpn = NULL;
	struct bgp *bgp_def = NULL;

	bgp_def = bgp_get_default();
	assert(bgp_def);

	vpn = (struct bgpevpn *)backet->data;
	if (vpn->tenant_vrf_id == bgp_vrf->vrf_id)
		bgpevpn_link_to_l3vni(vpn);
}

int bgp_evpn_local_l3vni_add(vni_t l3vni,
			     vrf_id_t vrf_id,
			     struct ethaddr *rmac,
			     struct in_addr originator_ip)
{
	struct bgp *bgp_vrf = NULL; /* bgp VRF instance */
	struct bgp *bgp_def = NULL; /* default bgp instance */
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;
	as_t as = 0;

	/* get the default instamce - required to get the AS number for VRF
	 * auto-creatio
	 */
	bgp_def = bgp_get_default();
	if (!bgp_def) {
		zlog_err("Cannot process L3VNI  %u ADD - default BGP instance not yet created",
			 l3vni);
		return -1;
	}
	as = bgp_def->as;

	/* if the BGP vrf instance doesnt exist - create one */
	bgp_vrf = bgp_lookup_by_name(vrf_id_to_name(vrf_id));
	if (!bgp_vrf) {

		int ret = 0;

		ret = bgp_get(&bgp_vrf, &as, vrf_id_to_name(vrf_id),
			      BGP_INSTANCE_TYPE_VRF);
		switch (ret) {
		case BGP_ERR_MULTIPLE_INSTANCE_NOT_SET:
			zlog_err("'bgp multiple-instance' not present\n");
			return -1;
		case BGP_ERR_AS_MISMATCH:
			zlog_err("BGP is already running; AS is %u\n", as);
			return -1;
		case BGP_ERR_INSTANCE_MISMATCH:
			zlog_err("BGP instance name and AS number mismatch\n");
			return -1;
		}

		/* mark as auto created */
		SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO);
	}

	/* associate with l3vni */
	bgp_vrf->l3vni = l3vni;

	/* set the router mac - to be used in mac-ip routes for this vrf */
	memcpy(&bgp_vrf->rmac, rmac, sizeof(struct ethaddr));

	/* set the originator ip */
	bgp_vrf->originator_ip = originator_ip;

	/* auto derive RD/RT */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD))
		evpn_auto_rt_import_add_for_vrf(bgp_vrf);
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD))
		evpn_auto_rt_export_add_for_vrf(bgp_vrf);
	bgp_evpn_derive_auto_rd_for_vrf(bgp_vrf);

	/* link all corresponding l2vnis */
	hash_iterate(bgp_def->vnihash,
		     (void (*)(struct hash_backet *, void *))
			link_l2vni_hash_to_l3vni,
		     bgp_vrf);

	/* updates all corresponding local mac-ip routes */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn))
		update_routes_for_vni(bgp_def, vpn);

	/* advertise type-5 routes if needed */
	update_advertise_vrf_routes(bgp_vrf);

	/* install all remote routes belonging to this l3vni into correspondng
	 * vrf */
	install_routes_for_vrf(bgp_vrf);

	return 0;
}

int bgp_evpn_local_l3vni_del(vni_t l3vni,
			     vrf_id_t vrf_id)
{
	struct bgp *bgp_vrf = NULL; /* bgp vrf instance */
	struct bgp *bgp_def = NULL; /* default bgp instance */
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;

	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf) {
		zlog_err("Cannot process L3VNI %u Del - Could not find BGP instance",
			 l3vni);
		return -1;
	}

	bgp_def = bgp_get_default();
	if (!bgp_def) {
		zlog_err("Cannot process L3VNI %u Del - Could not find default BGP instance",
			 l3vni);
		return -1;
	}

	/* unimport remote routes from VRF, if it is AUTO vrf bgp_delete will
	 * take care of uninstalling the routes from zebra
	 */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO))
		uninstall_routes_for_vrf(bgp_vrf);

	/* delete/withdraw all type-5 routes */
	delete_withdraw_vrf_routes(bgp_vrf);

	/* remove the l3vni from vrf instance */
	bgp_vrf->l3vni = 0;

	/* remove the Rmac from the BGP vrf */
	memset(&bgp_vrf->rmac, 0, sizeof(struct ethaddr));

	/* delete RD/RT */
	if (bgp_vrf->vrf_import_rtl && !list_isempty(bgp_vrf->vrf_import_rtl)) {
		bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);
		list_delete_all_node(bgp_vrf->vrf_import_rtl);
	}
	if (bgp_vrf->vrf_export_rtl && !list_isempty(bgp_vrf->vrf_export_rtl)) {
		list_delete_all_node(bgp_vrf->vrf_export_rtl);
	}

	/* update all corresponding local mac-ip routes */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn))
		update_routes_for_vni(bgp_def, vpn);


	/* Delete the instance if it was autocreated */
	if (CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO))
		bgp_delete(bgp_vrf);

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
			   struct in_addr originator_ip,
			   vrf_id_t tenant_vrf_id)
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

		/* update tenant_vrf_id if required */
		if (vpn->tenant_vrf_id != tenant_vrf_id) {
			bgpevpn_unlink_from_l3vni(vpn);
			vpn->tenant_vrf_id = tenant_vrf_id;
			bgpevpn_link_to_l3vni(vpn);

			/* update all routes with new export RT for VRFs */
			update_routes_for_vni(bgp, vpn);
		}

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
		vpn = bgp_evpn_new(bgp, vni, originator_ip, tenant_vrf_id);
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
	if (bgp->vrf_import_rt_hash)
		hash_free(bgp->vrf_import_rt_hash);
	bgp->vrf_import_rt_hash = NULL;
	if (bgp->vnihash)
		hash_free(bgp->vnihash);
	bgp->vnihash = NULL;
	if (bgp->vrf_import_rtl)
		list_delete_and_null(&bgp->vrf_import_rtl);
	if (bgp->vrf_export_rtl)
		list_delete_and_null(&bgp->vrf_export_rtl);
	if (bgp->l2vnis)
		list_delete_and_null(&bgp->l2vnis);
	bf_release_index(bm->rd_idspace, bgp->vrf_rd_id);
}

/*
 * Initialization for EVPN
 * Create
 *  VNI hash table
 *  hash for RT to VNI
 *  assign a unique rd id for auto derivation of vrf_prd
 */
void bgp_evpn_init(struct bgp *bgp)
{
	bgp->vnihash =
		hash_create(vni_hash_key_make, vni_hash_cmp, "BGP VNI Hash");
	bgp->import_rt_hash =
		hash_create(import_rt_hash_key_make, import_rt_hash_cmp,
			    "BGP Import RT Hash");
	bgp->vrf_import_rt_hash =
		hash_create(vrf_import_rt_hash_key_make, vrf_import_rt_hash_cmp,
			    "BGP VRF Import RT Hash");
	bgp->vrf_import_rtl = list_new();
	bgp->vrf_import_rtl->cmp =
		(int (*)(void *, void *))evpn_route_target_cmp;

	bgp->vrf_export_rtl = list_new();
	bgp->vrf_export_rtl->cmp =
		(int (*)(void *, void *))evpn_route_target_cmp;
	bgp->l2vnis = list_new();
	bgp->l2vnis->cmp =
		(int (*)(void *, void *))vni_hash_cmp;
	bf_assign_index(bm->rd_idspace, bgp->vrf_rd_id);

}

void bgp_evpn_vrf_delete(struct bgp *bgp_vrf)
{
	bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);
}
