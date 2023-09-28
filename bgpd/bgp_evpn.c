// SPDX-License-Identifier: GPL-2.0-or-later
/* Ethernet-VPN Packet and vty Processing File
 * Copyright (C) 2016 6WIND
 * Copyright (C) 2017 Cumulus Networks, Inc.
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
#include "zclient.h"

#include "lib/printfrr.h"

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_encap_types.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mac.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_trace.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_packet.h"

/*
 * Definitions and external declarations.
 */
DEFINE_QOBJ_TYPE(bgpevpn);
DEFINE_QOBJ_TYPE(bgp_evpn_es);

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_INFO, "BGP EVPN instance information");
DEFINE_MTYPE_STATIC(BGPD, VRF_ROUTE_TARGET, "L3 Route Target");

/*
 * Static function declarations
 */
static void bgp_evpn_remote_ip_hash_init(struct bgpevpn *evpn);
static void bgp_evpn_remote_ip_hash_destroy(struct bgpevpn *evpn);
static void bgp_evpn_remote_ip_hash_add(struct bgpevpn *vpn,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_del(struct bgpevpn *vpn,
					struct bgp_path_info *pi);
static void bgp_evpn_remote_ip_hash_iterate(struct bgpevpn *vpn,
					    void (*func)(struct hash_bucket *,
							 void *),
					    void *arg);
static void bgp_evpn_link_to_vni_svi_hash(struct bgp *bgp, struct bgpevpn *vpn);
static void bgp_evpn_unlink_from_vni_svi_hash(struct bgp *bgp,
					      struct bgpevpn *vpn);
static unsigned int vni_svi_hash_key_make(const void *p);
static bool vni_svi_hash_cmp(const void *p1, const void *p2);
static void bgp_evpn_remote_ip_process_nexthops(struct bgpevpn *vpn,
						struct ipaddr *addr,
						bool resolve);
static void bgp_evpn_remote_ip_hash_link_nexthop(struct hash_bucket *bucket,
						 void *args);
static void bgp_evpn_remote_ip_hash_unlink_nexthop(struct hash_bucket *bucket,
						   void *args);
static struct in_addr zero_vtep_ip;

/*
 * Private functions.
 */

/*
 * Make vni hash key.
 */
static unsigned int vni_hash_key_make(const void *p)
{
	const struct bgpevpn *vpn = p;
	return (jhash_1word(vpn->vni, 0));
}

/*
 * Comparison function for vni hash
 */
static bool vni_hash_cmp(const void *p1, const void *p2)
{
	const struct bgpevpn *vpn1 = p1;
	const struct bgpevpn *vpn2 = p2;

	return vpn1->vni == vpn2->vni;
}

int vni_list_cmp(void *p1, void *p2)
{
	const struct bgpevpn *vpn1 = p1;
	const struct bgpevpn *vpn2 = p2;

	return vpn1->vni - vpn2->vni;
}

/*
 * Make vrf import route target hash key.
 */
static unsigned int vrf_import_rt_hash_key_make(const void *p)
{
	const struct vrf_irt_node *irt = p;
	const char *pnt = irt->rt.val;

	return jhash(pnt, 8, 0x5abc1234);
}

/*
 * Comparison function for vrf import rt hash
 */
static bool vrf_import_rt_hash_cmp(const void *p1, const void *p2)
{
	const struct vrf_irt_node *irt1 = p1;
	const struct vrf_irt_node *irt2 = p2;

	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
}

/*
 * Create a new vrf import_rt in evpn instance
 */
static struct vrf_irt_node *vrf_import_rt_new(struct ecommunity_val *rt)
{
	struct bgp *bgp_evpn = NULL;
	struct vrf_irt_node *irt;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn) {
		flog_err(EC_BGP_NO_DFLT,
			 "vrf import rt new - evpn instance not created yet");
		return NULL;
	}

	irt = XCALLOC(MTYPE_BGP_EVPN_VRF_IMPORT_RT,
		      sizeof(struct vrf_irt_node));

	irt->rt = *rt;
	irt->vrfs = list_new();

	/* Add to hash */
	(void)hash_get(bgp_evpn->vrf_import_rt_hash, irt, hash_alloc_intern);

	return irt;
}

/*
 * Free the vrf import rt node
 */
static void vrf_import_rt_free(struct vrf_irt_node *irt)
{
	struct bgp *bgp_evpn = NULL;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn) {
		flog_err(EC_BGP_NO_DFLT,
			 "vrf import rt free - evpn instance not created yet");
		return;
	}

	hash_release(bgp_evpn->vrf_import_rt_hash, irt);
	list_delete(&irt->vrfs);
	XFREE(MTYPE_BGP_EVPN_VRF_IMPORT_RT, irt);
}

static void hash_vrf_import_rt_free(struct vrf_irt_node *irt)
{
	XFREE(MTYPE_BGP_EVPN_VRF_IMPORT_RT, irt);
}

/*
 * Function to lookup Import RT node - used to map a RT to set of
 * VNIs importing routes with that RT.
 */
static struct vrf_irt_node *lookup_vrf_import_rt(struct ecommunity_val *rt)
{
	struct bgp *bgp_evpn = NULL;
	struct vrf_irt_node *irt;
	struct vrf_irt_node tmp;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn) {
		flog_err(
			EC_BGP_NO_DFLT,
			"vrf import rt lookup - evpn instance not created yet");
		return NULL;
	}

	memset(&tmp, 0, sizeof(tmp));
	memcpy(&tmp.rt, rt, ECOMMUNITY_SIZE);
	irt = hash_lookup(bgp_evpn->vrf_import_rt_hash, &tmp);
	return irt;
}

/*
 * Is specified VRF present on the RT's list of "importing" VRFs?
 */
static int is_vrf_present_in_irt_vrfs(struct list *vrfs, struct bgp *bgp_vrf)
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
static unsigned int import_rt_hash_key_make(const void *p)
{
	const struct irt_node *irt = p;
	const char *pnt = irt->rt.val;

	return jhash(pnt, 8, 0xdeadbeef);
}

/*
 * Comparison function for import rt hash
 */
static bool import_rt_hash_cmp(const void *p1, const void *p2)
{
	const struct irt_node *irt1 = p1;
	const struct irt_node *irt2 = p2;

	return (memcmp(irt1->rt.val, irt2->rt.val, ECOMMUNITY_SIZE) == 0);
}

/*
 * Create a new import_rt
 */
static struct irt_node *import_rt_new(struct bgp *bgp,
				      struct ecommunity_val *rt)
{
	struct irt_node *irt;

	irt = XCALLOC(MTYPE_BGP_EVPN_IMPORT_RT, sizeof(struct irt_node));

	irt->rt = *rt;
	irt->vnis = list_new();

	/* Add to hash */
	(void)hash_get(bgp->import_rt_hash, irt, hash_alloc_intern);

	return irt;
}

/*
 * Free the import rt node
 */
static void import_rt_free(struct bgp *bgp, struct irt_node *irt)
{
	hash_release(bgp->import_rt_hash, irt);
	list_delete(&irt->vnis);
	XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
}

static void hash_import_rt_free(struct irt_node *irt)
{
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

	memset(&tmp, 0, sizeof(tmp));
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
int bgp_evpn_route_target_cmp(struct ecommunity *ecom1,
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
 * Compare L3 Route Targets.
 */
static int evpn_vrf_route_target_cmp(struct vrf_route_target *rt1,
				     struct vrf_route_target *rt2)
{
	return bgp_evpn_route_target_cmp(rt1->ecom, rt2->ecom);
}

void bgp_evpn_xxport_delete_ecomm(void *val)
{
	struct ecommunity *ecomm = val;
	ecommunity_free(&ecomm);
}

/*
 * Delete l3 Route Target.
 */
static void evpn_vrf_rt_del(void *val)
{
	struct vrf_route_target *l3rt = val;

	ecommunity_free(&l3rt->ecom);

	XFREE(MTYPE_VRF_ROUTE_TARGET, l3rt);
}

/*
 * Allocate a new l3 Route Target.
 */
static struct vrf_route_target *evpn_vrf_rt_new(struct ecommunity *ecom)
{
	struct vrf_route_target *l3rt;

	l3rt = XCALLOC(MTYPE_VRF_ROUTE_TARGET, sizeof(struct vrf_route_target));

	l3rt->ecom = ecom;

	return l3rt;
}

/*
 * Mask off global-admin field of specified extended community (RT),
 * just retain the local-admin field.
 */
static inline void mask_ecom_global_admin(struct ecommunity_val *dst,
					  const struct ecommunity_val *src)
{
	uint8_t type;

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
 * Converts the RT to Ecommunity Value and adjusts masking based
 * on flags set for RT.
 */
static void vrf_rt2ecom_val(struct ecommunity_val *to_eval,
			    const struct vrf_route_target *l3rt, int iter)
{
	const struct ecommunity_val *eval;

	eval = (const struct ecommunity_val *)(l3rt->ecom->val +
					       (iter * ECOMMUNITY_SIZE));
	/* If using "automatic" or "wildcard *" RT,
	 * we only care about the local-admin sub-field.
	 * This is to facilitate using L3VNI(VRF-VNI)
	 * as the RT for EBGP peering too and simplify
	 * configurations by allowing any ASN via '*'.
	 */
	memcpy(to_eval, eval, ECOMMUNITY_SIZE);

	if (CHECK_FLAG(l3rt->flags, BGP_VRF_RT_AUTO) ||
	    CHECK_FLAG(l3rt->flags, BGP_VRF_RT_WILD))
		mask_ecom_global_admin(to_eval, eval);
}

/*
 * Map one RT to specified VRF.
 * bgp_vrf = BGP vrf instance
 */
static void map_vrf_to_rt(struct bgp *bgp_vrf, struct vrf_route_target *l3rt)
{
	uint32_t i = 0;

	for (i = 0; i < l3rt->ecom->size; i++) {
		struct vrf_irt_node *irt = NULL;
		struct ecommunity_val eval_tmp;

		/* Adjust masking for value */
		vrf_rt2ecom_val(&eval_tmp, l3rt, i);

		irt = lookup_vrf_import_rt(&eval_tmp);

		if (irt && is_vrf_present_in_irt_vrfs(irt->vrfs, bgp_vrf))
			return; /* Already mapped. */

		if (!irt)
			irt = vrf_import_rt_new(&eval_tmp);

		/* Add VRF to the list for this RT. */
		listnode_add(irt->vrfs, bgp_vrf);
	}
}

/*
 * Unmap specified VRF from specified RT. If there are no other
 * VRFs for this RT, then the RT hash is deleted.
 * bgp_vrf: BGP VRF specific instance
 */
static void unmap_vrf_from_rt(struct bgp *bgp_vrf,
			      struct vrf_route_target *l3rt)
{
	uint32_t i;

	for (i = 0; i < l3rt->ecom->size; i++) {
		struct vrf_irt_node *irt;
		struct ecommunity_val eval_tmp;

		/* Adjust masking for value */
		vrf_rt2ecom_val(&eval_tmp, l3rt, i);

		irt = lookup_vrf_import_rt(&eval_tmp);

		if (!irt)
			return; /* Not mapped */

		/* Delete VRF from list for this RT. */
		listnode_delete(irt->vrfs, bgp_vrf);

		if (!listnode_head(irt->vrfs))
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
	if (irt)
		if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
			/* Already mapped. */
			return;

	if (!irt)
		irt = import_rt_new(bgp, &eval_tmp);

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
		import_rt_free(bgp, irt);
	}
}

static void bgp_evpn_get_rmac_nexthop(struct bgpevpn *vpn,
				      const struct prefix_evpn *p,
				      struct attr *attr, uint8_t flags)
{
	struct bgp *bgp_vrf = vpn->bgp_vrf;

	memset(&attr->rmac, 0, sizeof(struct ethaddr));
	if (!bgp_vrf)
		return;

	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	/* Copy sys (pip) RMAC and PIP IP as nexthop
	 * in case of route is self MAC-IP,
	 * advertise-pip and advertise-svi-ip features
	 * are enabled.
	 * Otherwise, for all host MAC-IP route's
	 * copy anycast RMAC.
	 */
	if (CHECK_FLAG(flags, BGP_EVPN_MACIP_TYPE_SVI_IP)
	    && bgp_vrf->evpn_info->advertise_pip &&
	    bgp_vrf->evpn_info->is_anycast_mac) {
		/* copy sys rmac */
		memcpy(&attr->rmac, &bgp_vrf->evpn_info->pip_rmac,
		       ETH_ALEN);
		attr->nexthop = bgp_vrf->evpn_info->pip_ip;
		attr->mp_nexthop_global_in =
			bgp_vrf->evpn_info->pip_ip;
	} else
		memcpy(&attr->rmac, &bgp_vrf->rmac, ETH_ALEN);
}

/*
 * Create RT extended community automatically from passed information:
 * of the form AS:VNI.
 * NOTE: We use only the lower 16 bits of the AS. This is sufficient as
 * the need is to get a RT value that will be unique across different
 * VNIs but the same across routers (in the same AS) for a particular
 * VNI.
 */
static void form_auto_rt(struct bgp *bgp, vni_t vni, struct list *rtl,
			 bool is_l3)
{
	struct ecommunity_val eval;
	struct ecommunity *ecomadd;
	struct ecommunity *ecom;
	struct vrf_route_target *l3rt;
	struct vrf_route_target *newrt;
	bool ecom_found = false;
	struct listnode *node;

	if (bgp->advertise_autort_rfc8365)
		vni |= EVPN_AUTORT_VXLAN;
	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval, true);

	ecomadd = ecommunity_new();
	ecommunity_add_val(ecomadd, &eval, false, false);

	if (is_l3) {
		for (ALL_LIST_ELEMENTS_RO(rtl, node, l3rt))
			if (ecommunity_cmp(ecomadd, l3rt->ecom)) {
				ecom_found = true;
				break;
			}
	} else {
		for (ALL_LIST_ELEMENTS_RO(rtl, node, ecom))
			if (ecommunity_cmp(ecomadd, ecom)) {
				ecom_found = true;
				break;
			}
	}

	if (!ecom_found) {
		if (is_l3) {
			newrt = evpn_vrf_rt_new(ecomadd);
			/* Label it as autoderived */
			SET_FLAG(newrt->flags, BGP_VRF_RT_AUTO);
			listnode_add_sort(rtl, newrt);
		} else
			listnode_add_sort(rtl, ecomadd);
	} else
		ecommunity_free(&ecomadd);
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
 * Convert nexthop (remote VTEP IP) into an IPv6 address.
 */
static void evpn_convert_nexthop_to_ipv6(struct attr *attr)
{
	if (BGP_ATTR_NEXTHOP_AFI_IP6(attr))
		return;
	ipv4_to_ipv4_mapped_ipv6(&attr->mp_nexthop_global, attr->nexthop);
	attr->mp_nexthop_len = IPV6_MAX_BYTELEN;
}

/*
 * Wrapper for node get in global table.
 */
struct bgp_dest *bgp_evpn_global_node_get(struct bgp_table *table, afi_t afi,
					  safi_t safi,
					  const struct prefix_evpn *evp,
					  struct prefix_rd *prd,
					  const struct bgp_path_info *local_pi)
{
	struct prefix_evpn global_p;

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy of the prefix
		 */
		evpn_type1_prefix_global_copy(&global_p, evp);
		evp = &global_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
		   local_pi) {
		/*
		 * prefix in the global table needs MAC/IP, ensure they are
		 * present, using one's from local table's path_info.
		 */
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(local_pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp,
				evpn_type2_path_info_get_mac(local_pi),
				NULL /* ip */);
		}

		evp = &global_p;
	}
	return bgp_afi_node_get(table, afi, safi, (struct prefix *)evp, prd);
}

/*
 * Wrapper for node lookup in global table.
 */
struct bgp_dest *bgp_evpn_global_node_lookup(
	struct bgp_table *table, safi_t safi, const struct prefix_evpn *evp,
	struct prefix_rd *prd, const struct bgp_path_info *local_pi)
{
	struct prefix_evpn global_p;

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy of the prefix
		 */
		evpn_type1_prefix_global_copy(&global_p, evp);
		evp = &global_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE &&
		   local_pi) {
		/*
		 * prefix in the global table needs MAC/IP, ensure they are
		 * present, using one's from local table's path_info.
		 */
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(local_pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&global_p, evp,
				evpn_type2_path_info_get_mac(local_pi),
				NULL /* ip */);
		}

		evp = &global_p;
	}
	return bgp_safi_node_lookup(table, safi, (struct prefix *)evp, prd);
}

/*
 * Wrapper for node get in VNI IP table.
 */
struct bgp_dest *bgp_evpn_vni_ip_node_get(struct bgp_table *const table,
					  const struct prefix_evpn *evp,
					  const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p;

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy for the VNI
		 */
		evpn_type1_prefix_vni_ip_copy(&vni_p, evp,
					      parent_pi->attr->nexthop);
		evp = &vni_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Only MAC-IP should go into this table, not mac-only */
		assert(is_evpn_prefix_ipaddr_none(evp) == false);

		/*
		 * prefix in the vni IP table doesn't include MAC so
		 * we need to create a different copy of the prefix.
		 */
		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
		evp = &vni_p;
	}
	return bgp_node_get(table, (struct prefix *)evp);
}

/*
 * Wrapper for node lookup in VNI IP table.
 */
struct bgp_dest *
bgp_evpn_vni_ip_node_lookup(const struct bgp_table *const table,
			    const struct prefix_evpn *evp,
			    const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p;

	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE && parent_pi) {
		/* prefix in the global table doesn't include the VTEP-IP so
		 * we need to create a different copy for the VNI
		 */
		evpn_type1_prefix_vni_ip_copy(&vni_p, evp,
					      parent_pi->attr->nexthop);
		evp = &vni_p;
	} else if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Only MAC-IP should go into this table, not mac-only */
		assert(is_evpn_prefix_ipaddr_none(evp) == false);

		/*
		 * prefix in the vni IP table doesn't include MAC so
		 * we need to create a different copy of the prefix.
		 */
		evpn_type2_prefix_vni_ip_copy(&vni_p, evp);
		evp = &vni_p;
	}
	return bgp_node_lookup(table, (struct prefix *)evp);
}

/*
 * Wrapper for node get in VNI MAC table.
 */
struct bgp_dest *
bgp_evpn_vni_mac_node_get(struct bgp_table *const table,
			  const struct prefix_evpn *evp,
			  const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p;

	/* Only type-2 should ever go into this table */
	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

	/*
	 * prefix in the vni MAC table doesn't include IP so
	 * we need to create a different copy of the prefix.
	 */
	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
	evp = &vni_p;
	return bgp_node_get(table, (struct prefix *)evp);
}

/*
 * Wrapper for node lookup in VNI MAC table.
 */
struct bgp_dest *
bgp_evpn_vni_mac_node_lookup(const struct bgp_table *const table,
			     const struct prefix_evpn *evp,
			     const struct bgp_path_info *parent_pi)
{
	struct prefix_evpn vni_p;

	/* Only type-2 should ever go into this table */
	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);

	/*
	 * prefix in the vni MAC table doesn't include IP so
	 * we need to create a different copy of the prefix.
	 */
	evpn_type2_prefix_vni_mac_copy(&vni_p, evp);
	evp = &vni_p;
	return bgp_node_lookup(table, (struct prefix *)evp);
}

/*
 * Wrapper for node get in both VNI tables.
 */
struct bgp_dest *bgp_evpn_vni_node_get(struct bgpevpn *vpn,
				       const struct prefix_evpn *p,
				       const struct bgp_path_info *parent_pi)
{
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return bgp_evpn_vni_mac_node_get(vpn->mac_table, p, parent_pi);

	return bgp_evpn_vni_ip_node_get(vpn->ip_table, p, parent_pi);
}

/*
 * Wrapper for node lookup in both VNI tables.
 */
struct bgp_dest *bgp_evpn_vni_node_lookup(const struct bgpevpn *vpn,
					  const struct prefix_evpn *p,
					  const struct bgp_path_info *parent_pi)
{
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return bgp_evpn_vni_mac_node_lookup(vpn->mac_table, p,
						    parent_pi);

	return bgp_evpn_vni_ip_node_lookup(vpn->ip_table, p, parent_pi);
}

/*
 * Add (update) or delete MACIP from zebra.
 */
static int bgp_zebra_send_remote_macip(struct bgp *bgp, struct bgpevpn *vpn,
				       const struct prefix_evpn *p,
				       const struct ethaddr *mac,
				       struct in_addr remote_vtep_ip, int add,
				       uint8_t flags, uint32_t seq, esi_t *esi)
{
	struct stream *s;
	uint16_t ipa_len;
	static struct in_addr zero_remote_vtep_ip;
	bool esi_valid;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing remote macip",
				__func__);
		return 0;
	}

	if (!esi)
		esi = zero_esi;
	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(
		s, add ? ZEBRA_REMOTE_MACIP_ADD : ZEBRA_REMOTE_MACIP_DEL,
		bgp->vrf_id);
	stream_putl(s, vpn->vni);

	if (mac) /* Mac Addr */
		stream_put(s, &mac->octet, ETH_ALEN);
	else
		stream_put(s, &p->prefix.macip_addr.mac.octet, ETH_ALEN);

	/* IP address length and IP address, if any. */
	if (is_evpn_prefix_ipaddr_none(p))
		stream_putw(s, 0);
	else {
		ipa_len = is_evpn_prefix_ipaddr_v4(p) ? IPV4_MAX_BYTELEN
						      : IPV6_MAX_BYTELEN;
		stream_putw(s, ipa_len);
		stream_put(s, &p->prefix.macip_addr.ip.ip.addr, ipa_len);
	}
	/* If the ESI is valid that becomes the nexthop; tape out the
	 * VTEP-IP for that case
	 */
	if (bgp_evpn_is_esi_valid(esi)) {
		esi_valid = true;
		stream_put_in_addr(s, &zero_remote_vtep_ip);
	} else {
		esi_valid = false;
		stream_put_in_addr(s, &remote_vtep_ip);
	}

	/* TX flags - MAC sticky status and/or gateway mac */
	/* Also TX the sequence number of the best route. */
	if (add) {
		stream_putc(s, flags);
		stream_putl(s, seq);
		stream_put(s, esi, sizeof(esi_t));
	}

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL)) {
		char esi_buf[ESI_STR_LEN];

		if (esi_valid)
			esi_to_str(esi, esi_buf, sizeof(esi_buf));
		else
			snprintf(esi_buf, sizeof(esi_buf), "-");
		zlog_debug(
			"Tx %s MACIP, VNI %u MAC %pEA IP %pIA flags 0x%x seq %u remote VTEP %pI4 esi %s",
			add ? "ADD" : "DEL", vpn->vni,
			(mac ? mac : &p->prefix.macip_addr.mac),
			&p->prefix.macip_addr.ip, flags, seq, &remote_vtep_ip,
			esi_buf);
	}

	frrtrace(5, frr_bgp, evpn_mac_ip_zsend, add, vpn, p, remote_vtep_ip,
		 esi);

        if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
          return -1;

        return 0;
}

/*
 * Add (update) or delete remote VTEP from zebra.
 */
static int bgp_zebra_send_remote_vtep(struct bgp *bgp, struct bgpevpn *vpn,
				      const struct prefix_evpn *p,
				      int flood_control, int add)
{
	struct stream *s;

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return 0;

	/* Don't try to register if Zebra doesn't know of this instance. */
	if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp)) {
		if (BGP_DEBUG(zebra, ZEBRA))
			zlog_debug(
				"%s: No zebra instance to talk to, not installing remote vtep",
				__func__);
		return 0;
	}

	s = zclient->obuf;
	stream_reset(s);

	zclient_create_header(
		s, add ? ZEBRA_REMOTE_VTEP_ADD : ZEBRA_REMOTE_VTEP_DEL,
		bgp->vrf_id);
	stream_putl(s, vpn->vni);
	if (is_evpn_prefix_ipaddr_v4(p))
		stream_put_in_addr(s, &p->prefix.imet_addr.ip.ipaddr_v4);
	else if (is_evpn_prefix_ipaddr_v6(p)) {
		flog_err(
			EC_BGP_VTEP_INVALID,
			"Bad remote IP when trying to %s remote VTEP for VNI %u",
			add ? "ADD" : "DEL", vpn->vni);
		return -1;
	}
	stream_putl(s, flood_control);

	stream_putw_at(s, 0, stream_get_endp(s));

	if (bgp_debug_zebra(NULL))
		zlog_debug("Tx %s Remote VTEP, VNI %u remote VTEP %pI4",
			   add ? "ADD" : "DEL", vpn->vni,
			   &p->prefix.imet_addr.ip.ipaddr_v4);

	frrtrace(3, frr_bgp, evpn_bum_vtep_zsend, add, vpn, p);

        if (zclient_send_message(zclient) == ZCLIENT_SEND_FAILURE)
          return -1;

        return 0;
}

/*
 * Build extended communities for EVPN prefix route.
 */
static void build_evpn_type5_route_extcomm(struct bgp *bgp_vrf,
					   struct attr *attr)
{
	struct ecommunity ecom_encap;
	struct ecommunity_val eval;
	struct ecommunity_val eval_rmac;
	bgp_encap_types tnl_type;
	struct listnode *node, *nnode;
	struct vrf_route_target *l3rt;
	struct ecommunity *old_ecom;
	struct ecommunity *ecom;
	struct list *vrf_export_rtl = NULL;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;

	/* Add Encap */
	if (bgp_attr_get_ecommunity(attr)) {
		old_ecom = bgp_attr_get_ecommunity(attr);
		ecom = ecommunity_merge(ecommunity_dup(old_ecom), &ecom_encap);
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else
		ecom = ecommunity_dup(&ecom_encap);
	bgp_attr_set_ecommunity(attr, ecom);
	attr->encap_tunneltype = tnl_type;

	/* Add the export RTs for L3VNI/VRF */
	vrf_export_rtl = bgp_vrf->vrf_export_rtl;
	for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode, l3rt))
		bgp_attr_set_ecommunity(
			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
					       l3rt->ecom));

	/* add the router mac extended community */
	if (!is_zero_mac(&attr->rmac)) {
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecommunity_add_val(bgp_attr_get_ecommunity(attr), &eval_rmac,
				   true, true);
	}
}

/*
 * Build extended communities for EVPN route.
 * This function is applicable for type-2 and type-3 routes. The layer-2 RT
 * and ENCAP extended communities are applicable for all routes.
 * The default gateway extended community and MAC mobility (sticky) extended
 * community are added as needed based on passed settings - only for type-2
 * routes. Likewise, the layer-3 RT and Router MAC extended communities are
 * added, if present, based on passed settings - only for non-link-local
 * type-2 routes.
 */
static void build_evpn_route_extcomm(struct bgpevpn *vpn, struct attr *attr,
				     int add_l3_ecomm,
				     struct ecommunity *macvrf_soo)
{
	struct ecommunity ecom_encap;
	struct ecommunity ecom_sticky;
	struct ecommunity ecom_default_gw;
	struct ecommunity ecom_na;
	struct ecommunity_val eval;
	struct ecommunity_val eval_sticky;
	struct ecommunity_val eval_default_gw;
	struct ecommunity_val eval_rmac;
	struct ecommunity_val eval_na;
	bool proxy;

	bgp_encap_types tnl_type;
	struct listnode *node, *nnode;
	struct ecommunity *ecom;
	struct vrf_route_target *l3rt;
	uint32_t seqnum;
	struct list *vrf_export_rtl = NULL;

	/* Encap */
	tnl_type = BGP_ENCAP_TYPE_VXLAN;
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(tnl_type, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;

	/* Add Encap */
	bgp_attr_set_ecommunity(attr, ecommunity_dup(&ecom_encap));
	attr->encap_tunneltype = tnl_type;

	/* Add the export RTs for L2VNI */
	for (ALL_LIST_ELEMENTS(vpn->export_rtl, node, nnode, ecom))
		bgp_attr_set_ecommunity(
			attr,
			ecommunity_merge(bgp_attr_get_ecommunity(attr), ecom));

	/* Add the export RTs for L3VNI if told to - caller determines
	 * when this should be done.
	 */
	if (add_l3_ecomm) {
		vrf_export_rtl = bgpevpn_get_vrf_export_rtl(vpn);
		if (vrf_export_rtl && !list_isempty(vrf_export_rtl)) {
			for (ALL_LIST_ELEMENTS(vrf_export_rtl, node, nnode,
					       l3rt))
				bgp_attr_set_ecommunity(
					attr,
					ecommunity_merge(
						bgp_attr_get_ecommunity(attr),
						l3rt->ecom));
		}
	}

	/* Add MAC mobility (sticky) if needed. */
	if (attr->sticky) {
		seqnum = 0;
		memset(&ecom_sticky, 0, sizeof(ecom_sticky));
		encode_mac_mobility_extcomm(1, seqnum, &eval_sticky);
		ecom_sticky.size = 1;
		ecom_sticky.unit_size = ECOMMUNITY_SIZE;
		ecom_sticky.val = (uint8_t *)eval_sticky.val;
		bgp_attr_set_ecommunity(
			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
					       &ecom_sticky));
	}

	/* Add RMAC, if told to. */
	if (add_l3_ecomm) {
		encode_rmac_extcomm(&eval_rmac, &attr->rmac);
		ecommunity_add_val(bgp_attr_get_ecommunity(attr), &eval_rmac,
				   true, true);
	}

	/* Add default gateway, if needed. */
	if (attr->default_gw) {
		memset(&ecom_default_gw, 0, sizeof(ecom_default_gw));
		encode_default_gw_extcomm(&eval_default_gw);
		ecom_default_gw.size = 1;
		ecom_default_gw.unit_size = ECOMMUNITY_SIZE;
		ecom_default_gw.val = (uint8_t *)eval_default_gw.val;
		bgp_attr_set_ecommunity(
			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
					       &ecom_default_gw));
	}

	proxy = !!(attr->es_flags & ATTR_ES_PROXY_ADVERT);
	if (attr->router_flag || proxy) {
		memset(&ecom_na, 0, sizeof(ecom_na));
		encode_na_flag_extcomm(&eval_na, attr->router_flag, proxy);
		ecom_na.size = 1;
		ecom_na.unit_size = ECOMMUNITY_SIZE;
		ecom_na.val = (uint8_t *)eval_na.val;
		bgp_attr_set_ecommunity(
			attr, ecommunity_merge(bgp_attr_get_ecommunity(attr),
					       &ecom_na));
	}

	/* Add MAC-VRF SoO, if configured */
	if (macvrf_soo)
		bgp_attr_set_ecommunity(
			attr, ecommunity_merge(attr->ecommunity, macvrf_soo));
}

/*
 * Add MAC mobility extended community to attribute.
 */
static void add_mac_mobility_to_attr(uint32_t seq_num, struct attr *attr)
{
	struct ecommunity ecom_tmp;
	struct ecommunity_val eval;
	uint8_t *ecom_val_ptr;
	uint32_t i;
	uint8_t *pnt;
	int type = 0;
	int sub_type = 0;
	struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

	/* Build MM */
	encode_mac_mobility_extcomm(0, seq_num, &eval);

	/* Find current MM ecommunity */
	ecom_val_ptr = NULL;

	if (ecomm) {
		for (i = 0; i < ecomm->size; i++) {
			pnt = ecomm->val + (i * ecomm->unit_size);
			type = *pnt++;
			sub_type = *pnt++;

			if (type == ECOMMUNITY_ENCODE_EVPN
			    && sub_type
				       == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY) {
				ecom_val_ptr =
					(ecomm->val + (i * ecomm->unit_size));
				break;
			}
		}
	}

	/* Update the existing MM ecommunity */
	if (ecom_val_ptr) {
		memcpy(ecom_val_ptr, eval.val, sizeof(char) * ecomm->unit_size);
	}
	/* Add MM to existing */
	else {
		memset(&ecom_tmp, 0, sizeof(ecom_tmp));
		ecom_tmp.size = 1;
		ecom_tmp.unit_size = ECOMMUNITY_SIZE;
		ecom_tmp.val = (uint8_t *)eval.val;

		if (ecomm)
			bgp_attr_set_ecommunity(
				attr, ecommunity_merge(ecomm, &ecom_tmp));
		else
			bgp_attr_set_ecommunity(attr,
						ecommunity_dup(&ecom_tmp));
	}
}

/* Install EVPN route into zebra. */
static int evpn_zebra_install(struct bgp *bgp, struct bgpevpn *vpn,
			      const struct prefix_evpn *p,
			      struct bgp_path_info *pi)
{
	int ret;
	uint8_t flags;
	int flood_control = VXLAN_FLOOD_DISABLED;
	uint32_t seq;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		flags = 0;

		if (pi->sub_type == BGP_ROUTE_IMPORTED) {
			if (pi->attr->sticky)
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY);
			if (pi->attr->default_gw)
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_GW);
			if (is_evpn_prefix_ipaddr_v6(p) &&
					pi->attr->router_flag)
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_ROUTER_FLAG);

			seq = mac_mobility_seqnum(pi->attr);
			/* if local ES notify zebra that this is a sync path */
			if (bgp_evpn_attr_is_local_es(pi->attr)) {
				SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
				if (bgp_evpn_attr_is_proxy(pi->attr))
					SET_FLAG(flags,
						ZEBRA_MACIP_TYPE_PROXY_ADVERT);
			}
		} else {
			if (!bgp_evpn_attr_is_sync(pi->attr))
				return 0;

			/* if a local path is being turned around and sent
			 * to zebra it is because it is a sync path on
			 * a local ES
			 */
			SET_FLAG(flags, ZEBRA_MACIP_TYPE_SYNC_PATH);
			/* supply the highest peer seq number to zebra
			 * for MM seq syncing
			 */
			seq = bgp_evpn_attr_get_sync_seq(pi->attr);
			/* if any of the paths from the peer have the ROUTER
			 * flag set install the local entry as a router entry
			 */
			if (is_evpn_prefix_ipaddr_v6(p) &&
					(pi->attr->es_flags &
					 ATTR_ES_PEER_ROUTER))
				SET_FLAG(flags,
						ZEBRA_MACIP_TYPE_ROUTER_FLAG);

			if (!(pi->attr->es_flags & ATTR_ES_PEER_ACTIVE))
				SET_FLAG(flags,
						ZEBRA_MACIP_TYPE_PROXY_ADVERT);
		}

		ret = bgp_zebra_send_remote_macip(
			bgp, vpn, p,
			(is_evpn_prefix_ipaddr_none(p)
				 ? NULL /* MAC update */
				 : evpn_type2_path_info_get_mac(
					   pi) /* MAC-IP update */),
			pi->attr->nexthop, 1, flags, seq,
			bgp_evpn_attr_get_esi(pi->attr));
	} else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE) {
		ret = bgp_evpn_remote_es_evi_add(bgp, vpn, p);
	} else {
		switch (bgp_attr_get_pmsi_tnl_type(pi->attr)) {
		case PMSI_TNLTYPE_INGR_REPL:
			flood_control = VXLAN_FLOOD_HEAD_END_REPL;
			break;

		case PMSI_TNLTYPE_PIM_SM:
			flood_control = VXLAN_FLOOD_PIM_SM;
			break;

		case PMSI_TNLTYPE_NO_INFO:
		case PMSI_TNLTYPE_RSVP_TE_P2MP:
		case PMSI_TNLTYPE_MLDP_P2MP:
		case PMSI_TNLTYPE_PIM_SSM:
		case PMSI_TNLTYPE_PIM_BIDIR:
		case PMSI_TNLTYPE_MLDP_MP2MP:
			flood_control = VXLAN_FLOOD_DISABLED;
			break;
		}
		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p, flood_control, 1);
	}

	return ret;
}

/* Uninstall EVPN route from zebra. */
static int evpn_zebra_uninstall(struct bgp *bgp, struct bgpevpn *vpn,
				const struct prefix_evpn *p,
				struct bgp_path_info *pi, bool is_sync)
{
	int ret;

	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ret = bgp_zebra_send_remote_macip(
			bgp, vpn, p,
			(is_evpn_prefix_ipaddr_none(p)
				 ? NULL /* MAC update */
				 : evpn_type2_path_info_get_mac(
					   pi) /* MAC-IP update */),
			(is_sync ? zero_vtep_ip : pi->attr->nexthop), 0, 0, 0,
			NULL);
	else if (p->prefix.route_type == BGP_EVPN_AD_ROUTE)
		ret = bgp_evpn_remote_es_evi_del(bgp, vpn, p);
	else
		ret = bgp_zebra_send_remote_vtep(bgp, vpn, p,
					VXLAN_FLOOD_DISABLED, 0);

	return ret;
}

/*
 * Due to MAC mobility, the prior "local" best route has been supplanted
 * by a "remote" best route. The prior route has to be deleted and withdrawn
 * from peers.
 */
static void evpn_delete_old_local_route(struct bgp *bgp, struct bgpevpn *vpn,
					struct bgp_dest *dest,
					struct bgp_path_info *old_local,
					struct bgp_path_info *new_select)
{
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
		char esi_buf[ESI_STR_LEN];
		char esi_buf2[ESI_STR_LEN];
		struct prefix_evpn *evp =
			(struct prefix_evpn *)bgp_dest_get_prefix(dest);

		zlog_debug("local path deleted %pFX es %s; new-path-es %s", evp,
			   esi_to_str(&old_local->attr->esi, esi_buf,
				      sizeof(esi_buf)),
			   new_select ? esi_to_str(&new_select->attr->esi,
						   esi_buf2, sizeof(esi_buf2))
				      : "");
	}

	/* Locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_dest = bgp_evpn_global_node_lookup(
		bgp->rib[afi][safi], safi,
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest),
		&vpn->prd, old_local);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, afi, safi, global_dest, &pi);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Delete route entry in the VNI route table, caller to remove. */
	bgp_path_info_delete(dest, old_local);
}

/*
 * Calculate the best path for an EVPN route. Install/update best path in zebra,
 * if appropriate.
 * Note: vpn is NULL for local EAD-ES routes.
 */
int evpn_route_select_install(struct bgp *bgp, struct bgpevpn *vpn,
				     struct bgp_dest *dest)
{
	struct bgp_path_info *old_select, *new_select;
	struct bgp_path_info_pair old_and_new;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int ret = 0;

	/* Compute the best path. */
	bgp_best_selection(bgp, dest, &bgp->maxpaths[afi][safi], &old_and_new,
			   afi, safi);
	old_select = old_and_new.old;
	new_select = old_and_new.new;

	/* If the best path hasn't changed - see if there is still something to
	 * update to zebra RIB.
	 * Remote routes and SYNC route (i.e. local routes with
	 * SYNCED_FROM_PEER flag) need to updated to zebra on any attr
	 * change.
	 */
	if (old_select && old_select == new_select
	    && old_select->type == ZEBRA_ROUTE_BGP
	    && (old_select->sub_type == BGP_ROUTE_IMPORTED ||
			bgp_evpn_attr_is_sync(old_select->attr))
	    && !CHECK_FLAG(dest->flags, BGP_NODE_USER_CLEAR)
	    && !CHECK_FLAG(old_select->flags, BGP_PATH_ATTR_CHANGED)
	    && !bgp_addpath_is_addpath_used(&bgp->tx_addpath, afi, safi)) {
		if (bgp_zebra_has_route_changed(old_select))
			ret = evpn_zebra_install(
				bgp, vpn,
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest),
				old_select);
		UNSET_FLAG(old_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(old_select->flags, BGP_PATH_LINK_BW_CHG);
		bgp_zebra_clear_route_change_flags(dest);
		return ret;
	}

	/* If the user did a "clear" this flag will be set */
	UNSET_FLAG(dest->flags, BGP_NODE_USER_CLEAR);

	/* bestpath has changed; update relevant fields and install or uninstall
	 * into the zebra RIB.
	 */
	if (old_select || new_select)
		bgp_bump_version(dest);

	if (old_select)
		bgp_path_info_unset_flag(dest, old_select, BGP_PATH_SELECTED);
	if (new_select) {
		bgp_path_info_set_flag(dest, new_select, BGP_PATH_SELECTED);
		bgp_path_info_unset_flag(dest, new_select,
					 BGP_PATH_ATTR_CHANGED);
		UNSET_FLAG(new_select->flags, BGP_PATH_MULTIPATH_CHG);
		UNSET_FLAG(new_select->flags, BGP_PATH_LINK_BW_CHG);
	}

	/* a local entry with the SYNC flag also results in a MAC-IP update
	 * to zebra
	 */
	if (new_select && new_select->type == ZEBRA_ROUTE_BGP
	    && (new_select->sub_type == BGP_ROUTE_IMPORTED ||
			bgp_evpn_attr_is_sync(new_select->attr))) {
		ret = evpn_zebra_install(
			bgp, vpn,
			(struct prefix_evpn *)bgp_dest_get_prefix(dest),
			new_select);

		/* If an old best existed and it was a "local" route, the only
		 * reason
		 * it would be supplanted is due to MAC mobility procedures. So,
		 * we
		 * need to do an implicit delete and withdraw that route from
		 * peers.
		 */
		if (new_select->sub_type == BGP_ROUTE_IMPORTED &&
				old_select && old_select->peer == bgp->peer_self
				&& old_select->type == ZEBRA_ROUTE_BGP
				&& old_select->sub_type == BGP_ROUTE_STATIC
				&& vpn)
			evpn_delete_old_local_route(bgp, vpn, dest,
					old_select, new_select);
	} else {
		if (old_select && old_select->type == ZEBRA_ROUTE_BGP
		    && old_select->sub_type == BGP_ROUTE_IMPORTED)
			ret = evpn_zebra_uninstall(
				bgp, vpn,
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest),
				old_select, false);
	}

	/* Clear any route change flags. */
	bgp_zebra_clear_route_change_flags(dest);

	/* Reap old select bgp_path_info, if it has been removed */
	if (old_select && CHECK_FLAG(old_select->flags, BGP_PATH_REMOVED))
		bgp_path_info_reap(dest, old_select);

	return ret;
}

static struct bgp_path_info *bgp_evpn_route_get_local_path(
		struct bgp *bgp, struct bgp_dest *dest)
{
	struct bgp_path_info *tmp_pi;
	struct bgp_path_info *local_pi = NULL;

	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
			tmp_pi = tmp_pi->next) {
		if (bgp_evpn_is_path_local(bgp, tmp_pi)) {
			local_pi = tmp_pi;
			break;
		}
	}

	return local_pi;
}

static int update_evpn_type5_route_entry(struct bgp *bgp_evpn,
					 struct bgp *bgp_vrf, afi_t afi,
					 safi_t safi, struct bgp_dest *dest,
					 struct attr *attr, int *route_changed)
{
	struct attr *attr_new = NULL;
	struct bgp_path_info *pi = NULL;
	mpls_label_t label = MPLS_INVALID_LABEL;
	struct bgp_path_info *local_pi = NULL;
	struct bgp_path_info *tmp_pi = NULL;

	*route_changed = 0;

	/* See if this is an update of an existing route, or a new add. */
	local_pi = bgp_evpn_route_get_local_path(bgp_evpn, dest);

	/*
	 * create a new route entry if one doesn't exist.
	 * Otherwise see if route attr has changed
	 */
	if (!local_pi) {

		/* route has changed as this is the first entry */
		*route_changed = 1;

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(attr);

		/* create the route info from attribute */
		pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
			       bgp_evpn->peer_self, attr_new, dest);
		SET_FLAG(pi->flags, BGP_PATH_VALID);

		/* Type-5 routes advertise the L3-VNI */
		bgp_path_info_extra_get(pi);
		vni2label(bgp_vrf->l3vni, &label);
		memcpy(&pi->extra->label, &label, sizeof(label));
		pi->extra->num_labels = 1;

		/* add the route entry to route node*/
		bgp_path_info_add(dest, pi);
	} else {

		tmp_pi = local_pi;
		if (!attrhash_cmp(tmp_pi->attr, attr)) {

			/* attribute changed */
			*route_changed = 1;

			/* The attribute has changed. */
			/* Add (or update) attribute to hash. */
			attr_new = bgp_attr_intern(attr);
			bgp_path_info_set_flag(dest, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = monotime(NULL);
		}
	}
	return 0;
}

/* update evpn type-5 route entry */
static int update_evpn_type5_route(struct bgp *bgp_vrf, struct prefix_evpn *evp,
				   struct attr *src_attr, afi_t src_afi,
				   safi_t src_safi)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct attr attr;
	struct bgp_dest *dest = NULL;
	struct bgp *bgp_evpn = NULL;
	int route_changed = 0;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return 0;

	/* Build path attribute for this route - use the source attr, if
	 * present, else treat as locally originated.
	 */
	if (src_attr)
		attr = *src_attr;
	else {
		memset(&attr, 0, sizeof(attr));
		bgp_attr_default_set(&attr, bgp_vrf, BGP_ORIGIN_IGP);
	}

	/* Advertise Primary IP (PIP) is enabled, send individual
	 * IP (default instance router-id) as nexthop.
	 * PIP is disabled or vrr interface is not present
	 * use anycast-IP as nexthop and anycast RMAC.
	 */
	if (!bgp_vrf->evpn_info->advertise_pip ||
	    (!bgp_vrf->evpn_info->is_anycast_mac)) {
		attr.nexthop = bgp_vrf->originator_ip;
		attr.mp_nexthop_global_in = bgp_vrf->originator_ip;
		memcpy(&attr.rmac, &bgp_vrf->rmac, ETH_ALEN);
	} else {
		/* copy sys rmac */
		memcpy(&attr.rmac, &bgp_vrf->evpn_info->pip_rmac, ETH_ALEN);
		if (bgp_vrf->evpn_info->pip_ip.s_addr != INADDR_ANY) {
			attr.nexthop = bgp_vrf->evpn_info->pip_ip;
			attr.mp_nexthop_global_in = bgp_vrf->evpn_info->pip_ip;
		} else if (bgp_vrf->evpn_info->pip_ip.s_addr == INADDR_ANY)
			if (bgp_debug_zebra(NULL))
				zlog_debug(
					"VRF %s evp %pFX advertise-pip primary ip is not configured",
					vrf_id_to_name(bgp_vrf->vrf_id), evp);
	}

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"VRF %s type-5 route evp %pFX RMAC %pEA nexthop %pI4",
			vrf_id_to_name(bgp_vrf->vrf_id), evp, &attr.rmac,
			&attr.nexthop);

	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;

	if (src_afi == AFI_IP6 &&
	    CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP)) {
		if (src_attr &&
		    !IN6_IS_ADDR_UNSPECIFIED(&src_attr->mp_nexthop_global)) {
			attr.evpn_overlay.type = OVERLAY_INDEX_GATEWAY_IP;
			SET_IPADDR_V6(&attr.evpn_overlay.gw_ip);
			memcpy(&attr.evpn_overlay.gw_ip.ipaddr_v6,
			       &src_attr->mp_nexthop_global,
			       sizeof(struct in6_addr));
		}
	} else if (src_afi == AFI_IP &&
		   CHECK_FLAG(bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN],
			      BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP)) {
		if (src_attr && src_attr->nexthop.s_addr != 0) {
			attr.evpn_overlay.type = OVERLAY_INDEX_GATEWAY_IP;
			SET_IPADDR_V4(&attr.evpn_overlay.gw_ip);
			memcpy(&attr.evpn_overlay.gw_ip.ipaddr_v4,
			       &src_attr->nexthop, sizeof(struct in_addr));
		}
	}

	/* Setup RT and encap extended community */
	build_evpn_type5_route_extcomm(bgp_vrf, &attr);

	/* get the route node in global table */
	dest = bgp_evpn_global_node_get(bgp_evpn->rib[afi][safi], afi, safi,
					evp, &bgp_vrf->vrf_prd, NULL);
	assert(dest);

	/* create or update the route entry within the route node */
	update_evpn_type5_route_entry(bgp_evpn, bgp_vrf, afi, safi, dest, &attr,
				      &route_changed);

	/* schedule for processing and unlock node */
	if (route_changed) {
		bgp_process(bgp_evpn, dest, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* uninten temporary */
	if (!src_attr)
		aspath_unintern(&attr.aspath);
	return 0;
}

static void bgp_evpn_get_sync_info(struct bgp *bgp, esi_t *esi,
				   struct bgp_dest *dest, uint32_t loc_seq,
				   uint32_t *max_sync_seq, bool *active_on_peer,
				   bool *peer_router, bool *proxy_from_peer,
				   const struct ethaddr *mac)
{
	struct bgp_path_info *tmp_pi;
	struct bgp_path_info *second_best_path = NULL;
	uint32_t tmp_mm_seq = 0;
	esi_t *tmp_esi;
	int paths_eq;
	struct ethaddr *tmp_mac;
	bool mac_cmp = false;
	struct prefix_evpn *evp = (struct prefix_evpn *)&dest->rn->p;


	/* mac comparison is not needed for MAC-only routes */
	if (mac && !is_evpn_prefix_ipaddr_none(evp))
		mac_cmp = true;

	/* find the best non-local path. a local path can only be present
	 * as best path
	 */
	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
	     tmp_pi = tmp_pi->next) {
		if (tmp_pi->sub_type != BGP_ROUTE_IMPORTED ||
			!CHECK_FLAG(tmp_pi->flags, BGP_PATH_VALID))
			continue;

		/* ignore paths that have a different mac */
		if (mac_cmp) {
			tmp_mac = evpn_type2_path_info_get_mac(tmp_pi);
			if (memcmp(mac, tmp_mac, sizeof(*mac)))
				continue;
		}

		if (bgp_evpn_path_info_cmp(bgp, tmp_pi, second_best_path,
					   &paths_eq, false))
			second_best_path = tmp_pi;
	}

	if (!second_best_path)
		return;

	tmp_esi = bgp_evpn_attr_get_esi(second_best_path->attr);
	/* if this has the same ES desination as the local path
	 * it is a sync path
	 */
	if (!memcmp(esi, tmp_esi, sizeof(esi_t))) {
		tmp_mm_seq = mac_mobility_seqnum(second_best_path->attr);
		if (tmp_mm_seq < loc_seq)
			return;

		/* we have a non-proxy path from the ES peer.  */
		if (second_best_path->attr->es_flags &
					ATTR_ES_PROXY_ADVERT) {
			*proxy_from_peer = true;
		} else {
			*active_on_peer = true;
		}

		if (second_best_path->attr->router_flag)
			*peer_router = true;

		/* we use both proxy and non-proxy imports to
		 * determine the max sync sequence
		 */
		if (tmp_mm_seq > *max_sync_seq)
			*max_sync_seq = tmp_mm_seq;
	}
}

/* Bubble up sync-info from all paths (non-best) to the local-path.
 * This is need for MM sequence number syncing and proxy advertisement.
 * Note: The local path can only exist as a best path in the
 * VPN route table. It will take precedence over all sync paths.
 */
static void update_evpn_route_entry_sync_info(struct bgp *bgp,
					      struct bgp_dest *dest,
					      struct attr *attr,
					      uint32_t loc_seq, bool setup_sync,
					      const struct ethaddr *mac)
{
	esi_t *esi;
	struct prefix_evpn *evp =
		(struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	esi = bgp_evpn_attr_get_esi(attr);
	if (bgp_evpn_is_esi_valid(esi)) {
		if (setup_sync) {
			uint32_t max_sync_seq = 0;
			bool active_on_peer = false;
			bool peer_router = false;
			bool proxy_from_peer = false;

			bgp_evpn_get_sync_info(bgp, esi, dest, loc_seq,
					       &max_sync_seq, &active_on_peer,
					       &peer_router, &proxy_from_peer,
					       mac);
			attr->mm_sync_seqnum = max_sync_seq;
			if (active_on_peer)
				attr->es_flags |= ATTR_ES_PEER_ACTIVE;
			else
				attr->es_flags &= ~ATTR_ES_PEER_ACTIVE;
			if (proxy_from_peer)
				attr->es_flags |= ATTR_ES_PEER_PROXY;
			else
				attr->es_flags &= ~ATTR_ES_PEER_PROXY;
			if (peer_router)
				attr->es_flags |= ATTR_ES_PEER_ROUTER;
			else
				attr->es_flags &= ~ATTR_ES_PEER_ROUTER;

			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
				char esi_buf[ESI_STR_LEN];

				zlog_debug(
					"setup sync info for %pFX es %s max_seq %d %s%s%s",
					evp,
					esi_to_str(esi, esi_buf,
						   sizeof(esi_buf)),
					max_sync_seq,
					(attr->es_flags & ATTR_ES_PEER_ACTIVE)
						? "peer-active "
						: "",
					(attr->es_flags & ATTR_ES_PEER_PROXY)
						? "peer-proxy "
						: "",
					(attr->es_flags & ATTR_ES_PEER_ROUTER)
						? "peer-router "
						: "");
			}
		}
	} else {
		attr->mm_sync_seqnum = 0;
		attr->es_flags &= ~ATTR_ES_PEER_ACTIVE;
		attr->es_flags &= ~ATTR_ES_PEER_PROXY;
	}
}

/*
 * Create or update EVPN route entry. This could be in the VNI route tables
 * or the global route table.
 */
static int update_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				   afi_t afi, safi_t safi,
				   struct bgp_dest *dest, struct attr *attr,
				   const struct ethaddr *mac,
				   const struct ipaddr *ip, int add,
				   struct bgp_path_info **pi, uint8_t flags,
				   uint32_t seq, bool vpn_rt, bool *old_is_sync)
{
	struct bgp_path_info *tmp_pi;
	struct bgp_path_info *local_pi;
	struct attr *attr_new;
	struct attr local_attr;
	mpls_label_t label[BGP_MAX_LABELS];
	uint32_t num_labels = 1;
	int route_change = 1;
	uint8_t sticky = 0;
	const struct prefix_evpn *evp;

	*pi = NULL;
	evp = (const struct prefix_evpn *)bgp_dest_get_prefix(dest);
	memset(&label, 0, sizeof(label));

	/* See if this is an update of an existing route, or a new add. */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest);

	/* If route doesn't exist already, create a new one, if told to.
	 * Otherwise act based on whether the attributes of the route have
	 * changed or not.
	 */
	if (!local_pi && !add)
		return 0;

	if (old_is_sync && local_pi)
		*old_is_sync = bgp_evpn_attr_is_sync(local_pi->attr);

	/* if a local path is being added with a non-zero esi look
	 * for SYNC paths from ES peers and bubble up the sync-info
	 */
	update_evpn_route_entry_sync_info(bgp, dest, attr, seq, vpn_rt, mac);

	/* For non-GW MACs, update MAC mobility seq number, if needed. */
	if (seq && !CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW))
		add_mac_mobility_to_attr(seq, attr);

	if (!local_pi) {
		local_attr = *attr;

		/* Extract MAC mobility sequence number, if any. */
		local_attr.mm_seqnum =
			bgp_attr_mac_mobility_seqnum(&local_attr, &sticky);
		local_attr.sticky = sticky;

		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(&local_attr);

		/* Create new route with its attribute. */
		tmp_pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
				   bgp->peer_self, attr_new, dest);
		SET_FLAG(tmp_pi->flags, BGP_PATH_VALID);
		bgp_path_info_extra_get(tmp_pi);

		/* The VNI goes into the 'label' field of the route */
		vni2label(vpn->vni, &label[0]);

		/* Type-2 routes may carry a second VNI - the L3-VNI.
		 * Only attach second label if we are advertising two labels for
		 * type-2 routes.
		 */
		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
		    && CHECK_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS)) {
			vni_t l3vni;

			l3vni = bgpevpn_get_l3vni(vpn);
			if (l3vni) {
				vni2label(l3vni, &label[1]);
				num_labels++;
			}
		}

		memcpy(&tmp_pi->extra->label, label, sizeof(label));
		tmp_pi->extra->num_labels = num_labels;

		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
			if (mac)
				evpn_type2_path_info_set_mac(tmp_pi, *mac);
			else if (ip)
				evpn_type2_path_info_set_ip(tmp_pi, *ip);
		}

		/* Mark route as self type-2 route */
		if (flags && CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
			tmp_pi->extra->evpn->af_flags =
				BGP_EVPN_MACIP_TYPE_SVI_IP;
		bgp_path_info_add(dest, tmp_pi);
	} else {
		tmp_pi = local_pi;
		if (attrhash_cmp(tmp_pi->attr, attr)
		    && !CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
			route_change = 0;
		else {
			/*
			 * The attributes have changed, type-2 routes needs to
			 * be advertised with right labels.
			 */
			vni2label(vpn->vni, &label[0]);
			if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
			    && CHECK_FLAG(vpn->flags,
					  VNI_FLAG_USE_TWO_LABELS)) {
				vni_t l3vni;

				l3vni = bgpevpn_get_l3vni(vpn);
				if (l3vni) {
					vni2label(l3vni, &label[1]);
					num_labels++;
				}
			}
			memcpy(&tmp_pi->extra->label, label, sizeof(label));
			tmp_pi->extra->num_labels = num_labels;

			if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
				if (mac)
					evpn_type2_path_info_set_mac(tmp_pi,
								     *mac);
				else if (ip)
					evpn_type2_path_info_set_ip(tmp_pi,
								    *ip);
			}

			/* The attribute has changed. */
			/* Add (or update) attribute to hash. */
			local_attr = *attr;
			bgp_path_info_set_flag(dest, tmp_pi,
					       BGP_PATH_ATTR_CHANGED);

			/* Extract MAC mobility sequence number, if any. */
			local_attr.mm_seqnum = bgp_attr_mac_mobility_seqnum(
				&local_attr, &sticky);
			local_attr.sticky = sticky;

			attr_new = bgp_attr_intern(&local_attr);

			/* Restore route, if needed. */
			if (CHECK_FLAG(tmp_pi->flags, BGP_PATH_REMOVED))
				bgp_path_info_restore(dest, tmp_pi);

			/* Unintern existing, set to new. */
			bgp_attr_unintern(&tmp_pi->attr);
			tmp_pi->attr = attr_new;
			tmp_pi->uptime = monotime(NULL);
		}
	}

	/* local MAC-IP routes in the VNI table are linked to
	 * the destination ES
	 */
	if (route_change && vpn_rt
	    && (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE))
		bgp_evpn_path_es_link(tmp_pi, vpn->vni,
				      bgp_evpn_attr_get_esi(tmp_pi->attr));

	/* Return back the route entry. */
	*pi = tmp_pi;
	return route_change;
}

static void evpn_zebra_reinstall_best_route(struct bgp *bgp,
					    struct bgpevpn *vpn,
					    struct bgp_dest *dest)
{
	struct bgp_path_info *tmp_ri;
	struct bgp_path_info *curr_select = NULL;

	for (tmp_ri = bgp_dest_get_bgp_path_info(dest); tmp_ri;
	     tmp_ri = tmp_ri->next) {
		if (CHECK_FLAG(tmp_ri->flags, BGP_PATH_SELECTED)) {
			curr_select = tmp_ri;
			break;
		}
	}

	if (curr_select && curr_select->type == ZEBRA_ROUTE_BGP
			&& (curr_select->sub_type == BGP_ROUTE_IMPORTED ||
				bgp_evpn_attr_is_sync(curr_select->attr)))
		evpn_zebra_install(bgp, vpn,
		   (const struct prefix_evpn *)bgp_dest_get_prefix(dest),
		   curr_select);
}

/*
 * If the local route was not selected evict it and tell zebra to re-add
 * the best remote dest.
 *
 * Typically a local path added by zebra is expected to be selected as
 * best. In which case when a remote path wins as best (later)
 * evpn_route_select_install itself evicts the older-local-best path.
 *
 * However if bgp's add and zebra's add cross paths (race condition) it
 * is possible that the local path is no longer the "older" best path.
 * It is a path that was never designated as best and hence requires
 * additional handling to prevent bgp from injecting and holding on to a
 * non-best local path.
 */
static struct bgp_dest *
evpn_cleanup_local_non_best_route(struct bgp *bgp, struct bgpevpn *vpn,
				  struct bgp_dest *dest,
				  struct bgp_path_info *local_pi)
{
	/* local path was not picked as the winner; kick it out */
	if (bgp_debug_zebra(NULL))
		zlog_debug("evicting local evpn prefix %pBD as remote won",
			   dest);

	evpn_delete_old_local_route(bgp, vpn, dest, local_pi, NULL);

	/* tell zebra to re-add the best remote path */
	evpn_zebra_reinstall_best_route(bgp, vpn, dest);

	return bgp_path_info_reap(dest, local_pi);
}

static inline bool bgp_evpn_route_add_l3_ecomm_ok(struct bgpevpn *vpn,
						  const struct prefix_evpn *p,
						  esi_t *esi)
{
	return p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
	       && (is_evpn_prefix_ipaddr_v4(p)
		   || (is_evpn_prefix_ipaddr_v6(p)
		       && !IN6_IS_ADDR_LINKLOCAL(
			       &p->prefix.macip_addr.ip.ipaddr_v6)))
	       && CHECK_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS)
	       && bgpevpn_get_l3vni(vpn) && bgp_evpn_es_add_l3_ecomm_ok(esi);
}

/*
 * Create or update EVPN route (of type based on prefix) for specified VNI
 * and schedule for processing.
 */
static int update_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
			     struct prefix_evpn *p, uint8_t flags,
			     uint32_t seq, esi_t *esi)
{
	struct bgp_dest *dest;
	struct attr attr;
	struct attr *attr_new;
	int add_l3_ecomm = 0;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	int route_change;
	bool old_is_sync = false;
	bool mac_only = false;
	struct ecommunity *macvrf_soo = NULL;

	memset(&attr, 0, sizeof(attr));

	/* Build path-attribute for this route. */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.nexthop = vpn->originator_ip;
	attr.mp_nexthop_global_in = vpn->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr.sticky = CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY) ? 1 : 0;
	attr.default_gw = CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_GW) ? 1 : 0;
	attr.router_flag = CHECK_FLAG(flags,
				      ZEBRA_MACIP_TYPE_ROUTER_FLAG) ? 1 : 0;
	if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_PROXY_ADVERT))
		attr.es_flags |= ATTR_ES_PROXY_ADVERT;

	if (esi && bgp_evpn_is_esi_valid(esi)) {
		memcpy(&attr.esi, esi, sizeof(esi_t));
		attr.es_flags |= ATTR_ES_IS_LOCAL;
	}

	/* PMSI is only needed for type-3 routes */
	if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE) {
		attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL);
		bgp_attr_set_pmsi_tnl_type(&attr, PMSI_TNLTYPE_INGR_REPL);
	}

	/* router mac is only needed for type-2 routes here. */
	if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		uint8_t af_flags = 0;

		if (CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_SVI_IP))
			SET_FLAG(af_flags, BGP_EVPN_MACIP_TYPE_SVI_IP);

		bgp_evpn_get_rmac_nexthop(vpn, p, &attr, af_flags);
	}

	if (bgp_debug_zebra(NULL)) {
		char buf3[ESI_STR_LEN];

		zlog_debug(
			"VRF %s vni %u type-%u route evp %pFX RMAC %pEA nexthop %pI4 esi %s",
			vpn->bgp_vrf ? vrf_id_to_name(vpn->bgp_vrf->vrf_id)
				     : "None",
			vpn->vni, p->prefix.route_type, p, &attr.rmac,
			&attr.mp_nexthop_global_in,
			esi_to_str(esi, buf3, sizeof(buf3)));
	}

	vni2label(vpn->vni, &(attr.label));

	/* Include L3 VNI related RTs and RMAC for type-2 routes, if they're
	 * IPv4 or IPv6 global addresses and we're advertising L3VNI with
	 * these routes.
	 */
	add_l3_ecomm = bgp_evpn_route_add_l3_ecomm_ok(
		vpn, p, (attr.es_flags & ATTR_ES_IS_LOCAL) ? &attr.esi : NULL);

	if (bgp->evpn_info)
		macvrf_soo = bgp->evpn_info->soo;

	/* Set up extended community. */
	build_evpn_route_extcomm(vpn, &attr, add_l3_ecomm, macvrf_soo);

	/* First, create (or fetch) route node within the VNI.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_evpn_vni_node_get(vpn, p, NULL);

	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		mac_only = true;

	/* Create or update route entry. */
	route_change = update_evpn_route_entry(
		bgp, vpn, afi, safi, dest, &attr,
		(mac_only ? NULL : &p->prefix.macip_addr.mac), NULL /* ip */, 1,
		&pi, flags, seq, true /* setup_sync */, &old_is_sync);
	assert(pi);
	attr_new = pi->attr;

	/* lock ri to prevent freeing in evpn_route_select_install */
	bgp_path_info_lock(pi);

       /* Perform route selection. Normally, the local route in the
        * VNI is expected to win and be the best route. However, if
        * there is a race condition where a host moved from local to
        * remote and the remote route was received in BGP just prior
        * to the local MACIP notification from zebra, the remote
        * route would win, and we should evict the defunct local route
        * and (re)install the remote route into zebra.
	*/
	evpn_route_select_install(bgp, vpn, dest);
	/*
	 * If the new local route was not selected evict it and tell zebra
	 * to re-add the best remote dest. BGP doesn't retain non-best local
	 * routes.
	 */
	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
		route_change = 0;
	} else {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			route_change = 0;
			dest = evpn_cleanup_local_non_best_route(bgp, vpn, dest,
								 pi);
		} else {
			bool new_is_sync;

			/* If the local path already existed and is still the
			 * best path we need to also check if it transitioned
			 * from being a sync path to a non-sync path. If it
			 * it did we need to notify zebra that the sync-path
			 * has been removed.
			 */
			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
			if (!new_is_sync && old_is_sync)
				evpn_zebra_uninstall(bgp, vpn, p, pi, true);
		}
	}
	bgp_path_info_unlock(pi);

	if (dest)
		bgp_dest_unlock_node(dest);

	/* If this is a new route or some attribute has changed, export the
	 * route to the global table. The route will be advertised to peers
	 * from there. Note that this table is a 2-level tree (RD-level +
	 * Prefix-level) similar to L3VPN routes.
	 */
	if (route_change) {
		struct bgp_path_info *global_pi;

		dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
						p, &vpn->prd, NULL);
		update_evpn_route_entry(
			bgp, vpn, afi, safi, dest, attr_new, NULL /* mac */,
			NULL /* ip */, 1, &global_pi, flags, seq,
			false /* setup_sync */, NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, dest, afi, safi);
		bgp_dest_unlock_node(dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);

	return 0;
}

/*
 * Delete EVPN route entry.
 * The entry can be in ESI/VNI table or the global table.
 */
void delete_evpn_route_entry(struct bgp *bgp, afi_t afi, safi_t safi,
				    struct bgp_dest *dest,
				    struct bgp_path_info **pi)
{
	struct bgp_path_info *tmp_pi;

	*pi = NULL;

	/* Now, find matching route. */
	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
	     tmp_pi = tmp_pi->next)
		if (tmp_pi->peer == bgp->peer_self
		    && tmp_pi->type == ZEBRA_ROUTE_BGP
		    && tmp_pi->sub_type == BGP_ROUTE_STATIC)
			break;

	*pi = tmp_pi;

	/* Mark route for delete. */
	if (tmp_pi)
		bgp_path_info_delete(dest, tmp_pi);
}

/* Delete EVPN type5 route */
static int delete_evpn_type5_route(struct bgp *bgp_vrf, struct prefix_evpn *evp)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi = NULL;
	struct bgp *bgp_evpn = NULL; /* evpn bgp instance */

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return 0;

	/* locate the global route entry for this type-5 prefix */
	dest = bgp_evpn_global_node_lookup(bgp_evpn->rib[afi][safi], safi, evp,
					   &bgp_vrf->vrf_prd, NULL);
	if (!dest)
		return 0;

	delete_evpn_route_entry(bgp_evpn, afi, safi, dest, &pi);
	if (pi)
		bgp_process(bgp_evpn, dest, afi, safi);
	bgp_dest_unlock_node(dest);
	return 0;
}

/*
 * Delete EVPN route (of type based on prefix) for specified VNI and
 * schedule for processing.
 */
static int delete_evpn_route(struct bgp *bgp, struct bgpevpn *vpn,
			     struct prefix_evpn *p)
{
	struct bgp_dest *dest, *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* First, locate the route node within the VNI. If it doesn't exist,
	 * there
	 * is nothing further to do.
	 * NOTE: There is no RD here.
	 */
	dest = bgp_evpn_vni_node_lookup(vpn, p, NULL);
	if (!dest)
		return 0;

	/* Next, locate route node in the global EVPN routing table. Note that
	 * this table is a 2-level tree (RD-level + Prefix-level) similar to
	 * L3VPN routes.
	 */
	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, p,
						  &vpn->prd, NULL);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, afi, safi, global_dest, &pi);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Delete route entry in the VNI route table. This can just be removed.
	 */
	delete_evpn_route_entry(bgp, afi, safi, dest, &pi);
	if (pi) {
		dest = bgp_path_info_reap(dest, pi);
		assert(dest);
		evpn_route_select_install(bgp, vpn, dest);
	}

	/* dest should still exist due to locking make coverity happy */
	assert(dest);
	bgp_dest_unlock_node(dest);

	return 0;
}

void bgp_evpn_update_type2_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				       struct bgp_dest *dest,
				       struct bgp_path_info *local_pi,
				       const char *caller)
{
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;
	struct bgp_path_info *pi;
	struct attr attr;
	struct attr *attr_new;
	uint32_t seq;
	int add_l3_ecomm = 0;
	struct bgp_dest *global_dest;
	struct bgp_path_info *global_pi;
	struct prefix_evpn evp;
	int route_change;
	bool old_is_sync = false;
	struct ecommunity *macvrf_soo = NULL;

	if (CHECK_FLAG(local_pi->flags, BGP_PATH_REMOVED))
		return;

	/*
	 * VNI table MAC-IP prefixes don't have MAC so make sure it's set from
	 * path info here.
	 */
	if (is_evpn_prefix_ipaddr_none((struct prefix_evpn *)&dest->rn->p)) {
		/* VNI MAC -> Global */
		evpn_type2_prefix_global_copy(
			&evp, (struct prefix_evpn *)&dest->rn->p, NULL /* mac */,
			evpn_type2_path_info_get_ip(local_pi));
	} else {
		/* VNI IP -> Global */
		evpn_type2_prefix_global_copy(
			&evp, (struct prefix_evpn *)&dest->rn->p,
			evpn_type2_path_info_get_mac(local_pi), NULL /* ip */);
	}

	/*
	 * Build attribute per local route as the MAC mobility and
	 * some other values could differ for different routes. The
	 * attributes will be shared in the hash table.
	 */
	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);
	attr.nexthop = vpn->originator_ip;
	attr.mp_nexthop_global_in = vpn->originator_ip;
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	attr.sticky = (local_pi->attr->sticky) ? 1 : 0;
	attr.router_flag = (local_pi->attr->router_flag) ? 1 : 0;
	attr.es_flags = local_pi->attr->es_flags;
	if (local_pi->attr->default_gw) {
		attr.default_gw = 1;
		if (is_evpn_prefix_ipaddr_v6(&evp))
			attr.router_flag = 1;
	}
	memcpy(&attr.esi, &local_pi->attr->esi, sizeof(esi_t));
	bgp_evpn_get_rmac_nexthop(vpn, &evp, &attr,
				  local_pi->extra->evpn->af_flags);
	vni2label(vpn->vni, &(attr.label));
	/* Add L3 VNI RTs and RMAC for non IPv6 link-local if
	 * using L3 VNI for type-2 routes also.
	 */
	add_l3_ecomm = bgp_evpn_route_add_l3_ecomm_ok(
		vpn, &evp,
		(attr.es_flags & ATTR_ES_IS_LOCAL) ? &attr.esi : NULL);

	if (bgp->evpn_info)
		macvrf_soo = bgp->evpn_info->soo;

	/* Set up extended community. */
	build_evpn_route_extcomm(vpn, &attr, add_l3_ecomm, macvrf_soo);
	seq = mac_mobility_seqnum(local_pi->attr);

	if (bgp_debug_zebra(NULL)) {
		char buf3[ESI_STR_LEN];

		zlog_debug(
			"VRF %s vni %u evp %pFX RMAC %pEA nexthop %pI4 esi %s esf 0x%x from %s",
			vpn->bgp_vrf ? vrf_id_to_name(vpn->bgp_vrf->vrf_id)
				     : " ",
			vpn->vni, &evp, &attr.rmac, &attr.mp_nexthop_global_in,
			esi_to_str(&attr.esi, buf3, sizeof(buf3)),
			attr.es_flags, caller);
	}

	/* Update the route entry. */
	route_change = update_evpn_route_entry(
		bgp, vpn, afi, safi, dest, &attr, NULL /* mac */, NULL /* ip */,
		0, &pi, 0, seq, true /* setup_sync */, &old_is_sync);

	assert(pi);
	attr_new = pi->attr;
	/* lock ri to prevent freeing in evpn_route_select_install */
	bgp_path_info_lock(pi);

	/* Perform route selection. Normally, the local route in the
	 * VNI is expected to win and be the best route. However,
	 * under peculiar situations (e.g., tunnel (next hop) IP change
	 * that causes best selection to be based on next hop), a
	 * remote route could win. If the local route is the best,
	 * ensure it is updated in the global EVPN route table and
	 * advertised to peers; otherwise, ensure it is evicted and
	 * (re)install the remote route into zebra.
	 */
	evpn_route_select_install(bgp, vpn, dest);

	if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
		route_change = 0;
	} else {
		if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
			route_change = 0;
			evpn_cleanup_local_non_best_route(bgp, vpn, dest, pi);
		} else {
			bool new_is_sync;

			/* If the local path already existed and is still the
			 * best path we need to also check if it transitioned
			 * from being a sync path to a non-sync path. If it
			 * it did we need to notify zebra that the sync-path
			 * has been removed.
			 */
			new_is_sync = bgp_evpn_attr_is_sync(pi->attr);
			if (!new_is_sync && old_is_sync)
				evpn_zebra_uninstall(bgp, vpn, &evp, pi, true);
		}
	}


	/* unlock pi */
	bgp_path_info_unlock(pi);

	if (route_change) {
		/* Update route in global routing table. */
		global_dest = bgp_evpn_global_node_get(
			bgp->rib[afi][safi], afi, safi, &evp, &vpn->prd, NULL);
		assert(global_dest);
		update_evpn_route_entry(
			bgp, vpn, afi, safi, global_dest, attr_new,
			NULL /* mac */, NULL /* ip */, 0, &global_pi, 0,
			mac_mobility_seqnum(attr_new), false /* setup_sync */,
			NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Unintern temporary. */
	aspath_unintern(&attr.aspath);
}

static void update_type2_route(struct bgp *bgp, struct bgpevpn *vpn,
			       struct bgp_dest *dest)
{
	struct bgp_path_info *tmp_pi;

	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return;

	/* Identify local route. */
	for (tmp_pi = bgp_dest_get_bgp_path_info(dest); tmp_pi;
	     tmp_pi = tmp_pi->next) {
		if (tmp_pi->peer == bgp->peer_self &&
		    tmp_pi->type == ZEBRA_ROUTE_BGP &&
		    tmp_pi->sub_type == BGP_ROUTE_STATIC)
			break;
	}

	if (!tmp_pi)
		return;

	bgp_evpn_update_type2_route_entry(bgp, vpn, dest, tmp_pi, __func__);
}

/*
 * Update all type-2 (MACIP) local routes for this VNI - these should also
 * be scheduled for advertise to peers.
 */
static void update_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct bgp_dest *dest;

	/* Walk this VNI's route MAC & IP table and update local type-2
	 * routes. For any routes updated, update corresponding entry in the
	 * global table too.
	 */
	for (dest = bgp_table_top(vpn->mac_table); dest;
	     dest = bgp_route_next(dest))
		update_type2_route(bgp, vpn, dest);

	for (dest = bgp_table_top(vpn->ip_table); dest;
	     dest = bgp_route_next(dest))
		update_type2_route(bgp, vpn, dest);
}

/*
 * Delete all type-2 (MACIP) local routes for this VNI - only from the
 * global routing table. These are also scheduled for withdraw from peers.
 */
static void delete_global_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rddest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	rddest = bgp_node_lookup(bgp->rib[afi][safi],
				 (struct prefix *)&vpn->prd);
	if (rddest) {
		table = bgp_dest_get_bgp_table_info(rddest);
		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
				continue;

			delete_evpn_route_entry(bgp, afi, safi, dest, &pi);
			if (pi)
				bgp_process(bgp, dest, afi, safi);
		}

		/* Unlock RD node. */
		bgp_dest_unlock_node(rddest);
	}
}

static struct bgp_dest *delete_vni_type2_route(struct bgp *bgp,
					       struct bgp_dest *dest)
{
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return dest;

	delete_evpn_route_entry(bgp, afi, safi, dest, &pi);

	/* Route entry in local table gets deleted immediately. */
	if (pi)
		dest = bgp_path_info_reap(dest, pi);

	return dest;
}

static void delete_vni_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct bgp_dest *dest;

	/* Next, walk this VNI's MAC & IP route table and delete local type-2
	 * routes.
	 */
	for (dest = bgp_table_top(vpn->mac_table); dest;
	     dest = bgp_route_next(dest)) {
		dest = delete_vni_type2_route(bgp, dest);
		assert(dest);
	}

	for (dest = bgp_table_top(vpn->ip_table); dest;
	     dest = bgp_route_next(dest)) {
		dest = delete_vni_type2_route(bgp, dest);
		assert(dest);
	}
}

/*
 * Delete all type-2 (MACIP) local routes for this VNI - from the global
 * table as well as the per-VNI route table.
 */
static void delete_all_type2_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	/* First, walk the global route table for this VNI's type-2 local
	 * routes.
	 * EVPN routes are a 2-level table, first get the RD table.
	 */
	delete_global_type2_routes(bgp, vpn);
	delete_vni_type2_routes(bgp, vpn);
}

/*
 * Delete all routes in the per-VNI route table.
 */
static void delete_all_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi, *nextpi;

	/* Walk this VNI's MAC & IP route table and delete all routes. */
	for (dest = bgp_table_top(vpn->mac_table); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_evpn_remote_ip_hash_del(vpn, pi);
			bgp_path_info_delete(dest, pi);
			dest = bgp_path_info_reap(dest, pi);

			assert(dest);
		}
	}

	for (dest = bgp_table_top(vpn->ip_table); dest;
	     dest = bgp_route_next(dest)) {
		for (pi = bgp_dest_get_bgp_path_info(dest);
		     (pi != NULL) && (nextpi = pi->next, 1); pi = nextpi) {
			bgp_path_info_delete(dest, pi);
			dest = bgp_path_info_reap(dest, pi);

			assert(dest);
		}
	}
}

/* BUM traffic flood mode per-l2-vni */
static int bgp_evpn_vni_flood_mode_get(struct bgp *bgp,
					struct bgpevpn *vpn)
{
	/* if flooding has been globally disabled per-vni mode is
	 * not relevant
	 */
	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_DISABLED)
		return VXLAN_FLOOD_DISABLED;

	/* if mcast group ip has been specified we use a PIM-SM MDT */
	if (vpn->mcast_grp.s_addr != INADDR_ANY)
		return VXLAN_FLOOD_PIM_SM;

	/* default is ingress replication */
	return VXLAN_FLOOD_HEAD_END_REPL;
}

/*
 * Update (and advertise) local routes for a VNI. Invoked upon the VNI
 * export RT getting modified or change to tunnel IP. Note that these
 * situations need the route in the per-VNI table as well as the global
 * table to be updated (as attributes change).
 */
int update_routes_for_vni(struct bgp *bgp, struct bgpevpn *vpn)
{
	int ret;
	struct prefix_evpn p;

	update_type1_routes_for_evi(bgp, vpn);

	/* Update and advertise the type-3 route (only one) followed by the
	 * locally learnt type-2 routes (MACIP) - for this VNI.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_vni_flood_mode_get(bgp, vpn)
				== VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, vpn->originator_ip);
		ret = update_evpn_route(bgp, vpn, &p, 0, 0, NULL);
		if (ret)
			return ret;
	}

	update_all_type2_routes(bgp, vpn);
	return 0;
}

/* Update Type-2/3 Routes for L2VNI.
 * Called by hash_iterate()
 */
static void update_routes_for_vni_hash(struct hash_bucket *bucket,
				       struct bgp *bgp)
{
	struct bgpevpn *vpn;

	if (!bucket)
		return;

	vpn = (struct bgpevpn *)bucket->data;
	update_routes_for_vni(bgp, vpn);
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
	delete_all_type2_routes(bgp, vpn);

	build_evpn_type3_prefix(&p, vpn->originator_ip);
	ret = delete_evpn_route(bgp, vpn, &p);
	if (ret)
		return ret;

	/* Delete all routes from the per-VNI table. */
	delete_all_vni_routes(bgp, vpn);
	return 0;
}

/*
 * There is a flood mcast IP address change. Update the mcast-grp and
 * remove the type-3 route if any. A new type-3 route will be generated
 * post tunnel_ip update if the new flood mode is head-end-replication.
 */
static int bgp_evpn_mcast_grp_change(struct bgp *bgp, struct bgpevpn *vpn,
		struct in_addr mcast_grp)
{
	struct prefix_evpn p;

	vpn->mcast_grp = mcast_grp;

	if (is_vni_live(vpn)) {
		build_evpn_type3_prefix(&p, vpn->originator_ip);
		delete_evpn_route(bgp, vpn, &p);
	}

	return 0;
}

/*
 * If there is a tunnel endpoint IP address (VTEP-IP) change for this VNI.
     - Deletes tip_hash entry for old VTEP-IP
     - Adds tip_hash entry/refcount for new VTEP-IP
     - Deletes prior type-3 route for L2VNI (if needed)
     - Updates originator_ip
 * Note: Route re-advertisement happens elsewhere after other processing
 * other changes.
 */
static void handle_tunnel_ip_change(struct bgp *bgp_vrf, struct bgp *bgp_evpn,
				    struct bgpevpn *vpn,
				    struct in_addr originator_ip)
{
	struct prefix_evpn p;
	struct in_addr old_vtep_ip;

	if (bgp_vrf) /* L3VNI */
		old_vtep_ip = bgp_vrf->originator_ip;
	else /* L2VNI */
		old_vtep_ip = vpn->originator_ip;

	/* TIP didn't change, nothing to do */
	if (IPV4_ADDR_SAME(&old_vtep_ip, &originator_ip))
		return;

	/* If L2VNI is not live, we only need to update the originator_ip.
	 * L3VNIs are updated immediately, so we can't bail out early.
	 */
	if (!bgp_vrf && !is_vni_live(vpn)) {
		vpn->originator_ip = originator_ip;
		return;
	}

	/* Update the tunnel-ip hash */
	bgp_tip_del(bgp_evpn, &old_vtep_ip);
	if (bgp_tip_add(bgp_evpn, &originator_ip))
		/* The originator_ip was not already present in the
		 * bgp martian next-hop table as a tunnel-ip, so we
		 * need to go back and filter routes matching the new
		 * martian next-hop.
		 */
		bgp_filter_evpn_routes_upon_martian_change(bgp_evpn,
							   BGP_MARTIAN_TUN_IP);

	if (!bgp_vrf) {
		/* Need to withdraw type-3 route as the originator IP is part
		 * of the key.
		 */
		build_evpn_type3_prefix(&p, vpn->originator_ip);
		delete_evpn_route(bgp_evpn, vpn, &p);

		vpn->originator_ip = originator_ip;
	} else
		bgp_vrf->originator_ip = originator_ip;

	return;
}

static struct bgp_path_info *
bgp_create_evpn_bgp_path_info(struct bgp_path_info *parent_pi,
			      struct bgp_dest *dest, struct attr *attr)
{
	struct attr *attr_new;
	struct bgp_path_info *pi;

	/* Add (or update) attribute to hash. */
	attr_new = bgp_attr_intern(attr);

	/* Create new route with its attribute. */
	pi = info_make(parent_pi->type, BGP_ROUTE_IMPORTED, 0, parent_pi->peer,
		       attr_new, dest);
	SET_FLAG(pi->flags, BGP_PATH_VALID);
	bgp_path_info_extra_get(pi);
	if (!pi->extra->vrfleak)
		pi->extra->vrfleak =
			XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
				sizeof(struct bgp_path_info_extra_vrfleak));
	pi->extra->vrfleak->parent = bgp_path_info_lock(parent_pi);
	bgp_dest_lock_node((struct bgp_dest *)parent_pi->net);
	if (parent_pi->extra) {
		memcpy(&pi->extra->label, &parent_pi->extra->label,
		       sizeof(pi->extra->label));
		pi->extra->num_labels = parent_pi->extra->num_labels;
		pi->extra->igpmetric = parent_pi->extra->igpmetric;
	}

	bgp_path_info_add(dest, pi);

	return pi;
}

/*
 * Install route entry into the VRF routing table and invoke route selection.
 */
static int install_evpn_route_entry_in_vrf(struct bgp *bgp_vrf,
					   const struct prefix_evpn *evp,
					   struct bgp_path_info *parent_pi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct attr attr;
	struct attr *attr_new;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;
	bool new_pi = false;
	bool use_l3nhg = false;
	bool is_l3nhg_active = false;
	char buf1[INET6_ADDRSTRLEN];

	memset(pp, 0, sizeof(struct prefix));
	ip_prefix_from_evpn_prefix(evp, pp);

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"vrf %s: import evpn prefix %pFX parent %p flags 0x%x",
			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
			parent_pi->flags);

	/* Create (or fetch) route within the VRF. */
	/* NOTE: There is no RD here. */
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		dest = bgp_node_get(bgp_vrf->rib[afi][safi], pp);
	} else
		return 0;

	/* EVPN routes currently only support a IPv4 next hop which corresponds
	 * to the remote VTEP. When importing into a VRF, if it is IPv6 host
	 * or prefix route, we have to convert the next hop to an IPv4-mapped
	 * address for the rest of the code to flow through. In the case of IPv4,
	 * make sure to set the flag for next hop attribute.
	 */
	attr = *parent_pi->attr;
	if (attr.evpn_overlay.type != OVERLAY_INDEX_GATEWAY_IP) {
		if (afi == AFI_IP6)
			evpn_convert_nexthop_to_ipv6(&attr);
		else {
			attr.nexthop = attr.mp_nexthop_global_in;
			attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		}
	} else {

		/*
		 * If gateway IP overlay index is specified in the NLRI of
		 * EVPN RT-5, this gateway IP should be used as the nexthop
		 * for the prefix in the VRF
		 */
		if (bgp_debug_zebra(NULL)) {
			zlog_debug(
				"Install gateway IP %s as nexthop for prefix %pFX in vrf %s",
				inet_ntop(pp->family, &attr.evpn_overlay.gw_ip,
					  buf1, sizeof(buf1)), pp,
					  vrf_id_to_name(bgp_vrf->vrf_id));
		}

		if (afi == AFI_IP6) {
			memcpy(&attr.mp_nexthop_global,
			       &attr.evpn_overlay.gw_ip.ipaddr_v6,
			       sizeof(struct in6_addr));
			attr.mp_nexthop_len = IPV6_MAX_BYTELEN;
		} else {
			attr.nexthop = attr.evpn_overlay.gw_ip.ipaddr_v4;
			attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		}
	}

	bgp_evpn_es_vrf_use_nhg(bgp_vrf, &parent_pi->attr->esi, &use_l3nhg,
				&is_l3nhg_active, NULL);
	if (use_l3nhg)
		attr.es_flags |= ATTR_ES_L3_NHG_USE;
	if (is_l3nhg_active)
		attr.es_flags |= ATTR_ES_L3_NHG_ACTIVE;

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest, &attr);
		new_pi = true;
	} else {
		if (attrhash_cmp(pi->attr, &attr)
		    && !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED)) {
			bgp_dest_unlock_node(dest);
			return 0;
		}
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(&attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(dest, pi);

		/* Mark if nexthop has changed. */
		if ((afi == AFI_IP
		     && !IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
		    || (afi == AFI_IP6
			&& !IPV6_ADDR_SAME(&pi->attr->mp_nexthop_global,
					   &attr_new->mp_nexthop_global)))
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

		bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	}

	/* Gateway IP nexthop should be resolved */
	if (attr.evpn_overlay.type == OVERLAY_INDEX_GATEWAY_IP) {
		if (bgp_find_or_add_nexthop(bgp_vrf, bgp_vrf, afi, safi, pi,
					    NULL, 0, NULL))
			bgp_path_info_set_flag(dest, pi, BGP_PATH_VALID);
		else {
			if (BGP_DEBUG(nht, NHT)) {
				inet_ntop(pp->family,
					  &attr.evpn_overlay.gw_ip,
					  buf1, sizeof(buf1));
				zlog_debug("%s: gateway IP NH unresolved",
					   buf1);
			}
			bgp_path_info_unset_flag(dest, pi, BGP_PATH_VALID);
		}
	} else {

		/* as it is an importation, change nexthop */
		bgp_path_info_set_flag(dest, pi, BGP_PATH_ANNC_NH_SELF);
	}

	/* Link path to evpn nexthop */
	bgp_evpn_path_nh_add(bgp_vrf, pi);

	bgp_aggregate_increment(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
				safi);

	/* Perform route selection and update zebra, if required. */
	bgp_process(bgp_vrf, dest, afi, safi);

	/* Process for route leaking. */
	vpn_leak_from_vrf_update(bgp_get_default(), bgp_vrf, pi);

	if (bgp_debug_zebra(NULL))
		zlog_debug("... %s pi dest %p (l %d) pi %p (l %d, f 0x%x)",
			   new_pi ? "new" : "update", dest,
			   bgp_dest_get_lock_count(dest), pi, pi->lock,
			   pi->flags);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Common handling for vni route tables install/selection.
 */
static int install_evpn_route_entry_in_vni_common(
	struct bgp *bgp, struct bgpevpn *vpn, const struct prefix_evpn *p,
	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
{
	struct bgp_path_info *pi;
	struct bgp_path_info *local_pi;
	struct attr *attr_new;
	int ret;
	bool old_local_es = false;
	bool new_local_es;

	/* Check if route entry is already present. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		/* Create an info */
		pi = bgp_create_evpn_bgp_path_info(parent_pi, dest,
						    parent_pi->attr);

		if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
			if (is_evpn_type2_dest_ipaddr_none(dest))
				evpn_type2_path_info_set_ip(
					pi, p->prefix.macip_addr.ip);
			else
				evpn_type2_path_info_set_mac(
					pi, p->prefix.macip_addr.mac);
		}

		new_local_es = bgp_evpn_attr_is_local_es(pi->attr);
	} else {
		/* Return early if attributes haven't changed
		 * and dest isn't flagged for removal.
		 * dest will be unlocked by either
		 * install_evpn_route_entry_in_vni_mac() or
		 * install_evpn_route_entry_in_vni_ip()
		 */
		if (attrhash_cmp(pi->attr, parent_pi->attr) &&
		    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			return 0;
		/* The attribute has changed. */
		/* Add (or update) attribute to hash. */
		attr_new = bgp_attr_intern(parent_pi->attr);

		/* Restore route, if needed. */
		if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(dest, pi);

		/* Mark if nexthop has changed. */
		if (!IPV4_ADDR_SAME(&pi->attr->nexthop, &attr_new->nexthop))
			SET_FLAG(pi->flags, BGP_PATH_IGP_CHANGED);

		old_local_es = bgp_evpn_attr_is_local_es(pi->attr);
		new_local_es = bgp_evpn_attr_is_local_es(attr_new);
		/* If ESI is different or if its type has changed we
		 * need to reinstall the path in zebra
		 */
		if ((old_local_es != new_local_es)
		    || memcmp(&pi->attr->esi, &attr_new->esi,
			      sizeof(attr_new->esi))) {

			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT))
				zlog_debug("VNI %d path %pFX chg to %s es",
					   vpn->vni, &pi->net->rn->p,
					   new_local_es ? "local"
							: "non-local");
			bgp_path_info_set_flag(dest, pi, BGP_PATH_ATTR_CHANGED);
		}

		/* Unintern existing, set to new. */
		bgp_attr_unintern(&pi->attr);
		pi->attr = attr_new;
		pi->uptime = monotime(NULL);
	}

	/* Add this route to remote IP hashtable */
	bgp_evpn_remote_ip_hash_add(vpn, pi);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, vpn, dest);

	/* if the best path is a local path with a non-zero ES
	 * sync info against the local path may need to be updated
	 * when a remote path is added/updated (including changes
	 * from sync-path to remote-path)
	 */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest);
	if (local_pi && (old_local_es || new_local_es))
		bgp_evpn_update_type2_route_entry(bgp, vpn, dest, local_pi,
						  __func__);

	return ret;
}

/*
 * Common handling for vni route tables uninstall/selection.
 */
static int uninstall_evpn_route_entry_in_vni_common(
	struct bgp *bgp, struct bgpevpn *vpn, const struct prefix_evpn *p,
	struct bgp_dest *dest, struct bgp_path_info *parent_pi)
{
	struct bgp_path_info *pi;
	struct bgp_path_info *local_pi;
	int ret;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi)
		return 0;

	bgp_evpn_remote_ip_hash_del(vpn, pi);

	/* Mark entry for deletion */
	bgp_path_info_delete(dest, pi);

	/* Perform route selection and update zebra, if required. */
	ret = evpn_route_select_install(bgp, vpn, dest);

	/* if the best path is a local path with a non-zero ES
	 * sync info against the local path may need to be updated
	 * when a remote path is deleted
	 */
	local_pi = bgp_evpn_route_get_local_path(bgp, dest);
	if (local_pi && bgp_evpn_attr_is_local_es(local_pi->attr))
		bgp_evpn_update_type2_route_entry(bgp, vpn, dest, local_pi,
						  __func__);

	return ret;
}

/*
 * Install route entry into VNI IP table and invoke route selection.
 */
static int install_evpn_route_entry_in_vni_ip(struct bgp *bgp,
					      struct bgpevpn *vpn,
					      const struct prefix_evpn *p,
					      struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Ignore MAC Only Type-2 */
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return 0;

	/* Create (or fetch) route within the VNI IP table. */
	dest = bgp_evpn_vni_ip_node_get(vpn->ip_table, p, parent_pi);

	ret = install_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
						     parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Install route entry into VNI MAC table and invoke route selection.
 */
static int install_evpn_route_entry_in_vni_mac(struct bgp *bgp,
					       struct bgpevpn *vpn,
					       const struct prefix_evpn *p,
					       struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Only type-2 routes go into this table */
	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return 0;

	/* Create (or fetch) route within the VNI MAC table. */
	dest = bgp_evpn_vni_mac_node_get(vpn->mac_table, p, parent_pi);

	ret = install_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
						     parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Uninstall route entry from VNI IP table and invoke route selection.
 */
static int uninstall_evpn_route_entry_in_vni_ip(struct bgp *bgp,
						struct bgpevpn *vpn,
						const struct prefix_evpn *p,
						struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Ignore MAC Only Type-2 */
	if ((p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) &&
	    (is_evpn_prefix_ipaddr_none(p) == true))
		return 0;

	/* Locate route within the VNI IP table. */
	dest = bgp_evpn_vni_ip_node_lookup(vpn->ip_table, p, parent_pi);
	if (!dest)
		return 0;

	ret = uninstall_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
						       parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Uninstall route entry from VNI IP table and invoke route selection.
 */
static int
uninstall_evpn_route_entry_in_vni_mac(struct bgp *bgp, struct bgpevpn *vpn,
				      const struct prefix_evpn *p,
				      struct bgp_path_info *parent_pi)
{
	int ret;
	struct bgp_dest *dest;

	/* Only type-2 routes go into this table */
	if (p->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
		return 0;

	/* Locate route within the VNI MAC table. */
	dest = bgp_evpn_vni_mac_node_lookup(vpn->mac_table, p, parent_pi);
	if (!dest)
		return 0;

	ret = uninstall_evpn_route_entry_in_vni_common(bgp, vpn, p, dest,
						       parent_pi);

	bgp_dest_unlock_node(dest);

	return ret;
}
/*
 * Uninstall route entry from the VRF routing table and send message
 * to zebra, if appropriate.
 */
static int uninstall_evpn_route_entry_in_vrf(struct bgp *bgp_vrf,
					     const struct prefix_evpn *evp,
					     struct bgp_path_info *parent_pi)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	int ret = 0;
	struct prefix p;
	struct prefix *pp = &p;
	afi_t afi = 0;
	safi_t safi = 0;

	memset(pp, 0, sizeof(struct prefix));
	ip_prefix_from_evpn_prefix(evp, pp);

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"vrf %s: unimport evpn prefix %pFX parent %p flags 0x%x",
			vrf_id_to_name(bgp_vrf->vrf_id), evp, parent_pi,
			parent_pi->flags);

	/* Locate route within the VRF. */
	/* NOTE: There is no RD here. */
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		afi = AFI_IP;
		safi = SAFI_UNICAST;
		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	} else {
		afi = AFI_IP6;
		safi = SAFI_UNICAST;
		dest = bgp_node_lookup(bgp_vrf->rib[afi][safi], pp);
	}

	if (!dest)
		return 0;

	/* Find matching route entry. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->extra && pi->extra->vrfleak &&
		    (struct bgp_path_info *)pi->extra->vrfleak->parent ==
			    parent_pi)
			break;

	if (!pi) {
		bgp_dest_unlock_node(dest);
		return 0;
	}

	if (bgp_debug_zebra(NULL))
		zlog_debug("... delete dest %p (l %d) pi %p (l %d, f 0x%x)",
			   dest, bgp_dest_get_lock_count(dest), pi, pi->lock,
			   pi->flags);

	/* Process for route leaking. */
	vpn_leak_from_vrf_withdraw(bgp_get_default(), bgp_vrf, pi);

	bgp_aggregate_decrement(bgp_vrf, bgp_dest_get_prefix(dest), pi, afi,
				safi);

	/* Force deletion */
	SET_FLAG(dest->flags, BGP_NODE_PROCESS_CLEAR);

	/* Mark entry for deletion */
	bgp_path_info_delete(dest, pi);

	/* Unlink path to evpn nexthop */
	bgp_evpn_path_nh_del(bgp_vrf, pi);

	/* Perform route selection and update zebra, if required. */
	bgp_process(bgp_vrf, dest, afi, safi);

	/* Unlock route node. */
	bgp_dest_unlock_node(dest);

	return ret;
}

/*
 * Install route entry into the VNI routing tables.
 */
static int install_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				    const struct prefix_evpn *p,
				    struct bgp_path_info *parent_pi)
{
	int ret = 0;

	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1))
		zlog_debug(
			"%s (%u): Installing EVPN %pFX route in VNI %u IP/MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

	ret = install_evpn_route_entry_in_vni_mac(bgp, vpn, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to install EVPN %pFX route in VNI %u MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

		return ret;
	}

	ret = install_evpn_route_entry_in_vni_ip(bgp, vpn, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to install EVPN %pFX route in VNI %u IP table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

		return ret;
	}

	return ret;
}

/*
 * Uninstall route entry from the VNI routing tables.
 */
static int uninstall_evpn_route_entry(struct bgp *bgp, struct bgpevpn *vpn,
				      const struct prefix_evpn *p,
				      struct bgp_path_info *parent_pi)
{
	int ret = 0;

	if (bgp_debug_update(parent_pi->peer, NULL, NULL, 1))
		zlog_debug(
			"%s (%u): Uninstalling EVPN %pFX route from VNI %u IP/MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

	ret = uninstall_evpn_route_entry_in_vni_ip(bgp, vpn, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u IP table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

		return ret;
	}

	ret = uninstall_evpn_route_entry_in_vni_mac(bgp, vpn, p, parent_pi);

	if (ret) {
		flog_err(
			EC_BGP_EVPN_FAIL,
			"%s (%u): Failed to uninstall EVPN %pFX route from VNI %u MAC table",
			vrf_id_to_name(bgp->vrf_id), bgp->vrf_id, p, vpn->vni);

		return ret;
	}

	return ret;
}

/*
 * Given a route entry and a VRF, see if this route entry should be
 * imported into the VRF i.e., RTs match + Site-of-Origin check passes.
 */
static int is_route_matching_for_vrf(struct bgp *bgp_vrf,
				     struct bgp_path_info *pi)
{
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;

	assert(attr);
	/* Route should have valid RT to be even considered. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	/* For each extended community RT, see if it matches this VNI. If any RT
	 * matches, we're done.
	 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct vrf_irt_node *irt;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ecom->unit_size));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* See if this RT matches specified VNIs import RTs */
		irt = lookup_vrf_import_rt(eval);
		if (irt)
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
			memcpy(&eval_tmp, eval, ecom->unit_size);
			mask_ecom_global_admin(&eval_tmp, eval);
			irt = lookup_vrf_import_rt(&eval_tmp);
		}
		if (irt)
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
				     struct bgp_path_info *pi)
{
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;

	assert(attr);
	/* Route should have valid RT to be even considered. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	/* For each extended community RT, see if it matches this VNI. If any RT
	 * matches, we're done.
	 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct irt_node *irt;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ecom->unit_size));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* See if this RT matches specified VNIs import RTs */
		irt = lookup_import_rt(bgp, eval);
		if (irt)
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
			memcpy(&eval_tmp, eval, ecom->unit_size);
			mask_ecom_global_admin(&eval_tmp, eval);
			irt = lookup_import_rt(bgp, &eval_tmp);
		}
		if (irt)
			if (is_vni_present_in_irt_vnis(irt->vnis, vpn))
				return 1;
	}

	return 0;
}

static bool bgp_evpn_route_matches_macvrf_soo(struct bgp_path_info *pi,
					      const struct prefix_evpn *evp)
{
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct ecommunity *macvrf_soo;
	bool ret = false;

	if (!bgp_evpn->evpn_info)
		return false;

	/* We only stamp the mac-vrf soo on routes from our local L2VNI.
	 * No need to filter additional EVPN routes that originated outside
	 * the MAC-VRF/L2VNI.
	 */
	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
	    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
		return false;

	macvrf_soo = bgp_evpn->evpn_info->soo;
	ret = route_matches_soo(pi, macvrf_soo);

	if (ret && bgp_debug_zebra(NULL)) {
		char *ecom_str;

		ecom_str = ecommunity_ecom2str(macvrf_soo,
					       ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		zlog_debug(
			"import of evpn prefix %pFX skipped, local mac-vrf soo %s",
			evp, ecom_str);
		ecommunity_strfree(&ecom_str);
	}

	return ret;
}

/* This API will scan evpn routes for checking attribute's rmac
 * macthes with bgp instance router mac. It avoid installing
 * route into bgp vrf table and remote rmac in bridge table.
 */
static int bgp_evpn_route_rmac_self_check(struct bgp *bgp_vrf,
					  const struct prefix_evpn *evp,
					  struct bgp_path_info *pi)
{
	/* evpn route could have learnt prior to L3vni has come up,
	 * perform rmac check before installing route and
	 * remote router mac.
	 * The route will be removed from global bgp table once
	 * SVI comes up with MAC and stored in hash, triggers
	 * bgp_mac_rescan_all_evpn_tables.
	 */
	if (memcmp(&bgp_vrf->rmac, &pi->attr->rmac, ETH_ALEN) == 0) {
		if (bgp_debug_update(pi->peer, NULL, NULL, 1)) {
			char attr_str[BUFSIZ] = {0};

			bgp_dump_attr(pi->attr, attr_str, sizeof(attr_str));

			zlog_debug(
				"%s: bgp %u prefix %pFX with attr %s - DENIED due to self mac",
				__func__, bgp_vrf->vrf_id, evp, attr_str);
		}

		return 1;
	}

	return 0;
}

/* don't import hosts that are locally attached */
static inline bool
bgp_evpn_skip_vrf_import_of_local_es(struct bgp *bgp_vrf,
				     const struct prefix_evpn *evp,
				     struct bgp_path_info *pi, int install)
{
	esi_t *esi;

	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		esi = bgp_evpn_attr_get_esi(pi->attr);

		/* Don't import routes that point to a local destination */
		if (bgp_evpn_attr_is_local_es(pi->attr)) {
			if (BGP_DEBUG(evpn_mh, EVPN_MH_RT)) {
				char esi_buf[ESI_STR_LEN];

				zlog_debug(
					"vrf %s of evpn prefix %pFX skipped, local es %s",
					install ? "import" : "unimport", evp,
					esi_to_str(esi, esi_buf,
						   sizeof(esi_buf)));
			}
			return true;
		}
	}
	return false;
}

/*
 * Install or uninstall a mac-ip route in the provided vrf if
 * there is a rt match
 */
int bgp_evpn_route_entry_install_if_vrf_match(struct bgp *bgp_vrf,
					      struct bgp_path_info *pi,
					      int install)
{
	int ret = 0;
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(pi->net);

	/* Consider "valid" remote routes applicable for
	 * this VRF.
	 */
	if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID)
	      && pi->type == ZEBRA_ROUTE_BGP
	      && pi->sub_type == BGP_ROUTE_NORMAL))
		return 0;

	if (is_route_matching_for_vrf(bgp_vrf, pi)) {
		if (bgp_evpn_route_rmac_self_check(bgp_vrf, evp, pi))
			return 0;

		/* don't import hosts that are locally attached */
		if (install && (bgp_evpn_skip_vrf_import_of_local_es(
					bgp_vrf, evp, pi, install) ||
				bgp_evpn_route_matches_macvrf_soo(pi, evp)))
			return 0;

		if (install)
			ret = install_evpn_route_entry_in_vrf(bgp_vrf, evp, pi);
		else
			ret = uninstall_evpn_route_entry_in_vrf(bgp_vrf, evp,
								pi);

		if (ret)
			flog_err(EC_BGP_EVPN_FAIL,
				 "Failed to %s EVPN %pFX route in VRF %s",
				 install ? "install" : "uninstall", evp,
				 vrf_id_to_name(bgp_vrf->vrf_id));
	}

	return ret;
}

/*
 * Install or uninstall mac-ip routes are appropriate for this
 * particular VRF.
 */
static int install_uninstall_routes_for_vrf(struct bgp *bgp_vrf, int install)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	int ret;
	struct bgp *bgp_evpn = NULL;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return -1;

	/* Walk entire global routing table and evaluate routes which could be
	 * imported into this VRF. Note that we need to loop through all global
	 * routes to determine which route matches the import rt on vrf
	 */
	for (rd_dest = bgp_table_top(bgp_evpn->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			/* if not mac-ip route skip this route */
			if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
			      || evp->prefix.route_type
					 == BGP_EVPN_IP_PREFIX_ROUTE))
				continue;

			/* if not a mac+ip route skip this route */
			if (!(is_evpn_prefix_ipaddr_v4(evp)
			      || is_evpn_prefix_ipaddr_v6(evp)))
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				ret = bgp_evpn_route_entry_install_if_vrf_match(
					bgp_vrf, pi, install);
				if (ret) {
					bgp_dest_unlock_node(rd_dest);
					bgp_dest_unlock_node(dest);
					return ret;
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
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
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
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix_evpn *evp =
				(const struct prefix_evpn *)bgp_dest_get_prefix(
					dest);

			if (evp->prefix.route_type != rtype)
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				/* Consider "valid" remote routes applicable for
				 * this VNI. */
				if (!(CHECK_FLAG(pi->flags, BGP_PATH_VALID)
				      && pi->type == ZEBRA_ROUTE_BGP
				      && pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (!is_route_matching_for_vni(bgp, vpn, pi))
					continue;

				if (install) {
					if (bgp_evpn_route_matches_macvrf_soo(
						    pi, evp))
						continue;

					ret = install_evpn_route_entry(bgp, vpn,
								       evp, pi);
				} else
					ret = uninstall_evpn_route_entry(
						bgp, vpn, evp, pi);

				if (ret) {
					flog_err(
						EC_BGP_EVPN_FAIL,
						"%u: Failed to %s EVPN %s route in VNI %u",
						bgp->vrf_id,
						install ? "install"
							: "uninstall",
						rtype == BGP_EVPN_MAC_IP_ROUTE
							? "MACIP"
							: "IMET",
						vpn->vni);

					bgp_dest_unlock_node(rd_dest);
					bgp_dest_unlock_node(dest);
					return ret;
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

	ret = install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_AD_ROUTE,
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

	ret = install_uninstall_routes_for_vni(bgp, vpn, BGP_EVPN_AD_ROUTE,
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
					   struct bgp_path_info *pi,
					   struct list *vrfs, int install)
{
	struct bgp *bgp_vrf;
	struct listnode *node, *nnode;

	/* Only type-2/type-5 routes go into a VRF */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return 0;

	/* if it is type-2 route and not a mac+ip route skip this route */
	if ((evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
	    && !(is_evpn_prefix_ipaddr_v4(evp)
		 || is_evpn_prefix_ipaddr_v6(evp)))
		return 0;

	for (ALL_LIST_ELEMENTS(vrfs, node, nnode, bgp_vrf)) {
		int ret;

		/* don't import hosts that are locally attached */
		if (install && bgp_evpn_skip_vrf_import_of_local_es(
				       bgp_vrf, evp, pi, install))
			return 0;

		if (install)
			ret = install_evpn_route_entry_in_vrf(bgp_vrf, evp, pi);
		else
			ret = uninstall_evpn_route_entry_in_vrf(bgp_vrf, evp,
								pi);

		if (ret) {
			flog_err(EC_BGP_EVPN_FAIL,
				 "%u: Failed to %s prefix %pFX in VRF %s",
				 bgp_def->vrf_id,
				 install ? "install" : "uninstall", evp,
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
					   struct bgp_path_info *pi,
					   struct list *vnis, int install)
{
	struct bgpevpn *vpn;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(vnis, node, nnode, vpn)) {
		int ret;

		if (!is_vni_live(vpn))
			continue;

		if (install)
			ret = install_evpn_route_entry(bgp, vpn, evp, pi);
		else
			ret = uninstall_evpn_route_entry(bgp, vpn, evp, pi);

		if (ret) {
			flog_err(EC_BGP_EVPN_FAIL,
				 "%u: Failed to %s EVPN %s route in VNI %u",
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
 * Install or uninstall route for appropriate VNIs/ESIs.
 */
static int bgp_evpn_install_uninstall_table(struct bgp *bgp, afi_t afi,
					    safi_t safi, const struct prefix *p,
					    struct bgp_path_info *pi,
					    int import, bool in_vni_rt,
					    bool in_vrf_rt)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	struct attr *attr = pi->attr;
	struct ecommunity *ecom;
	uint32_t i;
	struct prefix_evpn ad_evp;

	assert(attr);

	/* Only type-1, type-2, type-3, type-4 and type-5
	 * are supported currently
	 */
	if (!(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IMET_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_ES_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_AD_ROUTE
	      || evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return 0;

	/* If we don't have Route Target, nothing much to do. */
	if (!(attr->flag & ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)))
		return 0;

	/* EAD prefix in the global table doesn't include the VTEP-IP so
	 * we need to create a different copy for the VNI
	 */
	if (evp->prefix.route_type == BGP_EVPN_AD_ROUTE)
		evp = evpn_type1_prefix_vni_ip_copy(&ad_evp, evp,
						    attr->nexthop);

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return -1;

	/* Filter routes carrying a Site-of-Origin that matches our
	 * local MAC-VRF SoO.
	 */
	if (import && bgp_evpn_route_matches_macvrf_soo(pi, evp))
		return 0;

	/* An EVPN route belongs to a VNI or a VRF or an ESI based on the RTs
	 * attached to the route */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;
		struct ecommunity_val *eval;
		struct ecommunity_val eval_tmp;
		struct irt_node *irt;	 /* import rt for l2vni */
		struct vrf_irt_node *vrf_irt; /* import rt for l3vni */
		struct bgp_evpn_es *es;

		/* Only deal with RTs */
		pnt = (ecom->val + (i * ecom->unit_size));
		eval = (struct ecommunity_val *)(ecom->val
						 + (i * ecom->unit_size));
		type = *pnt++;
		sub_type = *pnt++;
		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		/* non-local MAC-IP routes in the global route table are linked
		 * to the destination ES
		 */
		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
			bgp_evpn_path_es_link(pi, 0,
					      bgp_evpn_attr_get_esi(pi->attr));

		/*
		 * macip routes (type-2) are imported into VNI and VRF tables.
		 * IMET route is imported into VNI table.
		 * prefix routes are imported into VRF table.
		 */
		if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE ||
		    evp->prefix.route_type == BGP_EVPN_IMET_ROUTE ||
		    evp->prefix.route_type == BGP_EVPN_AD_ROUTE ||
		    evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE) {

			irt = in_vni_rt ? lookup_import_rt(bgp, eval) : NULL;
			if (irt)
				install_uninstall_route_in_vnis(
					bgp, afi, safi, evp, pi, irt->vnis,
					import);

			vrf_irt = in_vrf_rt ? lookup_vrf_import_rt(eval) : NULL;
			if (vrf_irt)
				install_uninstall_route_in_vrfs(
					bgp, afi, safi, evp, pi, vrf_irt->vrfs,
					import);

			/* Also check for non-exact match.
			 * In this, we mask out the AS and
			 * only check on the local-admin sub-field.
			 * This is to facilitate using
			 * VNI as the RT for EBGP peering too.
			 */
			irt = NULL;
			vrf_irt = NULL;
			if (type == ECOMMUNITY_ENCODE_AS
			    || type == ECOMMUNITY_ENCODE_AS4
			    || type == ECOMMUNITY_ENCODE_IP) {
				memcpy(&eval_tmp, eval, ecom->unit_size);
				mask_ecom_global_admin(&eval_tmp, eval);
				if (in_vni_rt)
					irt = lookup_import_rt(bgp, &eval_tmp);
				if (in_vrf_rt)
					vrf_irt =
						lookup_vrf_import_rt(&eval_tmp);
			}

			if (irt)
				install_uninstall_route_in_vnis(
					bgp, afi, safi, evp, pi, irt->vnis,
					import);
			if (vrf_irt)
				install_uninstall_route_in_vrfs(
					bgp, afi, safi, evp, pi, vrf_irt->vrfs,
					import);
		}

		/* es route is imported into the es table */
		if (evp->prefix.route_type == BGP_EVPN_ES_ROUTE) {

			/* we will match based on the entire esi to avoid
			 * import of an es route for esi2 into esi1
			 */
			es = bgp_evpn_es_find(&evp->prefix.es_addr.esi);
			if (es && bgp_evpn_is_es_local(es))
				bgp_evpn_es_route_install_uninstall(
					bgp, es, afi, safi, evp, pi, import);
		}
	}

	return 0;
}

/*
 * Install or uninstall route for appropriate VNIs/ESIs.
 */
static int install_uninstall_evpn_route(struct bgp *bgp, afi_t afi, safi_t safi,
					const struct prefix *p,
					struct bgp_path_info *pi, int import)
{
	return bgp_evpn_install_uninstall_table(bgp, afi, safi, p, pi, import,
						true, true);
}

void bgp_evpn_import_type2_route(struct bgp_path_info *pi, int import)
{
	struct bgp *bgp_evpn;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	install_uninstall_evpn_route(bgp_evpn, AFI_L2VPN, SAFI_EVPN,
				     &pi->net->rn->p, pi, import);
}

/*
 * delete and withdraw all ipv4 and ipv6 routes in the vrf table as type-5
 * routes
 */
static void delete_withdraw_vrf_routes(struct bgp *bgp_vrf)
{
	/* Delete ipv4 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP,
							 SAFI_UNICAST, false);

	/* delete all ipv4 routes and withdraw from peers */
	if (advertise_type5_routes(bgp_vrf, AFI_IP))
		bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* Delete ipv6 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6,
							 SAFI_UNICAST, false);

	/* delete all ipv6 routes and withdraw from peers */
	if (advertise_type5_routes(bgp_vrf, AFI_IP6))
		bgp_evpn_withdraw_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);
}

/*
 * update and advertise all ipv4 and ipv6 routes in thr vrf table as type-5
 * routes
 */
void update_advertise_vrf_routes(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn = NULL; /* EVPN bgp instance */

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	/* update all ipv4 routes */
	if (advertise_type5_routes(bgp_vrf, AFI_IP))
		bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP, SAFI_UNICAST);

	/* update ipv4 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP,
							 SAFI_UNICAST, true);

	/* update all ipv6 routes */
	if (advertise_type5_routes(bgp_vrf, AFI_IP6))
		bgp_evpn_advertise_type5_routes(bgp_vrf, AFI_IP6, SAFI_UNICAST);

	/* update ipv6 default route and withdraw from peers */
	if (evpn_default_originate_set(bgp_vrf, AFI_IP6, SAFI_UNICAST))
		bgp_evpn_install_uninstall_default_route(bgp_vrf, AFI_IP6,
							 SAFI_UNICAST, true);

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

static void update_advertise_vni_route(struct bgp *bgp, struct bgpevpn *vpn,
				       struct bgp_dest *dest)
{
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi, *global_pi;
	struct attr *attr;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	struct prefix_evpn tmp_evp;
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	/*
	 * We have already processed type-3 routes.
	 * Process only type-1 and type-2 routes here.
	 */
	if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
	    evp->prefix.route_type != BGP_EVPN_AD_ROUTE)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_STATIC)
			break;
	if (!pi)
		return;

	/*
	 * VNI table MAC-IP prefixes don't have MAC so make sure it's
	 * set from path info here.
	 */
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		if (is_evpn_prefix_ipaddr_none(evp)) {
			/* VNI MAC -> Global */
			evpn_type2_prefix_global_copy(
				&tmp_evp, evp, NULL /* mac */,
				evpn_type2_path_info_get_ip(pi));
		} else {
			/* VNI IP -> Global */
			evpn_type2_prefix_global_copy(
				&tmp_evp, evp, evpn_type2_path_info_get_mac(pi),
				NULL /* ip */);
		}
	} else {
		memcpy(&tmp_evp, evp, sizeof(tmp_evp));
	}

	/* Create route in global routing table using this route entry's
	 * attribute.
	 */
	attr = pi->attr;
	global_dest = bgp_evpn_global_node_get(bgp->rib[afi][safi], afi, safi,
					       &tmp_evp, &vpn->prd, NULL);
	assert(global_dest);

	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE) {
		/* Type-2 route */
		update_evpn_route_entry(
			bgp, vpn, afi, safi, global_dest, attr, NULL /* mac */,
			NULL /* ip */, 1, &global_pi, 0,
			mac_mobility_seqnum(attr), false /* setup_sync */,
			NULL /* old_is_sync */);
	} else {
		/* Type-1 route */
		struct bgp_evpn_es *es;
		int route_changed = 0;

		es = bgp_evpn_es_find(&evp->prefix.ead_addr.esi);
		bgp_evpn_mh_route_update(bgp, es, vpn, afi, safi, global_dest,
					 attr, &global_pi, &route_changed);
	}

	/* Schedule for processing and unlock node. */
	bgp_process(bgp, global_dest, afi, safi);
	bgp_dest_unlock_node(global_dest);
}

/*
 * Update and advertise local routes for a VNI. Invoked upon router-id
 * change. Note that the processing is done only on the global route table
 * using routes that already exist in the per-VNI table.
 */
static void update_advertise_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct prefix_evpn p;
	struct bgp_dest *dest, *global_dest;
	struct bgp_path_info *pi;
	struct attr *attr;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Locate type-3 route for VNI in the per-VNI table and use its
	 * attributes to create and advertise the type-3 route for this VNI
	 * in the global table.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_vni_flood_mode_get(bgp, vpn)
				== VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, vpn->originator_ip);
		dest = bgp_evpn_vni_node_lookup(vpn, &p, NULL);
		if (!dest) /* unexpected */
			return;
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			if (pi->peer == bgp->peer_self &&
			    pi->type == ZEBRA_ROUTE_BGP
			    && pi->sub_type == BGP_ROUTE_STATIC)
				break;
		if (!pi) {
			bgp_dest_unlock_node(dest);
			return;
		}

		attr = pi->attr;

		global_dest = bgp_evpn_global_node_get(
			bgp->rib[afi][safi], afi, safi, &p, &vpn->prd, NULL);
		update_evpn_route_entry(
			bgp, vpn, afi, safi, global_dest, attr, NULL /* mac */,
			NULL /* ip */, 1, &pi, 0, mac_mobility_seqnum(attr),
			false /* setup_sync */, NULL /* old_is_sync */);

		/* Schedule for processing and unlock node. */
		bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}

	/* Now, walk this VNI's MAC & IP route table and use the route and its
	 * attribute to create and schedule route in global table.
	 */
	for (dest = bgp_table_top(vpn->mac_table); dest;
	     dest = bgp_route_next(dest))
		update_advertise_vni_route(bgp, vpn, dest);

	for (dest = bgp_table_top(vpn->ip_table); dest;
	     dest = bgp_route_next(dest))
		update_advertise_vni_route(bgp, vpn, dest);
}

/*
 * Delete (and withdraw) local routes for a VNI - only from the global
 * table. Invoked upon router-id change.
 */
static int delete_withdraw_vni_routes(struct bgp *bgp, struct bgpevpn *vpn)
{
	struct prefix_evpn p;
	struct bgp_dest *global_dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_L2VPN;
	safi_t safi = SAFI_EVPN;

	/* Delete and withdraw locally learnt type-2 routes (MACIP)
	 * for this VNI - from the global table.
	 */
	delete_global_type2_routes(bgp, vpn);

	/* Remove type-3 route for this VNI from global table. */
	build_evpn_type3_prefix(&p, vpn->originator_ip);
	global_dest = bgp_evpn_global_node_lookup(bgp->rib[afi][safi], safi, &p,
						  &vpn->prd, NULL);
	if (global_dest) {
		/* Delete route entry in the global EVPN table. */
		delete_evpn_route_entry(bgp, afi, safi, global_dest, &pi);

		/* Schedule for processing - withdraws to peers happen from
		 * this table.
		 */
		if (pi)
			bgp_process(bgp, global_dest, afi, safi);
		bgp_dest_unlock_node(global_dest);
	}


	delete_global_ead_evi_routes(bgp, vpn);
	return 0;
}

/*
 * Handle router-id change. Update and advertise local routes corresponding
 * to this VNI from peers. Note that this is invoked after updating the
 * router-id. The routes in the per-VNI table are used to create routes in
 * the global table and schedule them.
 */
static void update_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

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
static void withdraw_router_id_vni(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

	/* Skip VNIs with configured RD. */
	if (is_rd_configured(vpn))
		return;

	delete_withdraw_vni_routes(bgp, vpn);
}

/*
 * Create RT-3 for a VNI and schedule for processing and advertisement.
 * This is invoked upon flooding mode changing to head-end replication.
 */
static void create_advertise_type3(struct hash_bucket *bucket, void *data)
{
	struct bgpevpn *vpn = bucket->data;
	struct bgp *bgp = data;
	struct prefix_evpn p;

	if (!vpn || !is_vni_live(vpn) ||
		bgp_evpn_vni_flood_mode_get(bgp, vpn)
					!= VXLAN_FLOOD_HEAD_END_REPL)
		return;

	build_evpn_type3_prefix(&p, vpn->originator_ip);
	if (update_evpn_route(bgp, vpn, &p, 0, 0, NULL))
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
			 "Type3 route creation failure for VNI %u", vpn->vni);
}

/*
 * Delete RT-3 for a VNI and schedule for processing and withdrawal.
 * This is invoked upon flooding mode changing to drop BUM packets.
 */
static void delete_withdraw_type3(struct hash_bucket *bucket, void *data)
{
	struct bgpevpn *vpn = bucket->data;
	struct bgp *bgp = data;
	struct prefix_evpn p;

	if (!vpn || !is_vni_live(vpn))
		return;

	build_evpn_type3_prefix(&p, vpn->originator_ip);
	delete_evpn_route(bgp, vpn, &p);
}

/*
 * Process received EVPN type-2 route (advertise or withdraw).
 */
static int process_type2_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p = {};
	struct bgp_route_evpn evpn = {};
	uint8_t ipaddr_len;
	uint8_t macaddr_len;
	/* holds the VNI(s) as in packet */
	mpls_label_t label[BGP_MAX_LABELS] = {};
	uint32_t num_labels = 0;
	uint32_t eth_tag;
	int ret = 0;

	/* Type-2 route should be either 33, 37 or 49 bytes or an
	 * additional 3 bytes if there is a second label (VNI):
	 * RD (8), ESI (10), Eth Tag (4), MAC Addr Len (1),
	 * MAC Addr (6), IP len (1), IP (0, 4 or 16),
	 * MPLS Lbl1 (3), MPLS Lbl2 (0 or 3)
	 */
	if (psize != 33 && psize != 37 && psize != 49 && psize != 36
	    && psize != 40 && psize != 52) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-2 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	struct stream *pkt = stream_new(psize);
	stream_put(pkt, pfx, psize);

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	STREAM_GET(&prd.val, pkt, 8);

	/* Make EVPN prefix. */
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;

	/* Copy Ethernet Seg Identifier */
	if (attr) {
		STREAM_GET(&attr->esi, pkt, sizeof(esi_t));

		if (bgp_evpn_is_esi_local_and_non_bypass(&attr->esi))
			attr->es_flags |= ATTR_ES_IS_LOCAL;
		else
			attr->es_flags &= ~ATTR_ES_IS_LOCAL;
	} else {
		STREAM_FORWARD_GETP(pkt, sizeof(esi_t));
	}

	/* Copy Ethernet Tag */
	STREAM_GET(&eth_tag, pkt, 4);
	p.prefix.macip_addr.eth_tag = ntohl(eth_tag);

	/* Get the MAC Addr len */
	STREAM_GETC(pkt, macaddr_len);

	/* Get the MAC Addr */
	if (macaddr_len == (ETH_ALEN * 8)) {
		STREAM_GET(&p.prefix.macip_addr.mac.octet, pkt, ETH_ALEN);
	} else {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported MAC address length %d",
			peer->bgp->vrf_id, peer->host, macaddr_len);
		goto fail;
	}


	/* Get the IP. */
	STREAM_GETC(pkt, ipaddr_len);

	if (ipaddr_len != 0 && ipaddr_len != IPV4_MAX_BITLEN
	    && ipaddr_len != IPV6_MAX_BITLEN) {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-2 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		goto fail;
	}

	if (ipaddr_len) {
		ipaddr_len /= 8; /* Convert to bytes. */
		p.prefix.macip_addr.ip.ipa_type = (ipaddr_len == IPV4_MAX_BYTELEN)
					       ? IPADDR_V4
					       : IPADDR_V6;
		STREAM_GET(&p.prefix.macip_addr.ip.ip.addr, pkt, ipaddr_len);
	}

	/* Get the VNI(s). Stored as bytes here. */
	STREAM_GET(&label[0], pkt, BGP_LABEL_BYTES);
	num_labels++;

	/* Do we have a second VNI? */
	if (STREAM_READABLE(pkt)) {
		num_labels++;
		STREAM_GET(&label[1], pkt, BGP_LABEL_BYTES);
	}

	/* Process the route. */
	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd,
			   &label[0], num_labels, 0, &evpn);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, &label[0],
			     num_labels, &evpn);
	goto done;

fail:
stream_failure:
	flog_err(EC_BGP_EVPN_ROUTE_INVALID,
		 "%u:%s - Rx EVPN Type-2 NLRI - corrupt, discarding",
		 peer->bgp->vrf_id, peer->host);
	ret = -1;
done:
	stream_free(pkt);
	return ret;
}

/*
 * Process received EVPN type-3 route (advertise or withdraw).
 */
static int process_type3_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	uint8_t ipaddr_len;
	uint32_t eth_tag;

	/* Type-3 route should be either 17 or 29 bytes: RD (8), Eth Tag (4),
	 * IP len (1) and IP (4 or 16).
	 */
	if (psize != 17 && psize != 29) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-3 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* If PMSI is present, log if it is anything other than IR.
	 * Note: We just simply ignore the values as it is not clear if
	 * doing anything else is better.
	 */
	if (attr &&
	    (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_PMSI_TUNNEL))) {
		enum pta_type pmsi_tnl_type = bgp_attr_get_pmsi_tnl_type(attr);

		if (pmsi_tnl_type != PMSI_TNLTYPE_INGR_REPL
		    && pmsi_tnl_type != PMSI_TNLTYPE_PIM_SM) {
			flog_warn(
				EC_BGP_EVPN_PMSI_PRESENT,
				"%u:%s - Rx EVPN Type-3 NLRI with unsupported PTA %d",
				peer->bgp->vrf_id, peer->host, pmsi_tnl_type);
		}
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(p));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_IMET_ROUTE;

	/* Copy Ethernet Tag */
	memcpy(&eth_tag, pfx, 4);
	p.prefix.imet_addr.eth_tag = ntohl(eth_tag);
	pfx += 4;

	/* Get the IP. */
	ipaddr_len = *pfx++;
	if (ipaddr_len == IPV4_MAX_BITLEN) {
		p.prefix.imet_addr.ip.ipa_type = IPADDR_V4;
		memcpy(&p.prefix.imet_addr.ip.ip.addr, pfx, IPV4_MAX_BYTELEN);
	} else {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-3 NLRI with unsupported IP address length %d",
			peer->bgp->vrf_id, peer->host, ipaddr_len);
		return -1;
	}

	/* Process the route. */
	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL,
			   0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0,
			     NULL);
	return 0;
}

/*
 * Process received EVPN type-5 route (advertise or withdraw).
 */
static int process_type5_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id)
{
	struct prefix_rd prd;
	struct prefix_evpn p;
	struct bgp_route_evpn evpn;
	uint8_t ippfx_len;
	uint32_t eth_tag;
	mpls_label_t label; /* holds the VNI as in the packet */
	bool is_valid_update = true;

	/* Type-5 route should be 34 or 58 bytes:
	 * RD (8), ESI (10), Eth Tag (4), IP len (1), IP (4 or 16),
	 * GW (4 or 16) and VNI (3).
	 * Note that the IP and GW should both be IPv4 or both IPv6.
	 */
	if (psize != 34 && psize != 58) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%u:%s - Rx EVPN Type-5 NLRI with invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(&prd.val, pfx, 8);
	pfx += 8;

	/* Make EVPN prefix. */
	memset(&p, 0, sizeof(p));
	p.family = AF_EVPN;
	p.prefixlen = EVPN_ROUTE_PREFIXLEN;
	p.prefix.route_type = BGP_EVPN_IP_PREFIX_ROUTE;

	/* Additional information outside of prefix - ESI and GW IP */
	memset(&evpn, 0, sizeof(evpn));

	/* Fetch ESI overlay index */
	if (attr)
		memcpy(&evpn.eth_s_id, pfx, sizeof(esi_t));
	pfx += ESI_BYTES;

	/* Fetch Ethernet Tag. */
	memcpy(&eth_tag, pfx, 4);
	p.prefix.prefix_addr.eth_tag = ntohl(eth_tag);
	pfx += 4;

	/* Fetch IP prefix length. */
	ippfx_len = *pfx++;
	if (ippfx_len > IPV6_MAX_BITLEN) {
		flog_err(
			EC_BGP_EVPN_ROUTE_INVALID,
			"%u:%s - Rx EVPN Type-5 NLRI with invalid IP Prefix length %d",
			peer->bgp->vrf_id, peer->host, ippfx_len);
		return -1;
	}
	p.prefix.prefix_addr.ip_prefix_length = ippfx_len;

	/* Determine IPv4 or IPv6 prefix */
	/* Since the address and GW are from the same family, this just becomes
	 * a simple check on the total size.
	 */
	if (psize == 34) {
		SET_IPADDR_V4(&p.prefix.prefix_addr.ip);
		memcpy(&p.prefix.prefix_addr.ip.ipaddr_v4, pfx, 4);
		pfx += 4;
		SET_IPADDR_V4(&evpn.gw_ip);
		memcpy(&evpn.gw_ip.ipaddr_v4, pfx, 4);
		pfx += 4;
	} else {
		SET_IPADDR_V6(&p.prefix.prefix_addr.ip);
		memcpy(&p.prefix.prefix_addr.ip.ipaddr_v6, pfx,
		       IPV6_MAX_BYTELEN);
		pfx += IPV6_MAX_BYTELEN;
		SET_IPADDR_V6(&evpn.gw_ip);
		memcpy(&evpn.gw_ip.ipaddr_v6, pfx, IPV6_MAX_BYTELEN);
		pfx += IPV6_MAX_BYTELEN;
	}

	/* Get the VNI (in MPLS label field). Stored as bytes here. */
	memset(&label, 0, sizeof(label));
	memcpy(&label, pfx, BGP_LABEL_BYTES);

	/*
	 * If in future, we are required to access additional fields,
	 * we MUST increment pfx by BGP_LABEL_BYTES in before reading the next
	 * field
	 */

	/*
	 * An update containing a non-zero gateway IP and a non-zero ESI
	 * at the same time is should be treated as withdraw
	 */
	if (bgp_evpn_is_esi_valid(&evpn.eth_s_id) &&
	    !ipaddr_is_zero(&evpn.gw_ip)) {
		flog_err(EC_BGP_EVPN_ROUTE_INVALID,
			 "%s - Rx EVPN Type-5 ESI and gateway-IP both non-zero.",
			 peer->host);
		is_valid_update = false;
	} else if (bgp_evpn_is_esi_valid(&evpn.eth_s_id))
		evpn.type = OVERLAY_INDEX_ESI;
	else if (!ipaddr_is_zero(&evpn.gw_ip))
		evpn.type = OVERLAY_INDEX_GATEWAY_IP;
	if (attr) {
		if (is_zero_mac(&attr->rmac) &&
		    !bgp_evpn_is_esi_valid(&evpn.eth_s_id) &&
		    ipaddr_is_zero(&evpn.gw_ip) && label == 0) {
			flog_err(EC_BGP_EVPN_ROUTE_INVALID,
				 "%s - Rx EVPN Type-5 ESI, gateway-IP, RMAC and label all zero",
				 peer->host);
			is_valid_update = false;
		}

		if (is_mcast_mac(&attr->rmac) || is_bcast_mac(&attr->rmac))
			is_valid_update = false;
	}

	/* Process the route. */
	if (attr && is_valid_update)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi,
			   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd,
			   &label, 1, 0, &evpn);
	else {
		if (!is_valid_update) {
			char attr_str[BUFSIZ] = {0};

			bgp_dump_attr(attr, attr_str, BUFSIZ);
			zlog_warn(
				"Invalid update from peer %s vrf %u prefix %pFX attr %s - treat as withdraw",
				peer->hostname, peer->bgp->vrf_id, &p,
				attr_str);
		}
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi,
			     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, &label, 1,
			     &evpn);
	}

	return 0;
}

static void evpn_mpattr_encode_type5(struct stream *s, const struct prefix *p,
				     const struct prefix_rd *prd,
				     mpls_label_t *label, uint32_t num_labels,
				     struct attr *attr)
{
	int len;
	char temp[16];
	const struct evpn_addr *p_evpn_p;

	memset(&temp, 0, sizeof(temp));
	if (p->family != AF_EVPN)
		return;
	p_evpn_p = &(p->u.prefix_evpn);

	/* len denites the total len of IP and GW-IP in the route
	   IP and GW-IP have to be both ipv4 or ipv6
	 */
	if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
		len = 8; /* IP and GWIP are both ipv4 */
	else
		len = 32; /* IP and GWIP are both ipv6 */
	/* Prefix contains RD, ESI, EthTag, IP length, IP, GWIP and VNI */
	stream_putc(s, 8 + 10 + 4 + 1 + len + 3);
	stream_put(s, prd->val, 8);
	if (attr && attr->evpn_overlay.type == OVERLAY_INDEX_ESI)
		stream_put(s, &attr->esi, sizeof(esi_t));
	else
		stream_put(s, 0, sizeof(esi_t));
	stream_putl(s, p_evpn_p->prefix_addr.eth_tag);
	stream_putc(s, p_evpn_p->prefix_addr.ip_prefix_length);
	if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
		stream_put_ipv4(s, p_evpn_p->prefix_addr.ip.ipaddr_v4.s_addr);
	else
		stream_put(s, &p_evpn_p->prefix_addr.ip.ipaddr_v6, 16);
	if (attr && attr->evpn_overlay.type == OVERLAY_INDEX_GATEWAY_IP) {
		const struct bgp_route_evpn *evpn_overlay =
			bgp_attr_get_evpn_overlay(attr);

		if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
			stream_put_ipv4(s,
					evpn_overlay->gw_ip.ipaddr_v4.s_addr);
		else
			stream_put(s, &(evpn_overlay->gw_ip.ipaddr_v6), 16);
	} else {
		if (IS_IPADDR_V4(&p_evpn_p->prefix_addr.ip))
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
static void cleanup_vni_on_disable(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

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
static void free_vni_entry(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

	delete_all_vni_routes(bgp, vpn);
	bgp_evpn_free(bgp, vpn);
}

/*
 * Derive AUTO import RT for BGP VRF - L3VNI
 */
static void evpn_auto_rt_import_add_for_vrf(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn = NULL;

	form_auto_rt(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_import_rtl, true);

	/* Map RT to VRF */
	bgp_evpn = bgp_get_evpn();

	if (!bgp_evpn)
		return;

	bgp_evpn_map_vrf_to_its_rts(bgp_vrf);
}

/*
 * Delete AUTO import RT from BGP VRF - L3VNI
 */
static void evpn_auto_rt_import_delete_for_vrf(struct bgp *bgp_vrf)
{
	evpn_rt_delete_auto(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_import_rtl,
			    true);
}

/*
 * Derive AUTO export RT for BGP VRF - L3VNI
 */
static void evpn_auto_rt_export_add_for_vrf(struct bgp *bgp_vrf)
{
	form_auto_rt(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_export_rtl, true);
}

/*
 * Delete AUTO export RT from BGP VRF - L3VNI
 */
static void evpn_auto_rt_export_delete_for_vrf(struct bgp *bgp_vrf)
{
	evpn_rt_delete_auto(bgp_vrf, bgp_vrf->l3vni, bgp_vrf->vrf_export_rtl,
			    true);
}

static void bgp_evpn_handle_export_rt_change_for_vrf(struct bgp *bgp_vrf)
{
	struct bgp *bgp_evpn = NULL;
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	/* update all type-5 routes */
	update_advertise_vrf_routes(bgp_vrf);

	/* update all type-2 routes */
	for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn))
		update_routes_for_vni(bgp_evpn, vpn);
}

/*
 * Handle autort change for a given VNI.
 */
static void update_autort_vni(struct hash_bucket *bucket, struct bgp *bgp)
{
	struct bgpevpn *vpn = bucket->data;

	if (!is_import_rt_configured(vpn)) {
		if (is_vni_live(vpn))
			bgp_evpn_uninstall_routes(bgp, vpn);
		bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);
		list_delete_all_node(vpn->import_rtl);
		bgp_evpn_derive_auto_rt_import(bgp, vpn);
		if (is_vni_live(vpn))
			bgp_evpn_install_routes(bgp, vpn);
	}
	if (!is_export_rt_configured(vpn)) {
		list_delete_all_node(vpn->export_rtl);
		bgp_evpn_derive_auto_rt_export(bgp, vpn);
		if (is_vni_live(vpn))
			bgp_evpn_handle_export_rt_change(bgp, vpn);
	}
}

/*
 * Handle autort change for L3VNI.
 */
static void update_autort_l3vni(struct bgp *bgp)
{
	if ((CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD))
	    && (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)))
		return;

	if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_IMPORT_RT_CFGD)) {
		if (is_l3vni_live(bgp))
			uninstall_routes_for_vrf(bgp);

		/* Cleanup the RT to VRF mapping */
		bgp_evpn_unmap_vrf_from_its_rts(bgp);

		/* Remove auto generated RT */
		evpn_auto_rt_import_delete_for_vrf(bgp);

		list_delete_all_node(bgp->vrf_import_rtl);

		/* Map auto derive or configured RTs */
		evpn_auto_rt_import_add_for_vrf(bgp);
	}

	if (!CHECK_FLAG(bgp->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
		list_delete_all_node(bgp->vrf_export_rtl);

		evpn_auto_rt_export_delete_for_vrf(bgp);

		evpn_auto_rt_export_add_for_vrf(bgp);

		if (is_l3vni_live(bgp))
			bgp_evpn_map_vrf_to_its_rts(bgp);
	}

	if (!is_l3vni_live(bgp))
		return;

	/* advertise type-5 routes if needed */
	update_advertise_vrf_routes(bgp);

	/* install all remote routes belonging to this l3vni
	 * into corresponding vrf
	 */
	install_routes_for_vrf(bgp);
}

/*
 * Public functions.
 */

/* withdraw type-5 route corresponding to ip prefix */
void bgp_evpn_withdraw_type5_route(struct bgp *bgp_vrf, const struct prefix *p,
				   afi_t afi, safi_t safi)
{
	int ret = 0;
	struct prefix_evpn evp;

	build_type5_prefix_from_ip_prefix(&evp, p);
	ret = delete_evpn_type5_route(bgp_vrf, &evp);
	if (ret)
		flog_err(
			EC_BGP_EVPN_ROUTE_DELETE,
			"%u failed to delete type-5 route for prefix %pFX in vrf %s",
			bgp_vrf->vrf_id, p, vrf_id_to_name(bgp_vrf->vrf_id));
}

/* withdraw all type-5 routes for an address family */
void bgp_evpn_withdraw_type5_routes(struct bgp *bgp_vrf, afi_t afi, safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi;

	table = bgp_vrf->rib[afi][safi];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		/* Only care about "selected" routes. Also ensure that
		 * these are routes that are injectable into EVPN.
		 */
		/* TODO: Support for AddPath for EVPN. */
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    && is_route_injectable_into_evpn(pi)) {
				bgp_evpn_withdraw_type5_route(
					bgp_vrf, bgp_dest_get_prefix(dest), afi,
					safi);
				break;
			}
		}
	}
}

/*
 * evpn - enable advertisement of default g/w
 */
void bgp_evpn_install_uninstall_default_route(struct bgp *bgp_vrf, afi_t afi,
					      safi_t safi, bool add)
{
	struct prefix ip_prefix;

	/* form the default prefix 0.0.0.0/0 */
	memset(&ip_prefix, 0, sizeof(ip_prefix));
	ip_prefix.family = afi2family(afi);

	if (add) {
		bgp_evpn_advertise_type5_route(bgp_vrf, &ip_prefix,
					       NULL, afi, safi);
	} else {
		bgp_evpn_withdraw_type5_route(bgp_vrf, &ip_prefix,
					      afi, safi);
	}
}


/*
 * Advertise IP prefix as type-5 route. The afi/safi and src_attr passed
 * to this function correspond to those of the source IP prefix (best
 * path in the case of the attr. In the case of a local prefix (when we
 * are advertising local subnets), the src_attr will be NULL.
 */
void bgp_evpn_advertise_type5_route(struct bgp *bgp_vrf, const struct prefix *p,
				    struct attr *src_attr, afi_t afi,
				    safi_t safi)
{
	int ret = 0;
	struct prefix_evpn evp;

	build_type5_prefix_from_ip_prefix(&evp, p);
	ret = update_evpn_type5_route(bgp_vrf, &evp, src_attr, afi, safi);
	if (ret)
		flog_err(EC_BGP_EVPN_ROUTE_CREATE,
			 "%u: Failed to create type-5 route for prefix %pFX",
			 bgp_vrf->vrf_id, p);
}

/* Inject all prefixes of a particular address-family (currently, IPv4 or
 * IPv6 unicast) into EVPN as type-5 routes. This is invoked when the
 * advertisement is enabled.
 */
void bgp_evpn_advertise_type5_routes(struct bgp *bgp_vrf, afi_t afi,
				     safi_t safi)
{
	struct bgp_table *table = NULL;
	struct bgp_dest *dest = NULL;
	struct bgp_path_info *pi;

	table = bgp_vrf->rib[afi][safi];
	for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
		/* Need to identify the "selected" route entry to use its
		 * attribute. Also, ensure that the route is injectable
		 * into EVPN.
		 * TODO: Support for AddPath for EVPN.
		 */
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)
			    && is_route_injectable_into_evpn(pi)) {

				/* apply the route-map */
				if (bgp_vrf->adv_cmd_rmap[afi][safi].map) {
					route_map_result_t ret;
					struct bgp_path_info tmp_pi;
					struct bgp_path_info_extra tmp_pie;
					struct attr tmp_attr;

					tmp_attr = *pi->attr;

					/* Fill temp path_info */
					prep_for_rmap_apply(&tmp_pi, &tmp_pie,
							    dest, pi, pi->peer,
							    &tmp_attr);

					RESET_FLAG(tmp_attr.rmap_change_flags);

					ret = route_map_apply(
						bgp_vrf->adv_cmd_rmap[afi][safi]
							.map,
						bgp_dest_get_prefix(dest),
						&tmp_pi);
					if (ret == RMAP_DENYMATCH) {
						bgp_attr_flush(&tmp_attr);
						continue;
					}
					bgp_evpn_advertise_type5_route(
						bgp_vrf,
						bgp_dest_get_prefix(dest),
						&tmp_attr, afi, safi);
				} else
					bgp_evpn_advertise_type5_route(
						bgp_vrf,
						bgp_dest_get_prefix(dest),
						pi->attr, afi, safi);
				break;
			}
		}
	}
}

static void rt_list_remove_node(struct list *rt_list,
				struct ecommunity *ecomdel, bool is_l3)
{
	struct listnode *node = NULL, *nnode = NULL, *node_to_del = NULL;
	struct vrf_route_target *l3rt = NULL;
	struct ecommunity *ecom = NULL;

	if (is_l3) {
		for (ALL_LIST_ELEMENTS(rt_list, node, nnode, l3rt)) {
			if (ecommunity_match(l3rt->ecom, ecomdel)) {
				evpn_vrf_rt_del(l3rt);
				node_to_del = node;
				break;
			}
		}
	} else {
		for (ALL_LIST_ELEMENTS(rt_list, node, nnode, ecom)) {
			if (ecommunity_match(ecom, ecomdel)) {
				ecommunity_free(&ecom);
				node_to_del = node;
				break;
			}
		}
	}


	if (node_to_del)
		list_delete_node(rt_list, node_to_del);
}

void evpn_rt_delete_auto(struct bgp *bgp, vni_t vni, struct list *rtl,
			 bool is_l3)
{
	struct ecommunity *ecom_auto;
	struct ecommunity_val eval;

	if (bgp->advertise_autort_rfc8365)
		vni |= EVPN_AUTORT_VXLAN;

	encode_route_target_as((bgp->as & 0xFFFF), vni, &eval, true);

	ecom_auto = ecommunity_new();
	ecommunity_add_val(ecom_auto, &eval, false, false);

	rt_list_remove_node(rtl, ecom_auto, is_l3);

	ecommunity_free(&ecom_auto);
}

static void evpn_vrf_rt_routes_map(struct bgp *bgp_vrf)
{
	/* map VRFs to its RTs and install routes matching this new RT */
	if (is_l3vni_live(bgp_vrf)) {
		bgp_evpn_map_vrf_to_its_rts(bgp_vrf);
		install_routes_for_vrf(bgp_vrf);
	}
}

static void evpn_vrf_rt_routes_unmap(struct bgp *bgp_vrf)
{
	/* uninstall routes from vrf */
	if (is_l3vni_live(bgp_vrf))
		uninstall_routes_for_vrf(bgp_vrf);

	/* Cleanup the RT to VRF mapping */
	bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);
}

static bool rt_list_has_cfgd_rt(struct list *rt_list)
{
	struct listnode *node = NULL, *nnode = NULL;
	struct vrf_route_target *l3rt = NULL;

	for (ALL_LIST_ELEMENTS(rt_list, node, nnode, l3rt)) {
		if (!CHECK_FLAG(l3rt->flags, BGP_VRF_RT_AUTO))
			return true;
	}

	return false;
}

static void unconfigure_import_rt_for_vrf_fini(struct bgp *bgp_vrf)
{
	if (!bgp_vrf->vrf_import_rtl)
		return; /* this should never fail */

	if (!is_l3vni_live(bgp_vrf))
		return; /* Nothing to do if no vni */

	/* fall back to auto-generated RT if this was the last RT */
	if (list_isempty(bgp_vrf->vrf_import_rtl))
		evpn_auto_rt_import_add_for_vrf(bgp_vrf);
}

static void unconfigure_export_rt_for_vrf_fini(struct bgp *bgp_vrf)
{

	if (!bgp_vrf->vrf_export_rtl)
		return; /* this should never fail */

	if (!is_l3vni_live(bgp_vrf))
		return; /* Nothing to do if no vni */

	/* fall back to auto-generated RT if this was the last RT */
	if (list_isempty(bgp_vrf->vrf_export_rtl))
		evpn_auto_rt_export_add_for_vrf(bgp_vrf);

	bgp_evpn_handle_export_rt_change_for_vrf(bgp_vrf);
}

void bgp_evpn_configure_import_rt_for_vrf(struct bgp *bgp_vrf,
					  struct ecommunity *ecomadd,
					  bool is_wildcard)
{
	struct vrf_route_target *newrt;

	newrt = evpn_vrf_rt_new(ecomadd);

	if (is_wildcard)
		SET_FLAG(newrt->flags, BGP_VRF_RT_WILD);

	evpn_vrf_rt_routes_unmap(bgp_vrf);

	/* Remove auto generated RT if not configured */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD))
		evpn_auto_rt_import_delete_for_vrf(bgp_vrf);

	/* Add the newly configured RT to RT list */
	listnode_add_sort(bgp_vrf->vrf_import_rtl, newrt);

	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD);

	evpn_vrf_rt_routes_map(bgp_vrf);
}

void bgp_evpn_configure_import_auto_rt_for_vrf(struct bgp *bgp_vrf)
{
	if (CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD))
		return; /* Already configured */

	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD);

	if (!is_l3vni_live(bgp_vrf))
		return; /* Wait for VNI before adding rts */

	evpn_vrf_rt_routes_unmap(bgp_vrf);

	evpn_auto_rt_import_add_for_vrf(bgp_vrf);

	evpn_vrf_rt_routes_map(bgp_vrf);
}

void bgp_evpn_unconfigure_import_rt_for_vrf(struct bgp *bgp_vrf,
					    struct ecommunity *ecomdel)
{
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD))
		return; /* Already un-configured */

	evpn_vrf_rt_routes_unmap(bgp_vrf);

	/* Remove rt */
	rt_list_remove_node(bgp_vrf->vrf_import_rtl, ecomdel, true);

	if (!rt_list_has_cfgd_rt(bgp_vrf->vrf_import_rtl))
		UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD);

	unconfigure_import_rt_for_vrf_fini(bgp_vrf);

	evpn_vrf_rt_routes_map(bgp_vrf);
}

void bgp_evpn_unconfigure_import_auto_rt_for_vrf(struct bgp *bgp_vrf)
{
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD))
		return; /* Already un-configured */

	evpn_vrf_rt_routes_unmap(bgp_vrf);

	/* remove auto-generated RT */
	evpn_auto_rt_import_delete_for_vrf(bgp_vrf);

	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD);

	unconfigure_import_rt_for_vrf_fini(bgp_vrf);

	evpn_vrf_rt_routes_map(bgp_vrf);
}

void bgp_evpn_configure_export_rt_for_vrf(struct bgp *bgp_vrf,
					  struct ecommunity *ecomadd)
{
	struct vrf_route_target *newrt;

	newrt = evpn_vrf_rt_new(ecomadd);

	/* Remove auto generated RT if not configured */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD))
		evpn_auto_rt_export_delete_for_vrf(bgp_vrf);

	/* Add the new RT to the RT list */
	listnode_add_sort(bgp_vrf->vrf_export_rtl, newrt);

	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD);

	if (is_l3vni_live(bgp_vrf))
		bgp_evpn_handle_export_rt_change_for_vrf(bgp_vrf);
}

void bgp_evpn_configure_export_auto_rt_for_vrf(struct bgp *bgp_vrf)
{
	if (CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD))
		return; /* Already configured */

	SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD);

	if (!is_l3vni_live(bgp_vrf))
		return; /* Wait for VNI before adding rts */

	evpn_auto_rt_export_add_for_vrf(bgp_vrf);

	bgp_evpn_handle_export_rt_change_for_vrf(bgp_vrf);
}

void bgp_evpn_unconfigure_export_rt_for_vrf(struct bgp *bgp_vrf,
					    struct ecommunity *ecomdel)
{
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD))
		return; /* Already un-configured */

	/* Remove rt */
	rt_list_remove_node(bgp_vrf->vrf_export_rtl, ecomdel, true);

	if (!rt_list_has_cfgd_rt(bgp_vrf->vrf_export_rtl))
		UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD);

	unconfigure_export_rt_for_vrf_fini(bgp_vrf);
}

void bgp_evpn_unconfigure_export_auto_rt_for_vrf(struct bgp *bgp_vrf)
{
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD))
		return; /* Already un-configured */

	/* remove auto-generated RT */
	evpn_auto_rt_export_delete_for_vrf(bgp_vrf);

	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD);

	unconfigure_export_rt_for_vrf_fini(bgp_vrf);
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
	struct listnode *node;
	struct bgp *bgp_vrf;

	if (withdraw) {

		/* delete and withdraw all the type-5 routes
		   stored in the global table for this vrf
		 */
		withdraw_router_id_vrf(bgp);

		/* delete all the VNI routes (type-2/type-3) routes for all the
		 * L2-VNIs
		 */
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_bucket *,
				       void *))withdraw_router_id_vni,
			     bgp);

		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
				if (bgp_vrf->evpn_info->advertise_pip &&
				    (bgp_vrf->evpn_info->pip_ip_static.s_addr
				     == INADDR_ANY))
					bgp_vrf->evpn_info->pip_ip.s_addr
						= INADDR_ANY;
			}
		}
	} else {

		/* Assign new default instance router-id */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_DEFAULT) {
			for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp_vrf)) {
				if (bgp_vrf->evpn_info->advertise_pip &&
				    (bgp_vrf->evpn_info->pip_ip_static.s_addr
				     == INADDR_ANY)) {
					bgp_vrf->evpn_info->pip_ip =
						bgp->router_id;
					/* advertise type-5 routes with
					 * new nexthop
					 */
					update_advertise_vrf_routes(bgp_vrf);
				}
			}
		}

		/* advertise all routes in the vrf as type-5 routes with the new
		 * RD
		 */
		update_router_id_vrf(bgp);

		/* advertise all the VNI routes (type-2/type-3) routes with the
		 * new RD
		 */
		hash_iterate(bgp->vnihash,
			     (void (*)(struct hash_bucket *,
				       void *))update_router_id_vni,
			     bgp);
	}
}

/*
 * Handle change to auto-RT algorithm - update and advertise local routes.
 */
void bgp_evpn_handle_autort_change(struct bgp *bgp)
{
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_bucket *,
			       void*))update_autort_vni,
		     bgp);
	if (bgp->l3vni)
		update_autort_l3vni(bgp);
}

/*
 * Handle change to export RT - update and advertise local routes.
 */
int bgp_evpn_handle_export_rt_change(struct bgp *bgp, struct bgpevpn *vpn)
{
	return update_routes_for_vni(bgp, vpn);
}

void bgp_evpn_handle_vrf_rd_change(struct bgp *bgp_vrf, int withdraw)
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

/* "mac-vrf soo" vty handler
 * Handle change to the global MAC-VRF Site-of-Origin:
 *   - Unimport routes with new SoO from VNI/VRF
 *   - Import routes with old SoO into VNI/VRF
 *   - Update SoO on local VNI routes + re-advertise
 */
void bgp_evpn_handle_global_macvrf_soo_change(struct bgp *bgp,
					      struct ecommunity *new_soo)
{
	struct ecommunity *old_soo;

	old_soo = bgp->evpn_info->soo;

	/* cleanup and bail out if old_soo == new_soo */
	if (ecommunity_match(old_soo, new_soo)) {
		ecommunity_free(&new_soo);
		return;
	}

	/* set new_soo */
	bgp->evpn_info->soo = new_soo;

	/* Unimport routes matching the new_soo */
	bgp_filter_evpn_routes_upon_martian_change(bgp, BGP_MARTIAN_SOO);

	/* Reimport routes with old_soo and !new_soo.
	 */
	bgp_reimport_evpn_routes_upon_martian_change(
		bgp, BGP_MARTIAN_SOO, (void *)old_soo, (void *)new_soo);

	/* Update locally originated routes for all L2VNIs */
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))update_routes_for_vni_hash,
		     bgp);

	/* clear old_soo */
	ecommunity_free(&old_soo);
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
char *bgp_evpn_label2str(mpls_label_t *label, uint32_t num_labels, char *buf,
			 int len)
{
	vni_t vni1, vni2;

	vni1 = label2vni(label);
	if (num_labels == 2) {
		vni2 = label2vni(label + 1);
		snprintf(buf, len, "%u/%u", vni1, vni2);
	} else
		snprintf(buf, len, "%u", vni1);
	return buf;
}

/*
 * Function to convert evpn route to json format.
 * NOTE: We don't use prefix2str as the output here is a bit different.
 */
void bgp_evpn_route2json(const struct prefix_evpn *p, json_object *json)
{
	char buf1[ETHER_ADDR_STRLEN];
	char buf2[PREFIX2STR_BUFFER];
	uint8_t family;
	uint8_t prefixlen;

	if (!json)
		return;

	json_object_int_add(json, "routeType", p->prefix.route_type);

	switch (p->prefix.route_type) {
	case BGP_EVPN_MAC_IP_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.macip_addr.eth_tag);
		json_object_int_add(json, "macLen", 8 * ETH_ALEN);
		json_object_string_add(json, "mac",
			prefix_mac2str(&p->prefix.macip_addr.mac, buf1,
			sizeof(buf1)));

		if (!is_evpn_prefix_ipaddr_none(p)) {
			family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET :
				AF_INET6;
			prefixlen = (family == AF_INET) ?
				IPV4_MAX_BITLEN : IPV6_MAX_BITLEN;
			inet_ntop(family, &p->prefix.macip_addr.ip.ip.addr,
				buf2, PREFIX2STR_BUFFER);
			json_object_int_add(json, "ipLen", prefixlen);
			json_object_string_add(json, "ip", buf2);
		}
	break;

	case BGP_EVPN_IMET_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.imet_addr.eth_tag);
		family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET : AF_INET6;
		prefixlen = (family == AF_INET) ?  IPV4_MAX_BITLEN :
			IPV6_MAX_BITLEN;
		inet_ntop(family, &p->prefix.imet_addr.ip.ip.addr, buf2,
			PREFIX2STR_BUFFER);
		json_object_int_add(json, "ipLen", prefixlen);
		json_object_string_add(json, "ip", buf2);
	break;

	case BGP_EVPN_IP_PREFIX_ROUTE:
		json_object_int_add(json, "ethTag",
			p->prefix.prefix_addr.eth_tag);
		family = is_evpn_prefix_ipaddr_v4(p) ? AF_INET : AF_INET6;
		inet_ntop(family, &p->prefix.prefix_addr.ip.ip.addr,
			  buf2, sizeof(buf2));
		json_object_int_add(json, "ipLen",
				    p->prefix.prefix_addr.ip_prefix_length);
		json_object_string_add(json, "ip", buf2);
	break;

	default:
	break;
	}
}

/*
 * Encode EVPN prefix in Update (MP_REACH)
 */
void bgp_evpn_encode_prefix(struct stream *s, const struct prefix *p,
			    const struct prefix_rd *prd, mpls_label_t *label,
			    uint32_t num_labels, struct attr *attr,
			    bool addpath_capable, uint32_t addpath_tx_id)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)p;
	int len, ipa_len = 0;

	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	/* Route type */
	stream_putc(s, evp->prefix.route_type);

	switch (evp->prefix.route_type) {
	case BGP_EVPN_MAC_IP_ROUTE:
		if (is_evpn_prefix_ipaddr_v4(evp))
			ipa_len = IPV4_MAX_BYTELEN;
		else if (is_evpn_prefix_ipaddr_v6(evp))
			ipa_len = IPV6_MAX_BYTELEN;
		/* RD, ESI, EthTag, MAC+len, IP len, [IP], 1 VNI */
		len = 8 + 10 + 4 + 1 + 6 + 1 + ipa_len + 3;
		if (ipa_len && num_labels > 1) /* There are 2 VNIs */
			len += 3;
		stream_putc(s, len);
		stream_put(s, prd->val, 8);   /* RD */
		if (attr)
			stream_put(s, &attr->esi, ESI_BYTES);
		else
			stream_put(s, 0, 10);
		stream_putl(s, evp->prefix.macip_addr.eth_tag);	/* Ethernet Tag ID */
		stream_putc(s, 8 * ETH_ALEN); /* Mac Addr Len - bits */
		stream_put(s, evp->prefix.macip_addr.mac.octet, 6); /* Mac Addr */
		stream_putc(s, 8 * ipa_len); /* IP address Length */
		if (ipa_len) /* IP */
			stream_put(s, &evp->prefix.macip_addr.ip.ip.addr,
				   ipa_len);
		/* 1st label is the L2 VNI */
		stream_put(s, label, BGP_LABEL_BYTES);
		/* Include 2nd label (L3 VNI) if advertising MAC+IP */
		if (ipa_len && num_labels > 1)
			stream_put(s, label + 1, BGP_LABEL_BYTES);
		break;

	case BGP_EVPN_IMET_ROUTE:
		stream_putc(s, 17); // TODO: length - assumes IPv4 address
		stream_put(s, prd->val, 8);      /* RD */
		stream_putl(s, evp->prefix.imet_addr.eth_tag); /* Ethernet Tag ID */
		stream_putc(s, IPV4_MAX_BITLEN); /* IP address Length - bits */
		/* Originating Router's IP Addr */
		stream_put_in_addr(s, &evp->prefix.imet_addr.ip.ipaddr_v4);
		break;

	case BGP_EVPN_ES_ROUTE:
		stream_putc(s, 23); /* TODO: length: assumes ipv4 VTEP */
		stream_put(s, prd->val, 8); /* RD */
		stream_put(s, evp->prefix.es_addr.esi.val, 10); /* ESI */
		stream_putc(s, IPV4_MAX_BITLEN); /* IP address Length - bits */
		/* VTEP IP */
		stream_put_in_addr(s, &evp->prefix.es_addr.ip.ipaddr_v4);
		break;

	case BGP_EVPN_AD_ROUTE:
		/* RD, ESI, EthTag, 1 VNI */
		len = RD_BYTES + ESI_BYTES + EVPN_ETH_TAG_BYTES + BGP_LABEL_BYTES;
		stream_putc(s, len);
		stream_put(s, prd->val, RD_BYTES); /* RD */
		stream_put(s, evp->prefix.ead_addr.esi.val, ESI_BYTES); /* ESI */
		stream_putl(s, evp->prefix.ead_addr.eth_tag); /* Ethernet Tag */
		stream_put(s, label, BGP_LABEL_BYTES);
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
			struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	int psize = 0;
	uint8_t rtype;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* Deal with path-id if AddPath is supported. */
		if (addpath_capable) {
			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* All EVPN NLRI types start with type and length. */
		if (pnt + 2 > lim)
			return BGP_NLRI_PARSE_ERROR_EVPN_MISSING_TYPE;

		rtype = *pnt++;
		psize = *pnt++;

		/* When packet overflow occur return immediately. */
		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		switch (rtype) {
		case BGP_EVPN_MAC_IP_ROUTE:
			if (process_type2_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_EVPN_FAIL,
					"%u:%s - Error in processing EVPN type-2 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE2_SIZE;
			}
			break;

		case BGP_EVPN_IMET_ROUTE:
			if (process_type3_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-3 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE3_SIZE;
			}
			break;

		case BGP_EVPN_ES_ROUTE:
			if (bgp_evpn_type4_route_process(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-4 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE4_SIZE;
			}
			break;

		case BGP_EVPN_AD_ROUTE:
			if (bgp_evpn_type1_route_process(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-1 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE1_SIZE;
			}
			break;

		case BGP_EVPN_IP_PREFIX_ROUTE:
			if (process_type5_route(peer, afi, safi,
						withdraw ? NULL : attr, pnt,
						psize, addpath_id)) {
				flog_err(
					EC_BGP_PKT_PROCESS,
					"%u:%s - Error in processing EVPN type-5 NLRI size %d",
					peer->bgp->vrf_id, peer->host, psize);
				return BGP_NLRI_PARSE_ERROR_EVPN_TYPE5_SIZE;
			}
			break;

		default:
			break;
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}

/*
 * Map the RTs (configured or automatically derived) of a VRF to the VRF.
 * The mapping will be used during route processing.
 * bgp_vrf: specific bgp vrf instance on which RT is configured
 */
void bgp_evpn_map_vrf_to_its_rts(struct bgp *bgp_vrf)
{
	struct listnode *node, *nnode;
	struct vrf_route_target *l3rt;

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, l3rt))
		map_vrf_to_rt(bgp_vrf, l3rt);
}

/*
 * Unmap the RTs (configured or automatically derived) of a VRF from the VRF.
 */
void bgp_evpn_unmap_vrf_from_its_rts(struct bgp *bgp_vrf)
{
	struct listnode *node, *nnode;
	struct vrf_route_target *l3rt;

	for (ALL_LIST_ELEMENTS(bgp_vrf->vrf_import_rtl, node, nnode, l3rt))
		unmap_vrf_from_rt(bgp_vrf, l3rt);
}

/*
 * Map the RTs (configured or automatically derived) of a VNI to the VNI.
 * The mapping will be used during route processing.
 */
void bgp_evpn_map_vni_to_its_rts(struct bgp *bgp, struct bgpevpn *vpn)
{
	uint32_t i;
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
	uint32_t i;
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
	form_auto_rt(bgp, vpn->vni, vpn->import_rtl, false);
	UNSET_FLAG(vpn->flags, VNI_FLAG_IMPRT_CFGD);

	/* Map RT to VNI */
	bgp_evpn_map_vni_to_its_rts(bgp, vpn);
}

/*
 * Derive Export RT automatically for VNI.
 */
void bgp_evpn_derive_auto_rt_export(struct bgp *bgp, struct bgpevpn *vpn)
{
	form_auto_rt(bgp, vpn->vni, vpn->export_rtl, false);
	UNSET_FLAG(vpn->flags, VNI_FLAG_EXPRT_CFGD);
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vni.
 */
void bgp_evpn_derive_auto_rd_for_vrf(struct bgp *bgp)
{
	if (is_vrf_rd_configured(bgp))
		return;

	form_auto_rd(bgp->router_id, bgp->vrf_rd_id, &bgp->vrf_prd);
}

/*
 * Derive RD automatically for VNI using passed information - it
 * is of the form RouterId:unique-id-for-vni.
 */
void bgp_evpn_derive_auto_rd(struct bgp *bgp, struct bgpevpn *vpn)
{
	char buf[BGP_EVPN_PREFIX_RD_LEN];

	vpn->prd.family = AF_UNSPEC;
	vpn->prd.prefixlen = 64;
	snprintfrr(buf, sizeof(buf), "%pI4:%hu", &bgp->router_id, vpn->rd_id);
	(void)str2prefix_rd(buf, &vpn->prd);
	if (vpn->prd_pretty)
		XFREE(MTYPE_BGP, vpn->prd_pretty);
	UNSET_FLAG(vpn->flags, VNI_FLAG_RD_CFGD);
}

/*
 * Lookup L3-VNI
 */
bool bgp_evpn_lookup_l3vni_l2vni_table(vni_t vni)
{
	struct list *inst = bm->bgp;
	struct listnode *node;
	struct bgp *bgp_vrf;

	for (ALL_LIST_ELEMENTS_RO(inst, node, bgp_vrf)) {
		if (bgp_vrf->l3vni == vni)
			return true;
	}

	return false;
}

/*
 * Lookup VNI.
 */
struct bgpevpn *bgp_evpn_lookup_vni(struct bgp *bgp, vni_t vni)
{
	struct bgpevpn *vpn;
	struct bgpevpn tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.vni = vni;
	vpn = hash_lookup(bgp->vnihash, &tmp);
	return vpn;
}

/*
 * Create a new vpn - invoked upon configuration or zebra notification.
 */
struct bgpevpn *bgp_evpn_new(struct bgp *bgp, vni_t vni,
		struct in_addr originator_ip,
		vrf_id_t tenant_vrf_id,
		struct in_addr mcast_grp,
		ifindex_t svi_ifindex)
{
	struct bgpevpn *vpn;

	vpn = XCALLOC(MTYPE_BGP_EVPN, sizeof(struct bgpevpn));

	/* Set values - RD and RT set to defaults. */
	vpn->vni = vni;
	vpn->originator_ip = originator_ip;
	vpn->tenant_vrf_id = tenant_vrf_id;
	vpn->mcast_grp = mcast_grp;
	vpn->svi_ifindex = svi_ifindex;

	/* Initialize route-target import and export lists */
	vpn->import_rtl = list_new();
	vpn->import_rtl->cmp =
		(int (*)(void *, void *))bgp_evpn_route_target_cmp;
	vpn->import_rtl->del = bgp_evpn_xxport_delete_ecomm;
	vpn->export_rtl = list_new();
	vpn->export_rtl->cmp =
		(int (*)(void *, void *))bgp_evpn_route_target_cmp;
	vpn->export_rtl->del = bgp_evpn_xxport_delete_ecomm;
	bf_assign_index(bm->rd_idspace, vpn->rd_id);
	derive_rd_rt_for_vni(bgp, vpn);

	/* Initialize EVPN route tables. */
	vpn->ip_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);
	vpn->mac_table = bgp_table_init(bgp, AFI_L2VPN, SAFI_EVPN);

	/* Add to hash */
	(void)hash_get(bgp->vnihash, vpn, hash_alloc_intern);

	bgp_evpn_remote_ip_hash_init(vpn);
	bgp_evpn_link_to_vni_svi_hash(bgp, vpn);

	/* add to l2vni list on corresponding vrf */
	bgpevpn_link_to_l3vni(vpn);

	bgp_evpn_vni_es_init(vpn);

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
	bgp_evpn_remote_ip_hash_destroy(vpn);
	bgp_evpn_vni_es_cleanup(vpn);
	bgpevpn_unlink_from_l3vni(vpn);
	bgp_table_unlock(vpn->ip_table);
	bgp_table_unlock(vpn->mac_table);
	bgp_evpn_unmap_vni_from_its_rts(bgp, vpn);
	list_delete(&vpn->import_rtl);
	list_delete(&vpn->export_rtl);
	bf_release_index(bm->rd_idspace, vpn->rd_id);
	hash_release(bgp->vni_svi_hash, vpn);
	hash_release(bgp->vnihash, vpn);
	if (vpn->prd_pretty)
		XFREE(MTYPE_BGP, vpn->prd_pretty);
	QOBJ_UNREG(vpn);
	XFREE(MTYPE_BGP_EVPN, vpn);
}

static void hash_evpn_free(struct bgpevpn *vpn)
{
	XFREE(MTYPE_BGP_EVPN, vpn);
}

/*
 * Import evpn route from global table to VNI/VRF/ESI.
 */
int bgp_evpn_import_route(struct bgp *bgp, afi_t afi, safi_t safi,
			  const struct prefix *p, struct bgp_path_info *pi)
{
	return install_uninstall_evpn_route(bgp, afi, safi, p, pi, 1);
}

/*
 * Unimport evpn route from VNI/VRF/ESI.
 */
int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
			    const struct prefix *p, struct bgp_path_info *pi)
{
	return install_uninstall_evpn_route(bgp, afi, safi, p, pi, 0);
}

/* Refresh previously-discarded EVPN routes carrying "self" MAC-VRF SoO.
 * Walk global EVPN rib + import remote routes with old_soo && !new_soo.
 */
void bgp_reimport_evpn_routes_upon_macvrf_soo_change(struct bgp *bgp,
						     struct ecommunity *old_soo,
						     struct ecommunity *new_soo)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* EVPN routes are a 2-level table: outer=prefix_rd, inner=prefix_evpn.
	 * A remote route could have any RD, so we need to walk them all.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {
			const struct prefix *p;
			struct prefix_evpn *evp;

			p = bgp_dest_get_prefix(dest);
			evp = (struct prefix_evpn *)p;

			/* On export we only add MAC-VRF SoO to RT-2/3, so we
			 * can skip evaluation of other RTs.
			 */
			if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE &&
			    evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
				continue;

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				bool old_soo_fnd = false;
				bool new_soo_fnd = false;

				/* Only consider routes learned from peers */
				if (!(pi->type == ZEBRA_ROUTE_BGP &&
				      pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				if (!CHECK_FLAG(pi->flags, BGP_PATH_VALID))
					continue;

				old_soo_fnd = route_matches_soo(pi, old_soo);
				new_soo_fnd = route_matches_soo(pi, new_soo);

				if (old_soo_fnd && !new_soo_fnd) {
					if (bgp_debug_update(pi->peer, p, NULL,
							     1)) {
						char attr_str[BUFSIZ] = {0};

						bgp_dump_attr(pi->attr,
							      attr_str, BUFSIZ);

						zlog_debug(
							"mac-vrf soo changed: evaluating reimport of prefix %pBD with attr %s",
							dest, attr_str);
					}

					bgp_evpn_import_route(bgp, afi, safi, p,
							      pi);
				}
			}
		}
	}
}

/* Filter learned (!local) EVPN routes carrying "self" attributes.
 * Walk the Global EVPN loc-rib unimporting martian routes from the appropriate
 * L2VNIs (MAC-VRFs) / L3VNIs (IP-VRFs), and deleting them from the Global
 * loc-rib when applicable (based on martian_type).
 * This function is the handler for new martian entries, which is triggered by
 * events occurring on the local system,
 * e.g.
 * - New VTEP-IP
 *   + bgp_zebra_process_local_vni
 *   + bgp_zebra_process_local_l3vni
 * - New MAC-VRF Site-of-Origin
 *   + bgp_evpn_handle_global_macvrf_soo_change
 * This will likely be extended in the future to cover these events too:
 * - New Interface IP
 *   + bgp_interface_address_add
 * - New Interface MAC
 *   + bgp_ifp_up
 *   + bgp_ifp_create
 * - New RMAC
 *   + bgp_zebra_process_local_l3vni
 */
void bgp_filter_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type)
{
	afi_t afi;
	safi_t safi;
	struct bgp_dest *rd_dest, *dest;
	struct bgp_table *table;
	struct bgp_path_info *pi;
	struct ecommunity *macvrf_soo;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;
	macvrf_soo = bgp->evpn_info->soo;

	/* EVPN routes are a 2-level table: outer=prefix_rd, inner=prefix_evpn.
	 * A remote route could have any RD, so we need to walk them all.
	 */
	for (rd_dest = bgp_table_top(bgp->rib[afi][safi]); rd_dest;
	     rd_dest = bgp_route_next(rd_dest)) {
		table = bgp_dest_get_bgp_table_info(rd_dest);
		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest;
		     dest = bgp_route_next(dest)) {

			for (pi = bgp_dest_get_bgp_path_info(dest); pi;
			     pi = pi->next) {
				bool affected = false;
				const struct prefix *p;

				/* Only consider routes learned from peers */
				if (!(pi->type == ZEBRA_ROUTE_BGP
				      && pi->sub_type == BGP_ROUTE_NORMAL))
					continue;

				p = bgp_dest_get_prefix(dest);

				switch (martian_type) {
				case BGP_MARTIAN_TUN_IP:
					affected = bgp_nexthop_self(
						bgp, afi, pi->type,
						pi->sub_type, pi->attr, dest);
					break;
				case BGP_MARTIAN_SOO:
					affected = route_matches_soo(
						pi, macvrf_soo);
					break;
				case BGP_MARTIAN_IF_IP:
				case BGP_MARTIAN_IF_MAC:
				case BGP_MARTIAN_RMAC:
					break;
				}

				if (affected) {
					if (bgp_debug_update(pi->peer, p, NULL,
							     1)) {
						char attr_str[BUFSIZ] = {0};

						bgp_dump_attr(pi->attr,
							      attr_str,
							      sizeof(attr_str));

						zlog_debug(
							"%u: prefix %pBD with attr %s - DISCARDED due to Martian/%s",
							bgp->vrf_id, dest,
							attr_str,
							bgp_martian_type2str(
								martian_type));
					}


					bgp_evpn_unimport_route(bgp, afi, safi,
								p, pi);

					/* For now, retain existing handling of
					 * tip_hash updates: (Self SoO routes
					 * are unimported from L2VNI/VRF but
					 *  retained in global loc-rib, but Self
					 * IP/MAC routes are also deleted from
					 * global loc-rib).
					 * TODO: use consistent handling for all
					 * martian types
					 */
					if (martian_type == BGP_MARTIAN_TUN_IP)
						bgp_rib_remove(dest, pi,
							       pi->peer, afi,
							       safi);
				}
			}
		}
	}
}

/* Refresh previously-discarded EVPN routes carrying "self" attributes.
 * This function is the handler for deleted martian entries, which is triggered
 * by events occurring on the local system,
 * e.g.
 * - Del MAC-VRF Site-of-Origin
 *   + bgp_evpn_handle_global_macvrf_soo_change
 * This will likely be extended in the future to cover these events too:
 * - Del VTEP-IP
 *   + bgp_zebra_process_local_vni
 *   + bgp_zebra_process_local_l3vni
 * - Del Interface IP
 *   + bgp_interface_address_delete
 * - Del Interface MAC
 *   + bgp_ifp_down
 *   + bgp_ifp_destroy
 * - Del RMAC
 *   + bgp_zebra_process_local_l3vni
 */
void bgp_reimport_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type, void *old_martian,
	void *new_martian)
{
	struct listnode *node;
	struct peer *peer;
	safi_t safi;
	afi_t afi;
	struct ecommunity *old_soo, *new_soo;

	afi = AFI_L2VPN;
	safi = SAFI_EVPN;

	/* Self-SoO routes are held in the global EVPN loc-rib, so we can
	 * reimport routes w/o triggering soft-reconfig/route-refresh.
	 */
	if (martian_type == BGP_MARTIAN_SOO) {
		old_soo = (struct ecommunity *)old_martian;
		new_soo = (struct ecommunity *)new_martian;

		/* If !old_soo, then we can skip the reimport because we
		 * wouldn't have filtered anything via the self-SoO import check
		 */
		if (old_martian)
			bgp_reimport_evpn_routes_upon_macvrf_soo_change(
				bgp, old_soo, new_soo);

		return;
	}

	/* Self-TIP/IP/MAC/RMAC routes are deleted from the global EVPN
	 * loc-rib, so we need to re-learn the routes via soft-reconfig/
	 * route-refresh.
	 */
	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {

		if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP))
			continue;

		if (peer->connection->status != Established)
			continue;

		if (CHECK_FLAG(peer->af_flags[afi][safi],
			       PEER_FLAG_SOFT_RECONFIG)) {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"Processing EVPN Martian/%s change on peer %s (inbound, soft-reconfig)",
					bgp_martian_type2str(martian_type),
					peer->host);

			bgp_soft_reconfig_in(peer, afi, safi);
		} else {
			if (bgp_debug_update(peer, NULL, NULL, 1))
				zlog_debug(
					"Processing EVPN Martian/%s change on peer %s",
					bgp_martian_type2str(martian_type),
					peer->host);
			bgp_route_refresh_send(peer, afi, safi, 0,
					       REFRESH_IMMEDIATE, 0,
					       BGP_ROUTE_REFRESH_NORMAL);
		}
	}
}

/*
 * Handle del of a local MACIP.
 */
int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
			     struct ipaddr *ip, int state)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp_dest *dest;

	/* Lookup VNI hash - should exist. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn || !is_vni_live(vpn)) {
		flog_warn(EC_BGP_EVPN_VPN_VNI,
			  "%u: VNI hash entry for VNI %u %s at MACIP DEL",
			  bgp->vrf_id, vni, vpn ? "not live" : "not found");
		return -1;
	}

	build_evpn_type2_prefix(&p, mac, ip);
	if (state == ZEBRA_NEIGH_ACTIVE) {
		/* Remove EVPN type-2 route and schedule for processing. */
		delete_evpn_route(bgp, vpn, &p);
	} else {
		/* Re-instate the current remote best path if any */
		dest = bgp_evpn_vni_node_lookup(vpn, &p, NULL);
		if (dest) {
			evpn_zebra_reinstall_best_route(bgp, vpn, dest);
			bgp_dest_unlock_node(dest);
		}
	}

	return 0;
}

/*
 * Handle add of a local MACIP.
 */
int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni, struct ethaddr *mac,
		struct ipaddr *ip, uint8_t flags, uint32_t seq, esi_t *esi)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;

	/* Lookup VNI hash - should exist. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn || !is_vni_live(vpn)) {
		flog_warn(EC_BGP_EVPN_VPN_VNI,
			  "%u: VNI hash entry for VNI %u %s at MACIP ADD",
			  bgp->vrf_id, vni, vpn ? "not live" : "not found");
		return -1;
	}

	/* Create EVPN type-2 route and schedule for processing. */
	build_evpn_type2_prefix(&p, mac, ip);
	if (update_evpn_route(bgp, vpn, &p, flags, seq, esi)) {
		flog_err(
			EC_BGP_EVPN_ROUTE_CREATE,
			"%u:Failed to create Type-2 route, VNI %u %s MAC %pEA IP %pIA (flags: 0x%x)",
			bgp->vrf_id, vpn->vni,
			CHECK_FLAG(flags, ZEBRA_MACIP_TYPE_STICKY)
				? "sticky gateway"
				: "",
			mac, ip, flags);
		return -1;
	}

	return 0;
}

static void link_l2vni_hash_to_l3vni(struct hash_bucket *bucket,
				     struct bgp *bgp_vrf)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct bgp *bgp_evpn = NULL;

	bgp_evpn = bgp_get_evpn();
	assert(bgp_evpn);

	if (vpn->tenant_vrf_id == bgp_vrf->vrf_id)
		bgpevpn_link_to_l3vni(vpn);
}

int bgp_evpn_local_l3vni_add(vni_t l3vni, vrf_id_t vrf_id,
			     struct ethaddr *svi_rmac,
			     struct ethaddr *vrr_rmac,
			     struct in_addr originator_ip, int filter,
			     ifindex_t svi_ifindex,
			     bool is_anycast_mac)
{
	struct bgp *bgp_vrf = NULL; /* bgp VRF instance */
	struct bgp *bgp_evpn = NULL; /* EVPN bgp instance */
	struct listnode *node = NULL;
	struct bgpevpn *vpn = NULL;
	as_t as = 0;

	/* get the EVPN instance - required to get the AS number for VRF
	 * auto-creatio
	 */
	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn) {
		flog_err(
			EC_BGP_NO_DFLT,
			"Cannot process L3VNI  %u ADD - EVPN BGP instance not yet created",
			l3vni);
		return -1;
	}

	if (CHECK_FLAG(bgp_evpn->flags, BGP_FLAG_DELETE_IN_PROGRESS)) {
		flog_err(EC_BGP_NO_DFLT,
			  "Cannot process L3VNI %u ADD - EVPN BGP instance is shutting down",
			  l3vni);
		return -1;
	}

	as = bgp_evpn->as;

	/* if the BGP vrf instance doesn't exist - create one */
	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf) {

		int ret = 0;

		ret = bgp_get_vty(&bgp_vrf, &as, vrf_id_to_name(vrf_id),
				  vrf_id == VRF_DEFAULT
					  ? BGP_INSTANCE_TYPE_DEFAULT
					  : BGP_INSTANCE_TYPE_VRF,
				  NULL, ASNOTATION_UNDEFINED);
		switch (ret) {
		case BGP_ERR_AS_MISMATCH:
			flog_err(EC_BGP_EVPN_AS_MISMATCH,
				 "BGP instance is already running; AS is %s",
				 bgp_vrf->as_pretty);
			return -1;
		case BGP_ERR_INSTANCE_MISMATCH:
			flog_err(EC_BGP_EVPN_INSTANCE_MISMATCH,
				 "BGP instance type mismatch");
			return -1;
		}

		/* mark as auto created */
		SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_AUTO);
	}

	/* associate the vrf with l3vni and related parameters */
	bgp_vrf->l3vni = l3vni;
	bgp_vrf->l3vni_svi_ifindex = svi_ifindex;
	bgp_vrf->evpn_info->is_anycast_mac = is_anycast_mac;

	/* Update tip_hash of the EVPN underlay BGP instance (bgp_evpn)
	 * if the VTEP-IP (originator_ip) has changed
	 */
	handle_tunnel_ip_change(bgp_vrf, bgp_evpn, vpn, originator_ip);

	/* copy anycast MAC from VRR MAC */
	memcpy(&bgp_vrf->rmac, vrr_rmac, ETH_ALEN);
	/* copy sys RMAC from SVI MAC */
	memcpy(&bgp_vrf->evpn_info->pip_rmac_zebra, svi_rmac, ETH_ALEN);
	/* PIP user configured mac is not present use svi mac as sys mac */
	if (is_zero_mac(&bgp_vrf->evpn_info->pip_rmac_static))
		memcpy(&bgp_vrf->evpn_info->pip_rmac, svi_rmac, ETH_ALEN);

	if (bgp_debug_zebra(NULL))
		zlog_debug(
			"VRF %s vni %u pip %s RMAC %pEA sys RMAC %pEA static RMAC %pEA is_anycast_mac %s",
			vrf_id_to_name(bgp_vrf->vrf_id), bgp_vrf->l3vni,
			bgp_vrf->evpn_info->advertise_pip ? "enable"
							  : "disable",
			&bgp_vrf->rmac, &bgp_vrf->evpn_info->pip_rmac,
			&bgp_vrf->evpn_info->pip_rmac_static,
			is_anycast_mac ? "Enable" : "Disable");

	/* set the right filter - are we using l3vni only for prefix routes? */
	if (filter) {
		SET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);

		/*
		 * VNI_FLAG_USE_TWO_LABELS flag for linked L2VNIs should not be
		 * set before linking vrf to L3VNI. Thus, no need to clear
		 * that explicitly.
		 */
	} else {
		UNSET_FLAG(bgp_vrf->vrf_flags,
			   BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);

		for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn)) {
			if (!CHECK_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS)) {

				/*
				 * If we are flapping VNI_FLAG_USE_TWO_LABELS
				 * flag, update all MACIP routes in this VNI
				 */
				SET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);
				update_all_type2_routes(bgp_evpn, vpn);
			}
		}
	}

	/* Map auto derive or configured RTs */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD) ||
	    CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_AUTO_RT_CFGD))
		evpn_auto_rt_import_add_for_vrf(bgp_vrf);
	else
		bgp_evpn_map_vrf_to_its_rts(bgp_vrf);

	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD) ||
	    CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_AUTO_RT_CFGD))
		evpn_auto_rt_export_add_for_vrf(bgp_vrf);

	/* auto derive RD */
	bgp_evpn_derive_auto_rd_for_vrf(bgp_vrf);

	/* link all corresponding l2vnis */
	hash_iterate(bgp_evpn->vnihash,
		     (void (*)(struct hash_bucket *,
			       void *))link_l2vni_hash_to_l3vni,
		     bgp_vrf);

	/* Only update all corresponding type-2 routes if we are advertising two
	 * labels along with type-2 routes
	 */
	if (!filter)
		for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn))
			update_routes_for_vni(bgp_evpn, vpn);

	/* advertise type-5 routes if needed */
	update_advertise_vrf_routes(bgp_vrf);

	/* install all remote routes belonging to this l3vni into correspondng
	 * vrf */
	install_routes_for_vrf(bgp_vrf);

	return 0;
}

int bgp_evpn_local_l3vni_del(vni_t l3vni, vrf_id_t vrf_id)
{
	struct bgp *bgp_vrf = NULL; /* bgp vrf instance */
	struct bgp *bgp_evpn = NULL; /* EVPN bgp instance */
	struct listnode *node = NULL;
	struct listnode *next = NULL;
	struct bgpevpn *vpn = NULL;

	bgp_vrf = bgp_lookup_by_vrf_id(vrf_id);
	if (!bgp_vrf) {
		flog_err(
			EC_BGP_NO_DFLT,
			"Cannot process L3VNI %u Del - Could not find BGP instance",
			l3vni);
		return -1;
	}

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn) {
		flog_err(
			EC_BGP_NO_DFLT,
			"Cannot process L3VNI %u Del - Could not find EVPN BGP instance",
			l3vni);
		return -1;
	}

	if (CHECK_FLAG(bgp_evpn->flags, BGP_FLAG_DELETE_IN_PROGRESS)) {
		flog_err(EC_BGP_NO_DFLT,
			  "Cannot process L3VNI %u ADD - EVPN BGP instance is shutting down",
			  l3vni);
		return -1;
	}

	/* Remove remote routes from BGT VRF even if BGP_VRF_AUTO is configured,
	 * bgp_delete would not remove/decrement bgp_path_info of the ip_prefix
	 * routes. This will uninstalling the routes from zebra and decremnt the
	 * bgp info count.
	 */
	uninstall_routes_for_vrf(bgp_vrf);

	/* delete/withdraw all type-5 routes */
	delete_withdraw_vrf_routes(bgp_vrf);

	/* Tunnel is no longer active.
	 * Delete VTEP-IP from EVPN underlay's tip_hash.
	 */
	bgp_tip_del(bgp_evpn, &bgp_vrf->originator_ip);

	/* remove the l3vni from vrf instance */
	bgp_vrf->l3vni = 0;

	/* remove the Rmac from the BGP vrf */
	memset(&bgp_vrf->rmac, 0, sizeof(struct ethaddr));
	memset(&bgp_vrf->evpn_info->pip_rmac_zebra, 0, ETH_ALEN);
	if (is_zero_mac(&bgp_vrf->evpn_info->pip_rmac_static) &&
	    !is_zero_mac(&bgp_vrf->evpn_info->pip_rmac))
		memset(&bgp_vrf->evpn_info->pip_rmac, 0, ETH_ALEN);

	/* remove default import RT or Unmap non-default import RT */
	if (!list_isempty(bgp_vrf->vrf_import_rtl)) {
		bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);
		if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_IMPORT_RT_CFGD))
			list_delete_all_node(bgp_vrf->vrf_import_rtl);
	}

	/* remove default export RT */
	if (!list_isempty(bgp_vrf->vrf_export_rtl) &&
	    !CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_EXPORT_RT_CFGD)) {
		list_delete_all_node(bgp_vrf->vrf_export_rtl);
	}

	/* update all corresponding local mac-ip routes */
	if (!CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY)) {
		for (ALL_LIST_ELEMENTS_RO(bgp_vrf->l2vnis, node, vpn)) {
			UNSET_FLAG(vpn->flags, VNI_FLAG_USE_TWO_LABELS);
			update_routes_for_vni(bgp_evpn, vpn);
		}
	}

	/* If any L2VNIs point to this instance, unlink them. */
	for (ALL_LIST_ELEMENTS(bgp_vrf->l2vnis, node, next, vpn))
		bgpevpn_unlink_from_l3vni(vpn);

	UNSET_FLAG(bgp_vrf->vrf_flags, BGP_VRF_L3VNI_PREFIX_ROUTES_ONLY);

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

	/* Locate VNI hash */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn)
		return 0;

	/* Remove all local EVPN routes and schedule for processing (to
	 * withdraw from peers).
	 */
	delete_routes_for_vni(bgp, vpn);

	bgp_evpn_unlink_from_vni_svi_hash(bgp, vpn);

	vpn->svi_ifindex = 0;
	/* Tunnel is no longer active.
	 * Delete VTEP-IP from EVPN underlay's tip_hash.
	 */
	bgp_tip_del(bgp, &vpn->originator_ip);

	/* Clear "live" flag and see if hash needs to be freed. */
	UNSET_FLAG(vpn->flags, VNI_FLAG_LIVE);
	if (!is_vni_configured(vpn))
		bgp_evpn_free(bgp, vpn);

	return 0;
}

/*
 * Handle add (or update) of a local VNI. The VNI changes we care
 * about are for the local-tunnel-ip and the (tenant) VRF.
 */
int bgp_evpn_local_vni_add(struct bgp *bgp, vni_t vni,
			   struct in_addr originator_ip,
			   vrf_id_t tenant_vrf_id,
			   struct in_addr mcast_grp,
			   ifindex_t svi_ifindex)
{
	struct bgpevpn *vpn;
	struct prefix_evpn p;
	struct bgp *bgp_evpn = bgp_get_evpn();

	/* Lookup VNI. If present and no change, exit. */
	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (vpn) {

		if (is_vni_live(vpn)
		    && IPV4_ADDR_SAME(&vpn->originator_ip, &originator_ip)
		    && IPV4_ADDR_SAME(&vpn->mcast_grp, &mcast_grp)
		    && vpn->tenant_vrf_id == tenant_vrf_id
		    && vpn->svi_ifindex == svi_ifindex)
			/* Probably some other param has changed that we don't
			 * care about. */
			return 0;

		bgp_evpn_mcast_grp_change(bgp, vpn, mcast_grp);

		if (vpn->svi_ifindex != svi_ifindex) {

			/*
			 * Unresolve all the gateway IP nexthops for this VNI
			 * for old SVI
			 */
			bgp_evpn_remote_ip_hash_iterate(
				vpn,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_unlink_nexthop,
				vpn);
			bgp_evpn_unlink_from_vni_svi_hash(bgp, vpn);
			vpn->svi_ifindex = svi_ifindex;
			bgp_evpn_link_to_vni_svi_hash(bgp, vpn);

			/*
			 * Resolve all the gateway IP nexthops for this VNI
			 * for new SVI
			 */
			bgp_evpn_remote_ip_hash_iterate(
				vpn,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_link_nexthop,
				vpn);
		}

		/* Update tenant_vrf_id if it has changed. */
		if (vpn->tenant_vrf_id != tenant_vrf_id) {

			/*
			 * Unresolve all the gateway IP nexthops for this VNI
			 * in old tenant vrf
			 */
			bgp_evpn_remote_ip_hash_iterate(
				vpn,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_unlink_nexthop,
				vpn);
			bgpevpn_unlink_from_l3vni(vpn);
			vpn->tenant_vrf_id = tenant_vrf_id;
			bgpevpn_link_to_l3vni(vpn);

			/*
			 * Resolve all the gateway IP nexthops for this VNI
			 * in new tenant vrf
			 */
			bgp_evpn_remote_ip_hash_iterate(
				vpn,
				(void (*)(struct hash_bucket *, void *))
					bgp_evpn_remote_ip_hash_link_nexthop,
				vpn);
		}

		/* If tunnel endpoint IP has changed, update (and delete prior
		 * type-3 route, if needed.)
		 */
		handle_tunnel_ip_change(NULL, bgp, vpn, originator_ip);

		/* Update all routes with new endpoint IP and/or export RT
		 * for VRFs
		 */
		if (is_vni_live(vpn))
			update_routes_for_vni(bgp, vpn);
	} else {
		/* Create or update as appropriate. */
		vpn = bgp_evpn_new(bgp, vni, originator_ip, tenant_vrf_id,
				   mcast_grp, svi_ifindex);
	}

	/* if the VNI is live already, there is nothing more to do */
	if (is_vni_live(vpn))
		return 0;

	/* Mark as "live" */
	SET_FLAG(vpn->flags, VNI_FLAG_LIVE);

	/* Tunnel is newly active.
	 * Add TIP to tip_hash of the EVPN underlay instance (bgp_get_evpn()).
	 */
	if (bgp_tip_add(bgp, &originator_ip))
		/* The originator_ip was not already present in the
		 * bgp martian next-hop table as a tunnel-ip, so we
		 * need to go back and filter routes matching the new
		 * martian next-hop.
		 */
		bgp_filter_evpn_routes_upon_martian_change(bgp_evpn,
							   BGP_MARTIAN_TUN_IP);

	/*
	 * Create EVPN type-3 route and schedule for processing.
	 *
	 * RT-3 only if doing head-end replication
	 */
	if (bgp_evpn_vni_flood_mode_get(bgp, vpn)
			== VXLAN_FLOOD_HEAD_END_REPL) {
		build_evpn_type3_prefix(&p, vpn->originator_ip);
		if (update_evpn_route(bgp, vpn, &p, 0, 0, NULL)) {
			flog_err(EC_BGP_EVPN_ROUTE_CREATE,
				 "%u: Type3 route creation failure for VNI %u",
				 bgp->vrf_id, vni);
			return -1;
		}
	}

	/* If we have learnt and retained remote routes (VTEPs, MACs) for this
	 * VNI,
	 * install them.
	 */
	install_routes_for_vni(bgp, vpn);

	/* If we are advertising gateway mac-ip
	   It needs to be conveyed again to zebra */
	bgp_zebra_advertise_gw_macip(bgp, vpn->advertise_gw_macip, vpn->vni);

	/* advertise svi mac-ip knob to zebra */
	bgp_zebra_advertise_svi_macip(bgp, vpn->advertise_svi_macip, vpn->vni);

	return 0;
}

/*
 * Handle change in setting for BUM handling. The supported values
 * are head-end replication and dropping all BUM packets. Any change
 * should be registered with zebra. Also, if doing head-end replication,
 * need to advertise local VNIs as EVPN RT-3 wheras, if BUM packets are
 * to be dropped, the RT-3s must be withdrawn.
 */
void bgp_evpn_flood_control_change(struct bgp *bgp)
{
	zlog_info("L2VPN EVPN BUM handling is %s",
		  bgp->vxlan_flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL ?
		  "Flooding" : "Flooding Disabled");

	bgp_zebra_vxlan_flood_control(bgp, bgp->vxlan_flood_ctrl);
	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL)
		hash_iterate(bgp->vnihash, create_advertise_type3, bgp);
	else if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_DISABLED)
		hash_iterate(bgp->vnihash, delete_withdraw_type3, bgp);
}

/*
 * Cleanup EVPN information on disable - Need to delete and withdraw
 * EVPN routes from peers.
 */
void bgp_evpn_cleanup_on_disable(struct bgp *bgp)
{
	hash_iterate(bgp->vnihash, (void (*)(struct hash_bucket *,
					     void *))cleanup_vni_on_disable,
		     bgp);
}

/*
 * Cleanup EVPN information - invoked at the time of bgpd exit or when the
 * BGP instance (default) is being freed.
 */
void bgp_evpn_cleanup(struct bgp *bgp)
{
	hash_iterate(bgp->vnihash,
		     (void (*)(struct hash_bucket *, void *))free_vni_entry,
		     bgp);

	hash_clean_and_free(&bgp->import_rt_hash,
			    (void (*)(void *))hash_import_rt_free);

	hash_clean_and_free(&bgp->vrf_import_rt_hash,
			    (void (*)(void *))hash_vrf_import_rt_free);

	hash_clean_and_free(&bgp->vni_svi_hash,
			    (void (*)(void *))hash_evpn_free);

	/*
	 * Why is the vnihash freed at the top of this function and
	 * then deleted here?
	 */
	hash_clean_and_free(&bgp->vnihash, NULL);

	list_delete(&bgp->vrf_import_rtl);
	list_delete(&bgp->vrf_export_rtl);
	list_delete(&bgp->l2vnis);

	if (bgp->evpn_info) {
		ecommunity_free(&bgp->evpn_info->soo);
		XFREE(MTYPE_BGP_EVPN_INFO, bgp->evpn_info);
	}

	if (bgp->vrf_prd_pretty)
		XFREE(MTYPE_BGP, bgp->vrf_prd_pretty);
}

/*
 * Initialization for EVPN
 * Create
 *  VNI hash table
 *  hash for RT to VNI
 */
void bgp_evpn_init(struct bgp *bgp)
{
	bgp->vnihash =
		hash_create(vni_hash_key_make, vni_hash_cmp, "BGP VNI Hash");
	bgp->vni_svi_hash =
		hash_create(vni_svi_hash_key_make, vni_svi_hash_cmp,
			    "BGP VNI hash based on SVI ifindex");
	bgp->import_rt_hash =
		hash_create(import_rt_hash_key_make, import_rt_hash_cmp,
			    "BGP Import RT Hash");
	bgp->vrf_import_rt_hash =
		hash_create(vrf_import_rt_hash_key_make, vrf_import_rt_hash_cmp,
			    "BGP VRF Import RT Hash");
	bgp->vrf_import_rtl = list_new();
	bgp->vrf_import_rtl->cmp =
		(int (*)(void *, void *))evpn_vrf_route_target_cmp;
	bgp->vrf_import_rtl->del = evpn_vrf_rt_del;
	bgp->vrf_export_rtl = list_new();
	bgp->vrf_export_rtl->cmp =
		(int (*)(void *, void *))evpn_vrf_route_target_cmp;
	bgp->vrf_export_rtl->del = evpn_vrf_rt_del;
	bgp->l2vnis = list_new();
	bgp->l2vnis->cmp = vni_list_cmp;
	bgp->evpn_info =
		XCALLOC(MTYPE_BGP_EVPN_INFO, sizeof(struct bgp_evpn_info));
	/* By default Duplicate Address Dection is enabled.
	 * Max-moves (N) 5, detection time (M) 180
	 * default action is warning-only
	 * freeze action permanently freezes address,
	 * and freeze time (auto-recovery) is disabled.
	 */
	if (bgp->evpn_info) {
		bgp->evpn_info->dup_addr_detect = true;
		bgp->evpn_info->dad_time = EVPN_DAD_DEFAULT_TIME;
		bgp->evpn_info->dad_max_moves = EVPN_DAD_DEFAULT_MAX_MOVES;
		bgp->evpn_info->dad_freeze = false;
		bgp->evpn_info->dad_freeze_time = 0;
		/* Initialize zebra vxlan */
		bgp_zebra_dup_addr_detection(bgp);
		/* Enable PIP feature by default for bgp vrf instance */
		if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
			struct bgp *bgp_default;

			bgp->evpn_info->advertise_pip = true;
			bgp_default = bgp_get_default();
			if (bgp_default)
				bgp->evpn_info->pip_ip = bgp_default->router_id;
		}
	}

	/* Default BUM handling is to do head-end replication. */
	bgp->vxlan_flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	bgp_evpn_nh_init(bgp);
}

void bgp_evpn_vrf_delete(struct bgp *bgp_vrf)
{
	bgp_evpn_unmap_vrf_from_its_rts(bgp_vrf);
	bgp_evpn_nh_finish(bgp_vrf);
}

/*
 * Get the prefixlen of the ip prefix carried within the type5 evpn route.
 */
int bgp_evpn_get_type5_prefixlen(const struct prefix *pfx)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)pfx;

	if (!pfx || pfx->family != AF_EVPN)
		return 0;

	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return 0;

	return evp->prefix.prefix_addr.ip_prefix_length;
}

/*
 * Should we register nexthop for this EVPN prefix for nexthop tracking?
 */
bool bgp_evpn_is_prefix_nht_supported(const struct prefix *pfx)
{
	struct prefix_evpn *evp = (struct prefix_evpn *)pfx;

	/*
	 * EVPN routes should be marked as valid only if the nexthop is
	 * reachable. Only if this happens, the route should be imported
	 * (into VNI or VRF routing tables) and/or advertised.
	 * Note: This is currently applied for EVPN type-1, type-2,
	 * type-3, type-4 and type-5 routes.
	 * It may be tweaked later on for other routes, or
	 * even removed completely when all routes are handled.
	 */
	if (pfx && pfx->family == AF_EVPN
	    && (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_AD_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_ES_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_IMET_ROUTE
		|| evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE))
		return true;

	return false;
}

static void *bgp_evpn_remote_ip_hash_alloc(void *p)
{
	const struct evpn_remote_ip *key = (const struct evpn_remote_ip *)p;
	struct evpn_remote_ip *ip;

	ip = XMALLOC(MTYPE_EVPN_REMOTE_IP, sizeof(struct evpn_remote_ip));
	*ip = *key;
	ip->macip_path_list = list_new();

	return ip;
}

static unsigned int bgp_evpn_remote_ip_hash_key_make(const void *p)
{
	const struct evpn_remote_ip *ip = p;
	const struct ipaddr *addr = &ip->addr;

	if (IS_IPADDR_V4(addr))
		return jhash_1word(addr->ipaddr_v4.s_addr, 0);

	return jhash2(addr->ipaddr_v6.s6_addr32,
		      array_size(addr->ipaddr_v6.s6_addr32), 0);
}

static bool bgp_evpn_remote_ip_hash_cmp(const void *p1, const void *p2)
{
	const struct evpn_remote_ip *ip1 = p1;
	const struct evpn_remote_ip *ip2 = p2;

	return !ipaddr_cmp(&ip1->addr, &ip2->addr);
}

static void bgp_evpn_remote_ip_hash_init(struct bgpevpn *vpn)
{
	if (!evpn_resolve_overlay_index())
		return;

	vpn->remote_ip_hash = hash_create(bgp_evpn_remote_ip_hash_key_make,
					  bgp_evpn_remote_ip_hash_cmp,
					  "BGP EVPN remote IP hash");
}

static void bgp_evpn_remote_ip_hash_free(struct hash_bucket *bucket, void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgpevpn *vpn = (struct bgpevpn *)args;

	bgp_evpn_remote_ip_process_nexthops(vpn, &ip->addr, false);

	list_delete(&ip->macip_path_list);

	hash_release(vpn->remote_ip_hash, ip);
	XFREE(MTYPE_EVPN_REMOTE_IP, ip);
}

static void bgp_evpn_remote_ip_hash_destroy(struct bgpevpn *vpn)
{
	if (!evpn_resolve_overlay_index() || vpn->remote_ip_hash == NULL)
		return;

	hash_iterate(vpn->remote_ip_hash,
	(void (*)(struct hash_bucket *, void *))bgp_evpn_remote_ip_hash_free,
	vpn);

	hash_free(vpn->remote_ip_hash);
	vpn->remote_ip_hash = NULL;
}

/* Add a remote MAC/IP route to hash table */
static void bgp_evpn_remote_ip_hash_add(struct bgpevpn *vpn,
					struct bgp_path_info *pi)
{
	struct evpn_remote_ip tmp;
	struct evpn_remote_ip *ip;
	struct prefix_evpn *evp;

	if (!evpn_resolve_overlay_index())
		return;

	if (pi->type != ZEBRA_ROUTE_BGP || pi->sub_type != BGP_ROUTE_IMPORTED
	    || !CHECK_FLAG(pi->flags, BGP_PATH_VALID))
		return;

	evp = (struct prefix_evpn *)&pi->net->rn->p;

	if (evp->family != AF_EVPN
	    || evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE
	    || is_evpn_prefix_ipaddr_none(evp))
		return;

	tmp.addr = evp->prefix.macip_addr.ip;
	ip = hash_lookup(vpn->remote_ip_hash, &tmp);
	if (ip) {
		if (listnode_lookup(ip->macip_path_list, pi) != NULL)
			return;
		(void)listnode_add(ip->macip_path_list, pi);
		return;
	}

	ip = hash_get(vpn->remote_ip_hash, &tmp, bgp_evpn_remote_ip_hash_alloc);
	(void)listnode_add(ip->macip_path_list, pi);

	bgp_evpn_remote_ip_process_nexthops(vpn, &ip->addr, true);
}

/* Delete a remote MAC/IP route from hash table */
static void bgp_evpn_remote_ip_hash_del(struct bgpevpn *vpn,
					struct bgp_path_info *pi)
{
	struct evpn_remote_ip tmp;
	struct evpn_remote_ip *ip;
	struct prefix_evpn *evp;

	if (!evpn_resolve_overlay_index())
		return;

	evp = (struct prefix_evpn *)&pi->net->rn->p;

	if (evp->family != AF_EVPN
	    || evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE
	    || is_evpn_prefix_ipaddr_none(evp))
		return;

	tmp.addr = evp->prefix.macip_addr.ip;
	ip = hash_lookup(vpn->remote_ip_hash, &tmp);
	if (ip == NULL)
		return;

	listnode_delete(ip->macip_path_list, pi);

	if (ip->macip_path_list->count == 0) {
		bgp_evpn_remote_ip_process_nexthops(vpn, &ip->addr, false);
		hash_release(vpn->remote_ip_hash, ip);
		list_delete(&ip->macip_path_list);
		XFREE(MTYPE_EVPN_REMOTE_IP, ip);
	}
}

static void bgp_evpn_remote_ip_hash_iterate(struct bgpevpn *vpn,
					    void (*func)(struct hash_bucket *,
							 void *),
					    void *arg)
{
	if (!evpn_resolve_overlay_index())
		return;

	hash_iterate(vpn->remote_ip_hash, func, arg);
}

static void show_remote_ip_entry(struct hash_bucket *bucket, void *args)
{
	char buf[INET6_ADDRSTRLEN];
	struct listnode *node = NULL;
	struct bgp_path_info *pi = NULL;
	struct vty *vty = (struct vty *)args;
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;

	vty_out(vty, "  Remote IP: %s\n",
		ipaddr2str(&ip->addr, buf, sizeof(buf)));
	vty_out(vty, "      Linked MAC/IP routes:\n");
	for (ALL_LIST_ELEMENTS_RO(ip->macip_path_list, node, pi))
		vty_out(vty, "        %pFX\n", &pi->net->rn->p);
}

void bgp_evpn_show_remote_ip_hash(struct hash_bucket *bucket, void *args)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct vty *vty = (struct vty *)args;

	vty_out(vty, "VNI: %u\n", vpn->vni);
	bgp_evpn_remote_ip_hash_iterate(
		vpn,
		(void (*)(struct hash_bucket *, void *))show_remote_ip_entry,
		vty);
	vty_out(vty, "\n");
}

static void bgp_evpn_remote_ip_hash_link_nexthop(struct hash_bucket *bucket,
						 void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgpevpn *vpn = (struct bgpevpn *)args;

	bgp_evpn_remote_ip_process_nexthops(vpn, &ip->addr, true);
}

static void bgp_evpn_remote_ip_hash_unlink_nexthop(struct hash_bucket *bucket,
						   void *args)
{
	struct evpn_remote_ip *ip = (struct evpn_remote_ip *)bucket->data;
	struct bgpevpn *vpn = (struct bgpevpn *)args;

	bgp_evpn_remote_ip_process_nexthops(vpn, &ip->addr, false);
}

static unsigned int vni_svi_hash_key_make(const void *p)
{
	const struct bgpevpn *vpn = p;

	return jhash_1word(vpn->svi_ifindex, 0);
}

static bool vni_svi_hash_cmp(const void *p1, const void *p2)
{
	const struct bgpevpn *vpn1 = p1;
	const struct bgpevpn *vpn2 = p2;

	return (vpn1->svi_ifindex == vpn2->svi_ifindex);
}

static struct bgpevpn *bgp_evpn_vni_svi_hash_lookup(struct bgp *bgp,
						    ifindex_t svi)
{
	struct bgpevpn *vpn;
	struct bgpevpn tmp;

	memset(&tmp, 0, sizeof(tmp));
	tmp.svi_ifindex = svi;
	vpn = hash_lookup(bgp->vni_svi_hash, &tmp);
	return vpn;
}

static void bgp_evpn_link_to_vni_svi_hash(struct bgp *bgp, struct bgpevpn *vpn)
{
	if (vpn->svi_ifindex == 0)
		return;

	(void)hash_get(bgp->vni_svi_hash, vpn, hash_alloc_intern);
}

static void bgp_evpn_unlink_from_vni_svi_hash(struct bgp *bgp,
					      struct bgpevpn *vpn)
{
	if (vpn->svi_ifindex == 0)
		return;

	hash_release(bgp->vni_svi_hash, vpn);
}

void bgp_evpn_show_vni_svi_hash(struct hash_bucket *bucket, void *args)
{
	struct bgpevpn *evpn = (struct bgpevpn *)bucket->data;
	struct vty *vty = (struct vty *)args;

	vty_out(vty, "SVI: %u VNI: %u\n", evpn->svi_ifindex, evpn->vni);
}

/*
 * This function is called for a bgp_nexthop_cache entry when the nexthop is
 * gateway IP overlay index.
 * This function returns true if there is a remote MAC/IP route for the gateway
 * IP in the EVI of the nexthop SVI.
 */
bool bgp_evpn_is_gateway_ip_resolved(struct bgp_nexthop_cache *bnc)
{
	struct bgp *bgp_evpn = NULL;
	struct bgpevpn *vpn = NULL;
	struct evpn_remote_ip tmp;
	struct prefix *p;

	if (!evpn_resolve_overlay_index())
		return false;

	if (!bnc->nexthop || bnc->nexthop->ifindex == 0)
		return false;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return false;

	/*
	 * Gateway IP is resolved by nht over SVI interface.
	 * Use this SVI to find corresponding EVI(L2 context)
	 */
	vpn = bgp_evpn_vni_svi_hash_lookup(bgp_evpn, bnc->nexthop->ifindex);
	if (!vpn)
		return false;

	if (vpn->bgp_vrf != bnc->bgp)
		return false;

	/*
	 * Check if the gateway IP is present in the EVI remote_ip_hash table
	 * which stores all the remote IP addresses received via MAC/IP routes
	 * in this EVI
	 */
	memset(&tmp, 0, sizeof(tmp));

	p = &bnc->prefix;
	if (p->family == AF_INET) {
		tmp.addr.ipa_type = IPADDR_V4;
		memcpy(&(tmp.addr.ipaddr_v4), &(p->u.prefix4),
		       sizeof(struct in_addr));
	} else if (p->family == AF_INET6) {
		tmp.addr.ipa_type = IPADDR_V6;
		memcpy(&(tmp.addr.ipaddr_v6), &(p->u.prefix6),
		       sizeof(struct in6_addr));
	} else
		return false;

	if (hash_lookup(vpn->remote_ip_hash, &tmp) == NULL)
		return false;

	return true;
}

/* Resolve/Unresolve nexthops when a MAC/IP route is added/deleted */
static void bgp_evpn_remote_ip_process_nexthops(struct bgpevpn *vpn,
						struct ipaddr *addr,
						bool resolve)
{
	afi_t afi;
	struct prefix p;
	struct bgp_nexthop_cache *bnc;
	struct bgp_nexthop_cache_head *tree = NULL;

	if (!vpn->bgp_vrf || vpn->svi_ifindex == 0)
		return;

	memset(&p, 0, sizeof(p));

	if (addr->ipa_type == IPADDR_V4) {
		afi = AFI_IP;
		p.family = AF_INET;
		memcpy(&(p.u.prefix4), &(addr->ipaddr_v4),
		       sizeof(struct in_addr));
		p.prefixlen = IPV4_MAX_BITLEN;
	} else if (addr->ipa_type == IPADDR_V6) {
		afi = AFI_IP6;
		p.family = AF_INET6;
		memcpy(&(p.u.prefix6), &(addr->ipaddr_v6),
		       sizeof(struct in6_addr));
		p.prefixlen = IPV6_MAX_BITLEN;
	} else
		return;

	tree = &vpn->bgp_vrf->nexthop_cache_table[afi];
	bnc = bnc_find(tree, &p, 0, 0);

	if (!bnc || !bnc->is_evpn_gwip_nexthop)
		return;

	if (!bnc->nexthop || bnc->nexthop->ifindex != vpn->svi_ifindex)
		return;

	if (BGP_DEBUG(nht, NHT))
		zlog_debug("%s(%u): vni %u mac/ip %s for NH %pFX",
			   vpn->bgp_vrf->name_pretty, vpn->tenant_vrf_id,
			   vpn->vni, (resolve ? "add" : "delete"),
			   &bnc->prefix);

	/*
	 * MAC/IP route or SVI or tenant vrf being added to EVI.
	 * Set nexthop as valid only if it is already L3 reachable
	 */
	if (resolve && bnc->flags & BGP_NEXTHOP_EVPN_INCOMPLETE) {
		bnc->flags &= ~BGP_NEXTHOP_EVPN_INCOMPLETE;
		bnc->flags |= BGP_NEXTHOP_VALID;
		bnc->change_flags |= BGP_NEXTHOP_MACIP_CHANGED;
		evaluate_paths(bnc);
	}

	 /* MAC/IP route or SVI or tenant vrf being deleted from EVI */
	if (!resolve &&  bnc->flags & BGP_NEXTHOP_VALID) {
		bnc->flags &= ~BGP_NEXTHOP_VALID;
		bnc->flags |= BGP_NEXTHOP_EVPN_INCOMPLETE;
		bnc->change_flags |= BGP_NEXTHOP_MACIP_CHANGED;
		evaluate_paths(bnc);
	}
}

void bgp_evpn_handle_resolve_overlay_index_set(struct hash_bucket *bucket,
					       void *arg)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	bgp_evpn_remote_ip_hash_init(vpn);

	for (dest = bgp_table_top(vpn->ip_table); dest;
	     dest = bgp_route_next(dest))
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
			bgp_evpn_remote_ip_hash_add(vpn, pi);
}

void bgp_evpn_handle_resolve_overlay_index_unset(struct hash_bucket *bucket,
						 void *arg)
{
	struct bgpevpn *vpn = (struct bgpevpn *)bucket->data;

	bgp_evpn_remote_ip_hash_destroy(vpn);
}

/*
 * Helper function for getting the correct label index for l3vni.
 *
 * Returns the label with the l3vni of the path's label stack.
 *
 * L3vni is always last label. Type5 will only
 * have one label, Type2 will have two.
 *
 */
mpls_label_t *bgp_evpn_path_info_labels_get_l3vni(mpls_label_t *labels,
						  uint32_t num_labels)
{
	if (!labels)
		return NULL;

	if (!num_labels)
		return NULL;

	return &labels[num_labels - 1];
}

/*
 * Returns the l3vni of the path converted from the label stack.
 */
vni_t bgp_evpn_path_info_get_l3vni(const struct bgp_path_info *pi)
{
	if (!pi->extra)
		return 0;

	return label2vni(bgp_evpn_path_info_labels_get_l3vni(
		pi->extra->label, pi->extra->num_labels));
}

/*
 * Returns true if the l3vni of any of this path doesn't match vrf's l3vni.
 */
static bool bgp_evpn_path_is_dvni(const struct bgp *bgp_vrf,
				  const struct bgp_path_info *pi)
{
	vni_t vni = 0;

	vni = bgp_evpn_path_info_get_l3vni(pi);

	if ((vni > 0) && (vni != bgp_vrf->l3vni))
		return true;

	return false;
}

/*
 * Returns true if the l3vni of any of the mpath's doesn't match vrf's l3vni.
 */
bool bgp_evpn_mpath_has_dvni(const struct bgp *bgp_vrf,
			     struct bgp_path_info *mpinfo)
{
	for (; mpinfo; mpinfo = bgp_path_info_mpath_next(mpinfo)) {
		if (bgp_evpn_path_is_dvni(bgp_vrf, mpinfo))
			return true;
	}

	return false;
}
