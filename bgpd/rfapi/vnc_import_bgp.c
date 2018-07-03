/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * File:	vnc_import_bgp.c
 * Purpose:	Import routes from BGP unicast directly (not via zebra)
 */

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/linklist.h"
#include "lib/plist.h"
#include "lib/routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mplsvpn.h" /* for RD_TYPE_IP */

#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_monitor.h"
#include "bgpd/rfapi/rfapi_vty.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_import_bgp_p.h"
#include "bgpd/rfapi/vnc_debug.h"

#define ENABLE_VNC_RHNCK

#define DEBUG_RHN_LIST	0

static struct rfapi_descriptor vncHDBgpDirect;  /* dummy nve descriptor */
static struct rfapi_descriptor vncHDResolveNve; /* dummy nve descriptor */

/*
 * For routes from another AS:
 *
 * If MED is set,
 *	LOCAL_PREF = 255 - MIN(255, MED)
 * else
 *	LOCAL_PREF = default_local_pref
 *
 * For routes from the same AS:
 *
 *	LOCAL_PREF unchanged
 */
uint32_t calc_local_pref(struct attr *attr, struct peer *peer)
{
	uint32_t local_pref = 0;

	if (!attr) {
		if (peer) {
			return peer->bgp->default_local_pref;
		}
		return bgp_get_default()->default_local_pref;
	}

	if (peer && (peer->as != peer->bgp->as)) {
		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC)) {
			if (attr->med > 255) {
				local_pref = 0;
			} else {
				local_pref = 255 - attr->med;
			}
		} else {
			local_pref = peer->bgp->default_local_pref;
		}
	} else {
		if (attr->flag & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
			local_pref = attr->local_pref;
		} else {
			if (peer && peer->bgp) {
				local_pref = peer->bgp->default_local_pref;
			}
		}
	}

	return local_pref;
}

static int is_host_prefix(struct prefix *p)
{
	switch (p->family) {
	case AF_INET:
		return (p->prefixlen == 32);
	case AF_INET6:
		return (p->prefixlen == 128);
	}
	return 0;
}

/***********************************************************************
 *				RHN list
 ***********************************************************************/

struct prefix_bag {
	struct prefix hpfx;   /* ce address = unicast nexthop */
	struct prefix upfx;   /* unicast prefix */
	struct bgp_info *ubi; /* unicast route */
};

static const uint8_t maskbit[] = {0x00, 0x80, 0xc0, 0xe0, 0xf0,
				  0xf8, 0xfc, 0xfe, 0xff};

int vnc_prefix_cmp(void *pfx1, void *pfx2)
{
	int offset;
	int shift;
	uint8_t mask;

	struct prefix *p1 = pfx1;
	struct prefix *p2 = pfx2;

	if (p1->family < p2->family)
		return -1;
	if (p1->family > p2->family)
		return 1;

	if (p1->prefixlen < p2->prefixlen)
		return -1;
	if (p1->prefixlen > p2->prefixlen)
		return 1;

	offset = p1->prefixlen / 8;
	shift = p1->prefixlen % 8;
	if (shift == 0 && offset) { /* catch aligned case */
		offset--;
		shift = 8;
	}

	/* Set both prefix's head pointer. */
	const uint8_t *pp1 = (const uint8_t *)&p1->u.prefix;
	const uint8_t *pp2 = (const uint8_t *)&p2->u.prefix;

	while (offset--) {
		if (*pp1 < *pp2)
			return -1;
		if (*pp1 > *pp2)
			return 1;
		++pp1;
		++pp2;
	}

	mask = maskbit[shift];
	if ((*pp1 & mask) < (*pp2 & mask))
		return -1;
	if ((*pp1 & mask) > (*pp2 & mask))
		return 1;

	return 0;
}

static void prefix_bag_free(void *pb)
{
	XFREE(MTYPE_RFAPI_PREFIX_BAG, pb);
}

#if DEBUG_RHN_LIST
static void print_rhn_list(const char *tag1, const char *tag2)
{
	struct bgp *bgp;
	struct skiplist *sl;
	struct skiplistnode *p;
	struct prefix_bag *pb;
	int count = 0;

	bgp = bgp_get_default();
	if (!bgp)
		return;

	sl = bgp->frapi->resolve_nve_nexthop;
	if (!sl) {
		vnc_zlog_debug_verbose("%s: %s: RHN List is empty",
				       (tag1 ? tag1 : ""), (tag2 ? tag2 : ""));
		return;
	}

	vnc_zlog_debug_verbose("%s: %s: RHN list:", (tag1 ? tag1 : ""),
			       (tag2 ? tag2 : ""));

	/* XXX uses secret knowledge of skiplist structure */
	for (p = sl->header->forward[0]; p; p = p->forward[0]) {
		char kbuf[PREFIX_STRLEN];
		char hbuf[PREFIX_STRLEN];
		char ubuf[PREFIX_STRLEN];

		pb = p->value;

		prefix2str(p->key, kbuf, sizeof(kbuf));
		prefix2str(&pb->hpfx, hbuf, sizeof(hbuf));
		prefix2str(&pb->upfx, ubuf, sizeof(ubuf));

		vnc_zlog_debug_verbose(
			"RHN Entry %d (q=%p): kpfx=%s, upfx=%s, hpfx=%s, ubi=%p",
			++count, p, kbuf, ubuf, hbuf, pb->ubi);
	}
}
#endif

#ifdef ENABLE_VNC_RHNCK
static void vnc_rhnck(char *tag)
{
	struct bgp *bgp;
	struct skiplist *sl;
	struct skiplistnode *p;

	bgp = bgp_get_default();
	if (!bgp)
		return;
	sl = bgp->rfapi->resolve_nve_nexthop;

	if (!sl)
		return;

	/* XXX uses secret knowledge of skiplist structure */
	for (p = sl->header->forward[0]; p; p = p->forward[0]) {
		struct prefix_bag *pb;
		struct prefix *pkey;
		afi_t afi;
		struct prefix pfx_orig_nexthop;

		memset(&pfx_orig_nexthop, 0,
		       sizeof(struct prefix)); /* keep valgrind happy */

		pkey = p->key;
		pb = p->value;

		afi = family2afi(pb->upfx.family);

		rfapiUnicastNexthop2Prefix(afi, pb->ubi->attr,
					   &pfx_orig_nexthop);

		/* pb->hpfx, pb->ubi nexthop, pkey should all reflect the same
		 * pfx */
		assert(!vnc_prefix_cmp(&pb->hpfx, pkey));
		if (vnc_prefix_cmp(&pb->hpfx, &pfx_orig_nexthop)) {
			char str_onh[PREFIX_STRLEN];
			char str_nve_pfx[PREFIX_STRLEN];

			prefix2str(&pfx_orig_nexthop, str_onh, sizeof(str_onh));
			prefix2str(&pb->hpfx, str_nve_pfx, sizeof(str_nve_pfx));

			vnc_zlog_debug_verbose(
				"%s: %s: FATAL: resolve_nve_nexthop list item bi nexthop %s != nve pfx %s",
				__func__, tag, str_onh, str_nve_pfx);
			assert(0);
		}
	}
	vnc_zlog_debug_verbose("%s: vnc_rhnck OK", tag);
}

#define VNC_RHNCK(n)	do {char buf[BUFSIZ];sprintf(buf,"%s: %s", __func__, #n);vnc_rhnck(buf);} while (0)

#else

#define VNC_RHNCK(n)

#endif

/***********************************************************************
 *			Add/Delete Unicast Route
 ***********************************************************************/

/*
 * "Adding a Route" import process
 */

/*
 * extract and package information from the BGP unicast route.
 * Return code 0 means OK, non-0 means drop.
 *
 * If return code is 0, caller MUST release ecom
 */
static int process_unicast_route(struct bgp *bgp,		 /* in */
				 afi_t afi,			 /* in */
				 struct prefix *prefix,		 /* in */
				 struct bgp_info *info,		 /* in */
				 struct ecommunity **ecom,       /* OUT */
				 struct prefix *unicast_nexthop) /* OUT */
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;
	struct peer *peer = info->peer;
	struct attr *attr = info->attr;
	struct attr hattr;
	struct route_map *rmap = NULL;
	struct prefix pfx_orig_nexthop;

	memset(&pfx_orig_nexthop, 0,
	       sizeof(struct prefix)); /* keep valgrind happy */

	/*
	 * prefix list check
	 */
	if (hc->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi]) {
		vnc_zlog_debug_verbose("%s: HC prefix list is set, checking",
				       __func__);
		if (prefix_list_apply(
			    hc->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi],
			    prefix)
		    == PREFIX_DENY) {
			vnc_zlog_debug_verbose(
				"%s: prefix list returns DENY, blocking route",
				__func__);
			return -1;
		}
		vnc_zlog_debug_verbose(
			"%s: prefix list returns PASS, allowing route",
			__func__);
	}

	/* apply routemap, if any, later */
	rmap = hc->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT];

	/*
	 * Extract original nexthop, which we expect to be a NVE connected
	 * router
	 * Note that this is the nexthop before any possible application of
	 * policy
	 */
	/*
	 * Incoming prefix is unicast. If v6, it is in multiprotocol area,
	 * but if v4 it is in attr->nexthop
	 */
	rfapiUnicastNexthop2Prefix(afi, attr, &pfx_orig_nexthop);

	/*
	 * route map handling
	 * This code is here because it allocates an interned attr which
	 * must be freed before we return. It's easier to put it after
	 * all of the possible returns above.
	 */
	memset(&hattr, 0, sizeof(struct attr));
	bgp_attr_dup(&hattr, attr); /* hattr becomes a ghost attr */

	if (rmap) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = peer;
		info.attr = &hattr;
		ret = route_map_apply(rmap, prefix, RMAP_BGP, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			vnc_zlog_debug_verbose(
				"%s: route map \"%s\" says DENY, returning",
				__func__, rmap->name);
			return -1;
		}
	}

	/*
	 * Get the (possibly altered by policy) unicast nexthop
	 * for later lookup in the Import Table by caller
	 */
	rfapiUnicastNexthop2Prefix(afi, &hattr, unicast_nexthop);

	if (hattr.ecommunity)
		*ecom = ecommunity_dup(hattr.ecommunity);
	else
		*ecom = ecommunity_new();

	/*
	 * Done with hattr, clean up
	 */
	bgp_attr_flush(&hattr);

	/*
	 * Add EC that carries original NH of iBGP route (2 bytes = magic
	 * value indicating it came from an VNC gateway; default 5226, but
	 * must be user configurable). Note that this is the nexthop before
	 * any application of policy.
	 */
	{
		struct ecommunity_val vnc_gateway_magic;
		uint16_t localadmin;

		/* Using route origin extended community type */
		memset(&vnc_gateway_magic, 0, sizeof(vnc_gateway_magic));
		vnc_gateway_magic.val[0] = 0x01;
		vnc_gateway_magic.val[1] = 0x03;

		/* Only works for IPv4 nexthops */
		if (prefix->family == AF_INET) {
			memcpy(vnc_gateway_magic.val + 2,
			       &unicast_nexthop->u.prefix4, 4);
		}
		localadmin = htons(hc->resolve_nve_roo_local_admin);
		memcpy(vnc_gateway_magic.val + 6, (char *)&localadmin, 2);

		ecommunity_add_val(*ecom, &vnc_gateway_magic);
	}

	return 0;
}


static void vnc_import_bgp_add_route_mode_resolve_nve_one_bi(
	struct bgp *bgp, afi_t afi, struct bgp_info *bi, /* VPN bi */
	struct prefix_rd *prd,				 /* RD */
	struct prefix *prefix,   /* unicast route prefix */
	uint32_t *local_pref,    /* NULL = no local_pref */
	uint32_t *med,		 /* NULL = no med */
	struct ecommunity *ecom) /* generated ecoms */
{
	struct prefix un;
	struct prefix nexthop;
	struct rfapi_ip_addr nexthop_h;
	uint32_t lifetime;
	uint32_t *plifetime;
	struct bgp_attr_encap_subtlv *encaptlvs;
	uint32_t label = 0;

	struct rfapi_un_option optary[3];
	struct rfapi_un_option *opt = NULL;
	int cur_opt = 0;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (bi->type != ZEBRA_ROUTE_BGP && bi->type != ZEBRA_ROUTE_BGP_DIRECT) {

		return;
	}
	if (bi->sub_type != BGP_ROUTE_NORMAL && bi->sub_type != BGP_ROUTE_STATIC
	    && bi->sub_type != BGP_ROUTE_RFP) {

		return;
	}
	if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
		return;

	vncHDResolveNve.peer = bi->peer;
	if (!rfapiGetVncTunnelUnAddr(bi->attr, &un)) {
		if (rfapiQprefix2Raddr(&un, &vncHDResolveNve.un_addr))
			return;
	} else {
		memset(&vncHDResolveNve.un_addr, 0,
		       sizeof(vncHDResolveNve.un_addr));
	}

	/* Use nexthop of VPN route as nexthop of constructed route */
	rfapiNexthop2Prefix(bi->attr, &nexthop);
	rfapiQprefix2Raddr(&nexthop, &nexthop_h);

	if (rfapiGetVncLifetime(bi->attr, &lifetime)) {
		plifetime = NULL;
	} else {
		plifetime = &lifetime;
	}

	if (bi->attr) {
		encaptlvs = bi->attr->vnc_subtlvs;
		if (bi->attr->encap_tunneltype != BGP_ENCAP_TYPE_RESERVED
		    && bi->attr->encap_tunneltype != BGP_ENCAP_TYPE_MPLS) {
			if (opt != NULL)
				opt->next = &optary[cur_opt];
			opt = &optary[cur_opt++];
			memset(opt, 0, sizeof(struct rfapi_un_option));
			opt->type = RFAPI_UN_OPTION_TYPE_TUNNELTYPE;
			opt->v.tunnel.type = bi->attr->encap_tunneltype;
			/* TBD parse bi->attr->extra->encap_subtlvs */
		}
	} else {
		encaptlvs = NULL;
	}

	struct ecommunity *new_ecom = ecommunity_dup(ecom);

	if (bi->attr && bi->attr->ecommunity)
		ecommunity_merge(new_ecom, bi->attr->ecommunity);

	if (bi->extra)
		label = decode_label(&bi->extra->label[0]);

	add_vnc_route(&vncHDResolveNve, bgp, SAFI_MPLS_VPN,
		      prefix,	  /* unicast route prefix */
		      prd, &nexthop_h, /* new nexthop */
		      local_pref, plifetime,
		      (struct bgp_tea_options *)encaptlvs, /* RFP options */
		      opt, NULL, new_ecom, med, /* NULL => don't set med */
		      (label ? &label : NULL),  /* NULL= default */
		      ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE,
		      RFAPI_AHR_RFPOPT_IS_VNCTLV); /* flags */

	ecommunity_free(&new_ecom);
}

static void vnc_import_bgp_add_route_mode_resolve_nve_one_rd(
	struct prefix_rd *prd,      /* RD */
	struct bgp_table *table_rd, /* per-rd VPN route table */
	afi_t afi, struct bgp *bgp, struct prefix *prefix, /* unicast prefix */
	struct ecommunity *ecom,			   /* generated ecoms */
	uint32_t *local_pref,       /* NULL = no local_pref */
	uint32_t *med,		    /* NULL = no med */
	struct prefix *ubi_nexthop) /* unicast nexthop */
{
	struct bgp_node *bn;
	struct bgp_info *bi;

	if (!table_rd)
		return;

	{
		char str_nh[PREFIX_STRLEN];

		prefix2str(ubi_nexthop, str_nh, sizeof(str_nh));

		vnc_zlog_debug_verbose("%s: ubi_nexthop=%s", __func__, str_nh);
	}

	/* exact match */
	bn = bgp_node_lookup(table_rd, ubi_nexthop);
	if (!bn) {
		vnc_zlog_debug_verbose(
			"%s: no match in RD's table for ubi_nexthop", __func__);
		return;
	}

	/* Iterate over bgp_info items at this node */
	for (bi = bn->info; bi; bi = bi->next) {

		vnc_import_bgp_add_route_mode_resolve_nve_one_bi(
			bgp, afi, bi, /* VPN bi */
			prd, prefix, local_pref, med, ecom);
	}

	bgp_unlock_node(bn);
}

static void vnc_import_bgp_add_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix *prefix, /* unicast prefix */
	struct bgp_info *info)			/* unicast info */
{
	afi_t afi = family2afi(prefix->family);
	struct rfapi_cfg *hc = NULL;

	struct prefix pfx_unicast_nexthop = {0}; /* happy valgrind */

	struct ecommunity *ecom = NULL;
	uint32_t local_pref;
	uint32_t *med = NULL;

	struct prefix_bag *pb;
	struct bgp_node *bnp; /* prd table node */

	/*debugging */
	if (VNC_DEBUG(VERBOSE)) {
		char str_pfx[PREFIX_STRLEN];
		char str_nh[PREFIX_STRLEN];
		struct prefix nh;

		prefix2str(prefix, str_pfx, sizeof(str_pfx));

		nh.prefixlen = 0;
		rfapiUnicastNexthop2Prefix(afi, info->attr, &nh);
		if (nh.prefixlen) {
			prefix2str(&nh, str_nh, sizeof(str_nh));
		} else {
			str_nh[0] = '?';
			str_nh[1] = 0;
		}

		vnc_zlog_debug_verbose(
			"%s(bgp=%p, unicast prefix=%s, unicast nh=%s)",
			__func__, bgp, str_pfx, str_nh);
	}

	if (info->type != ZEBRA_ROUTE_BGP) {
		vnc_zlog_debug_verbose(
			"%s: unicast type %d=\"%s\" is not %d=%s, skipping",
			__func__, info->type, zebra_route_string(info->type),
			ZEBRA_ROUTE_BGP, "ZEBRA_ROUTE_BGP");
		return;
	}

	/*
	 * Preliminary checks
	 */

	if (!afi) {
		zlog_err("%s: can't get afi of prefix", __func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi);
		return;
	}


	if (process_unicast_route(bgp, afi, prefix, info, &ecom,
				  &pfx_unicast_nexthop)) {

		vnc_zlog_debug_verbose(
			"%s: process_unicast_route error, skipping", __func__);
		return;
	}

	local_pref = calc_local_pref(info->attr, info->peer);
	if (info->attr
	    && (info->attr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))) {

		med = &info->attr->med;
	}


	/*
	 * At this point, we have allocated:
	 *
	 *  ecom    ecommunity ptr, union of unicast and ROO parts (no NVE part)
	 *
	 * And we have set:
	 *
	 *  pfx_unicast_nexthop     nexthop of uncast route
	 */

	if (!bgp->rfapi->resolve_nve_nexthop) {
		bgp->rfapi->resolve_nve_nexthop =
			skiplist_new(SKIPLIST_FLAG_ALLOW_DUPLICATES,
				     vnc_prefix_cmp, prefix_bag_free);
	}

	pb = XCALLOC(MTYPE_RFAPI_PREFIX_BAG, sizeof(struct prefix_bag));
	pb->hpfx = pfx_unicast_nexthop;
	pb->ubi = info;
	pb->upfx = *prefix;

	bgp_info_lock(info); /* skiplist refers to it */
	skiplist_insert(bgp->rfapi->resolve_nve_nexthop, &pb->hpfx, pb);

	/*
	 * Iterate over RDs in VPN RIB. For each RD, look up unicast nexthop
	 * (exact match, /32). If an exact match is found, call add_vnc_route.
	 */

	for (bnp = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); bnp;
	     bnp = bgp_route_next(bnp)) {

		struct bgp_table *table;

		table = (struct bgp_table *)(bnp->info);

		if (!table)
			continue;

		vnc_import_bgp_add_route_mode_resolve_nve_one_rd(
			(struct prefix_rd *)&bnp->p, table, afi, bgp, prefix,
			ecom, &local_pref, med, &pfx_unicast_nexthop);
	}


	if (ecom)
		ecommunity_free(&ecom);

	vnc_zlog_debug_verbose("%s: done", __func__);
}


static void vnc_import_bgp_add_route_mode_plain(struct bgp *bgp,
						struct prefix *prefix,
						struct bgp_info *info)
{
	afi_t afi = family2afi(prefix->family);
	struct peer *peer = info->peer;
	struct attr *attr = info->attr;
	struct attr hattr;
	struct rfapi_cfg *hc = NULL;
	struct attr *iattr = NULL;

	struct rfapi_ip_addr vnaddr;
	struct prefix vn_pfx_space;
	struct prefix *vn_pfx = NULL;
	int ahr_flags = 0;
	struct ecommunity *ecom = NULL;
	struct prefix_rd prd;
	struct route_map *rmap = NULL;
	uint32_t local_pref;
	uint32_t *med = NULL;

	{
		char buf[PREFIX_STRLEN];

		prefix2str(prefix, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s(prefix=%s) entry", __func__, buf);
	}

	if (!afi) {
		zlog_err("%s: can't get afi of prefix", __func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi);
		return;
	}

	/*
	 * mode "plain" specific code
	 */
	{
		vnc_zlog_debug_verbose("%s: NOT using redist RFG", __func__);

		/*
		 * prefix list check
		 */
		if (hc->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi]) {
			vnc_zlog_debug_verbose(
				"%s: HC prefix list is set, checking",
				__func__);
			if (prefix_list_apply(
				    hc->plist_redist[ZEBRA_ROUTE_BGP_DIRECT]
						    [afi],
				    prefix)
			    == PREFIX_DENY) {
				vnc_zlog_debug_verbose(
					"%s: prefix list returns DENY, blocking route",
					__func__);
				return;
			}
			vnc_zlog_debug_verbose(
				"%s: prefix list returns PASS, allowing route",
				__func__);
		}

		/* apply routemap, if any, later */
		rmap = hc->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT];

		/*
		 * Incoming prefix is unicast. If v6, it is in multiprotocol
		 * area,
		 * but if v4 it is in attr->nexthop
		 */
		rfapiUnicastNexthop2Prefix(afi, attr, &vn_pfx_space);
		vn_pfx = &vn_pfx_space;

		/* UN address */
		ahr_flags |= RFAPI_AHR_NO_TUNNEL_SUBTLV;
	}

	if (VNC_DEBUG(IMPORT_BGP_ADD_ROUTE)) {
		char buf[PREFIX_STRLEN];

		prefix2str(vn_pfx, buf, sizeof(buf));
		vnc_zlog_debug_any("%s vn_pfx=%s", __func__, buf);
	}

	/*
	 * Compute VN address
	 */
	if (rfapiQprefix2Raddr(vn_pfx, &vnaddr)) {
		vnc_zlog_debug_verbose("%s: redist VN invalid, skipping",
				       __func__);
		return;
	}

	/*
	 * route map handling
	 * This code is here because it allocates an interned attr which
	 * must be freed before we return. It's easier to put it after
	 * all of the possible returns above.
	 */
	memset(&hattr, 0, sizeof(struct attr));
	bgp_attr_dup(&hattr, attr); /* hattr becomes a ghost attr */

	if (rmap) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = peer;
		info.attr = &hattr;
		ret = route_map_apply(rmap, prefix, RMAP_BGP, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			vnc_zlog_debug_verbose(
				"%s: route map \"%s\" says DENY, returning",
				__func__, rmap->name);
			return;
		}
	}

	iattr = bgp_attr_intern(&hattr);
	bgp_attr_flush(&hattr);

	/* Now iattr is an allocated interned attr */

	/*
	 * Mode "plain" specific code
	 *
	 * Sets RD in dummy HD
	 * Allocates ecom
	 */
	{
		if (vnaddr.addr_family != AF_INET) {
			vnc_zlog_debug_verbose(
				"%s: can't auto-assign RD, VN AF (%d) is not IPv4, skipping",
				__func__, vnaddr.addr_family);
			if (iattr) {
				bgp_attr_unintern(&iattr);
			}
			return;
		}
		memset(&prd, 0, sizeof(prd));
		rfapi_set_autord_from_vn(&prd, &vnaddr);

		if (iattr && iattr->ecommunity)
			ecom = ecommunity_dup(iattr->ecommunity);
	}

	local_pref = calc_local_pref(iattr, peer);

	if (iattr && (iattr->flag & ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))) {
		med = &iattr->med;
	}

	if (VNC_DEBUG(IMPORT_BGP_ADD_ROUTE)) {
		char buf[PREFIX_STRLEN];

		rfapiRfapiIpAddr2Str(&vnaddr, buf, sizeof(buf));
		vnc_zlog_debug_any("%s: setting vnaddr to %s", __func__, buf);
	}

	vncHDBgpDirect.peer = peer;
	add_vnc_route(&vncHDBgpDirect, bgp, SAFI_MPLS_VPN, prefix, &prd,
		      &vnaddr, &local_pref, &(bgp->rfapi_cfg->redist_lifetime),
		      NULL,		     /* RFP options */
		      NULL, NULL, ecom, med, /* med */
		      NULL,		     /* label: default */
		      ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE,
		      ahr_flags);
	vncHDBgpDirect.peer = NULL;

	if (ecom)
		ecommunity_free(&ecom);
}

static void
vnc_import_bgp_add_route_mode_nvegroup(struct bgp *bgp, struct prefix *prefix,
				       struct bgp_info *info,
				       struct rfapi_nve_group_cfg *rfg)
{
	afi_t afi = family2afi(prefix->family);
	struct peer *peer = info->peer;
	struct attr *attr = info->attr;
	struct attr hattr;
	struct rfapi_cfg *hc = NULL;
	struct attr *iattr = NULL;

	struct rfapi_ip_addr vnaddr;
	struct prefix *vn_pfx = NULL;
	int ahr_flags = 0;
	struct ecommunity *ecom = NULL;
	struct prefix_rd prd;
	struct route_map *rmap = NULL;
	uint32_t local_pref;

	{
		char buf[PREFIX_STRLEN];

		prefix2str(prefix, buf, sizeof(buf));
		vnc_zlog_debug_verbose("%s(prefix=%s) entry", __func__, buf);
	}

	assert(rfg);

	if (!afi) {
		zlog_err("%s: can't get afi of prefix", __func__);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi);
		return;
	}


	/*
	 * RFG-specific code
	 */
	{

		struct rfapi_ip_prefix pfx_un;

		vnc_zlog_debug_verbose("%s: using redist RFG", __func__);

		/*
		 * RFG prefix list check
		 */
		if (rfg->plist_redist[ZEBRA_ROUTE_BGP_DIRECT][afi]) {
			vnc_zlog_debug_verbose(
				"%s: RFG prefix list is set, checking",
				__func__);
			if (prefix_list_apply(
				    rfg->plist_redist[ZEBRA_ROUTE_BGP_DIRECT]
						     [afi],
				    prefix)
			    == PREFIX_DENY) {
				vnc_zlog_debug_verbose(
					"%s: prefix list returns DENY, blocking route",
					__func__);
				return;
			}
			vnc_zlog_debug_verbose(
				"%s: prefix list returns PASS, allowing route",
				__func__);
		}

		/* apply routemap, if any, later */
		rmap = rfg->routemap_redist[ZEBRA_ROUTE_BGP_DIRECT];

		/*
		 * export nve group's VN addr prefix must be a /32 which
		 * will yield the VN addr to use
		 */
		vn_pfx = &rfg->vn_prefix;

		/*
		 * UN Address
		 */
		if (!is_host_prefix(&rfg->un_prefix)) {
			/* NB prefixlen==0 means it has not been configured */
			vnc_zlog_debug_verbose(
				"%s: redist RFG UN pfx not host pfx (plen=%d), skipping",
				__func__, rfg->un_prefix.prefixlen);
			return;
		}

		rfapiQprefix2Rprefix(&rfg->un_prefix, &pfx_un);

		vncHDBgpDirect.un_addr = pfx_un.prefix;
	}

	if (VNC_DEBUG(IMPORT_BGP_ADD_ROUTE)) {
		char buf[PREFIX_STRLEN];

		prefix2str(vn_pfx, buf, sizeof(buf));
		vnc_zlog_debug_any("%s vn_pfx=%s", __func__, buf);
	}

	/*
	 * Compute VN address
	 */
	if (rfapiQprefix2Raddr(vn_pfx, &vnaddr)) {
		vnc_zlog_debug_verbose("%s: redist VN invalid, skipping",
				       __func__);
		return;
	}

	/*
	 * route map handling
	 * This code is here because it allocates an interned attr which
	 * must be freed before we return. It's easier to put it after
	 * all of the possible returns above.
	 */
	memset(&hattr, 0, sizeof(struct attr));
	bgp_attr_dup(&hattr, attr); /* hattr becomes a ghost attr */

	if (rmap) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = peer;
		info.attr = &hattr;
		ret = route_map_apply(rmap, prefix, RMAP_BGP, &info);
		if (ret == RMAP_DENYMATCH) {
			bgp_attr_flush(&hattr);
			vnc_zlog_debug_verbose(
				"%s: route map \"%s\" says DENY, returning",
				__func__, rmap->name);
			return;
		}
	}

	iattr = bgp_attr_intern(&hattr);
	bgp_attr_flush(&hattr);

	/* Now iattr is an allocated interned attr */

	/*
	 * RFG-specific code
	 *
	 * Sets RD in dummy HD
	 * Allocates ecom
	 */
	{

		memset(&prd, 0, sizeof(prd));
		prd = rfg->rd;
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;

		if (rfg->rd.family == AF_UNIX) {
			rfapi_set_autord_from_vn(&prd, &vnaddr);
		}

		if (rfg->rt_export_list)
			ecom = ecommunity_dup(
				bgp->rfapi_cfg->rfg_redist->rt_export_list);
		else
			ecom = ecommunity_new();

		if (iattr && iattr->ecommunity)
			ecom = ecommunity_merge(ecom, iattr->ecommunity);
	}

	local_pref = calc_local_pref(iattr, peer);

	if (VNC_DEBUG(IMPORT_BGP_ADD_ROUTE)) {
		char buf[BUFSIZ];

		buf[0] = 0;
		rfapiRfapiIpAddr2Str(&vnaddr, buf, BUFSIZ);
		buf[BUFSIZ - 1] = 0;
		vnc_zlog_debug_any("%s: setting vnaddr to %s", __func__, buf);
	}

	vncHDBgpDirect.peer = peer;
	add_vnc_route(&vncHDBgpDirect, bgp, SAFI_MPLS_VPN, prefix, &prd,
		      &vnaddr, &local_pref, &(bgp->rfapi_cfg->redist_lifetime),
		      NULL,		      /* RFP options */
		      NULL, NULL, ecom, NULL, /* med */
		      NULL,		      /* label: default */
		      ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE,
		      ahr_flags);
	vncHDBgpDirect.peer = NULL;

	if (ecom)
		ecommunity_free(&ecom);
}

static void vnc_import_bgp_del_route_mode_plain(struct bgp *bgp,
						struct prefix *prefix,
						struct bgp_info *info)
{
	struct prefix_rd prd;
	afi_t afi = family2afi(prefix->family);
	struct prefix *vn_pfx = NULL;
	struct rfapi_ip_addr vnaddr;
	struct prefix vn_pfx_space;


	assert(afi);

	/*
	 * Compute VN address
	 */

	if (info && info->attr) {
		rfapiUnicastNexthop2Prefix(afi, info->attr, &vn_pfx_space);
	} else {
		vnc_zlog_debug_verbose("%s: no attr, can't delete route",
				       __func__);
		return;
	}
	vn_pfx = &vn_pfx_space;

	vnaddr.addr_family = vn_pfx->family;
	switch (vn_pfx->family) {
	case AF_INET:
		if (vn_pfx->prefixlen != 32) {
			vnc_zlog_debug_verbose(
				"%s: redist VN plen (%d) != 32, skipping",
				__func__, vn_pfx->prefixlen);
			return;
		}
		vnaddr.addr.v4 = vn_pfx->u.prefix4;
		break;

	case AF_INET6:
		if (vn_pfx->prefixlen != 128) {
			vnc_zlog_debug_verbose(
				"%s: redist VN plen (%d) != 128, skipping",
				__func__, vn_pfx->prefixlen);
			return;
		}
		vnaddr.addr.v6 = vn_pfx->u.prefix6;
		break;

	default:
		vnc_zlog_debug_verbose(
			"%s: no redist RFG VN host pfx configured, skipping",
			__func__);
		return;
	}


	memset(&prd, 0, sizeof(prd));
	if (rfapi_set_autord_from_vn(&prd, &vnaddr)) {
		vnc_zlog_debug_verbose("%s: can't auto-assign RD, skipping",
				       __func__);
		return;
	}

	vncHDBgpDirect.peer = info->peer;
	vnc_zlog_debug_verbose("%s: setting peer to %p", __func__,
			       vncHDBgpDirect.peer);
	del_vnc_route(&vncHDBgpDirect, info->peer, bgp, SAFI_MPLS_VPN, prefix,
		      &prd, ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE,
		      NULL, 1);

	vncHDBgpDirect.peer = NULL;
}

static void vnc_import_bgp_del_route_mode_nvegroup(struct bgp *bgp,
						   struct prefix *prefix,
						   struct bgp_info *info)
{
	struct prefix_rd prd;
	afi_t afi = family2afi(prefix->family);
	struct rfapi_nve_group_cfg *rfg = NULL;
	struct prefix *vn_pfx = NULL;
	struct rfapi_ip_addr vnaddr;


	assert(afi);

	rfg = bgp->rfapi_cfg->rfg_redist;
	assert(rfg);

	/*
	 * Compute VN address
	 */

	/*
	 * export nve group's VN addr prefix must be a /32 which
	 * will yield the VN addr to use
	 */
	vn_pfx = &rfg->vn_prefix;


	vnaddr.addr_family = vn_pfx->family;
	switch (vn_pfx->family) {
	case AF_INET:
		if (vn_pfx->prefixlen != 32) {
			vnc_zlog_debug_verbose(
				"%s: redist VN plen (%d) != 32, skipping",
				__func__, vn_pfx->prefixlen);
			return;
		}
		vnaddr.addr.v4 = vn_pfx->u.prefix4;
		break;

	case AF_INET6:
		if (vn_pfx->prefixlen != 128) {
			vnc_zlog_debug_verbose(
				"%s: redist VN plen (%d) != 128, skipping",
				__func__, vn_pfx->prefixlen);
			return;
		}
		vnaddr.addr.v6 = vn_pfx->u.prefix6;
		break;

	default:
		vnc_zlog_debug_verbose(
			"%s: no redist RFG VN host pfx configured, skipping",
			__func__);
		return;
	}

	memset(&prd, 0, sizeof(prd));
	prd = rfg->rd;
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	if (rfg->rd.family == AF_UNIX) {
		/* means "auto" with VN addr */
		if (rfapi_set_autord_from_vn(&prd, &vnaddr)) {
			vnc_zlog_debug_verbose(
				"%s: can't auto-assign RD, skipping", __func__);
			return;
		}
	}


	vncHDBgpDirect.peer = info->peer;
	vnc_zlog_debug_verbose("%s: setting peer to %p", __func__,
			       vncHDBgpDirect.peer);
	del_vnc_route(&vncHDBgpDirect, info->peer, bgp, SAFI_MPLS_VPN, prefix,
		      &prd, ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE,
		      NULL, 1);

	vncHDBgpDirect.peer = NULL;
}

static void vnc_import_bgp_del_route_mode_resolve_nve_one_bi(
	struct bgp *bgp, afi_t afi, struct bgp_info *bi, /* VPN bi */
	struct prefix_rd *prd,				 /* RD */
	struct prefix *prefix) /* unicast route prefix */
{
	struct prefix un;

	if (bi->type != ZEBRA_ROUTE_BGP && bi->type != ZEBRA_ROUTE_BGP_DIRECT) {

		return;
	}
	if (bi->sub_type != BGP_ROUTE_NORMAL && bi->sub_type != BGP_ROUTE_STATIC
	    && bi->sub_type != BGP_ROUTE_RFP) {

		return;
	}
	if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
		return;

	vncHDResolveNve.peer = bi->peer;
	if (!rfapiGetVncTunnelUnAddr(bi->attr, &un)) {
		if (rfapiQprefix2Raddr(&un, &vncHDResolveNve.un_addr))
			return;
	} else {
		memset(&vncHDResolveNve.un_addr, 0,
		       sizeof(vncHDResolveNve.un_addr));
	}

	del_vnc_route(&vncHDResolveNve, vncHDResolveNve.peer, bgp,
		      SAFI_MPLS_VPN, prefix, /* unicast route prefix */
		      prd, ZEBRA_ROUTE_BGP_DIRECT, BGP_ROUTE_REDISTRIBUTE, NULL,
		      0); /* flags */
}

static void vnc_import_bgp_del_route_mode_resolve_nve_one_rd(
	struct prefix_rd *prd,
	struct bgp_table *table_rd, /* per-rd VPN route table */
	afi_t afi, struct bgp *bgp, struct prefix *prefix, /* unicast prefix */
	struct prefix *ubi_nexthop) /* unicast bi's nexthop */
{
	struct bgp_node *bn;
	struct bgp_info *bi;

	if (!table_rd)
		return;

	{
		char str_nh[PREFIX_STRLEN];

		prefix2str(ubi_nexthop, str_nh, sizeof(str_nh));
		vnc_zlog_debug_verbose("%s: ubi_nexthop=%s", __func__, str_nh);
	}


	/* exact match */
	bn = bgp_node_lookup(table_rd, ubi_nexthop);
	if (!bn) {
		vnc_zlog_debug_verbose(
			"%s: no match in RD's table for ubi_nexthop", __func__);
		return;
	}

	/* Iterate over bgp_info items at this node */
	for (bi = bn->info; bi; bi = bi->next) {

		vnc_import_bgp_del_route_mode_resolve_nve_one_bi(
			bgp, afi, bi, /* VPN bi */
			prd,	  /* VPN RD */
			prefix);      /* unicast route prefix */
	}

	bgp_unlock_node(bn);
}

static void vnc_import_bgp_del_route_mode_resolve_nve(struct bgp *bgp,
						      afi_t afi,
						      struct prefix *prefix,
						      struct bgp_info *info)
{
	struct ecommunity *ecom = NULL;
	struct prefix pfx_unicast_nexthop = {0}; /* happy valgrind */

	// struct listnode           *hnode;
	// struct rfapi_descriptor   *rfd;
	struct prefix_bag *pb;
	void *cursor;
	struct skiplist *sl = bgp->rfapi->resolve_nve_nexthop;
	int rc;
	struct bgp_node *bnp; /* prd table node */

	if (!sl) {
		vnc_zlog_debug_verbose("%s: no RHN entries, skipping",
				       __func__);
		return;
	}

	if (info->type != ZEBRA_ROUTE_BGP) {
		vnc_zlog_debug_verbose(
			"%s: unicast type %d=\"%s\" is not %d=%s, skipping",
			__func__, info->type, zebra_route_string(info->type),
			ZEBRA_ROUTE_BGP, "ZEBRA_ROUTE_BGP");
		return;
	}

	if (process_unicast_route(bgp, afi, prefix, info, &ecom,
				  &pfx_unicast_nexthop)) {

		vnc_zlog_debug_verbose(
			"%s: process_unicast_route error, skipping", __func__);
		return;
	}

	rc = skiplist_first_value(sl, &pfx_unicast_nexthop, (void *)&pb,
				  &cursor);
	while (!rc) {
		if (pb->ubi == info) {
			skiplist_delete(sl, &pfx_unicast_nexthop, pb);
			bgp_info_unlock(info);
			break;
		}
		rc = skiplist_next_value(sl, &pfx_unicast_nexthop, (void *)&pb,
					 &cursor);
	}

	/*
	 * Iterate over RDs in VPN RIB. For each RD, look up unicast nexthop
	 * (exact match, /32). If an exact match is found, call add_vnc_route.
	 */

	for (bnp = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); bnp;
	     bnp = bgp_route_next(bnp)) {

		struct bgp_table *table;

		table = (struct bgp_table *)(bnp->info);

		if (!table)
			continue;

		vnc_import_bgp_del_route_mode_resolve_nve_one_rd(
			(struct prefix_rd *)&bnp->p, table, afi, bgp, prefix,
			&pfx_unicast_nexthop); /* TBD how is this set? */
	}

	if (ecom)
		ecommunity_free(&ecom);
}


/***********************************************************************
 *			Add/Delete CE->NVE routes
 ***********************************************************************/

/*
 * Should be called whan a bi is added to VPN RIB. This function
 * will check if it is a host route and return immediately if not.
 */
void vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	struct prefix *prefix,			/* VPN prefix */
	struct bgp_info *bi)			/* new VPN host route */
{
	afi_t afi = family2afi(prefix->family);
	struct skiplist *sl = NULL;
	int rc;
	struct prefix_bag *pb;
	void *cursor;
	struct rfapi_cfg *hc = NULL;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (afi != AFI_IP && afi != AFI_IP6) {
		vnc_zlog_debug_verbose("%s: bad afi %d, skipping", __func__,
				       afi);
		return;
	}

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!hc->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi);
		return;
	}

	if (hc->redist_mode != VNC_REDIST_MODE_RESOLVE_NVE) {
		vnc_zlog_debug_verbose("%s: not in resolve-nve mode, skipping",
				       __func__);
		return;
	}

	if (bgp->rfapi)
		sl = bgp->rfapi->resolve_nve_nexthop;

	if (!sl) {
		vnc_zlog_debug_verbose(
			"%s: no resolve_nve_nexthop skiplist, skipping",
			__func__);
		return;
	}

	if (!is_host_prefix(prefix)) {
		vnc_zlog_debug_verbose("%s: not host prefix, skipping",
				       __func__);
		return;
	}

	rc = skiplist_first_value(sl, prefix, (void *)&pb, &cursor);
	while (!rc) {
		struct ecommunity *ecom;
		struct prefix pfx_unicast_nexthop;
		uint32_t *med = NULL;
		uint32_t local_pref;

		memset(&pfx_unicast_nexthop, 0,
		       sizeof(struct prefix)); /* keep valgrind happy */

		if (VNC_DEBUG(IMPORT_BGP_ADD_ROUTE)) {
			char hbuf[PREFIX_STRLEN];
			char ubuf[PREFIX_STRLEN];

			prefix2str(&pb->hpfx, hbuf, sizeof(hbuf));
			prefix2str(&pb->upfx, ubuf, sizeof(ubuf));

			vnc_zlog_debug_any(
				"%s: examining RHN Entry (q=%p): upfx=%s, hpfx=%s, ubi=%p",
				__func__, cursor, ubuf, hbuf, pb->ubi);
		}

		if (process_unicast_route(bgp, afi, &pb->upfx, pb->ubi, &ecom,
					  &pfx_unicast_nexthop)) {

			vnc_zlog_debug_verbose(
				"%s: process_unicast_route error, skipping",
				__func__);
			continue;
		}
		local_pref = calc_local_pref(pb->ubi->attr, pb->ubi->peer);

		if (pb->ubi->attr
		    && (pb->ubi->attr->flag
			& ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC))) {

			med = &pb->ubi->attr->med;
		}

		/*
		 * Sanity check
		 */
		if (vnc_prefix_cmp(&pfx_unicast_nexthop, prefix)) {
			char str_unh[PREFIX_STRLEN];
			char str_nve_pfx[PREFIX_STRLEN];

			prefix2str(&pfx_unicast_nexthop, str_unh,
				   sizeof(str_unh));
			prefix2str(prefix, str_nve_pfx, sizeof(str_nve_pfx));

			vnc_zlog_debug_verbose(
				"%s: FATAL: resolve_nve_nexthop list item bi nexthop %s != nve pfx %s",
				__func__, str_unh, str_nve_pfx);
			assert(0);
		}

		vnc_import_bgp_add_route_mode_resolve_nve_one_bi(
			bgp, afi, bi,   /* VPN bi */
			prd, &pb->upfx, /* unicast prefix */
			&local_pref, med, ecom);

		if (ecom)
			ecommunity_free(&ecom);

#if DEBUG_RHN_LIST
		/* debug */
		{
			char pbuf[PREFIX_STRLEN];

			prefix2str(prefix, pbuf, sizeof(pbuf));

			vnc_zlog_debug_verbose(
				"%s: advancing past RHN Entry (q=%p): with prefix %s",
				__func__, cursor, pbuf);
			print_rhn_list(__func__, NULL); /* debug */
		}
#endif
		rc = skiplist_next_value(sl, prefix, (void *)&pb, &cursor);
	}
	vnc_zlog_debug_verbose("%s: done", __func__);
}


void vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	struct prefix *prefix,			/* VPN prefix */
	struct bgp_info *bi)			/* old VPN host route */
{
	afi_t afi = family2afi(prefix->family);
	struct skiplist *sl = NULL;
	struct prefix_bag *pb;
	void *cursor;
	struct rfapi_cfg *hc = NULL;
	int rc;

	{
		char str_pfx[PREFIX_STRLEN];

		prefix2str(prefix, str_pfx, sizeof(str_pfx));

		vnc_zlog_debug_verbose("%s(bgp=%p, nve prefix=%s)", __func__,
				       bgp, str_pfx);
	}

	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	if (!(hc = bgp->rfapi_cfg)) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!hc->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi);
		return;
	}

	if (hc->redist_mode != VNC_REDIST_MODE_RESOLVE_NVE) {
		vnc_zlog_debug_verbose("%s: not in resolve-nve mode, skipping",
				       __func__);
		return;
	}

	if (bgp->rfapi)
		sl = bgp->rfapi->resolve_nve_nexthop;

	if (!sl) {
		vnc_zlog_debug_verbose("%s: no RHN entries, skipping",
				       __func__);
		return;
	}

	if (!is_host_prefix(prefix)) {
		vnc_zlog_debug_verbose("%s: not host route, skip", __func__);
		return;
	}

	/*
	 * Find all entries with key == CE in the RHN list
	 */
	rc = skiplist_first_value(sl, prefix, (void *)&pb, &cursor);
	while (!rc) {

		struct ecommunity *ecom;
		struct prefix pfx_unicast_nexthop;

		memset(&pfx_unicast_nexthop, 0,
		       sizeof(struct prefix)); /* keep valgrind happy */

		if (process_unicast_route(bgp, afi, &pb->upfx, pb->ubi, &ecom,
					  &pfx_unicast_nexthop)) {

			vnc_zlog_debug_verbose(
				"%s: process_unicast_route error, skipping",
				__func__);
			continue;
		}

		/*
		 * Sanity check
		 */
		if (vnc_prefix_cmp(&pfx_unicast_nexthop, prefix)) {
			char str_unh[PREFIX_STRLEN];
			char str_nve_pfx[PREFIX_STRLEN];

			prefix2str(&pfx_unicast_nexthop, str_unh,
				   sizeof(str_unh));
			prefix2str(prefix, str_nve_pfx, sizeof(str_nve_pfx));

			vnc_zlog_debug_verbose(
				"%s: FATAL: resolve_nve_nexthop list item bi nexthop %s != nve pfx %s",
				__func__, str_unh, str_nve_pfx);
			assert(0);
		}

		vnc_import_bgp_del_route_mode_resolve_nve_one_bi(
			bgp, afi, bi, prd, &pb->upfx);

		if (ecom)
			ecommunity_free(&ecom);

		rc = skiplist_next_value(sl, prefix, (void *)&pb, &cursor);
	}
}


/***********************************************************************
 *			Exterior Routes
 ***********************************************************************/

#define DEBUG_IS_USABLE_INTERIOR 1

static int is_usable_interior_route(struct bgp_info *bi_interior)
{
	if (!VALID_INTERIOR_TYPE(bi_interior->type)) {
#if DEBUG_IS_USABLE_INTERIOR
		vnc_zlog_debug_verbose(
			"%s: NO: type %d is not valid interior type", __func__,
			bi_interior->type);
#endif
		return 0;
	}
	if (!CHECK_FLAG(bi_interior->flags, BGP_INFO_VALID)) {
#if DEBUG_IS_USABLE_INTERIOR
		vnc_zlog_debug_verbose("%s: NO: BGP_INFO_VALID not set",
				       __func__);
#endif
		return 0;
	}
	return 1;
}

/*
 * There should be only one of these per prefix at a time.
 * This should be called as a result of selection operation
 *
 * NB should be called espacially for bgp instances that are named,
 * because the exterior routes will always come from one of those.
 * We filter here on the instance name to make sure we get only the
 * right routes.
 */
static void vnc_import_bgp_exterior_add_route_it(
	struct bgp *bgp,		    /* exterior instance, we hope */
	struct prefix *prefix,		    /* unicast prefix */
	struct bgp_info *info,		    /* unicast info */
	struct rfapi_import_table *it_only) /* NULL, or limit to this IT */
{
	struct rfapi *h;
	struct rfapi_cfg *hc;
	struct prefix pfx_orig_nexthop;
	struct rfapi_import_table *it;
	struct bgp *bgp_default = bgp_get_default();
	afi_t afi = family2afi(prefix->family);

	if (!bgp_default)
		return;

	h = bgp_default->rfapi;
	hc = bgp_default->rfapi_cfg;

	vnc_zlog_debug_verbose("%s: entry with it=%p", __func__, it_only);

	if (!h || !hc) {
		vnc_zlog_debug_verbose(
			"%s: rfapi or rfapi_cfg not instantiated, skipping",
			__func__);
		return;
	}
	if (!hc->redist_bgp_exterior_view) {
		vnc_zlog_debug_verbose("%s: exterior view not set, skipping",
				       __func__);
		return;
	}
	if (bgp != hc->redist_bgp_exterior_view) {
		vnc_zlog_debug_verbose(
			"%s: bgp %p != hc->redist_bgp_exterior_view %p, skipping",
			__func__, bgp, hc->redist_bgp_exterior_view);
		return;
	}

	if (!hc->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: redist of exterior routes not enabled, skipping",
			__func__);
		return;
	}

	if (!info->attr) {
		vnc_zlog_debug_verbose("%s: no info, skipping", __func__);
		return;
	}

	/*
	 * Extract nexthop from exterior route
	 *
	 * Incoming prefix is unicast. If v6, it is in multiprotocol area,
	 * but if v4 it is in attr->nexthop
	 */
	rfapiUnicastNexthop2Prefix(afi, info->attr, &pfx_orig_nexthop);

	for (it = h->imports; it; it = it->next) {
		struct route_table *table;
		struct route_node *rn;
		struct route_node *par;
		struct bgp_info *bi_interior;
		int have_usable_route;

		vnc_zlog_debug_verbose("%s: doing it %p", __func__, it);

		if (it_only && (it_only != it)) {
			vnc_zlog_debug_verbose("%s: doesn't match it_only %p",
					       __func__, it_only);
			continue;
		}

		table = it->imported_vpn[afi];

		for (rn = route_node_match(table, &pfx_orig_nexthop),
		    have_usable_route = 0;
		     (!have_usable_route) && rn;) {

			vnc_zlog_debug_verbose("%s: it %p trying rn %p",
					       __func__, it, rn);

			for (bi_interior = rn->info; bi_interior;
			     bi_interior = bi_interior->next) {
				struct prefix_rd *prd;
				struct attr new_attr;
				uint32_t label = 0;

				if (!is_usable_interior_route(bi_interior))
					continue;

				vnc_zlog_debug_verbose(
					"%s: usable: bi_interior %p", __func__,
					bi_interior);

				/*
				 * have a legitimate route to exterior's nexthop
				 * via NVE.
				 *
				 * Import unicast route to the import table
				 */
				have_usable_route = 1;

				if (bi_interior->extra) {
					prd = &bi_interior->extra->vnc.import
						       .rd;
					label = decode_label(
						&bi_interior->extra->label[0]);
				} else
					prd = NULL;

				/* use local_pref from unicast route */
				memset(&new_attr, 0, sizeof(struct attr));
				bgp_attr_dup(&new_attr, bi_interior->attr);
				if (info->attr->flag
				    & ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF)) {
					new_attr.local_pref =
						info->attr->local_pref;
					new_attr.flag |= ATTR_FLAG_BIT(
						BGP_ATTR_LOCAL_PREF);
				}

				rfapiBgpInfoFilteredImportVPN(
					it, FIF_ACTION_UPDATE,
					bi_interior->peer, NULL, /* rfd */
					prefix, NULL, afi, prd, &new_attr,
					ZEBRA_ROUTE_BGP_DIRECT_EXT,
					BGP_ROUTE_REDISTRIBUTE, &label);
			}

			if (have_usable_route) {
				/*
				 * Make monitor
				 *
				 * TBD factor this out into its own function
				 */
				struct prefix *pfx_mon = prefix_new();
				if (!RFAPI_MONITOR_EXTERIOR(rn)->source) {
					RFAPI_MONITOR_EXTERIOR(rn)->source =
						skiplist_new(
							0, NULL,
							(void (*)(void *))
								prefix_free);
					route_lock_node(rn); /* for skiplist */
				}
				route_lock_node(rn); /* for skiplist entry */
				prefix_copy(pfx_mon, prefix);
				if (!skiplist_insert(
					    RFAPI_MONITOR_EXTERIOR(rn)->source,
					    info, pfx_mon)) {

					bgp_info_lock(info);
				}
			}
			par = rn->parent;
			if (par)
				route_lock_node(par);
			route_unlock_node(rn);
			rn = par;
		}
		if (rn)
			route_unlock_node(rn);

		if (!have_usable_route) {
			struct prefix *pfx_mon = prefix_new();
			prefix_copy(pfx_mon, prefix);
			if (!skiplist_insert(it->monitor_exterior_orphans, info,
					     pfx_mon)) {

				bgp_info_lock(info);
			}
		}
	}
}

void vnc_import_bgp_exterior_add_route(
	struct bgp *bgp,       /* exterior instance, we hope */
	struct prefix *prefix, /* unicast prefix */
	struct bgp_info *info) /* unicast info */
{
	vnc_import_bgp_exterior_add_route_it(bgp, prefix, info, NULL);
}

/*
 * There should be only one of these per prefix at a time.
 * This should probably be called as a result of selection operation.
 *
 * NB should be called espacially for bgp instances that are named,
 * because the exterior routes will always come from one of those.
 * We filter here on the instance name to make sure we get only the
 * right routes.
 */
void vnc_import_bgp_exterior_del_route(
	struct bgp *bgp, struct prefix *prefix, /* unicast prefix */
	struct bgp_info *info)			/* unicast info */
{
	struct rfapi *h;
	struct rfapi_cfg *hc;
	struct rfapi_import_table *it;
	struct prefix pfx_orig_nexthop;
	afi_t afi = family2afi(prefix->family);
	struct bgp *bgp_default = bgp_get_default();

	if (!bgp_default)
		return;

	memset(&pfx_orig_nexthop, 0,
	       sizeof(struct prefix)); /* keep valgrind happy */

	h = bgp_default->rfapi;
	hc = bgp_default->rfapi_cfg;

	if (!h || !hc) {
		vnc_zlog_debug_verbose(
			"%s: rfapi or rfapi_cfg not instantiated, skipping",
			__func__);
		return;
	}
	if (!hc->redist_bgp_exterior_view) {
		vnc_zlog_debug_verbose("%s: exterior view not set, skipping",
				       __func__);
		return;
	}
	if (bgp != hc->redist_bgp_exterior_view) {
		vnc_zlog_debug_verbose(
			"%s: bgp %p != hc->redist_bgp_exterior_view %p, skipping",
			__func__, bgp, hc->redist_bgp_exterior_view);
		return;
	}
	if (!hc->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: redist of exterior routes no enabled, skipping",
			__func__);
		return;
	}

	if (!info->attr) {
		vnc_zlog_debug_verbose("%s: no info, skipping", __func__);
		return;
	}

	/*
	 * Extract nexthop from exterior route
	 *
	 * Incoming prefix is unicast. If v6, it is in multiprotocol area,
	 * but if v4 it is in attr->nexthop
	 */
	rfapiUnicastNexthop2Prefix(afi, info->attr, &pfx_orig_nexthop);

	for (it = h->imports; it; it = it->next) {
		struct route_table *table;
		struct route_node *rn;
		struct route_node *par;
		struct bgp_info *bi_interior;
		int have_usable_route;

		table = it->imported_vpn[afi];

		for (rn = route_node_match(table, &pfx_orig_nexthop),
		    have_usable_route = 0;
		     (!have_usable_route) && rn;) {

			for (bi_interior = rn->info; bi_interior;
			     bi_interior = bi_interior->next) {
				struct prefix_rd *prd;
				uint32_t label = 0;

				if (!is_usable_interior_route(bi_interior))
					continue;

				/*
				 * have a legitimate route to exterior's nexthop
				 * via NVE.
				 *
				 * Import unicast route to the import table
				 */
				have_usable_route = 1;

				if (bi_interior->extra) {
					prd = &bi_interior->extra->vnc.import
						       .rd;
					label = decode_label(
						&bi_interior->extra->label[0]);
				} else
					prd = NULL;

				rfapiBgpInfoFilteredImportVPN(
					it, FIF_ACTION_KILL, bi_interior->peer,
					NULL, /* rfd */
					prefix, NULL, afi, prd,
					bi_interior->attr,
					ZEBRA_ROUTE_BGP_DIRECT_EXT,
					BGP_ROUTE_REDISTRIBUTE, &label);

				/*
				 * Delete monitor
				 *
				 * TBD factor this out into its own function
				 */
				{
					if (RFAPI_MONITOR_EXTERIOR(rn)
						    ->source) {
						if (!skiplist_delete(
							    RFAPI_MONITOR_EXTERIOR(
								    rn)
								    ->source,
							    info, NULL)) {

							bgp_info_unlock(info);
							route_unlock_node(
								rn); /* sl entry
									*/
						}
						if (skiplist_empty(
							    RFAPI_MONITOR_EXTERIOR(
								    rn)
								    ->source)) {
							skiplist_free(
								RFAPI_MONITOR_EXTERIOR(
									rn)
									->source);
							RFAPI_MONITOR_EXTERIOR(
								rn)
								->source = NULL;
							route_unlock_node(
								rn); /* skiplist
									itself
									*/
						}
					}
				}
			}
			par = rn->parent;
			if (par)
				route_lock_node(par);
			route_unlock_node(rn);
			rn = par;
		}
		if (rn)
			route_unlock_node(rn);

		if (!have_usable_route) {
			if (!skiplist_delete(it->monitor_exterior_orphans, info,
					     NULL)) {

				bgp_info_unlock(info);
			}
		}
	}
}

/*
 * This function should be called after a new interior VPN route
 * has been added to an import_table.
 *
 * NB should also be called whenever an existing vpn interior route
 * becomes valid (e.g., valid_interior_count is inremented)
 */
void vnc_import_bgp_exterior_add_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct route_node *rn_interior, /* VPN IT node */
	struct bgp_info *bi_interior)   /* VPN IT route */
{
	afi_t afi = family2afi(rn_interior->p.family);
	struct route_node *par;
	struct bgp_info *bi_exterior;
	struct prefix *pfx_exterior; /* exterior pfx */
	void *cursor;
	int rc;
	struct list *list_adopted;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (!is_usable_interior_route(bi_interior)) {
		vnc_zlog_debug_verbose(
			"%s: not usable interior route, skipping", __func__);
		return;
	}

	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: redist of exterior routes no enabled, skipping",
			__func__);
		return;
	}

	if (it == bgp->rfapi->it_ce) {
		vnc_zlog_debug_verbose("%s: import table is it_ce, skipping",
				       __func__);
		return;
	}

	/*debugging */
	{
		char str_pfx[PREFIX_STRLEN];

		prefix2str(&rn_interior->p, str_pfx, sizeof(str_pfx));
		vnc_zlog_debug_verbose("%s: interior prefix=%s, bi type=%d",
				       __func__, str_pfx, bi_interior->type);
	}

	if (RFAPI_HAS_MONITOR_EXTERIOR(rn_interior)) {

		int count = 0; /* debugging */

		vnc_zlog_debug_verbose(
			"%s: has exterior monitor; ext src: %p", __func__,
			RFAPI_MONITOR_EXTERIOR(rn_interior)->source);

		/*
		 * There is a monitor here already. Therefore, we do not need
		 * to do any pulldown. Just construct exterior routes based
		 * on the new interior route.
		 */
		cursor = NULL;
		for (rc = skiplist_next(
			     RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
			     (void **)&bi_exterior, (void **)&pfx_exterior,
			     &cursor);
		     !rc; rc = skiplist_next(
				  RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
				  (void **)&bi_exterior, (void **)&pfx_exterior,
				  &cursor)) {

			struct prefix_rd *prd;
			struct attr new_attr;
			uint32_t label = 0;


			++count; /* debugging */

			assert(bi_exterior);
			assert(pfx_exterior);

			if (bi_interior->extra) {
				prd = &bi_interior->extra->vnc.import.rd;
				label = decode_label(
					&bi_interior->extra->label[0]);
			} else
				prd = NULL;

			/* use local_pref from unicast route */
			memset(&new_attr, 0, sizeof(struct attr));
			bgp_attr_dup(&new_attr, bi_interior->attr);
			if (bi_exterior
			    && (bi_exterior->attr->flag
				& ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
				new_attr.local_pref =
					bi_exterior->attr->local_pref;
				new_attr.flag |=
					ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
			}

			rfapiBgpInfoFilteredImportVPN(
				it, FIF_ACTION_UPDATE, bi_interior->peer,
				NULL, /* rfd */
				pfx_exterior, NULL, afi, prd, &new_attr,
				ZEBRA_ROUTE_BGP_DIRECT_EXT,
				BGP_ROUTE_REDISTRIBUTE, &label);
		}
		vnc_zlog_debug_verbose(
			"%s: finished constructing exteriors based on existing monitors",
			__func__);
		return;
	}

	vnc_zlog_debug_verbose("%s: no exterior monitor", __func__);

	/*
	 * No monitor at this node. Is this the first valid interior
	 * route at this node?
	 */
	if (RFAPI_MONITOR_EXTERIOR(rn_interior)->valid_interior_count > 1) {
		vnc_zlog_debug_verbose(
			"%s: new interior route not first valid one, skipping pulldown",
			__func__);
		return;
	}

	/*
	 * Look up the tree for possible pulldown candidates.
	 * Find nearest parent with an exterior route monitor
	 */
	for (par = rn_interior->parent; par; par = par->parent) {
		if (RFAPI_HAS_MONITOR_EXTERIOR(par))
			break;
	}

	if (par) {

		vnc_zlog_debug_verbose(
			"%s: checking parent %p for possible pulldowns",
			__func__, par);

		/* check monitors at par for possible pulldown */
		cursor = NULL;
		for (rc = skiplist_next(RFAPI_MONITOR_EXTERIOR(par)->source,
					(void **)&bi_exterior,
					(void **)&pfx_exterior, &cursor);
		     !rc;
		     rc = skiplist_next(RFAPI_MONITOR_EXTERIOR(par)->source,
					(void **)&bi_exterior,
					(void **)&pfx_exterior, &cursor)) {

			struct prefix pfx_nexthop;

			memset(&pfx_nexthop, 0,
			       sizeof(struct prefix)); /* keep valgrind happy */

			/* check original nexthop for prefix match */
			rfapiUnicastNexthop2Prefix(afi, bi_exterior->attr,
						   &pfx_nexthop);

			if (prefix_match(&rn_interior->p, &pfx_nexthop)) {

				struct bgp_info *bi;
				struct prefix_rd *prd;
				struct attr new_attr;
				uint32_t label = 0;

				/* do pull-down */

				/*
				 * add monitor to longer prefix
				 */
				struct prefix *pfx_mon = prefix_new();
				prefix_copy(pfx_mon, pfx_exterior);
				if (!RFAPI_MONITOR_EXTERIOR(rn_interior)
					     ->source) {
					RFAPI_MONITOR_EXTERIOR(rn_interior)
						->source = skiplist_new(
						0, NULL,
						(void (*)(void *))prefix_free);
					route_lock_node(rn_interior);
				}
				skiplist_insert(
					RFAPI_MONITOR_EXTERIOR(rn_interior)
						->source,
					bi_exterior, pfx_mon);
				route_lock_node(rn_interior);

				/*
				 * Delete constructed exterior routes based on
				 * parent routes.
				 */
				for (bi = par->info; bi; bi = bi->next) {

					if (bi->extra) {
						prd = &bi->extra->vnc.import.rd;
						label = decode_label(
							&bi->extra->label[0]);
					} else
						prd = NULL;

					rfapiBgpInfoFilteredImportVPN(
						it, FIF_ACTION_KILL, bi->peer,
						NULL, /* rfd */
						pfx_exterior, NULL, afi, prd,
						bi->attr,
						ZEBRA_ROUTE_BGP_DIRECT_EXT,
						BGP_ROUTE_REDISTRIBUTE, &label);
				}


				/*
				 * Add constructed exterior routes based on
				 * the new interior route at longer prefix.
				 */
				if (bi_interior->extra) {
					prd = &bi_interior->extra->vnc.import
						       .rd;
					label = decode_label(
						&bi_interior->extra->label[0]);
				} else
					prd = NULL;

				/* use local_pref from unicast route */
				memset(&new_attr, 0, sizeof(struct attr));
				bgp_attr_dup(&new_attr, bi_interior->attr);
				if (bi_exterior
				    && (bi_exterior->attr->flag
					& ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
					new_attr.local_pref =
						bi_exterior->attr->local_pref;
					new_attr.flag |= ATTR_FLAG_BIT(
						BGP_ATTR_LOCAL_PREF);
				}

				rfapiBgpInfoFilteredImportVPN(
					it, FIF_ACTION_UPDATE,
					bi_interior->peer, NULL, /* rfd */
					pfx_exterior, NULL, afi, prd, &new_attr,
					ZEBRA_ROUTE_BGP_DIRECT_EXT,
					BGP_ROUTE_REDISTRIBUTE, &label);
			}
		}

		/*
		 * The only monitors at rn_interior are the ones we added just
		 * above, so we can use the rn_interior list to identify which
		 * monitors to delete from the parent.
		 */
		cursor = NULL;
		for (rc = skiplist_next(
			     RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
			     (void **)&bi_exterior, NULL, &cursor);
		     !rc; rc = skiplist_next(
				  RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
				  (void **)&bi_exterior, NULL, &cursor)) {


			skiplist_delete(RFAPI_MONITOR_EXTERIOR(par)->source,
					bi_exterior, NULL);
			route_unlock_node(par); /* sl entry */
		}
		if (skiplist_empty(RFAPI_MONITOR_EXTERIOR(par)->source)) {
			skiplist_free(RFAPI_MONITOR_EXTERIOR(par)->source);
			RFAPI_MONITOR_EXTERIOR(par)->source = NULL;
			route_unlock_node(par); /* sl itself */
		}
	}

	vnc_zlog_debug_verbose("%s: checking orphans", __func__);

	/*
	 * See if any orphans can be pulled down to the current node
	 */
	cursor = NULL;
	list_adopted = NULL;
	for (rc = skiplist_next(it->monitor_exterior_orphans,
				(void **)&bi_exterior, (void **)&pfx_exterior,
				&cursor);
	     !rc; rc = skiplist_next(it->monitor_exterior_orphans,
				     (void **)&bi_exterior,
				     (void **)&pfx_exterior, &cursor)) {

		struct prefix pfx_nexthop;
		char buf[PREFIX_STRLEN];
		afi_t afi_exterior = family2afi(pfx_exterior->family);

		prefix2str(pfx_exterior, buf, sizeof(buf));
		vnc_zlog_debug_verbose(
			"%s: checking exterior orphan at prefix %s", __func__,
			buf);

		if (afi_exterior != afi) {
			vnc_zlog_debug_verbose(
				"%s: exterior orphan afi %d != interior afi %d, skip",
				__func__, afi_exterior, afi);
			continue;
		}

		/* check original nexthop for prefix match */
		rfapiUnicastNexthop2Prefix(afi, bi_exterior->attr,
					   &pfx_nexthop);

		if (prefix_match(&rn_interior->p, &pfx_nexthop)) {

			struct prefix_rd *prd;
			struct attr new_attr;
			uint32_t label = 0;

			/* do pull-down */

			/*
			 * add monitor to longer prefix
			 */

			struct prefix *pfx_mon = prefix_new();
			prefix_copy(pfx_mon, pfx_exterior);
			if (!RFAPI_MONITOR_EXTERIOR(rn_interior)->source) {
				RFAPI_MONITOR_EXTERIOR(rn_interior)->source =
					skiplist_new(
						0, NULL,
						(void (*)(void *))prefix_free);
				route_lock_node(rn_interior); /* sl */
			}
			skiplist_insert(
				RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
				bi_exterior, pfx_mon);
			route_lock_node(rn_interior); /* sl entry */
			if (!list_adopted) {
				list_adopted = list_new();
			}
			listnode_add(list_adopted, bi_exterior);

			/*
			 * Add constructed exterior routes based on the
			 * new interior route at the longer prefix.
			 */
			if (bi_interior->extra) {
				prd = &bi_interior->extra->vnc.import.rd;
				label = decode_label(
					&bi_interior->extra->label[0]);
			} else
				prd = NULL;

			/* use local_pref from unicast route */
			memset(&new_attr, 0, sizeof(struct attr));
			bgp_attr_dup(&new_attr, bi_interior->attr);
			if (bi_exterior
			    && (bi_exterior->attr->flag
				& ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
				new_attr.local_pref =
					bi_exterior->attr->local_pref;
				new_attr.flag |=
					ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF);
			}

			rfapiBgpInfoFilteredImportVPN(
				it, FIF_ACTION_UPDATE, bi_interior->peer,
				NULL, /* rfd */
				pfx_exterior, NULL, afi, prd, &new_attr,
				ZEBRA_ROUTE_BGP_DIRECT_EXT,
				BGP_ROUTE_REDISTRIBUTE, &label);
		}
	}
	if (list_adopted) {
		struct listnode *node;
		struct route_node *bi_exterior;

		for (ALL_LIST_ELEMENTS_RO(list_adopted, node, bi_exterior)) {
			skiplist_delete(it->monitor_exterior_orphans,
					bi_exterior, NULL);
		}
		list_delete_and_null(&list_adopted);
	}
}

/*
 * This function should be called after an interior VPN route
 * has been deleted from an import_table.
 * bi_interior must still be valid, but it must already be detached
 * from its route node and the route node's valid_interior_count
 * must already be decremented.
 *
 * NB should also be called whenever an existing vpn interior route
 * becomes invalid (e.g., valid_interior_count is decremented)
 */
void vnc_import_bgp_exterior_del_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct route_node *rn_interior, /* VPN IT node */
	struct bgp_info *bi_interior)   /* VPN IT route */
{
	afi_t afi = family2afi(rn_interior->p.family);
	struct route_node *par;
	struct bgp_info *bi_exterior;
	struct prefix *pfx_exterior; /* exterior pfx */
	void *cursor;
	int rc;

	if (!VALID_INTERIOR_TYPE(bi_interior->type)) {
		vnc_zlog_debug_verbose(
			"%s: type %d not valid interior type, skipping",
			__func__, bi_interior->type);
		return;
	}

	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: redist of exterior routes no enabled, skipping",
			__func__);
		return;
	}

	if (it == bgp->rfapi->it_ce) {
		vnc_zlog_debug_verbose("%s: it is it_ce, skipping", __func__);
		return;
	}

	/* If no exterior routes depend on this prefix, nothing to do */
	if (!RFAPI_HAS_MONITOR_EXTERIOR(rn_interior)) {
		vnc_zlog_debug_verbose("%s: no exterior monitor, skipping",
				       __func__);
		return;
	}

	/*debugging */
	{
		char str_pfx[PREFIX_STRLEN];

		prefix2str(&rn_interior->p, str_pfx, sizeof(str_pfx));

		vnc_zlog_debug_verbose("%s: interior prefix=%s, bi type=%d",
				       __func__, str_pfx, bi_interior->type);
	}

	/*
	 * Remove constructed routes based on the deleted interior route
	 */
	cursor = NULL;
	for (rc = skiplist_next(RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
				(void **)&bi_exterior, (void **)&pfx_exterior,
				&cursor);
	     !rc;
	     rc = skiplist_next(RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
				(void **)&bi_exterior, (void **)&pfx_exterior,
				&cursor)) {

		struct prefix_rd *prd;
		uint32_t label = 0;

		if (bi_interior->extra) {
			prd = &bi_interior->extra->vnc.import.rd;
			label = decode_label(&bi_interior->extra->label[0]);
		} else
			prd = NULL;

		rfapiBgpInfoFilteredImportVPN(
			it, FIF_ACTION_KILL, bi_interior->peer, NULL, /* rfd */
			pfx_exterior, NULL, afi, prd, bi_interior->attr,
			ZEBRA_ROUTE_BGP_DIRECT_EXT, BGP_ROUTE_REDISTRIBUTE,
			&label);
	}

	/*
	 * If there are no remaining valid interior routes at this prefix,
	 * we need to look up the tree for a possible node to move monitors to
	 */
	if (RFAPI_MONITOR_EXTERIOR(rn_interior)->valid_interior_count) {
		vnc_zlog_debug_verbose(
			"%s: interior routes still present, skipping",
			__func__);
		return;
	}

	/*
	 * Find nearest parent with at least one valid interior route
	 * If none is found, par will end up NULL, and we will move
	 * the monitors to the orphan list for this import table
	 */
	for (par = rn_interior->parent; par; par = par->parent) {
		if (RFAPI_MONITOR_EXTERIOR(par)->valid_interior_count)
			break;
	}

	vnc_zlog_debug_verbose("%s: par=%p, ext src: %p", __func__, par,
			       RFAPI_MONITOR_EXTERIOR(rn_interior)->source);

	/* move all monitors */
	/*
	 * We will use and delete every element of the source skiplist
	 */
	while (!skiplist_first(RFAPI_MONITOR_EXTERIOR(rn_interior)->source,
			       (void **)&bi_exterior, (void **)&pfx_exterior)) {

		struct prefix *pfx_mon = prefix_new();

		prefix_copy(pfx_mon, pfx_exterior);

		if (par) {

			struct bgp_info *bi;

			/*
			 * Add monitor to parent node
			 */
			if (!RFAPI_MONITOR_EXTERIOR(par)->source) {
				RFAPI_MONITOR_EXTERIOR(par)->source =
					skiplist_new(
						0, NULL,
						(void (*)(void *))prefix_free);
				route_lock_node(par); /* sl */
			}
			skiplist_insert(RFAPI_MONITOR_EXTERIOR(par)->source,
					bi_exterior, pfx_mon);
			route_lock_node(par); /* sl entry */

			/* Add constructed exterior routes based on parent */
			for (bi = par->info; bi; bi = bi->next) {

				struct prefix_rd *prd;
				struct attr new_attr;
				uint32_t label = 0;

				if (bi->type == ZEBRA_ROUTE_BGP_DIRECT_EXT)
					continue;

				if (bi->extra) {
					prd = &bi->extra->vnc.import.rd;
					label = decode_label(
						&bi->extra->label[0]);
				} else
					prd = NULL;

				/* use local_pref from unicast route */
				memset(&new_attr, 0, sizeof(struct attr));
				bgp_attr_dup(&new_attr, bi->attr);
				if (bi_exterior
				    && (bi_exterior->attr->flag
					& ATTR_FLAG_BIT(BGP_ATTR_LOCAL_PREF))) {
					new_attr.local_pref =
						bi_exterior->attr->local_pref;
					new_attr.flag |= ATTR_FLAG_BIT(
						BGP_ATTR_LOCAL_PREF);
				}

				rfapiBgpInfoFilteredImportVPN(
					it, FIF_ACTION_UPDATE, bi->peer,
					NULL, /* rfd */
					pfx_exterior, NULL, afi, prd, &new_attr,
					ZEBRA_ROUTE_BGP_DIRECT_EXT,
					BGP_ROUTE_REDISTRIBUTE, &label);
			}

		} else {

			/*
			 * No interior route for exterior's nexthop. Save
			 * monitor
			 * in orphan list to await future route.
			 */
			skiplist_insert(it->monitor_exterior_orphans,
					bi_exterior, pfx_mon);
		}

		skiplist_delete_first(
			RFAPI_MONITOR_EXTERIOR(rn_interior)->source);
		route_unlock_node(rn_interior); /* sl entry */
	}
	if (skiplist_empty(RFAPI_MONITOR_EXTERIOR(rn_interior)->source)) {
		skiplist_free(RFAPI_MONITOR_EXTERIOR(rn_interior)->source);
		RFAPI_MONITOR_EXTERIOR(rn_interior)->source = NULL;
		route_unlock_node(rn_interior); /* sl itself */
	}
}

/***********************************************************************
 *			Generic add/delete unicast routes
 ***********************************************************************/

void vnc_import_bgp_add_route(struct bgp *bgp, struct prefix *prefix,
			      struct bgp_info *info)
{
	afi_t afi = family2afi(prefix->family);

	if (VNC_DEBUG(VERBOSE)) {
		struct prefix pfx_nexthop;
		char buf[PREFIX_STRLEN];
		char buf_nh[PREFIX_STRLEN];

		prefix2str(prefix, buf, sizeof(buf));
		rfapiUnicastNexthop2Prefix(afi, info->attr, &pfx_nexthop);
		prefix2str(&pfx_nexthop, buf_nh, sizeof(buf_nh));

		vnc_zlog_debug_verbose("%s: pfx %s, nh %s", __func__, buf,
				       buf_nh);
	}
#if DEBUG_RHN_LIST
	print_rhn_list(__func__, "ENTER ");
#endif
	VNC_RHNCK(enter);

	if (!afi) {
		zlog_err("%s: can't get afi of prefix", __func__);
		return;
	}

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check vnc redist flag for bgp direct routes */
	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp->rfapi_cfg->redist[afi=%d][type=%d=ZEBRA_ROUTE_BGP_DIRECT] is 0, skipping",
			__func__, afi, ZEBRA_ROUTE_BGP_DIRECT);
		return;
	}

	switch (bgp->rfapi_cfg->redist_mode) {
	case VNC_REDIST_MODE_PLAIN:
		vnc_import_bgp_add_route_mode_plain(bgp, prefix, info);
		break;

	case VNC_REDIST_MODE_RFG:
		if (bgp->rfapi_cfg->rfg_redist)
			vnc_import_bgp_add_route_mode_nvegroup(
				bgp, prefix, info, bgp->rfapi_cfg->rfg_redist);
		else
			vnc_zlog_debug_verbose("%s: mode RFG but no redist RFG",
					       __func__);
		break;

	case VNC_REDIST_MODE_RESOLVE_NVE:
		vnc_import_bgp_add_route_mode_resolve_nve(bgp, prefix, info);
		break;
	}
#if DEBUG_RHN_LIST
	print_rhn_list(__func__, "LEAVE ");
#endif
	VNC_RHNCK(leave);
}

/*
 * "Withdrawing a Route" import process
 */
void vnc_import_bgp_del_route(struct bgp *bgp, struct prefix *prefix,
			      struct bgp_info *info) /* unicast info */
{
	afi_t afi = family2afi(prefix->family);

	assert(afi);

	{
		struct prefix pfx_nexthop;
		char buf[PREFIX_STRLEN];
		char buf_nh[PREFIX_STRLEN];

		prefix2str(prefix, buf, sizeof(buf));
		rfapiUnicastNexthop2Prefix(afi, info->attr, &pfx_nexthop);
		prefix2str(&pfx_nexthop, buf_nh, sizeof(buf_nh));

		vnc_zlog_debug_verbose("%s: pfx %s, nh %s", __func__, buf,
				       buf_nh);
	}
#if DEBUG_RHN_LIST
	print_rhn_list(__func__, "ENTER ");
#endif
	VNC_RHNCK(enter);

	if (!bgp->rfapi_cfg) {
		vnc_zlog_debug_verbose("%s: bgp->rfapi_cfg is NULL, skipping",
				       __func__);
		return;
	}

	/* check bgp redist flag for vnc direct ("vpn") routes */
	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: bgp redistribution of afi=%d VNC direct routes is off",
			__func__, afi);
		return;
	}

	switch (bgp->rfapi_cfg->redist_mode) {
	case VNC_REDIST_MODE_PLAIN:
		vnc_import_bgp_del_route_mode_plain(bgp, prefix, info);
		break;

	case VNC_REDIST_MODE_RFG:
		if (bgp->rfapi_cfg->rfg_redist)
			vnc_import_bgp_del_route_mode_nvegroup(bgp, prefix,
							       info);
		else
			vnc_zlog_debug_verbose("%s: mode RFG but no redist RFG",
					       __func__);
		break;

	case VNC_REDIST_MODE_RESOLVE_NVE:
		vnc_import_bgp_del_route_mode_resolve_nve(bgp, afi, prefix,
							  info);
		break;
	}
#if DEBUG_RHN_LIST
	print_rhn_list(__func__, "LEAVE ");
#endif
	VNC_RHNCK(leave);
}


/***********************************************************************
 *			Enable/Disable
 ***********************************************************************/

void vnc_import_bgp_redist_enable(struct bgp *bgp, afi_t afi)
{
	/* iterate over bgp unicast v4 and v6 routes, call
	 * vnc_import_bgp_add_route */

	struct bgp_node *rn;

	vnc_zlog_debug_verbose("%s: entry, afi=%d", __func__, afi);

	if (bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: already enabled for afi %d, skipping", __func__,
			afi);
		return;
	}
	bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT] = 1;

	for (rn = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); rn;
	     rn = bgp_route_next(rn)) {

		struct bgp_info *bi;

		for (bi = rn->info; bi; bi = bi->next) {

			if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
				continue;

			vnc_import_bgp_add_route(bgp, &rn->p, bi);
		}
	}
	vnc_zlog_debug_verbose(
		"%s: set redist[afi=%d][type=%d=ZEBRA_ROUTE_BGP_DIRECT] return",
		__func__, afi, ZEBRA_ROUTE_BGP_DIRECT);
}

void vnc_import_bgp_exterior_redist_enable(struct bgp *bgp, afi_t afi)
{
	struct bgp *bgp_exterior;
	struct bgp_node *rn;

	bgp_exterior = bgp->rfapi_cfg->redist_bgp_exterior_view;

	if (bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: already enabled for afi %d, skipping", __func__,
			afi);
		return;
	}
	bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT] = 1;

	if (!bgp_exterior) {
		vnc_zlog_debug_verbose(
			"%s: no exterior view set yet, no routes to import yet",
			__func__);
		return;
	}

	for (rn = bgp_table_top(bgp_exterior->rib[afi][SAFI_UNICAST]); rn;
	     rn = bgp_route_next(rn)) {

		struct bgp_info *bi;

		for (bi = rn->info; bi; bi = bi->next) {

			if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
				continue;

			vnc_import_bgp_exterior_add_route(bgp_exterior, &rn->p,
							  bi);
		}
	}
	vnc_zlog_debug_verbose(
		"%s: set redist[afi=%d][type=%d=ZEBRA_ROUTE_BGP_DIRECT] return",
		__func__, afi, ZEBRA_ROUTE_BGP_DIRECT);
}

/*
 * This function is for populating a newly-created Import Table
 */
void vnc_import_bgp_exterior_redist_enable_it(
	struct bgp *bgp, afi_t afi, struct rfapi_import_table *it_only)
{
	struct bgp *bgp_exterior;
	struct bgp_node *rn;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	bgp_exterior = bgp->rfapi_cfg->redist_bgp_exterior_view;

	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose("%s: not enabled for afi %d, skipping",
				       __func__, afi);
		return;
	}

	if (!bgp_exterior) {
		vnc_zlog_debug_verbose(
			"%s: no exterior view set yet, no routes to import yet",
			__func__);
		return;
	}

	for (rn = bgp_table_top(bgp_exterior->rib[afi][SAFI_UNICAST]); rn;
	     rn = bgp_route_next(rn)) {

		struct bgp_info *bi;

		for (bi = rn->info; bi; bi = bi->next) {

			if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
				continue;

			vnc_import_bgp_exterior_add_route_it(
				bgp_exterior, &rn->p, bi, it_only);
		}
	}
}


void vnc_import_bgp_redist_disable(struct bgp *bgp, afi_t afi)
{
	/*
	 * iterate over vpn routes, find routes of type ZEBRA_ROUTE_BGP_DIRECT,
	 * delete (call timer expire immediately)
	 */
	struct bgp_node *rn1;
	struct bgp_node *rn2;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (!bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT]) {
		vnc_zlog_debug_verbose(
			"%s: already disabled for afi %d, skipping", __func__,
			afi);
		return;
	}

	/*
	 * Two-level table for SAFI_MPLS_VPN
	 * Be careful when changing the things we iterate over
	 */
	for (rn1 = bgp_table_top(bgp->rib[afi][SAFI_MPLS_VPN]); rn1;
	     rn1 = bgp_route_next(rn1)) {

		if (rn1->info) {
			for (rn2 = bgp_table_top(rn1->info); rn2;
			     rn2 = bgp_route_next(rn2)) {

				struct bgp_info *bi;
				struct bgp_info *nextbi;

				for (bi = rn2->info; bi; bi = nextbi) {

					nextbi = bi->next;

					if (bi->type
					    == ZEBRA_ROUTE_BGP_DIRECT) {

						struct rfapi_descriptor *rfd;
						vncHDBgpDirect.peer = bi->peer;

						assert(bi->extra);

						rfd = bi->extra->vnc.export
							      .rfapi_handle;

						vnc_zlog_debug_verbose(
							"%s: deleting bi=%p, bi->peer=%p, bi->type=%d, bi->sub_type=%d, bi->extra->vnc.export.rfapi_handle=%p [passing rfd=%p]",
							__func__, bi, bi->peer,
							bi->type, bi->sub_type,
							(bi->extra
								 ? bi->extra
									   ->vnc
									   .export
									   .rfapi_handle
								 : NULL),
							rfd);


						del_vnc_route(
							rfd, bi->peer, bgp,
							SAFI_MPLS_VPN, &rn2->p,
							(struct prefix_rd *)&rn1
								->p,
							bi->type, bi->sub_type,
							NULL, 1); /* kill */

						vncHDBgpDirect.peer = NULL;
					}
				}
			}
		}
	}
	/* Clear RHN list */
	if (bgp->rfapi->resolve_nve_nexthop) {
		struct prefix_bag *pb;
		struct bgp_info *info;
		while (!skiplist_first(bgp->rfapi->resolve_nve_nexthop, NULL,
				       (void *)&pb)) {
			info = pb->ubi;
			skiplist_delete_first(bgp->rfapi->resolve_nve_nexthop);
			bgp_info_unlock(info);
		}
	}

	bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT] = 0;
	vnc_zlog_debug_verbose("%s: return", __func__);
}


void vnc_import_bgp_exterior_redist_disable(struct bgp *bgp, afi_t afi)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;
	struct bgp *bgp_exterior = hc->redist_bgp_exterior_view;

	vnc_zlog_debug_verbose("%s: entry", __func__);

	if (!hc->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
		vnc_zlog_debug_verbose(
			"%s: already disabled for afi %d, skipping", __func__,
			afi);
		return;
	}

	if (!bgp_exterior) {
		vnc_zlog_debug_verbose(
			"%s: bgp exterior view not defined, skipping",
			__func__);
		return;
	}


	{
		struct bgp_node *rn;
		for (rn = bgp_table_top(bgp_exterior->rib[afi][SAFI_UNICAST]);
		     rn; rn = bgp_route_next(rn)) {

			struct bgp_info *bi;

			for (bi = rn->info; bi; bi = bi->next) {

				if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
					continue;

				vnc_import_bgp_exterior_del_route(bgp_exterior,
								  &rn->p, bi);
			}
		}
#if DEBUG_RHN_LIST
		print_rhn_list(__func__, NULL);
#endif
	}

	bgp->rfapi_cfg->redist[afi][ZEBRA_ROUTE_BGP_DIRECT_EXT] = 0;
	vnc_zlog_debug_verbose("%s: return", __func__);
}
