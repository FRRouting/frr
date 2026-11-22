// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP VNC/RFAPI northbound callbacks
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#if ENABLE_BGP_VNC

#include "northbound.h"
#include "libfrr.h"
#include "prefix.h"
#include "filter.h"
#include "routemap.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_vnc_nb.h"
#include "bgpd/rfapi/bgp_rfapi_cfg.h"
#include "bgpd/rfapi/rfapi.h"
#include "bgpd/rfapi/rfapi_private.h"
#include "bgpd/rfapi/rfapi_import.h"
#include "bgpd/rfapi/vnc_import_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp.h"
#include "bgpd/rfapi/vnc_export_bgp_p.h"
#include "bgpd/rfapi/vnc_zebra.h"
#include "lib/agg_table.h"

/*
 * ===================================================================
 * VNC (Virtual Network Control / RFAPI) NB callbacks
 * ===================================================================
 */

/*
 * Helper: walk parents until a BGP running entry is found.
 * VNC nodes live under .../frr-bgp:bgp/frr-bgp-vnc:vnc/...
 */
struct bgp *bgp_nb_vnc_get_bgp(const struct lyd_node *dnode)
{
	const struct lyd_node *cur;

	/*
	 * VNC nodes hang under .../frr-bgp:bgp/frr-bgp-vnc:vnc/...
	 * Do not use yang_dnode_get_parent(dnode, "bgp"): VNC itself has
	 * nested containers named "bgp" (e.g. export/bgp), and the nearest
	 * match is wrong. Walk for the frr-bgp module's bgp container.
	 *
	 * Also avoid recursive nb_running_get_entry(): nve-group /
	 * vrf-policy list entries have running pointers that would be
	 * returned cast as struct bgp *.
	 */
	for (cur = dnode; cur; cur = lyd_parent(cur)) {
		if (cur->schema->nodetype != LYS_CONTAINER && cur->schema->nodetype != LYS_LIST)
			continue;
		if (!strmatch(cur->schema->name, "bgp"))
			continue;
		if (!cur->schema->module || !strmatch(cur->schema->module->name, "frr-bgp"))
			continue;
		return nb_running_get_entry_non_rec(cur, NULL, false);
	}
	return NULL;
}

static int vnc_nb_parse_l2rd(const char *val, uint8_t *out);

/*
 * Helper: parse the NN of an auto:vn:NN or auto:nh:NN RD. NN is a 2-octet
 * quantity; like the classic CLI, reject an empty value, trailing garbage
 * and anything above 0xffff.
 */
static int vnc_nb_parse_auto_rd(const char *nn_str, uint16_t *nn)
{
	char *end = NULL;
	unsigned long value;

	if (!isdigit((unsigned char)*nn_str))
		return -1;

	errno = 0;
	value = strtoul(nn_str, &end, 10);
	if (errno || *end || value > 0xffff)
		return -1;

	*nn = value;
	return 0;
}

/*
 * Helper: parse RD string including auto:vn:NN and auto:nh:NN formats.
 */
int vnc_nb_parse_rd(const char *rd_str, struct prefix_rd *prd, bool is_vrf_policy)
{
	uint16_t nn;

	memset(prd, 0, sizeof(*prd));

	if ((is_vrf_policy && !strncmp(rd_str, "auto:nh:", 8)) ||
	    (!is_vrf_policy && !strncmp(rd_str, "auto:vn:", 8))) {
		if (vnc_nb_parse_auto_rd(rd_str + 8, &nn))
			return -1;

		prd->family = AF_UNIX;
		prd->prefixlen = 64;
		prd->val[0] = (RD_TYPE_IP >> 8) & 0x0ff;
		prd->val[1] = RD_TYPE_IP & 0x0ff;
		prd->val[6] = (nn >> 8) & 0x0ff;
		prd->val[7] = nn & 0x0ff;
		return 0;
	}

	if (str2prefix_rd(rd_str, prd))
		return 0;

	return -1;
}

static int vnc_nb_rd_validate(const struct lyd_node *dnode, bool is_vrf_policy, char *errmsg,
			      size_t errmsg_len)
{
	struct prefix_rd prd;

	if (vnc_nb_parse_rd(yang_dnode_get_string(dnode, NULL), &prd, is_vrf_policy)) {
		snprintfrr(errmsg, errmsg_len, "Malformed rd");
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static int vnc_nb_validate_default_bgp(const struct lyd_node *dnode, char *errmsg,
				       size_t errmsg_len)
{
	const struct lyd_node *cur, *cpp;
	struct bgp *bgp;

	for (cur = dnode; cur; cur = lyd_parent(cur)) {
		if (cur->schema->nodetype != LYS_CONTAINER &&
		    cur->schema->nodetype != LYS_LIST)
			continue;
		if (!strmatch(cur->schema->name, "bgp"))
			continue;
		if (!cur->schema->module || !strmatch(cur->schema->module->name, "frr-bgp"))
			continue;

		if (yang_dnode_exists(cur, "./global/instance-type-view") &&
		    yang_dnode_get_bool(cur, "./global/instance-type-view")) {
			snprintfrr(errmsg, errmsg_len,
				   "VNC operations only permitted on default BGP instance.");
			return NB_ERR_VALIDATION;
		}
		cpp = yang_dnode_get_parent(cur, "control-plane-protocol");
		if (cpp && yang_dnode_exists(cpp, "./vrf") &&
		    !strmatch(yang_dnode_get_string(cpp, "./vrf"), VRF_DEFAULT_NAME)) {
			snprintfrr(errmsg, errmsg_len,
				   "VNC operations only permitted on default BGP instance.");
			return NB_ERR_VALIDATION;
		}
		bgp = nb_running_get_entry_non_rec(cur, NULL, false);
		if (bgp && (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT || !bgp->rfapi_cfg)) {
			snprintfrr(errmsg, errmsg_len,
				   "VNC operations only permitted on default BGP instance.");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	snprintfrr(errmsg, errmsg_len,
		   "VNC operations only permitted on default BGP instance.");
	return NB_ERR_VALIDATION;
}

int bgp_global_vnc_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	return NB_OK;
}

static void vnc_nb_sync_rfp_cfg(struct bgp *bgp)
{
	if (!bgp || !bgp->rfapi || !bgp->rfapi_cfg)
		return;
	if (bgp->rfapi->rfp_cfg_orig)
		*bgp->rfapi->rfp_cfg_orig = bgp->rfapi_cfg->rfp_cfg;
	if (bgp->rfapi->rfp)
		rfapi_rfp_set_configuration(bgp->rfapi->rfp, &bgp->rfapi_cfg->rfp_cfg);
}

int bgp_global_vnc_rfp_holddown_factor_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;

	bgp->rfapi_cfg->rfp_cfg.holddown_factor = yang_dnode_get_uint32(args->dnode, NULL);
	vnc_nb_sync_rfp_cfg(bgp);
	return NB_OK;
}

int bgp_global_vnc_rfp_full_table_download_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *mode;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;

	mode = yang_dnode_get_string(args->dnode, NULL);
	bgp->rfapi_cfg->rfp_cfg.download_type = !strcmp(mode, "on") ? RFAPI_RFP_DOWNLOAD_FULL
								    : RFAPI_RFP_DOWNLOAD_PARTIAL;
	vnc_nb_sync_rfp_cfg(bgp);
	return NB_OK;
}

int bgp_global_vnc_defaults_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	return NB_OK;
}

int bgp_global_vnc_defaults_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int bgp_global_vnc_defaults_rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct prefix_rd prd;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_rd_validate(args->dnode, false, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	if (vnc_nb_parse_rd(yang_dnode_get_string(args->dnode, NULL), &prd, false))
		return NB_ERR_INCONSISTENCY;

	bgp->rfapi_cfg->default_rd = prd;
	return NB_OK;
}

int bgp_global_vnc_defaults_response_lifetime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;
	uint32_t rspint;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	val = yang_dnode_get_string(args->dnode, NULL);
	if (!strcmp(val, "infinite")) {
		rspint = RFAPI_INFINITE_LIFETIME;
	} else {
		unsigned long parsed = strtoul(val, NULL, 10);

		if (parsed > INT32_MAX)
			parsed = INT32_MAX;
		rspint = (uint32_t)parsed;
	}

	bgp->rfapi_cfg->default_response_lifetime = rspint;

	if (bgp->rfapi) {
		struct listnode *hdnode;
		struct rfapi_descriptor *rfd;

		for (ALL_LIST_ELEMENTS_RO(&bgp->rfapi->descriptors, hdnode, rfd))
			if (rfd->rfg && !(rfd->rfg->flags & RFAPI_RFG_RESPONSE_LIFETIME))
				rfd->response_lifetime = rfd->rfg->response_lifetime = rspint;
	}
	return NB_OK;
}

int bgp_global_vnc_defaults_rt_import_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL),
				&bgp->rfapi_cfg->default_rt_import_list);
	return NB_OK;
}

int bgp_global_vnc_defaults_rt_export_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL),
				&bgp->rfapi_cfg->default_rt_export_list);
	return NB_OK;
}

int bgp_global_vnc_nve_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct rfapi_nve_group_cfg *rfg;
	const char *name;
	const struct lyd_node *defaults;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_NVE);
	if (!rfg) {
		rfg = rfapi_group_new(bgp, RFAPI_GROUP_CFG_NVE, name);

		/*
		 * Read defaults from YANG dnode (not C struct) to handle
		 * NB commit ordering: CREATEs fire before MODIFYs, so the
		 * C struct defaults may not be set yet. The YANG dnode tree
		 * already has the final committed state.
		 */
		defaults = yang_dnode_get(args->dnode, "../defaults");
		if (defaults) {
			if (yang_dnode_exists(defaults, "rd")) {
				vnc_nb_parse_rd(yang_dnode_get_string(defaults, "rd"), &rfg->rd,
						false);
			}
			if (yang_dnode_exists(defaults, "response-lifetime")) {
				const char *val = yang_dnode_get_string(defaults,
									"response-lifetime");
				if (!strcmp(val, "infinite"))
					rfg->response_lifetime = RFAPI_INFINITE_LIFETIME;
				else
					rfg->response_lifetime = strtoul(val, NULL, 10);
			} else {
				rfg->response_lifetime = BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT;
			}
			if (yang_dnode_exists(defaults, "rt-export")) {
				rfapi_set_ecom_from_str(yang_dnode_get_string(defaults,
									      "rt-export"),
							&rfg->rt_export_list);
			}
			if (yang_dnode_exists(defaults, "rt-import")) {
				rfapi_set_ecom_from_str(yang_dnode_get_string(defaults,
									      "rt-import"),
							&rfg->rt_import_list);
				if (rfg->rt_import_list)
					rfg->rfapi_import_table =
						rfapiImportTableRefAdd(bgp, rfg->rt_import_list,
								       rfg);
			}
			if (yang_dnode_exists(defaults, "l2rd")) {
				uint8_t l2rd_val = 0;

				if (!vnc_nb_parse_l2rd(yang_dnode_get_string(defaults, "l2rd"),
						       &l2rd_val)) {
					rfg->l2rd = l2rd_val;
					rfg->flags |= RFAPI_RFG_L2RD;
				}
			}
		} else {
			rfg->response_lifetime = BGP_VNC_DEFAULT_RESPONSE_LIFETIME_DEFAULT;
		}

		/* Link to redist group if name matches (baseline side effect) */
		if (!bgp->rfapi_cfg->rfg_redist && bgp->rfapi_cfg->rfg_redist_name &&
		    !strcmp(bgp->rfapi_cfg->rfg_redist_name, rfg->name)) {
			vnc_redistribute_prechange(bgp);
			bgp->rfapi_cfg->rfg_redist = rfg;
			vnc_redistribute_postchange(bgp);
		}

		/*
		 * Export-group name entries are created before the NVE group
		 * exists. Attach the backpointer the way bgp_rfapi_cfg_group_new()
		 * does, or vnc export never sees this group.
		 */
		if (bgp->rfapi_cfg->rfg_export_direct_bgp_l) {
			struct listnode *node, *nnode;
			struct rfapi_rfg_name *rfgn;

			for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node,
					       nnode, rfgn)) {
				if (strcmp(rfgn->name, rfg->name))
					continue;
				rfgn->rfg = rfg;
				vnc_direct_bgp_add_group(bgp, rfg);
				break;
			}
		}
		if (bgp->rfapi_cfg->rfg_export_zebra_l) {
			struct listnode *node, *nnode;
			struct rfapi_rfg_name *rfgn;

			for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_zebra_l, node, nnode,
					       rfgn)) {
				if (strcmp(rfgn->name, rfg->name))
					continue;
				rfgn->rfg = rfg;
				vnc_zebra_add_group(bgp, rfg);
				break;
			}
		}
	}

	nb_running_set_entry(args->dnode, rfg);
	return NB_OK;
}

int bgp_global_vnc_nve_group_destroy(struct nb_cb_destroy_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;
	char *name = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	rfg = nb_running_unset_entry(args->dnode);
	if (!bgp || !bgp->rfapi_cfg || !rfg)
		return NB_OK;

	if (rfg->name)
		name = XSTRDUP(MTYPE_TMP, rfg->name);
	bgp_rfapi_delete_named_nve_group(NULL, bgp, name, RFAPI_GROUP_CFG_NVE);
	XFREE(MTYPE_TMP, name);
	return NB_OK;
}

/*
 * Another group in this candidate already owns the prefix. Two creates in
 * one commit are not in the agg table yet, so the live tree is not enough.
 * A prefix still installed for a different group is rejected the same way
 * the classic "prefix vn|un" handler rejects rn->info.
 */
static int bgp_vnc_nve_prefix_validate(const struct lyd_node *group, const struct prefix *p,
				       bool un, char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *parent, *sib;
	const char *leaf = un ? "prefix-un" : "prefix-vn";
	const char *which = un ? "un" : "vn";
	struct bgp *bgp;
	struct rfapi_nve_group_cfg *rfg;
	afi_t afi;
	struct agg_table *rt;
	struct agg_node *an;

	parent = lyd_parent(group);
	if (parent) {
		LY_LIST_FOR (lyd_child(parent), sib) {
			struct prefix op;

			if (sib == group || !strmatch(sib->schema->name, "nve-group"))
				continue;
			if (!yang_dnode_exists(sib, leaf))
				continue;
			if (!str2prefix(yang_dnode_get_string(sib, "%s", leaf), &op) ||
			    !prefix_same(&op, p))
				continue;
			snprintfrr(errmsg, errmsg_len,
				   "nve group \"%s\" already has \"%s\" prefix %pFX",
				   yang_dnode_get_string(sib, "name"), which, p);
			return NB_ERR_VALIDATION;
		}
	}

	bgp = bgp_nb_vnc_get_bgp(group);
	rfg = nb_running_get_entry(group, NULL, false);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;

	afi = family2afi(p->family);
	if (!afi)
		return NB_OK;
	rt = un ? bgp->rfapi_cfg->nve_groups_un[afi] : bgp->rfapi_cfg->nve_groups_vn[afi];
	if (!rt)
		return NB_OK;

	an = agg_node_lookup(rt, p);
	if (!an)
		return NB_OK;
	if (an->info && an->info != rfg) {
		snprintfrr(errmsg, errmsg_len, "nve group \"%s\" already has \"%s\" prefix %pFX",
			   ((struct rfapi_nve_group_cfg *)an->info)->name, which, p);
		agg_unlock_node(an);
		return NB_ERR_VALIDATION;
	}
	agg_unlock_node(an);
	return NB_OK;
}

static int bgp_vnc_nve_prefix_apply(const struct lyd_node *dnode, bool un)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;
	struct prefix p;
	afi_t afi;
	struct agg_table *rt;
	struct agg_node *rn;
	struct agg_node **backref;

	rfg = nb_running_get_entry(lyd_parent(dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	if (!str2prefix(yang_dnode_get_string(dnode, NULL), &p))
		return NB_ERR_INCONSISTENCY;

	afi = family2afi(p.family);
	if (!afi)
		return NB_ERR_INCONSISTENCY;
	rt = un ? bgp->rfapi_cfg->nve_groups_un[afi] : bgp->rfapi_cfg->nve_groups_vn[afi];
	if (!rt)
		return NB_ERR_INCONSISTENCY;

	rn = agg_node_get(rt, &p);
	if (rn->info) {
		agg_unlock_node(rn);
		if (rn->info != rfg)
			return NB_ERR_INCONSISTENCY;
		return NB_OK;
	}

	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);

	/*
	 * Drop the old node before unlocking it. A node with children stays
	 * in the tree, and a later group delete would free this group while
	 * the old node still pointed at it.
	 */
	backref = un ? &rfg->un_node : &rfg->vn_node;
	if (*backref) {
		(*backref)->info = NULL;
		agg_unlock_node(*backref);
		*backref = NULL;
	}
	*backref = rn;
	if (un)
		rfg->un_prefix = p;
	else
		rfg->vn_prefix = p;
	rn->info = rfg;

	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_nve_group_prefix_vn_modify(struct nb_cb_modify_args *args)
{
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!str2prefix(yang_dnode_get_string(args->dnode, NULL), &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed prefix");
			return NB_ERR_VALIDATION;
		}
		if (!family2afi(p.family)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Unsupported address family");
			return NB_ERR_VALIDATION;
		}
		return bgp_vnc_nve_prefix_validate(lyd_parent(args->dnode), &p, false,
						   args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_vnc_nve_prefix_apply(args->dnode, false);
	}
	return NB_OK;
}

int bgp_global_vnc_nve_group_prefix_un_modify(struct nb_cb_modify_args *args)
{
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!str2prefix(yang_dnode_get_string(args->dnode, NULL), &p)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Malformed prefix");
			return NB_ERR_VALIDATION;
		}
		if (!family2afi(p.family)) {
			snprintfrr(args->errmsg, args->errmsg_len, "Unsupported address family");
			return NB_ERR_VALIDATION;
		}
		return bgp_vnc_nve_prefix_validate(lyd_parent(args->dnode), &p, true, args->errmsg,
						   args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		return bgp_vnc_nve_prefix_apply(args->dnode, true);
	}
	return NB_OK;
}

static void vnc_nb_rfg_rt_import_apply(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg,
				       const char *rt_str)
{
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;
	int is_export_bgp = 0;
	int is_export_zebra = 0;

	if (bgp->rfapi_cfg->rfg_export_direct_bgp_l) {
		for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node, rfgn)) {
			if (rfgn->rfg == rfg) {
				is_export_bgp = 1;
				break;
			}
		}
	}
	if (bgp->rfapi_cfg->rfg_export_zebra_l) {
		for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node, rfgn)) {
			if (rfgn->rfg == rfg) {
				is_export_zebra = 1;
				break;
			}
		}
	}

	if (is_export_bgp)
		vnc_direct_bgp_del_group(bgp, rfg);
	if (is_export_zebra)
		vnc_zebra_del_group(bgp, rfg);

	if (rfg->rfapi_import_table)
		rfapiImportTableRefDelByIt(bgp, rfg->rfapi_import_table);
	rfapi_set_ecom_from_str(rt_str, &rfg->rt_import_list);
	rfg->rfapi_import_table = rfg->rt_import_list
					  ? rfapiImportTableRefAdd(bgp, rfg->rt_import_list, rfg)
					  : NULL;

	if (rfg->type == RFAPI_GROUP_CFG_VRF && !rfg->rfd && rfg->rfapi_import_table &&
	    (is_export_bgp || is_export_zebra))
		vnc_add_vrf_opener(bgp, rfg);

	if (is_export_bgp)
		vnc_direct_bgp_add_group(bgp, rfg);
	if (is_export_zebra)
		vnc_zebra_add_group(bgp, rfg);
}

int bgp_global_vnc_nve_group_rd_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_rd_validate(args->dnode, false, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	vnc_nb_parse_rd(yang_dnode_get_string(args->dnode, NULL), &rfg->rd, false);
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_nve_group_response_lifetime_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	const char *val;
	uint32_t rspint;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;
	val = yang_dnode_get_string(args->dnode, NULL);

	if (!strcmp(val, "infinite")) {
		rspint = RFAPI_INFINITE_LIFETIME;
	} else {
		unsigned long parsed = strtoul(val, NULL, 10);

		if (parsed > INT32_MAX)
			parsed = INT32_MAX;
		rspint = (uint32_t)parsed;
	}
	rfg->response_lifetime = rspint;
	SET_FLAG(rfg->flags, RFAPI_RFG_RESPONSE_LIFETIME);
	if (rfg->nves) {
		struct listnode *hdnode;
		struct rfapi_descriptor *rfd;

		for (ALL_LIST_ELEMENTS_RO(rfg->nves, hdnode, rfd))
			rfd->response_lifetime = rspint;
	}
	return NB_OK;
}

int bgp_global_vnc_nve_group_rt_import_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	vnc_nb_rfg_rt_import_apply(bgp, rfg, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_vnc_nve_group_rt_export_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL), &rfg->rt_export_list);
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct rfapi_nve_group_cfg *rfg;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;
	name = yang_dnode_get_string(args->dnode, "name");
	rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_VRF);
	if (!rfg)
		rfg = rfapi_group_new(bgp, RFAPI_GROUP_CFG_VRF, name);
	nb_running_set_entry(args->dnode, rfg);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;
	char *name = NULL;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	rfg = nb_running_unset_entry(args->dnode);
	if (!bgp || !bgp->rfapi_cfg || !rfg)
		return NB_OK;

	if (rfg->name)
		name = XSTRDUP(MTYPE_TMP, rfg->name);
	bgp_rfapi_delete_named_nve_group(NULL, bgp, name, RFAPI_GROUP_CFG_VRF);
	XFREE(MTYPE_TMP, name);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_label_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	rfg->label = yang_dnode_get_uint32(args->dnode, NULL);
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_label_destroy(struct nb_cb_destroy_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	rfg->label = MPLS_LABEL_NONE;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_rd_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_rd_validate(args->dnode, true, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	vnc_nb_parse_rd(yang_dnode_get_string(args->dnode, NULL), &rfg->rd, true);
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_rt_import_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	vnc_nb_rfg_rt_import_apply(bgp, rfg, yang_dnode_get_string(args->dnode, NULL));
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_rt_export_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL), &rfg->rt_export_list);
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_vrf_policy_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	struct bgp *bgp;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!rfg || !bgp)
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_prechange(bgp);
	const char *nh = yang_dnode_get_string(args->dnode, NULL);

	if (!strcmp(nh, "self") || !str2prefix(nh, &p)) {
		SET_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF);
		memset(&rfg->vn_prefix, 0, sizeof(rfg->vn_prefix));
	} else {
		UNSET_FLAG(rfg->flags, RFAPI_RFG_VPN_NH_SELF);
		rfg->vn_prefix = p;
		rfg->un_prefix = p;
	}
	if (bgp->rfapi_cfg->rfg_redist == rfg)
		vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_export_bgp_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	vnc_export_bgp_prechange(bgp);
	const char *mode = yang_dnode_get_string(args->dnode, NULL);

	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS;
	if (!strcmp(mode, "group-nve"))
		bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_EXPORT_BGP_MODE_GRP;
	else if (!strcmp(mode, "registering-nve"))
		bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_EXPORT_BGP_MODE_RH;
	else if (!strcmp(mode, "ce"))
		bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE;
	/*
	 * vnc-direct routes are withheld from their originator for the whole
	 * subgroup. Split peers on router-id before the export is advertised
	 * again, and merge them back when export is turned off.
	 */
	bgp_update_groups_adjust(bgp);
	vnc_export_bgp_postchange(bgp);
	return NB_OK;
}

static int vnc_nb_export_group_validate(const struct lyd_node *dnode, char *errmsg,
					size_t errmsg_len)
{
	const char *name = lyd_get_value(dnode);
	const struct lyd_node *vnc = yang_dnode_get_parent(dnode, "vnc");
	char xpath[XPATH_MAXLEN];

	if (vnc_nb_validate_default_bgp(dnode, errmsg, errmsg_len) != NB_OK)
		return NB_ERR_VALIDATION;

	if (vnc) {
		snprintfrr(xpath, sizeof(xpath), "./nve-group[name='%s']", name);
		if (yang_dnode_exists(vnc, xpath))
			return NB_OK;
		snprintfrr(xpath, sizeof(xpath), "./vrf-policy[name='%s']", name);
		if (yang_dnode_exists(vnc, xpath))
			return NB_OK;
	}

	snprintfrr(errmsg, errmsg_len, "Can't find group named \"%s\".", name);
	return NB_ERR_VALIDATION;
}

int bgp_global_vnc_export_bgp_group_nve_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct rfapi_rfg_name *rfgn;
	struct listnode *node;
	struct rfapi_nve_group_cfg *rfg;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_export_group_validate(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	name = lyd_get_value(args->dnode);
	if (!bgp->rfapi_cfg->rfg_export_direct_bgp_l)
		bgp->rfapi_cfg->rfg_export_direct_bgp_l = list_new();

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node, rfgn)) {
		if (rfgn->name && !strcmp(rfgn->name, name))
			return NB_OK;
	}

	rfgn = XCALLOC(MTYPE_RFAPI_RFG_NAME, sizeof(struct rfapi_rfg_name));
	rfgn->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
	rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_NVE);
	if (!rfg) {
		rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_VRF);
		if (rfg && rfg->rfapi_import_table)
			vnc_add_vrf_opener(bgp, rfg);
	}
	rfgn->rfg = rfg;
	listnode_add(bgp->rfapi_cfg->rfg_export_direct_bgp_l, rfgn);
	if (rfg && VNC_EXPORT_BGP_GRP_ENABLED(bgp->rfapi_cfg))
		vnc_direct_bgp_add_group(bgp, rfg);
	return NB_OK;
}

int bgp_global_vnc_export_bgp_group_nve_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg || !bgp->rfapi_cfg->rfg_export_direct_bgp_l)
		return NB_OK;

	name = lyd_get_value(args->dnode);
	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node, nnode, rfgn)) {
		if (!rfgn->name || strcmp(rfgn->name, name))
			continue;
		if (rfgn->rfg)
			vnc_direct_bgp_del_group(bgp, rfgn->rfg);
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfgn->name);
		list_delete_node(bgp->rfapi_cfg->rfg_export_direct_bgp_l, node);
		XFREE(MTYPE_RFAPI_RFG_NAME, rfgn);
		break;
	}
	return NB_OK;
}

static void vnc_nb_zebra_export_mode_apply(struct bgp *bgp, uint32_t newmode)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;
	uint32_t oldmode = hc->flags & BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS;
	struct listnode *node;
	struct rfapi_rfg_name *rfgn;

	if (newmode == oldmode)
		return;

	if (oldmode == BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP && hc->rfg_export_zebra_l) {
		for (ALL_LIST_ELEMENTS_RO(hc->rfg_export_zebra_l, node, rfgn)) {
			if (rfgn->rfg)
				vnc_zebra_del_group(bgp, rfgn->rfg);
		}
	}

	hc->flags &= ~BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_BITS;
	hc->flags |= newmode;

	if (newmode == BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP && hc->rfg_export_zebra_l) {
		for (ALL_LIST_ELEMENTS_RO(hc->rfg_export_zebra_l, node, rfgn)) {
			if (rfgn->rfg)
				vnc_zebra_add_group(bgp, rfgn->rfg);
		}
	}
}

int bgp_global_vnc_export_zebra_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *mode;
	uint32_t newmode = BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_NONE;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	mode = yang_dnode_get_string(args->dnode, NULL);
	if (!strcmp(mode, "group-nve"))
		newmode = BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_GRP;
	else if (!strcmp(mode, "registering-nve"))
		newmode = BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_RH;

	vnc_nb_zebra_export_mode_apply(bgp, newmode);
	return NB_OK;
}

int bgp_global_vnc_export_zebra_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	vnc_nb_zebra_export_mode_apply(bgp, BGP_VNC_CONFIG_EXPORT_ZEBRA_MODE_NONE);
	return NB_OK;
}

int bgp_global_vnc_export_zebra_group_nve_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct rfapi_rfg_name *rfgn;
	struct listnode *node;
	struct rfapi_nve_group_cfg *rfg;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_export_group_validate(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	name = lyd_get_value(args->dnode);
	if (!bgp->rfapi_cfg->rfg_export_zebra_l)
		bgp->rfapi_cfg->rfg_export_zebra_l = list_new();

	for (ALL_LIST_ELEMENTS_RO(bgp->rfapi_cfg->rfg_export_zebra_l, node, rfgn)) {
		if (rfgn->name && !strcmp(rfgn->name, name))
			return NB_OK;
	}

	rfgn = XCALLOC(MTYPE_RFAPI_RFG_NAME, sizeof(struct rfapi_rfg_name));
	rfgn->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
	rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_NVE);
	if (!rfg) {
		rfg = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_VRF);
		if (rfg && rfg->rfapi_import_table)
			vnc_add_vrf_opener(bgp, rfg);
	}
	rfgn->rfg = rfg;
	listnode_add(bgp->rfapi_cfg->rfg_export_zebra_l, rfgn);
	if (rfg && VNC_EXPORT_ZEBRA_GRP_ENABLED(bgp->rfapi_cfg))
		vnc_zebra_add_group(bgp, rfg);
	return NB_OK;
}

int bgp_global_vnc_export_zebra_group_nve_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	struct listnode *node, *nnode;
	struct rfapi_rfg_name *rfgn;
	const char *name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg || !bgp->rfapi_cfg->rfg_export_zebra_l)
		return NB_OK;

	name = lyd_get_value(args->dnode);
	for (ALL_LIST_ELEMENTS(bgp->rfapi_cfg->rfg_export_zebra_l, node, nnode, rfgn)) {
		if (!rfgn->name || strcmp(rfgn->name, name))
			continue;
		if (rfgn->rfg)
			vnc_zebra_del_group(bgp, rfgn->rfg);
		XFREE(MTYPE_RFAPI_GROUP_CFG, rfgn->name);
		list_delete_node(bgp->rfapi_cfg->rfg_export_zebra_l, node);
		XFREE(MTYPE_RFAPI_RFG_NAME, rfgn);
		break;
	}
	return NB_OK;
}

int bgp_global_vnc_redistribute_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	vnc_redistribute_prechange(bgp);
	const char *mode = yang_dnode_get_string(args->dnode, NULL);

	if (!strcmp(mode, "nve-group"))
		bgp->rfapi_cfg->redist_mode = VNC_REDIST_MODE_RFG;
	else if (!strcmp(mode, "resolve-nve"))
		bgp->rfapi_cfg->redist_mode = VNC_REDIST_MODE_RESOLVE_NVE;
	else
		bgp->rfapi_cfg->redist_mode = VNC_REDIST_MODE_PLAIN;
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

static void vnc_nb_set_exterior_view_for_source(struct bgp *bgp, const struct lyd_node *dnode)
{
	const struct lyd_node *vnode = yang_dnode_get(dnode, "../bgp-direct-to-nve-groups-view");

	if (vnode) {
		const char *vname = yang_dnode_get_string(vnode, NULL);

		XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->redist_bgp_exterior_view_name);
		bgp->rfapi_cfg->redist_bgp_exterior_view_name =
			XSTRDUP(MTYPE_RFAPI_GROUP_CFG, vname);
		bgp->rfapi_cfg->redist_bgp_exterior_view = bgp_lookup_by_name(vname);
	} else {
		XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->redist_bgp_exterior_view_name);
		bgp->rfapi_cfg->redist_bgp_exterior_view = bgp;
	}
}

int bgp_global_vnc_redistribute_ipv4_source_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	const char *source = lyd_get_value(args->dnode);

	if (rfapi_str2route_type("ipv4", source, &afi, &type))
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->redist[afi][type])
		return NB_OK;
	switch (type) {
	case ZEBRA_ROUTE_BGP_DIRECT:
		vnc_import_bgp_redist_enable(bgp, afi);
		break;
	case ZEBRA_ROUTE_BGP_DIRECT_EXT:
		vnc_nb_set_exterior_view_for_source(bgp, args->dnode);
		vnc_import_bgp_exterior_redist_enable(bgp, afi);
		break;
	default:
		if (type < ZEBRA_ROUTE_MAX)
			vnc_redistribute_set(bgp, afi, type);
		break;
	}
	return NB_OK;
}

int bgp_global_vnc_redistribute_ipv4_source_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	const char *source = lyd_get_value(args->dnode);

	if (rfapi_str2route_type("ipv4", source, &afi, &type))
		return NB_ERR_INCONSISTENCY;
	switch (type) {
	case ZEBRA_ROUTE_BGP_DIRECT:
		vnc_import_bgp_redist_disable(bgp, afi);
		break;
	case ZEBRA_ROUTE_BGP_DIRECT_EXT:
		vnc_import_bgp_exterior_redist_disable(bgp, afi);
		if (!bgp->rfapi_cfg->redist[AFI_IP6][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      bgp->rfapi_cfg->redist_bgp_exterior_view_name);
			bgp->rfapi_cfg->redist_bgp_exterior_view = NULL;
		}
		break;
	default:
		if (type < ZEBRA_ROUTE_MAX)
			vnc_redistribute_unset(bgp, afi, type);
		break;
	}
	return NB_OK;
}

int bgp_global_vnc_redistribute_ipv6_source_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	const char *source = lyd_get_value(args->dnode);

	if (rfapi_str2route_type("ipv6", source, &afi, &type))
		return NB_ERR_INCONSISTENCY;
	if (bgp->rfapi_cfg->redist[afi][type])
		return NB_OK;
	switch (type) {
	case ZEBRA_ROUTE_BGP_DIRECT:
		vnc_import_bgp_redist_enable(bgp, afi);
		break;
	case ZEBRA_ROUTE_BGP_DIRECT_EXT:
		vnc_nb_set_exterior_view_for_source(bgp, args->dnode);
		vnc_import_bgp_exterior_redist_enable(bgp, afi);
		break;
	default:
		if (type < ZEBRA_ROUTE_MAX)
			vnc_redistribute_set(bgp, afi, type);
		break;
	}
	return NB_OK;
}

int bgp_global_vnc_redistribute_ipv6_source_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	int type;

	if (args->event != NB_EV_APPLY)
		return NB_OK;
	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	const char *source = lyd_get_value(args->dnode);

	if (rfapi_str2route_type("ipv6", source, &afi, &type))
		return NB_ERR_INCONSISTENCY;
	switch (type) {
	case ZEBRA_ROUTE_BGP_DIRECT:
		vnc_import_bgp_redist_disable(bgp, afi);
		break;
	case ZEBRA_ROUTE_BGP_DIRECT_EXT:
		vnc_import_bgp_exterior_redist_disable(bgp, afi);
		if (!bgp->rfapi_cfg->redist[AFI_IP][ZEBRA_ROUTE_BGP_DIRECT_EXT]) {
			XFREE(MTYPE_RFAPI_GROUP_CFG,
			      bgp->rfapi_cfg->redist_bgp_exterior_view_name);
			bgp->rfapi_cfg->redist_bgp_exterior_view = NULL;
		}
		break;
	default:
		if (type < ZEBRA_ROUTE_MAX)
			vnc_redistribute_unset(bgp, afi, type);
		break;
	}
	return NB_OK;
}


int bgp_global_vnc_redistribute_nve_group_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	name = yang_dnode_get_string(args->dnode, NULL);
	vnc_redistribute_prechange(bgp);
	bgp->rfapi_cfg->rfg_redist = bgp_rfapi_cfg_match_byname(bgp, name, RFAPI_GROUP_CFG_NVE);
	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->rfg_redist_name);
	bgp->rfapi_cfg->rfg_redist_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_nve_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	vnc_redistribute_prechange(bgp);
	bgp->rfapi_cfg->rfg_redist = NULL;
	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->rfg_redist_name);
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_lifetime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *val;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	val = yang_dnode_get_string(args->dnode, NULL);
	vnc_redistribute_prechange(bgp);
	if (strmatch(val, "infinite"))
		bgp->rfapi_cfg->redist_lifetime = RFAPI_INFINITE_LIFETIME;
	else
		bgp->rfapi_cfg->redist_lifetime = strtoul(val, NULL, 10);
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_lifetime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	vnc_redistribute_prechange(bgp);
	bgp->rfapi_cfg->redist_lifetime = 0;
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_resolve_nve_roo_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t localadmin;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	localadmin = yang_dnode_get_uint16(args->dnode, NULL);
	if (bgp->rfapi_cfg->resolve_nve_roo_local_admin == localadmin)
		return NB_OK;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) ==
	    BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE)
		vnc_export_bgp_prechange(bgp);
	vnc_redistribute_prechange(bgp);

	bgp->rfapi_cfg->resolve_nve_roo_local_admin = localadmin;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) ==
	    BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE)
		vnc_export_bgp_postchange(bgp);
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_resolve_nve_roo_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) ==
	    BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE)
		vnc_export_bgp_prechange(bgp);
	vnc_redistribute_prechange(bgp);

	bgp->rfapi_cfg->resolve_nve_roo_local_admin =
		BGP_VNC_CONFIG_RESOLVE_NVE_ROO_LOCAL_ADMIN_DEFAULT;

	if ((bgp->rfapi_cfg->flags & BGP_VNC_CONFIG_EXPORT_BGP_MODE_BITS) ==
	    BGP_VNC_CONFIG_EXPORT_BGP_MODE_CE)
		vnc_export_bgp_postchange(bgp);
	vnc_redistribute_postchange(bgp);
	return NB_OK;
}

int bgp_global_vnc_redistribute_exterior_view_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	if (bgp->rfapi_cfg->redist[AFI_IP][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_disable(bgp, AFI_IP);
	if (bgp->rfapi_cfg->redist[AFI_IP6][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_disable(bgp, AFI_IP6);

	name = yang_dnode_get_string(args->dnode, NULL);
	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->redist_bgp_exterior_view_name);
	bgp->rfapi_cfg->redist_bgp_exterior_view_name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
	bgp->rfapi_cfg->redist_bgp_exterior_view = bgp_lookup_by_name(name);
	return NB_OK;
}

int bgp_global_vnc_redistribute_exterior_view_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	if (bgp->rfapi_cfg->redist[AFI_IP][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_disable(bgp, AFI_IP);
	if (bgp->rfapi_cfg->redist[AFI_IP6][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_disable(bgp, AFI_IP6);

	XFREE(MTYPE_RFAPI_GROUP_CFG, bgp->rfapi_cfg->redist_bgp_exterior_view_name);
	bgp->rfapi_cfg->redist_bgp_exterior_view = NULL;
	return NB_OK;
}

static void bgp_global_vnc_redistribute_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp = bgp_nb_vnc_get_bgp(args->dnode);
	bool want_v4, want_v6;

	if (!bgp || !bgp->rfapi_cfg)
		return;

	want_v4 = yang_dnode_exists(args->dnode, "./ipv4-source[.='bgp-direct-to-nve-groups']");
	want_v6 = yang_dnode_exists(args->dnode, "./ipv6-source[.='bgp-direct-to-nve-groups']");

	if (!want_v4 && !want_v6)
		return;

	if (!bgp->rfapi_cfg->redist_bgp_exterior_view_name)
		bgp->rfapi_cfg->redist_bgp_exterior_view = bgp;

	if (want_v4 && !bgp->rfapi_cfg->redist[AFI_IP][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_enable(bgp, AFI_IP);
	if (want_v6 && !bgp->rfapi_cfg->redist[AFI_IP6][ZEBRA_ROUTE_BGP_DIRECT_EXT])
		vnc_import_bgp_exterior_redist_enable(bgp, AFI_IP6);
}

/* --- redistribute / export prefix-list and route-map filters --- */

static void vnc_nb_hc_plist_redist_set(struct bgp *bgp, int type, afi_t afi, const char *name)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;

	vnc_redistribute_prechange(bgp);
	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->plist_redist_name[type][afi]);
	if (name) {
		hc->plist_redist_name[type][afi] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		hc->plist_redist[type][afi] = prefix_list_lookup(afi, name);
	} else
		hc->plist_redist[type][afi] = NULL;
	vnc_redistribute_postchange(bgp);
}

static void vnc_nb_hc_rmap_redist_set(struct bgp *bgp, int type, const char *name)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;

	vnc_redistribute_prechange(bgp);
	XFREE(MTYPE_RFAPI_GROUP_CFG, hc->routemap_redist_name[type]);
	route_map_counter_decrement(hc->routemap_redist[type]);
	if (name) {
		hc->routemap_redist_name[type] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		hc->routemap_redist[type] = route_map_lookup_by_name(name);
		route_map_counter_increment(hc->routemap_redist[type]);
	} else
		hc->routemap_redist[type] = NULL;
	vnc_redistribute_postchange(bgp);
}

static void vnc_nb_hc_plist_export_set(struct bgp *bgp, bool is_bgp, afi_t afi, const char *name)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;

	char **pname = is_bgp ? &hc->plist_export_bgp_name[afi] : &hc->plist_export_zebra_name[afi];

	struct prefix_list **plist = is_bgp ? &hc->plist_export_bgp[afi]
					    : &hc->plist_export_zebra[afi];

	XFREE(MTYPE_RFAPI_GROUP_CFG, *pname);
	if (name) {
		*pname = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		*plist = prefix_list_lookup(afi, name);
	} else
		*plist = NULL;
	if (is_bgp)
		vnc_direct_bgp_reexport(bgp, afi);
}

static void vnc_nb_hc_rmap_export_set(struct bgp *bgp, bool is_bgp, const char *name)
{
	struct rfapi_cfg *hc = bgp->rfapi_cfg;

	char **pname = is_bgp ? &hc->routemap_export_bgp_name : &hc->routemap_export_zebra_name;
	struct route_map **rmap = is_bgp ? &hc->routemap_export_bgp : &hc->routemap_export_zebra;

	XFREE(MTYPE_RFAPI_GROUP_CFG, *pname);
	route_map_counter_decrement(*rmap);
	if (name) {
		*pname = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		*rmap = route_map_lookup_by_name(name);
		route_map_counter_increment(*rmap);
	} else
		*rmap = NULL;
	if (is_bgp) {
		vnc_direct_bgp_reexport(bgp, AFI_IP);
		vnc_direct_bgp_reexport(bgp, AFI_IP6);
	}
}

static void vnc_nb_rfg_plist_redist_set(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg, int type,
					afi_t afi, const char *name)
{
	vnc_redistribute_prechange(bgp);
	XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->plist_redist_name[type][afi]);
	if (name) {
		rfg->plist_redist_name[type][afi] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		rfg->plist_redist[type][afi] = prefix_list_lookup(afi, name);
	} else
		rfg->plist_redist[type][afi] = NULL;
	vnc_redistribute_postchange(bgp);
}

static void vnc_nb_rfg_rmap_redist_set(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg, int type,
				       const char *name)
{
	vnc_redistribute_prechange(bgp);
	XFREE(MTYPE_RFAPI_GROUP_CFG, rfg->routemap_redist_name[type]);
	route_map_counter_decrement(rfg->routemap_redist[type]);
	if (name) {
		rfg->routemap_redist_name[type] = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		rfg->routemap_redist[type] = route_map_lookup_by_name(name);
		route_map_counter_increment(rfg->routemap_redist[type]);
	} else
		rfg->routemap_redist[type] = NULL;
	vnc_redistribute_postchange(bgp);
}

static void vnc_nb_rfg_plist_export_set(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg,
					bool is_bgp, afi_t afi, const char *name)
{
	char **pname = is_bgp ? &rfg->plist_export_bgp_name[afi]
			      : &rfg->plist_export_zebra_name[afi];
	struct prefix_list **plist = is_bgp ? &rfg->plist_export_bgp[afi]
					    : &rfg->plist_export_zebra[afi];

	XFREE(MTYPE_RFAPI_GROUP_CFG, *pname);
	if (name) {
		*pname = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		*plist = prefix_list_lookup(afi, name);
	} else
		*plist = NULL;
	if (is_bgp)
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, afi);
	else
		vnc_zebra_reexport_group_afi(bgp, rfg, afi);
}

static void vnc_nb_rfg_rmap_export_set(struct bgp *bgp, struct rfapi_nve_group_cfg *rfg,
				       bool is_bgp, const char *name)
{
	char **pname = is_bgp ? &rfg->routemap_export_bgp_name : &rfg->routemap_export_zebra_name;
	struct route_map **rmap = is_bgp ? &rfg->routemap_export_bgp : &rfg->routemap_export_zebra;

	XFREE(MTYPE_RFAPI_GROUP_CFG, *pname);
	route_map_counter_decrement(*rmap);
	if (name) {
		*pname = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		*rmap = route_map_lookup_by_name(name);
		route_map_counter_increment(*rmap);
	} else
		*rmap = NULL;
	if (is_bgp) {
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP);
		vnc_direct_bgp_reexport_group_afi(bgp, rfg, AFI_IP6);
	} else {
		vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP);
		vnc_zebra_reexport_group_afi(bgp, rfg, AFI_IP6);
	}
}

#define VNC_NB_HC_PLIST_REDIST(fn, type, afi)                                                     \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event == NB_EV_VALIDATE)                                                \
			return vnc_nb_validate_default_bgp(args->dnode, args->errmsg,             \
							   args->errmsg_len);                     \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_plist_redist_set(bgp, type, afi,                                        \
					   yang_dnode_get_string(args->dnode, NULL));             \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_plist_redist_set(bgp, type, afi, NULL);                                 \
		return NB_OK;                                                                     \
	}

VNC_NB_HC_PLIST_REDIST(bgp_global_vnc_redist_bgp_direct_ipv4_plist, ZEBRA_ROUTE_BGP_DIRECT, AFI_IP)
VNC_NB_HC_PLIST_REDIST(bgp_global_vnc_redist_bgp_direct_ipv6_plist, ZEBRA_ROUTE_BGP_DIRECT, AFI_IP6)
VNC_NB_HC_PLIST_REDIST(bgp_global_vnc_redist_bgp_direct_ext_ipv4_plist, ZEBRA_ROUTE_BGP_DIRECT_EXT,
		       AFI_IP)
VNC_NB_HC_PLIST_REDIST(bgp_global_vnc_redist_bgp_direct_ext_ipv6_plist, ZEBRA_ROUTE_BGP_DIRECT_EXT,
		       AFI_IP6)

#define VNC_NB_HC_RMAP_REDIST(fn, type)                                                           \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event == NB_EV_VALIDATE)                                                \
			return vnc_nb_validate_default_bgp(args->dnode, args->errmsg,             \
							   args->errmsg_len);                     \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_rmap_redist_set(bgp, type, yang_dnode_get_string(args->dnode, NULL));   \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_rmap_redist_set(bgp, type, NULL);                                       \
		return NB_OK;                                                                     \
	}

VNC_NB_HC_RMAP_REDIST(bgp_global_vnc_redist_bgp_direct_rmap, ZEBRA_ROUTE_BGP_DIRECT)
VNC_NB_HC_RMAP_REDIST(bgp_global_vnc_redist_bgp_direct_ext_rmap, ZEBRA_ROUTE_BGP_DIRECT_EXT)

#define VNC_NB_HC_PLIST_EXPORT(fn, is_bgp, afi)                                                   \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event == NB_EV_VALIDATE)                                                \
			return vnc_nb_validate_default_bgp(args->dnode, args->errmsg,             \
							   args->errmsg_len);                     \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_plist_export_set(bgp, is_bgp, afi,                                      \
					   yang_dnode_get_string(args->dnode, NULL));             \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_plist_export_set(bgp, is_bgp, afi, NULL);                               \
		return NB_OK;                                                                     \
	}

VNC_NB_HC_PLIST_EXPORT(bgp_global_vnc_export_bgp_ipv4_plist, true, AFI_IP)
VNC_NB_HC_PLIST_EXPORT(bgp_global_vnc_export_bgp_ipv6_plist, true, AFI_IP6)
VNC_NB_HC_PLIST_EXPORT(bgp_global_vnc_export_zebra_ipv4_plist, false, AFI_IP)
VNC_NB_HC_PLIST_EXPORT(bgp_global_vnc_export_zebra_ipv6_plist, false, AFI_IP6)

#define VNC_NB_HC_RMAP_EXPORT(fn, is_bgp)                                                         \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event == NB_EV_VALIDATE)                                                \
			return vnc_nb_validate_default_bgp(args->dnode, args->errmsg,             \
							   args->errmsg_len);                     \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_rmap_export_set(bgp, is_bgp, yang_dnode_get_string(args->dnode, NULL)); \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		if (!bgp || !bgp->rfapi_cfg)                                                      \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_hc_rmap_export_set(bgp, is_bgp, NULL);                                     \
		return NB_OK;                                                                     \
	}

VNC_NB_HC_RMAP_EXPORT(bgp_global_vnc_export_bgp_rmap, true)
VNC_NB_HC_RMAP_EXPORT(bgp_global_vnc_export_zebra_rmap, false)

#define VNC_NB_RFG_PLIST_REDIST(fn, type, afi)                                                    \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_plist_redist_set(bgp, rfg, type, afi,                                  \
					    yang_dnode_get_string(args->dnode, NULL));            \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_plist_redist_set(bgp, rfg, type, afi, NULL);                           \
		return NB_OK;                                                                     \
	}

VNC_NB_RFG_PLIST_REDIST(bgp_global_vnc_nve_redist_bgp_direct_ipv4_plist, ZEBRA_ROUTE_BGP_DIRECT,
			AFI_IP)
VNC_NB_RFG_PLIST_REDIST(bgp_global_vnc_nve_redist_bgp_direct_ipv6_plist, ZEBRA_ROUTE_BGP_DIRECT,
			AFI_IP6)

#define VNC_NB_RFG_RMAP_REDIST(fn, type)                                                          \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_rmap_redist_set(bgp, rfg, type,                                        \
					   yang_dnode_get_string(args->dnode, NULL));             \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_rmap_redist_set(bgp, rfg, type, NULL);                                 \
		return NB_OK;                                                                     \
	}

VNC_NB_RFG_RMAP_REDIST(bgp_global_vnc_nve_redist_bgp_direct_rmap, ZEBRA_ROUTE_BGP_DIRECT)

#define VNC_NB_RFG_PLIST_EXPORT(fn, is_bgp, afi)                                                  \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_plist_export_set(bgp, rfg, is_bgp, afi,                                \
					    yang_dnode_get_string(args->dnode, NULL));            \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_plist_export_set(bgp, rfg, is_bgp, afi, NULL);                         \
		return NB_OK;                                                                     \
	}

VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_nve_export_bgp_ipv4_plist, true, AFI_IP)
VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_nve_export_bgp_ipv6_plist, true, AFI_IP6)
VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_nve_export_zebra_ipv4_plist, false, AFI_IP)
VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_nve_export_zebra_ipv6_plist, false, AFI_IP6)
/* vrf-policy export uses the same BGP export plist slots */
VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_vrf_export_ipv4_plist, true, AFI_IP)
VNC_NB_RFG_PLIST_EXPORT(bgp_global_vnc_vrf_export_ipv6_plist, true, AFI_IP6)

#define VNC_NB_RFG_RMAP_EXPORT(fn, is_bgp)                                                        \
	int fn##_modify(struct nb_cb_modify_args *args)                                           \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_rmap_export_set(bgp, rfg, is_bgp,                                      \
					   yang_dnode_get_string(args->dnode, NULL));             \
		return NB_OK;                                                                     \
	}                                                                                         \
	int fn##_destroy(struct nb_cb_destroy_args *args)                                         \
	{                                                                                         \
		struct bgp *bgp;                                                                  \
		struct rfapi_nve_group_cfg *rfg;                                                  \
		if (args->event != NB_EV_APPLY)                                                   \
			return NB_OK;                                                             \
		bgp = bgp_nb_vnc_get_bgp(args->dnode);                                            \
		rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);                  \
		if (!bgp || !rfg)                                                                 \
			return NB_ERR_INCONSISTENCY;                                              \
		vnc_nb_rfg_rmap_export_set(bgp, rfg, is_bgp, NULL);                               \
		return NB_OK;                                                                     \
	}

VNC_NB_RFG_RMAP_EXPORT(bgp_global_vnc_nve_export_bgp_rmap, true)
VNC_NB_RFG_RMAP_EXPORT(bgp_global_vnc_nve_export_zebra_rmap, false)
VNC_NB_RFG_RMAP_EXPORT(bgp_global_vnc_vrf_export_rmap, true)

int bgp_global_vnc_advertise_un_method_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	/* encap-safi sets flag; encap-attr clears (matches classic write/read). */
	if (strmatch(yang_dnode_get_string(args->dnode, NULL), "encap-safi"))
		bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP;
	else
		bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP;
	return NB_OK;
}

int bgp_global_vnc_advertise_un_method_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_ADV_UN_METHOD_ENCAP;
	return NB_OK;
}

static int vnc_nb_parse_l2rd(const char *val, uint8_t *out)
{
	unsigned long value_l;
	char *end = NULL;

	if (!val)
		return -1;
	if (strmatch(val, "auto-vn") || strmatch(val, "auto:vn")) {
		*out = 0;
		return 0;
	}
	value_l = strtoul(val, &end, 10);
	if (!val[0] || (end && *end) || value_l < 1 || value_l > 255)
		return -1;
	*out = value_l & 0xff;
	return 0;
}

int bgp_global_vnc_defaults_l2rd_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint8_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;
	if (vnc_nb_parse_l2rd(yang_dnode_get_string(args->dnode, NULL), &value))
		return NB_ERR_INCONSISTENCY;

	bgp->rfapi_cfg->flags |= BGP_VNC_CONFIG_L2RD;
	bgp->rfapi_cfg->default_l2rd = value;
	return NB_OK;
}

int bgp_global_vnc_defaults_l2rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_ERR_INCONSISTENCY;

	bgp->rfapi_cfg->default_l2rd = 0;
	bgp->rfapi_cfg->flags &= ~BGP_VNC_CONFIG_L2RD;
	return NB_OK;
}

int bgp_global_vnc_nve_group_l2rd_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_nve_group_cfg *rfg;
	uint8_t value;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;
	if (vnc_nb_parse_l2rd(yang_dnode_get_string(args->dnode, NULL), &value))
		return NB_ERR_INCONSISTENCY;

	rfg->l2rd = value;
	rfg->flags |= RFAPI_RFG_L2RD;
	return NB_OK;
}

int bgp_global_vnc_nve_group_l2rd_destroy(struct nb_cb_destroy_args *args)
{
	struct rfapi_nve_group_cfg *rfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;

	rfg->l2rd = 0;
	rfg->flags &= ~RFAPI_RFG_L2RD;
	return NB_OK;
}

int bgp_global_vnc_l2_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct rfapi_l2_group_cfg *rfg;
	const char *name;

	if (args->event == NB_EV_VALIDATE)
		return vnc_nb_validate_default_bgp(args->dnode, args->errmsg, args->errmsg_len);
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	if (!bgp || !bgp->rfapi_cfg)
		return NB_OK;

	name = yang_dnode_get_string(args->dnode, "name");
	rfg = rfapi_l2_group_lookup_byname(bgp, name);
	if (!rfg) {
		rfg = rfapi_l2_group_new();
		rfg->name = XSTRDUP(MTYPE_RFAPI_GROUP_CFG, name);
		listnode_add(bgp->rfapi_cfg->l2_groups, rfg);
	}
	nb_running_set_entry(args->dnode, rfg);
	return NB_OK;
}

int bgp_global_vnc_l2_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct rfapi_l2_group_cfg *rfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_vnc_get_bgp(args->dnode);
	rfg = nb_running_unset_entry(args->dnode);
	if (!bgp || !rfg)
		return NB_ERR_INCONSISTENCY;

	bgp_rfapi_delete_l2_group(NULL, bgp, rfg);
	return NB_OK;
}

int bgp_global_vnc_l2_group_logical_network_id_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_l2_group_cfg *rfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;

	rfg->logical_net_id = yang_dnode_get_uint32(args->dnode, NULL);
	return NB_OK;
}

int bgp_global_vnc_l2_group_labels_create(struct nb_cb_create_args *args)
{
	struct rfapi_l2_group_cfg *rfg;
	uint32_t label;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;

	label = yang_dnode_get_uint32(args->dnode, NULL);
	if (!rfg->labels)
		rfg->labels = list_new();
	if (!listnode_lookup(rfg->labels, (void *)(uintptr_t)label))
		listnode_add(rfg->labels, (void *)(uintptr_t)label);
	return NB_OK;
}

int bgp_global_vnc_l2_group_labels_destroy(struct nb_cb_destroy_args *args)
{
	struct rfapi_l2_group_cfg *rfg;
	uint32_t label;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg || !rfg->labels)
		return NB_OK;

	label = yang_dnode_get_uint32(args->dnode, NULL);
	listnode_delete(rfg->labels, (void *)(uintptr_t)label);
	return NB_OK;
}

int bgp_global_vnc_l2_group_rt_import_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_l2_group_cfg *rfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;

	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL), &rfg->rt_import_list);
	return NB_OK;
}

int bgp_global_vnc_l2_group_rt_export_modify(struct nb_cb_modify_args *args)
{
	struct rfapi_l2_group_cfg *rfg;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	rfg = nb_running_get_entry(lyd_parent(args->dnode), NULL, true);
	if (!rfg)
		return NB_ERR_INCONSISTENCY;

	rfapi_set_ecom_from_str(yang_dnode_get_string(args->dnode, NULL), &rfg->rt_export_list);
	return NB_OK;
}


int bgp_global_vnc_noop_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/* clang-format off */
static const char *frr_bgp_vnc_features[] = {
	"vnc",
	NULL,
};

const struct frr_yang_module_info frr_bgp_vnc_info = {
	.name = "frr-bgp-vnc",
	.features = frr_bgp_vnc_features,
	.nodes = {
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc",
			.cbs = {
				.cli_show = vnc_cli_show,
				.create = bgp_global_vnc_create,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/advertise-un-method",
			.cbs = {
				.modify = bgp_global_vnc_advertise_un_method_modify,
				.destroy = bgp_global_vnc_advertise_un_method_destroy,
				.cli_show = vnc_advertise_un_method_cli_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/rfp",
			.cbs = {
				.cli_show = vnc_rfp_cli_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/rfp/holddown-factor",
			.cbs = {
				.modify = bgp_global_vnc_rfp_holddown_factor_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/rfp/full-table-download",
			.cbs = {
				.modify = bgp_global_vnc_rfp_full_table_download_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults",
			.cbs = {
				.cli_show = vnc_defaults_cli_show,
				.cli_show_end = vnc_defaults_cli_show_end,
				.create = bgp_global_vnc_defaults_create,
				.destroy = bgp_global_vnc_defaults_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults/rd",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults/response-lifetime",
			.cbs = {
				.modify = bgp_global_vnc_defaults_response_lifetime_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_defaults_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/defaults/l2rd",
			.cbs = {
				.modify = bgp_global_vnc_defaults_l2rd_modify,
				.destroy = bgp_global_vnc_defaults_l2rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group",
			.cbs = {
				.cli_show = vnc_nve_group_cli_show,
				.cli_show_end = vnc_nve_group_cli_show_end,
				.create = bgp_global_vnc_nve_group_create,
				.destroy = bgp_global_vnc_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/prefix-vn",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_prefix_vn_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/prefix-un",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_prefix_un_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/rd",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/response-lifetime",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_response_lifetime_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/l2rd",
			.cbs = {
				.modify = bgp_global_vnc_nve_group_l2rd_modify,
				.destroy = bgp_global_vnc_nve_group_l2rd_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-direct-ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_redist_bgp_direct_ipv4_plist_modify,
				.destroy = bgp_global_vnc_nve_redist_bgp_direct_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-direct-ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_redist_bgp_direct_ipv6_plist_modify,
				.destroy = bgp_global_vnc_nve_redist_bgp_direct_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-direct-route-map",
			.cbs = {
				.modify = bgp_global_vnc_nve_redist_bgp_direct_rmap_modify,
				.destroy = bgp_global_vnc_nve_redist_bgp_direct_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-export-ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_bgp_ipv4_plist_modify,
				.destroy = bgp_global_vnc_nve_export_bgp_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-export-ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_bgp_ipv6_plist_modify,
				.destroy = bgp_global_vnc_nve_export_bgp_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/bgp-export-route-map",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_bgp_rmap_modify,
				.destroy = bgp_global_vnc_nve_export_bgp_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/zebra-export-ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_zebra_ipv4_plist_modify,
				.destroy = bgp_global_vnc_nve_export_zebra_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/zebra-export-ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_zebra_ipv6_plist_modify,
				.destroy = bgp_global_vnc_nve_export_zebra_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/nve-group/zebra-export-route-map",
			.cbs = {
				.modify = bgp_global_vnc_nve_export_zebra_rmap_modify,
				.destroy = bgp_global_vnc_nve_export_zebra_rmap_destroy,
			}
		},

		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/l2-group",
			.cbs = {
				.cli_show = vnc_l2_group_cli_show,
				.cli_show_end = vnc_l2_group_cli_show_end,
				.create = bgp_global_vnc_l2_group_create,
				.destroy = bgp_global_vnc_l2_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/l2-group/logical-network-id",
			.cbs = {
				.modify = bgp_global_vnc_l2_group_logical_network_id_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/l2-group/labels",
			.cbs = {
				.create = bgp_global_vnc_l2_group_labels_create,
				.destroy = bgp_global_vnc_l2_group_labels_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/l2-group/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_l2_group_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/l2-group/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_l2_group_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy",
			.cbs = {
				.cli_show = vnc_vrf_policy_cli_show,
				.cli_show_end = vnc_vrf_policy_cli_show_end,
				.create = bgp_global_vnc_vrf_policy_create,
				.destroy = bgp_global_vnc_vrf_policy_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/label",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_label_modify,
				.destroy = bgp_global_vnc_vrf_policy_label_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/rd",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rd_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/rt-import",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rt_import_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/rt-export",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_rt_export_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/nexthop",
			.cbs = {
				.modify = bgp_global_vnc_vrf_policy_nexthop_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/ipv4-export-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_vrf_export_ipv4_plist_modify,
				.destroy = bgp_global_vnc_vrf_export_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/ipv6-export-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_vrf_export_ipv6_plist_modify,
				.destroy = bgp_global_vnc_vrf_export_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/vrf-policy/export-route-map",
			.cbs = {
				.modify = bgp_global_vnc_vrf_export_rmap_modify,
				.destroy = bgp_global_vnc_vrf_export_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp",
			.cbs = {
				.cli_show = vnc_export_bgp_cli_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp/mode",
			.cbs = {
				.modify = bgp_global_vnc_export_bgp_mode_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp/group-nve-group",
			.cbs = {
				.create = bgp_global_vnc_export_bgp_group_nve_group_create,
				.destroy = bgp_global_vnc_export_bgp_group_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp/ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_export_bgp_ipv4_plist_modify,
				.destroy = bgp_global_vnc_export_bgp_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp/ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_export_bgp_ipv6_plist_modify,
				.destroy = bgp_global_vnc_export_bgp_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/bgp/route-map",
			.cbs = {
				.modify = bgp_global_vnc_export_bgp_rmap_modify,
				.destroy = bgp_global_vnc_export_bgp_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra",
			.cbs = {
				.cli_show = vnc_export_zebra_cli_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra/mode",
			.cbs = {
				.modify = bgp_global_vnc_export_zebra_mode_modify,
				.destroy = bgp_global_vnc_export_zebra_mode_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra/group-nve-group",
			.cbs = {
				.create = bgp_global_vnc_export_zebra_group_nve_group_create,
				.destroy = bgp_global_vnc_export_zebra_group_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra/ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_export_zebra_ipv4_plist_modify,
				.destroy = bgp_global_vnc_export_zebra_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra/ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_export_zebra_ipv6_plist_modify,
				.destroy = bgp_global_vnc_export_zebra_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/export/zebra/route-map",
			.cbs = {
				.modify = bgp_global_vnc_export_zebra_rmap_modify,
				.destroy = bgp_global_vnc_export_zebra_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute",
			.cbs = {
				.apply_finish = bgp_global_vnc_redistribute_apply_finish,
				.cli_show = vnc_redistribute_cli_show,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/mode",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_mode_modify,
				.destroy = bgp_global_vnc_noop_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/nve-group",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_nve_group_modify,
				.destroy = bgp_global_vnc_redistribute_nve_group_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/lifetime",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_lifetime_modify,
				.destroy = bgp_global_vnc_redistribute_lifetime_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/resolve-nve-roo-ec-local-admin",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_resolve_nve_roo_modify,
				.destroy = bgp_global_vnc_redistribute_resolve_nve_roo_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-view",
			.cbs = {
				.modify = bgp_global_vnc_redistribute_exterior_view_modify,
				.destroy = bgp_global_vnc_redistribute_exterior_view_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_ipv4_plist_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_ipv6_plist_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-ipv4-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_ext_ipv4_plist_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_ext_ipv4_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-ipv6-prefix-list",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_ext_ipv6_plist_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_ext_ipv6_plist_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-route-map",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_rmap_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/bgp-direct-to-nve-groups-route-map",
			.cbs = {
				.modify = bgp_global_vnc_redist_bgp_direct_ext_rmap_modify,
				.destroy = bgp_global_vnc_redist_bgp_direct_ext_rmap_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/ipv4-source",
			.cbs = {
				.create = bgp_global_vnc_redistribute_ipv4_source_create,
				.destroy = bgp_global_vnc_redistribute_ipv4_source_destroy,
			}
		},
		{
			.xpath = "/frr-routing:routing/control-plane-protocols/control-plane-protocol/frr-bgp:bgp/frr-bgp-vnc:vnc/redistribute/ipv6-source",
			.cbs = {
				.create = bgp_global_vnc_redistribute_ipv6_source_create,
				.destroy = bgp_global_vnc_redistribute_ipv6_source_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

#endif /* ENABLE_BGP_VNC */
