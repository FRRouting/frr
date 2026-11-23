// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Northbound candidate-tree helpers
 * Copyright (C) 2026 FRRouting
 */

#include <zebra.h>

#include "lib/northbound.h"
#include "lib/yang.h"
#include "lib/yang_translator.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_nb_candidate.h"

static const struct lyd_node *bgp_nb_cand_bgp_node(const struct lyd_node *dnode)
{
	const struct lyd_node *bgp;

	if (!dnode)
		return NULL;
	if (strmatch(dnode->schema->name, "bgp"))
		return dnode;
	if (strmatch(dnode->schema->name, "control-plane-protocol")) {
		bgp = yang_dnode_get(dnode, "frr-bgp:bgp");
		if (!bgp)
			bgp = yang_dnode_get(dnode, "bgp");
		return bgp;
	}
	return yang_dnode_get_parent(dnode, "bgp");
}

bool bgp_nb_cand_cpp_is_bgp(const struct lyd_node *cpp)
{
	const char *type;
	const char *id;

	if (!cpp || !strmatch(cpp->schema->name, "control-plane-protocol"))
		return false;
	if (!yang_dnode_exists(cpp, "./type"))
		return false;

	type = yang_dnode_get_string(cpp, "./type");
	if (!type)
		return false;
	id = strrchr(type, ':');
	id = id ? id + 1 : type;
	return strmatch(id, "bgp");
}

bool bgp_nb_cand_instance_key(const struct lyd_node *dnode, enum bgp_instance_type *inst_type,
			      const char **name, const char **vrf)
{
	const struct lyd_node *bgp_dnode;
	const struct lyd_node *cpp;
	const char *key_name;
	const char *key_vrf;
	enum bgp_instance_type type;
	const char *logical_name;

	if (!dnode)
		return false;

	bgp_dnode = bgp_nb_cand_bgp_node(dnode);
	cpp = strmatch(dnode->schema->name, "control-plane-protocol")
		      ? dnode
		      : yang_dnode_get_parent(bgp_dnode ? bgp_dnode : dnode,
					      "control-plane-protocol");
	if (!cpp || !bgp_nb_cand_cpp_is_bgp(cpp))
		return false;

	if (!yang_dnode_exists(cpp, "./name") || !yang_dnode_exists(cpp, "./vrf"))
		return false;

	key_name = yang_dnode_get_string(cpp, "./name");
	key_vrf = yang_dnode_get_string(cpp, "./vrf");

	if (bgp_dnode && yang_dnode_exists(bgp_dnode, "./global/instance-type-view") &&
	    yang_dnode_get_bool(bgp_dnode, "./global/instance-type-view")) {
		type = BGP_INSTANCE_TYPE_VIEW;
		logical_name = key_name;
	} else if (strmatch(key_vrf, VRF_DEFAULT_NAME)) {
		type = BGP_INSTANCE_TYPE_DEFAULT;
		logical_name = NULL;
	} else {
		type = BGP_INSTANCE_TYPE_VRF;
		logical_name = key_vrf;
	}

	if (inst_type)
		*inst_type = type;
	if (name)
		*name = logical_name;
	if (vrf)
		*vrf = key_vrf;
	return true;
}

const struct lyd_node *bgp_nb_cand_root(const struct lyd_node *dnode)
{
	const struct lyd_node *cand = nb_transaction_candidate_dnode();

	if (cand)
		return cand;
	if (dnode) {
		const struct lyd_node *cur = dnode;

		while (lyd_parent(cur))
			cur = lyd_parent(cur);
		return lyd_first_sibling(cur);
	}
	return running_config ? running_config->dnode : NULL;
}

bool bgp_nb_cand_each_instance_in_tree(const struct lyd_node *tree_dnode, bgp_nb_cand_inst_cb cb,
				       void *arg)
{
	const struct lyd_node *cpps;
	const struct lyd_node *cpp;

	if (!tree_dnode || !cb)
		return true;

	cpps = yang_dnode_get(tree_dnode, "/frr-routing:routing/control-plane-protocols");
	if (!cpps)
		return true;

	LY_LIST_FOR (lyd_child(cpps), cpp) {
		const struct lyd_node *bgp_dnode;

		if (!bgp_nb_cand_cpp_is_bgp(cpp))
			continue;
		bgp_dnode = yang_dnode_get(cpp, "frr-bgp:bgp");
		if (!bgp_dnode)
			bgp_dnode = yang_dnode_get(cpp, "bgp");
		if (!bgp_dnode)
			continue;
		if (!cb(bgp_dnode, arg))
			return false;
	}
	return true;
}

bool bgp_nb_cand_each_instance(bgp_nb_cand_inst_cb cb, void *arg)
{
	const struct lyd_node *root = bgp_nb_cand_root(NULL);

	return bgp_nb_cand_each_instance_in_tree(root, cb, arg);
}

bool bgp_nb_cand_evpn_enabled(const struct lyd_node *dnode)
{
	const struct lyd_node *bgp_dnode = bgp_nb_cand_bgp_node(dnode);
	const struct lyd_node *afis, *af;

	if (!bgp_dnode)
		return false;

	afis = yang_dnode_get(bgp_dnode, "global/afi-safis");
	if (!afis)
		return false;

	LY_LIST_FOR (lyd_child(afis), af) {
		afi_t afi = AFI_UNSPEC;
		safi_t safi = SAFI_UNSPEC;
		const char *name;

		if (!strmatch(af->schema->name, "afi-safi"))
			continue;
		if (!yang_dnode_exists(af, "afi-safi-name"))
			continue;
		name = yang_dnode_get_string(af, "afi-safi-name");
		yang_afi_safi_identity2value(name, &afi, &safi);
		if (afi != AFI_L2VPN || safi != SAFI_EVPN)
			continue;
		return yang_dnode_exists(af, "l2vpn-evpn/advertise-all-vni") &&
		       yang_dnode_get_bool(af, "l2vpn-evpn/advertise-all-vni");
	}
	return false;
}

struct cand_evpn_underlay_ctx {
	const struct lyd_node *evpn_inst;
	const struct lyd_node *dflt_inst;
};

static bool bgp_nb_cand_evpn_underlay_cb(const struct lyd_node *bgp_dnode, void *arg)
{
	struct cand_evpn_underlay_ctx *ctx = arg;
	enum bgp_instance_type inst_type;

	if (bgp_nb_cand_evpn_enabled(bgp_dnode)) {
		ctx->evpn_inst = bgp_dnode;
		return false;
	}
	if (!ctx->dflt_inst && bgp_nb_cand_instance_key(bgp_dnode, &inst_type, NULL, NULL) &&
	    inst_type == BGP_INSTANCE_TYPE_DEFAULT)
		ctx->dflt_inst = bgp_dnode;
	return true;
}

const struct lyd_node *bgp_nb_cand_evpn_underlay(const struct lyd_node *dnode)
{
	struct cand_evpn_underlay_ctx ctx = { NULL, NULL };
	const struct lyd_node *root = bgp_nb_cand_root(dnode);

	bgp_nb_cand_each_instance_in_tree(root, bgp_nb_cand_evpn_underlay_cb, &ctx);
	return ctx.evpn_inst ? ctx.evpn_inst : ctx.dflt_inst;
}

static bool bgp_nb_cand_is_peer_group_list(const struct lyd_node *dnode)
{
	return dnode && dnode->schema->nodetype == LYS_LIST &&
	       strmatch(dnode->schema->name, "peer-group");
}

const struct lyd_node *bgp_nb_cand_peer_node(const struct lyd_node *dnode)
{
	const struct lyd_node *nbr;

	if (!dnode)
		return NULL;
	if (dnode->schema->nodetype == LYS_LIST &&
	    (strmatch(dnode->schema->name, "neighbor") ||
	     strmatch(dnode->schema->name, "unnumbered-neighbor") ||
	     strmatch(dnode->schema->name, "peer-group")))
		return dnode;
	nbr = yang_dnode_get_parent(dnode, "neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "unnumbered-neighbor");
	if (!nbr)
		nbr = yang_dnode_get_parent(dnode, "peer-group");
	return nbr;
}

const struct lyd_node *bgp_nb_cand_peer_group_by_name(const struct lyd_node *dnode,
						      const char *name)
{
	const struct lyd_node *bgp;

	if (!dnode || !name)
		return NULL;
	bgp = bgp_nb_cand_bgp_node(dnode);
	if (!bgp)
		return NULL;
	return yang_dnode_getf(bgp, "peer-groups/peer-group[peer-group-name='%s']", name);
}

const struct lyd_node *bgp_nb_cand_peer_group(const struct lyd_node *peer_dnode)
{
	const struct lyd_node *nbr = bgp_nb_cand_peer_node(peer_dnode);

	if (!nbr || bgp_nb_cand_is_peer_group_list(nbr))
		return NULL;
	if (!yang_dnode_exists(nbr, "peer-group"))
		return NULL;
	return bgp_nb_cand_peer_group_by_name(nbr, yang_dnode_get_string(nbr, "peer-group"));
}

bool bgp_nb_cand_group_members(const struct lyd_node *group_dnode, bgp_nb_cand_member_cb cb,
			       void *arg)
{
	const struct lyd_node *grp;
	const struct lyd_node *bgp_node, *list, *member;
	const char *gname;

	if (!group_dnode || !cb)
		return true;

	grp = bgp_nb_cand_is_peer_group_list(group_dnode)
		      ? group_dnode
		      : yang_dnode_get_parent(group_dnode, "peer-group");
	if (!grp || !yang_dnode_exists(grp, "peer-group-name"))
		return true;

	gname = yang_dnode_get_string(grp, "peer-group-name");
	bgp_node = bgp_nb_cand_bgp_node(grp);
	list = bgp_node ? yang_dnode_get(bgp_node, "neighbors") : NULL;
	if (!gname || !list)
		return true;

	LY_LIST_FOR (lyd_child(list), member) {
		if (!strmatch(member->schema->name, "neighbor") &&
		    !strmatch(member->schema->name, "unnumbered-neighbor"))
			continue;
		if (!yang_dnode_exists(member, "peer-group"))
			continue;
		if (!strmatch(yang_dnode_get_string(member, "peer-group"), gname))
			continue;
		if (!cb(member, arg))
			return false;
	}
	return true;
}

static const struct lyd_node *bgp_nb_cand_remote_as_source(const struct lyd_node *nbr)
{
	const struct lyd_node *group;

	if (!nbr)
		return NULL;
	if (yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type"))
		return nbr;

	group = bgp_nb_cand_peer_group(nbr);
	if (group && yang_dnode_exists(group, "neighbor-remote-as/remote-as-type"))
		return group;
	return nbr;
}

static as_t bgp_nb_cand_peer_local_as(const struct lyd_node *nbr, const struct lyd_node *bgp_node)
{
	if (nbr && yang_dnode_exists(nbr, "local-as/local-as"))
		return yang_dnode_get_uint32(nbr, "local-as/local-as");

	if (nbr && !strmatch(nbr->schema->name, "peer-group")) {
		const struct lyd_node *group = bgp_nb_cand_peer_group(nbr);

		if (group && yang_dnode_exists(group, "local-as/local-as"))
			return yang_dnode_get_uint32(group, "local-as/local-as");
	}

	if (bgp_node && yang_dnode_exists(bgp_node, "global/local-as"))
		return yang_dnode_get_uint32(bgp_node, "global/local-as");
	return 0;
}

struct cand_first_member_ctx {
	const struct lyd_node *first;
};

static bool bgp_nb_cand_first_member_cb(const struct lyd_node *member, void *arg)
{
	struct cand_first_member_ctx *ctx = arg;

	ctx->first = member;
	return false;
}

static enum bgp_peer_sort bgp_nb_cand_peer_sort_single(const struct lyd_node *nbr,
						       const struct lyd_node *bgp_node)
{
	const struct lyd_node *src;
	const char *as_type = NULL;
	as_t bgp_as, local_as, remote_as = 0, confed_id = 0;
	bool has_as_type = false;

	if (!nbr)
		return BGP_PEER_INTERNAL;

	bgp_as = (bgp_node && yang_dnode_exists(bgp_node, "global/local-as"))
			 ? yang_dnode_get_uint32(bgp_node, "global/local-as")
			 : 0;
	local_as = bgp_nb_cand_peer_local_as(nbr, bgp_node);

	/* Peer-group */
	if (strmatch(nbr->schema->name, "peer-group")) {
		struct cand_first_member_ctx fctx = { NULL };

		if (yang_dnode_exists(nbr, "neighbor-remote-as/remote-as-type")) {
			as_type = yang_dnode_get_string(nbr, "neighbor-remote-as/remote-as-type");
			if (strmatch(as_type, "internal"))
				return BGP_PEER_IBGP;
			if (strmatch(as_type, "external"))
				return BGP_PEER_EBGP;
			if (strmatch(as_type, "as-specified") &&
			    yang_dnode_exists(nbr, "neighbor-remote-as/remote-as")) {
				remote_as = yang_dnode_get_uint32(nbr,
								  "neighbor-remote-as/remote-as");
				if (remote_as)
					return local_as == remote_as ? BGP_PEER_IBGP
								     : BGP_PEER_EBGP;
			}
		}

		/*
		 * Untyped peer-group: mirror peer_calc_sort() by taking the
		 * first member's sort, or BGP_PEER_INTERNAL when empty or
		 * when that member has remote-as auto.
		 */
		bgp_nb_cand_group_members(nbr, bgp_nb_cand_first_member_cb, &fctx);
		if (fctx.first) {
			if (yang_dnode_exists(fctx.first, "neighbor-remote-as/remote-as-type") &&
			    strmatch(yang_dnode_get_string(fctx.first,
							   "neighbor-remote-as/remote-as-type"),
				     "auto"))
				return BGP_PEER_INTERNAL;
			return bgp_nb_cand_peer_sort_single(fctx.first, bgp_node);
		}
		return BGP_PEER_INTERNAL;
	}

	/* Normal peer (neighbor or unnumbered-neighbor) */
	src = bgp_nb_cand_remote_as_source(nbr);
	if (src && yang_dnode_exists(src, "neighbor-remote-as/remote-as-type")) {
		has_as_type = true;
		as_type = yang_dnode_get_string(src, "neighbor-remote-as/remote-as-type");
		if (strmatch(as_type, "as-specified") &&
		    yang_dnode_exists(src, "neighbor-remote-as/remote-as"))
			remote_as = yang_dnode_get_uint32(src, "neighbor-remote-as/remote-as");
	}

	if (bgp_node && yang_dnode_exists(bgp_node, "global/confederation/identifier"))
		confed_id = yang_dnode_get_uint32(bgp_node, "global/confederation/identifier");

	if (confed_id) {
		if (local_as == 0)
			return BGP_PEER_INTERNAL;
		if (has_as_type && strmatch(as_type, "internal"))
			return BGP_PEER_IBGP;
		if (has_as_type && strmatch(as_type, "external"))
			return BGP_PEER_EBGP;

		if (local_as == remote_as) {
			if (bgp_as == confed_id)
				return local_as == bgp_as ? BGP_PEER_IBGP : BGP_PEER_EBGP;
			if (remote_as == confed_id)
				return BGP_PEER_IBGP;
			if (local_as == confed_id)
				return BGP_PEER_EBGP;
			return BGP_PEER_IBGP;
		}

		if (remote_as && bgp_node &&
		    yang_dnode_existsf(bgp_node, "global/confederation/member-as[.='%u']",
				       remote_as))
			return BGP_PEER_CONFED;

		return BGP_PEER_EBGP;
	}

	if (!has_as_type)
		return BGP_PEER_UNSPECIFIED;

	if (strmatch(as_type, "internal"))
		return BGP_PEER_IBGP;
	if (strmatch(as_type, "external"))
		return BGP_PEER_EBGP;

	/*
	 * Both as-specified and unresolved remote-as auto (remote_as == 0)
	 * mirror peer_calc_sort(): local_as == 0 -> INTERNAL,
	 * local_as == remote_as -> IBGP, else EBGP.
	 */
	if (local_as == 0)
		return BGP_PEER_INTERNAL;
	return local_as == remote_as ? BGP_PEER_IBGP : BGP_PEER_EBGP;
}

enum bgp_peer_sort bgp_nb_cand_peer_sort(const struct lyd_node *peer_dnode)
{
	const struct lyd_node *nbr = bgp_nb_cand_peer_node(peer_dnode);
	const struct lyd_node *bgp_node = bgp_nb_cand_bgp_node(nbr);

	return bgp_nb_cand_peer_sort_single(nbr, bgp_node);
}

struct cand_member_sort_ctx {
	const struct lyd_node *bgp_node;
	enum bgp_peer_sort req_sort;
	bool require_equal;
};

static bool bgp_nb_cand_member_sort_cb(const struct lyd_node *member, void *arg)
{
	struct cand_member_sort_ctx *ctx = arg;
	enum bgp_peer_sort msort = bgp_nb_cand_peer_sort_single(member, ctx->bgp_node);

	if (ctx->require_equal ? (msort != ctx->req_sort) : (msort == ctx->req_sort))
		return false;
	return true;
}

bool bgp_nb_cand_group_members_match_sort(const struct lyd_node *group_dnode,
					  enum bgp_peer_sort req_sort, bool require_equal)
{
	struct cand_member_sort_ctx ctx = {
		.bgp_node = bgp_nb_cand_bgp_node(group_dnode),
		.req_sort = req_sort,
		.require_equal = require_equal,
	};

	return bgp_nb_cand_group_members(group_dnode, bgp_nb_cand_member_sort_cb, &ctx);
}

int bgp_nb_cand_parse_default_afi_safi(const char *afi_safi, afi_t *afi, safi_t *safi,
				       char *errmsg, size_t errmsg_len)
{
	char buf[64];
	char *tok = NULL;
	char *afi_str;
	char *safi_str;

	if (!afi_safi) {
		if (errmsg && errmsg_len)
			snprintfrr(errmsg, errmsg_len, "Invalid AFI/SAFI");
		return NB_ERR_VALIDATION;
	}

	strlcpy(buf, afi_safi, sizeof(buf));
	afi_str = strtok_r(buf, "-", &tok);
	safi_str = strtok_r(NULL, "-", &tok);
	if (!afi_str || !safi_str) {
		if (errmsg && errmsg_len)
			snprintfrr(errmsg, errmsg_len, "Invalid AFI/SAFI %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	*afi = bgp_vty_afi_from_str(afi_str);
	if (*afi == AFI_MAX) {
		if (errmsg && errmsg_len)
			snprintfrr(errmsg, errmsg_len, "Invalid AFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}

	if (strmatch(safi_str, "labeled"))
		*safi = bgp_vty_safi_from_str("labeled-unicast");
	else
		*safi = bgp_vty_safi_from_str(safi_str);

	if (*safi == SAFI_MAX) {
		if (errmsg && errmsg_len)
			snprintfrr(errmsg, errmsg_len, "Invalid SAFI in %s", afi_safi);
		return NB_ERR_VALIDATION;
	}
	return NB_OK;
}

static void bgp_nb_cand_fill_default_afs(const struct lyd_node *bgp_node,
					 bool enabled[AFI_MAX][SAFI_MAX])
{
	const struct lyd_node *global;
	const struct lyd_node *child;

	if (!bgp_node)
		return;
	global = yang_dnode_get(bgp_node, "global");
	if (!global)
		return;

	LY_LIST_FOR (lyd_child(global), child) {
		afi_t a;
		safi_t s;

		if (!strmatch(child->schema->name, "default-afi-safi"))
			continue;
		if (bgp_nb_cand_parse_default_afi_safi(yang_dnode_get_string(child, NULL), &a, &s,
						       NULL, 0) == NB_OK)
			enabled[a][s] = true;
	}
}

bool bgp_nb_cand_default_af(const struct lyd_node *dnode, afi_t afi, safi_t safi)
{
	const struct lyd_node *bgp_node = bgp_nb_cand_bgp_node(dnode);
	bool enabled[AFI_MAX][SAFI_MAX] = {};

	if (afi <= AFI_UNSPEC || afi >= AFI_MAX || safi <= SAFI_UNSPEC || safi >= SAFI_MAX)
		return false;

	bgp_nb_cand_fill_default_afs(bgp_node, enabled);
	return enabled[afi][safi];
}

static void bgp_nb_cand_overlay_peer_afs(const struct lyd_node *peer_node,
					 bool enabled[AFI_MAX][SAFI_MAX])
{
	const struct lyd_node *af_list, *af;

	if (!peer_node)
		return;
	af_list = yang_dnode_get(peer_node, "afi-safis");
	if (!af_list)
		return;

	LY_LIST_FOR (lyd_child(af_list), af) {
		afi_t a = AFI_UNSPEC;
		safi_t s = SAFI_UNSPEC;
		const char *name;

		if (!strmatch(af->schema->name, "afi-safi"))
			continue;
		if (!yang_dnode_exists(af, "afi-safi-name") || !yang_dnode_exists(af, "enabled"))
			continue;
		name = yang_dnode_get_string(af, "afi-safi-name");
		yang_afi_safi_identity2value(name, &a, &s);
		if (a > AFI_UNSPEC && a < AFI_MAX && s > SAFI_UNSPEC && s < SAFI_MAX)
			enabled[a][s] = yang_dnode_get_bool(af, "enabled");
	}
}

void bgp_nb_cand_enabled_afs(const struct lyd_node *peer_dnode, bool enabled[AFI_MAX][SAFI_MAX])
{
	const struct lyd_node *nbr = bgp_nb_cand_peer_node(peer_dnode);
	const struct lyd_node *bgp_node = bgp_nb_cand_bgp_node(nbr);
	const struct lyd_node *grp;

	memset(enabled, 0, sizeof(bool) * AFI_MAX * SAFI_MAX);
	if (!nbr)
		return;

	bgp_nb_cand_fill_default_afs(bgp_node, enabled);

	grp = bgp_nb_cand_peer_group(nbr);
	if (grp)
		bgp_nb_cand_overlay_peer_afs(grp, enabled);

	bgp_nb_cand_overlay_peer_afs(nbr, enabled);
}

bool bgp_nb_cand_peer_af_enabled(const struct lyd_node *peer_dnode, afi_t afi, safi_t safi)
{
	bool enabled[AFI_MAX][SAFI_MAX];

	if (afi <= AFI_UNSPEC || afi >= AFI_MAX || safi <= SAFI_UNSPEC || safi >= SAFI_MAX)
		return false;

	bgp_nb_cand_enabled_afs(peer_dnode, enabled);
	return enabled[afi][safi];
}
